// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"log"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// Automatic failover — phase 3 of docs/FOX_HA_Plan.md, whose unlock is
// "recovery in about a minute with nobody awake".
//
// The watcher runs on the standby node. Every round it asks two independent
// questions — can I reach the primary, and can the witness (witness.go) — and
// promotes only when both say no, for long enough. The promotion itself is the
// ordinary fenced HAFailover: nothing here reimplements promotion, and nothing
// here skips the fence. `--force` is not reachable from the watcher at all,
// because the one thing an unattended process must never do is decide that a
// primary it cannot see has definitely gone.
//
// The plan says "do not write your own failover", and this takes that
// seriously: what is written here is the detection and the trigger, under a
// fence that already exists and a quorum that is refused rather than assumed.
// The promotion is pg_promote(), the fence is a probe of the primary, and the
// decision is a pure function below so it can be read without a cluster.
//
// Opt-in, and refused without a witness, or without the token that lets this
// machine check the witness's answers (witness.go). That refusal is the feature: two
// machines cannot tell a dead primary from an unreachable one, so an automatic
// failover configured without a third opinion is a scheduled split brain. It
// is better for the command not to work than for it to work most of the time.

// WatchOptions is how the watcher is configured.
type WatchOptions struct {
	Witness string // the witness's https URL (required)
	Token   string // the token shared with the witness (required)
	// Fingerprint pins the witness's certificate (its SHA-256, as the witness
	// prints it). Optional: the answer's MAC already authenticates it.
	Fingerprint string
	Interval    time.Duration // how often to look
	After       time.Duration // how long the primary must be unreachable before promoting
	Once        bool          // run one round and report, for a drill or a check
	DryRun      bool          // decide and say so, but never promote
	// AcceptUnfenced is the operator saying, with --accept-unfenced, that a
	// promotion may go ahead on the witness's word although the old primary,
	// on another machine, cannot be confirmed stopped. Required to promote.
	AcceptUnfenced bool
}

// Defaults chosen for the plan's "about a minute": a look every 10s and a
// promotion after 60s of agreement means the decision is made on six
// consecutive rounds, and recovery lands inside the minute the plan promises
// rather than at the end of it.
const (
	watchIntervalDefault = 10 * time.Second
	watchAfterDefault    = 60 * time.Second
	watchAskTimeout      = 5 * time.Second
)

// withDefaults fills in what was not asked for.
//
// A negative After means "not set", not "zero": `--after 0s` is a real request —
// promote as soon as both observers agree — and it is how a drill is run. An
// interval of zero is never a request, only an omission, since a watcher with no
// interval is a busy loop.
func (o *WatchOptions) withDefaults() {
	if o.Interval <= 0 {
		o.Interval = watchIntervalDefault
	}
	if o.After < 0 {
		o.After = watchAfterDefault
	}
}

// watchAction is what a round decides.
type watchAction int

const (
	watchWait    watchAction = iota // the primary is there, or not for long enough
	watchRefuse                     // the primary is there as far as somebody else can tell
	watchBlind                      // no second opinion to be had
	watchPromote                    // both agree, long enough: take over
)

func (a watchAction) String() string {
	switch a {
	case watchRefuse:
		return "refuse"
	case watchBlind:
		return "blind"
	case watchPromote:
		return "promote"
	}
	return "wait"
}

// watchDecide is the whole decision, as a function of what was observed.
//
// Pure, and table-tested, because this is the code that will run unattended at
// four in the morning and the cost of each wrong answer is different:
//
//   - promoting when the primary is alive gives two primaries and two
//     divergent copies that cannot be merged. Unrecoverable.
//   - failing to promote when it is dead gives an outage that a person ends.
//     Recoverable.
//
// So every uncertain case resolves to not promoting, and the two that matter
// are named rather than folded into "wait": watchRefuse is somebody else
// saying the primary is fine, which means *this* machine is the one that is
// cut off; watchBlind is having no second opinion at all, which is the same
// answer for a different reason and must be logged differently or an operator
// reading the log cannot tell a healthy quiet night from a watcher that has
// been unable to do its job since Tuesday.
func watchDecide(primaryUp bool, v witnessView, downFor, after time.Duration) watchAction {
	if primaryUp {
		return watchWait
	}
	switch {
	case v == witnessPrimaryUp:
		return watchRefuse
	case v == witnessSilent:
		return watchBlind
	}
	if downFor < after {
		return watchWait
	}
	return watchPromote
}

// Watch runs the watcher. It returns when it has promoted, when one round was
// asked for, or on an error it cannot act under.
func Watch(o WatchOptions) error {
	o.withDefaults()
	if o.Witness == "" {
		return fmt.Errorf("automatic failover needs a witness: two machines cannot tell a dead primary "+
			"from one they cannot reach, so a promotion decided here alone would eventually make two "+
			"primaries. Run `%s ha witness --primary <primary-address>` on a third host — where the "+
			"clients are, not beside either database — and point this at it with --witness", brand.CLI)
	}
	// Refused rather than run without a way to trust the answer. A watcher
	// from an older release has neither a token nor an https URL; it stops
	// here with the instructions, instead of watching in a mode that a forged
	// answer could steer.
	if err := checkWitnessToken(o.Token); err != nil {
		return err
	}
	if err := checkWitnessURL(o.Witness); err != nil {
		return err
	}
	j, ok := CurrentJoin()
	if !ok {
		return fmt.Errorf("this machine is not following a primary, so there is nothing to watch for — "+
			"`%s ha watch` runs on a standby that joined a primary elsewhere (`%s node join`)",
			brand.CLI, brand.CLI)
	}
	// The primary a watcher watches is always on another machine, which this
	// one cannot stop or see stopped. Two observers agreeing it is unreachable
	// is the best evidence there is, and still not proof, so a promotion on it
	// is something an operator has to have said yes to. --dry-run promotes
	// nothing and needs no such yes.
	if !o.DryRun && !o.AcceptUnfenced {
		return fmt.Errorf("automatic failover needs --accept-unfenced: the primary is on another machine, and " +
			"this one cannot stop it or confirm that it has stopped before promoting. If it is in fact still " +
			"serving clients that neither this machine nor the witness can see, the writes it takes after the " +
			"promotion are lost. Pass --accept-unfenced to accept that, or --dry-run to watch without promoting")
	}
	if ContainerState("standby") != "running" {
		return fmt.Errorf("this machine has no running copy to promote — `%s ha status` says what it is doing",
			brand.CLI)
	}

	fmt.Printf("watching %s:%d, asking %s for a second opinion every %s.\n",
		j.Address, j.Port, o.Witness, o.Interval)
	fmt.Printf("a promotion happens when both cannot reach it for %s, and never on one opinion.\n", o.After)
	if o.DryRun {
		fmt.Println("--dry-run: every decision is printed and none is acted on.")
	}
	fmt.Printf("the witness must be able to reach the primary the way clients do; put it where they are,\n" +
		"or it will agree with this machine about a primary that is serving somebody else.\n\n")

	var downSince time.Time
	for {
		primaryUp := RemotePrimaryAnswering(j, watchAskTimeout)
		if primaryUp {
			downSince = time.Time{}
		} else if downSince.IsZero() {
			downSince = time.Now()
		}
		downFor := time.Duration(0)
		if !downSince.IsZero() {
			downFor = time.Since(downSince)
		}
		action, v, answer, askErr := watchRound(primaryUp, downFor, o.After, func() (witnessView, WitnessAnswer, error) {
			return AskWitness(WitnessAsk{URL: o.Witness, Token: o.Token, Fingerprint: o.Fingerprint, Timeout: watchAskTimeout})
		})
		report(action, j, v, answer, askErr, downFor)

		if action == watchPromote && !o.DryRun {
			if err := promoteUnattended(j, answer, downFor, o.AcceptUnfenced); err != nil {
				log.Printf("ha watch: the promotion did not happen: %v", err)
				// Not fatal: the fence refusing is the system working. Keep
				// watching — if the primary really has gone, the next round
				// will find the fence satisfied.
			} else {
				return nil
			}
		}
		if o.Once {
			return nil
		}
		time.Sleep(o.Interval)
	}
}

// watchRound is one round's decision, given whether this machine reaches the
// primary and a way to ask the witness. Separate from the loop so a test can
// hand it a witness whose answers fail verification and see what it decides.
//
// The witness is only asked when it matters: it is somebody else's machine, and
// there is no reason to talk to it while the primary answers. An error from the
// asking always means no opinion, whatever view came with it, so an answer that
// failed a check can never count as agreement.
func watchRound(primaryUp bool, downFor, after time.Duration,
	ask func() (witnessView, WitnessAnswer, error)) (watchAction, witnessView, WitnessAnswer, error) {
	v := witnessSilent
	var answer WitnessAnswer
	var err error
	if !primaryUp {
		v, answer, err = ask()
		if err != nil {
			v = witnessSilent
		}
	}
	return watchDecide(primaryUp, v, downFor, after), v, answer, err
}

func report(a watchAction, j Joined, v witnessView, answer WitnessAnswer, askErr error, downFor time.Duration) {
	switch a {
	case watchWait:
		if downFor == 0 {
			return // the ordinary case: say nothing every ten seconds
		}
		log.Printf("ha watch: %s:%d unreachable for %s; %s", j.Address, j.Port, downFor.Round(time.Second), v)
	case watchRefuse:
		log.Printf("ha watch: NOT promoting — %s:%d is unreachable from here but %s reaches it. "+
			"This machine is the one that is cut off; promoting would make a second primary",
			j.Address, j.Port, answer.Witness)
	case watchBlind:
		log.Printf("ha watch: NOT promoting — %s:%d is unreachable and the witness could not be asked (%v). "+
			"A promotion needs two opinions and there is one", j.Address, j.Port, askErr)
	case watchPromote:
		log.Printf("ha watch: promoting — %s:%d unreachable for %s, and %s cannot reach it either",
			j.Address, j.Port, downFor.Round(time.Second), answer.Witness)
	}
}

// promoteUnattended takes over, and records it where an incident review will
// look. The fence is not skipped: the failover probes the primary again
// itself, so a primary that came back between the decision and the act stops
// this. The record says fencing was not confirmed, because across machines it
// never can be.
func promoteUnattended(j Joined, answer WitnessAnswer, downFor time.Duration, acceptUnfenced bool) error {
	detail := fmt.Sprintf("%s:%d unreachable for %s; witness %s agreed",
		j.Address, j.Port, downFor.Round(time.Second), answer.Witness)
	if err := haFailover(failoverAsk{unattended: true, witnessAgreed: true, acceptUnfenced: acceptUnfenced}); err != nil {
		auditWatch(auth.EvFailoverRefused, detail+"; refused: "+err.Error())
		return err
	}
	auditWatch(auth.EvFailoverPromoted, detail+"; fencing not confirmed (the old primary is on another machine), accepted by --accept-unfenced")
	fmt.Printf("\nthis machine is the primary now. %s must not be started as a primary again:\n"+
		"bring it back with `%s node join` against this machine, which replaces its copy.\n",
		j.Address, brand.CLI)
	return nil
}

// auditWatch writes to the security log, which is append-only and hash-chained
// and — because phase 2 deliberately left that log on each node — still
// writable here while the primary is gone.
func auditWatch(kind, detail string) {
	s, err := auth.OpenFromEnv()
	if err != nil {
		log.Printf("ha watch: could not record %s in the security log: %v", kind, err)
		return
	}
	defer s.Close()
	s.Audit(kind, "ha-watch", "", "", detail)
}
