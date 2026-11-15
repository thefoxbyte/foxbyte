// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// The decision an unattended process makes at four in the morning.
//
// The two wrong answers cost different amounts, and that asymmetry is the whole
// design: promoting while the primary is alive gives two primaries and two
// divergent copies that cannot be merged, and failing to promote a dead one
// gives an outage somebody ends. So every uncertain case must resolve to not
// promoting.
func TestWatchDecide(t *testing.T) {
	const after = time.Minute
	cases := []struct {
		what      string
		primaryUp bool
		view      witnessView
		downFor   time.Duration
		want      watchAction
	}{
		{"the primary answers", true, witnessSilent, 0, watchWait},
		{"…even if the witness is confused", true, witnessPrimaryDown, 0, watchWait},
		{"gone, but not for long enough", false, witnessPrimaryDown, 30 * time.Second, watchWait},
		{"gone, and the witness agrees", false, witnessPrimaryDown, time.Minute, watchPromote},
		{"…and well past the threshold", false, witnessPrimaryDown, time.Hour, watchPromote},
		{"the witness reaches it: this machine is the cut-off one", false, witnessPrimaryUp, time.Hour, watchRefuse},
		{"no second opinion to be had", false, witnessSilent, time.Hour, watchBlind},
	}
	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			if got := watchDecide(c.primaryUp, c.view, c.downFor, after); got != c.want {
				t.Errorf("watchDecide(%v, %v, %s) = %v, want %v", c.primaryUp, c.view, c.downFor, got, c.want)
			}
		})
	}
}

// Stated as a property rather than inferred from the table: exactly one
// combination promotes, and it is the one where two independent observers agree
// for long enough.
func TestOnlyAgreementPromotes(t *testing.T) {
	for _, up := range []bool{true, false} {
		for _, v := range []witnessView{witnessSilent, witnessPrimaryUp, witnessPrimaryDown} {
			for _, d := range []time.Duration{0, time.Second, time.Minute, time.Hour} {
				got := watchDecide(up, v, d, time.Minute)
				agreed := !up && v == witnessPrimaryDown && d >= time.Minute
				if (got == watchPromote) != agreed {
					t.Errorf("primaryUp=%v %v downFor=%s decided %v", up, v, d, got)
				}
			}
		}
	}
	// And the one combination is the one the loop and the log agree on.
	if !witnessAgreesPrimaryIsGone(witnessPrimaryDown) {
		t.Error("the agreement test disagrees with the decision")
	}
	for _, v := range []witnessView{witnessSilent, witnessPrimaryUp} {
		if witnessAgreesPrimaryIsGone(v) {
			t.Errorf("%v counts as agreement", v)
		}
	}
}

// A silent witness is not a witness. The distinction between "it says the
// primary is fine" and "it did not answer" has to survive into the log, or an
// operator cannot tell a quiet healthy night from a watcher that has been
// unable to do its job since Tuesday.
func TestABlindWatcherSaysSoDistinctly(t *testing.T) {
	if watchDecide(false, witnessSilent, time.Hour, time.Minute) == watchDecide(false, witnessPrimaryUp, time.Hour, time.Minute) {
		t.Error("being unable to ask and being told no are the same decision")
	}
	if witnessSilent.String() == witnessPrimaryUp.String() {
		t.Error("…and they read the same in a log line")
	}
	for _, v := range []witnessView{witnessSilent, witnessPrimaryUp, witnessPrimaryDown} {
		if v.String() == "" {
			t.Errorf("view %d has no words", v)
		}
	}
}

// Refused without a witness, and that refusal is the feature: an automatic
// failover configured without a third opinion is a scheduled split brain, so
// the command does not work rather than working most of the time.
func TestWatchRefusesWithoutAWitness(t *testing.T) {
	err := Watch(WatchOptions{})
	if err == nil {
		t.Fatal("ha watch ran with no witness")
	}
	for _, want := range []string{"needs a witness", "two primaries", "ha witness"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, err)
		}
	}
}

// Refused without a token too, and an older setup (no token, an http:// URL)
// is told what to change rather than watching in a mode a forged answer could
// steer.
func TestWatchRefusesWithoutAWayToTrustTheWitness(t *testing.T) {
	err := Watch(WatchOptions{Witness: "https://witness.example:7070" + WitnessPath})
	if !errors.Is(err, errWitnessToken) {
		t.Fatalf("ha watch ran with no token: %v", err)
	}
	for _, want := range []string{"--token", "HA_WITNESS_TOKEN"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say how to set one (%q): %v", want, err)
		}
	}
	if err := Watch(WatchOptions{Witness: "https://w:7070" + WitnessPath, Token: "short"}); !errors.Is(err, errWitnessToken) {
		t.Errorf("a short token was accepted: %v", err)
	}
	err = Watch(WatchOptions{Witness: "http://w:7070" + WitnessPath, Token: strings.Repeat("k", 32)})
	if err == nil || !strings.Contains(err.Error(), "https://") {
		t.Errorf("a plain-HTTP witness URL was accepted, or the refusal does not say https: %v", err)
	}
}

// One round, given a witness whose answer did not verify. Whatever view comes
// back with the error, the round decides not to promote.
func TestAWitnessAnswerThatFailsVerificationNeverPromotes(t *testing.T) {
	failed := errors.New("the witness's answer failed verification")
	for _, v := range []witnessView{witnessPrimaryDown, witnessPrimaryUp, witnessSilent} {
		action, got, _, err := watchRound(false, time.Hour, 0, func() (witnessView, WitnessAnswer, error) {
			return v, WitnessAnswer{Reachable: false}, failed
		})
		if action == watchPromote {
			t.Errorf("an unverified %v promoted", v)
		}
		if action != watchBlind || got != witnessSilent || err == nil {
			t.Errorf("an unverified %v gave %v / %v / %v, want blind and silent with the error", v, action, got, err)
		}
	}
	// And a verified agreement still promotes, so the check is not simply
	// switching the feature off.
	if action, _, _, _ := watchRound(false, time.Hour, 0, func() (witnessView, WitnessAnswer, error) {
		return witnessPrimaryDown, WitnessAnswer{}, nil
	}); action != watchPromote {
		t.Errorf("a verified agreement decided %v", action)
	}
	// The witness is not asked while the primary answers.
	asked := false
	watchRound(true, 0, 0, func() (witnessView, WitnessAnswer, error) { asked = true; return witnessSilent, WitnessAnswer{}, nil })
	if asked {
		t.Error("the witness was asked while the primary answered")
	}
}

func TestWatchDefaultsLandInsideTheMinuteThePlanPromises(t *testing.T) {
	o := WatchOptions{After: -1}
	o.withDefaults()
	if o.After > time.Minute {
		t.Errorf("a promotion waits %s, which is past the minute phase 3 promises", o.After)
	}
	if o.Interval <= 0 || o.After/o.Interval < 3 {
		t.Errorf("%s/%s is too few rounds for a decision this expensive", o.After, o.Interval)
	}
	// And a caller's own values are kept.
	custom := WatchOptions{Interval: time.Second, After: 5 * time.Second}
	custom.withDefaults()
	if custom.Interval != time.Second || custom.After != 5*time.Second {
		t.Errorf("the defaults overwrote what was asked for: %+v", custom)
	}
	// Zero is a request and must survive: it is how a drill asks for a
	// promotion as soon as both observers agree. An interval of zero is only
	// ever an omission, since a watcher without one is a busy loop.
	drill := WatchOptions{After: 0, Interval: 0}
	drill.withDefaults()
	if drill.After != 0 {
		t.Errorf("--after 0s became %s, so a drill cannot ask for an immediate decision", drill.After)
	}
	if drill.Interval != watchIntervalDefault {
		t.Errorf("an omitted interval became %s", drill.Interval)
	}
}
