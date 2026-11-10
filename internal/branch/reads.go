// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// Reads from the standby — phase 7 of docs/FOX_HA_Plan.md, which asks for
// read-only sessions routed to a standby "through a separate database name".
//
// The standby already exists for one reason: to take over. Between failovers it
// holds a complete, continuously updated copy of the database and answers
// nothing, while every analytical query, every report and every dashboard
// refresh competes with the writes on the primary. This routes those sessions
// to the copy.
//
// What it buys, stated honestly, because the plan calls this "a performance
// feature" and performance claims are the easiest kind to overstate:
//
//   - On one machine — the topology `ha enable` builds — the gain is process
//     isolation, not more hardware. A long sequential scan stops evicting the
//     primary's buffer cache and stops competing for its backends, which is
//     real and modest. It is not read scaling: the same disk and the same CPUs
//     serve both.
//   - Across two machines it is read scaling, and that is where the feature is
//     worth having. It is refused today, by measurement rather than by
//     caution: a joined node's copy carries the *primary's* roles, whose
//     passwords derive from the primary's install secret, while the standby
//     machine's gateway has its own secret and its own accounts. The login
//     fails. That is the shared state of plan §3.2 and phase 2, and no amount
//     of routing fixes it from here.
//
// What it costs is staleness. Replication is asynchronous unless `ha sync on`
// says otherwise, so a read here may be behind the primary — usually by
// milliseconds, by more when the primary is busy or the link is slow. A session
// that cannot tolerate that belongs on the primary, which is the default and
// stays the default. `ha status` shows how far behind the standby is.
//
// Deliberately not done here: refusing a read when the lag exceeds some bound.
// Staleness is inherent to the feature rather than a fault in it, there is no
// defensible default for the bound, and a connection that works or not
// depending on how busy the primary was a second ago is worse than one that is
// slightly behind. The lag is reported instead, everywhere it is visible.

// StandbySuffix turns a branch name into the routing key for its standby, which
// is how a session says "the copy, not the primary".
//
// ':' because it is the one readable separator a branch can never contain
// (safeNameRe allows letters, digits, '.', '-' and '_'), so this reserves a
// namespace without reserving any name somebody might want. '@' would read
// well and was rejected for a mundane reason: it survives a correct URI parser
// but not a naive one, and DSNs are pasted into every language's client. A
// password-bearing DSN already has an '@', and a parser that splits on the last
// one would take `postgresql://user:key@host:6432/main@standby` apart in the
// wrong place and dial a host called "standby".
const StandbySuffix = ":standby"

// SplitReadTarget separates a gateway routing key into the branch it names and
// whether the session asked for that branch's standby. Pure: the gateway
// resolves this before it checks anything, so every later check — the ACL, a
// key's scope, the audit record — is about the branch rather than about a name
// with a suffix on it.
func SplitReadTarget(key string) (name string, standby bool) {
	if n, ok := strings.CutSuffix(key, StandbySuffix); ok && n != "" {
		return n, true
	}
	return key, false
}

// StandbyReadName is the routing key for a branch's standby, for the places
// that print one.
func StandbyReadName(name string) string { return name + StandbySuffix }

// ErrNoStandbyRead reports that this install has no standby copy to read from.
// A sentinel because the gateway answers it differently from a transient
// refusal: no amount of retrying produces a standby nobody asked for.
var ErrNoStandbyRead = errors.New("no standby to read from")

// StandbyReadAddr is the backend a read-only session should be sent to, or why
// it cannot be.
func StandbyReadAddr(name string) (string, error) {
	// From the gateway's connect path, so on the short deadline. A refusal is
	// all that can come of a poor answer, and the client tries again.
	state := "absent"
	if f, err := containers.lookup(container("standby")); err == nil {
		state = f.state
	}
	if err := standbyReadRefusal(name, primaryBranch(), state, IsStandbyNode()); err != nil {
		return "", err
	}
	return BackendAddr("standby")
}

// standbyReadRefusal is the judgement: given where the primary is, what the
// standby container is doing and whether this machine follows a primary
// elsewhere, may a read-only session be routed to the standby?
//
// Pure, and tested, because three of the four refusals are states an install
// reaches on a bad day — mid-failover, mid-rebuild, or on the second machine —
// and the wrong answer in any of them is worse than the feature is worth. The
// one that matters most is the promoted standby: a read-only DSN that silently
// became a connection to the primary would keep working, keep looking right,
// and quietly put every read back on the machine the reader was trying to
// spare.
func standbyReadRefusal(name, primary, standbyState string, joined bool) error {
	if standbyState == "absent" {
		return fmt.Errorf("%w: this install has no standby — `%s ha enable` builds one",
			ErrNoStandbyRead, brand.CLI)
	}
	if joined {
		// This machine follows a primary elsewhere, so its copy was taken from
		// that primary and carries that primary's roles. Their passwords come
		// from the primary's install secret, which `node join` deliberately
		// does not carry (the token holds one replication role's password and
		// the CA, nothing that could derive the superuser's). This gateway
		// would authenticate against them with passwords of its own.
		return fmt.Errorf("%w: this machine follows a primary elsewhere, and its copy carries that "+
			"primary's roles while this install's keys are its own — reads from a second machine need "+
			"shared state (`%s ha status` names the primary)", ErrNoStandbyRead, brand.CLI)
	}
	if primary != "main" {
		return fmt.Errorf("the standby was promoted and is serving as the primary, so there is no "+
			"second copy to read from — `%s ha failback` rebuilds one, and until then reads belong "+
			"on %q", brand.CLI, "main")
	}
	if name != "main" {
		// Said this way rather than "branch %q is a clone", because this path
		// never asks whether the branch exists: the gateway's ACL has already
		// answered a name nobody may open, and claiming a non-existent branch
		// is a clone on this machine would be a confident lie.
		return fmt.Errorf("%w: only main has a standby, so there is no %q — connect to %q",
			ErrNoStandbyRead, StandbyReadName(name), name)
	}
	if standbyState != "running" {
		return fmt.Errorf("the standby is %s, so it has nothing to answer with — `%s ha status` says "+
			"what it is doing", standbyState, brand.CLI)
	}
	return nil
}

// standbyRoleWait is how long a read-only session waits for a role the primary
// has just been given to reach the standby. Long enough for streaming
// replication to carry one catalogue change, short enough that nobody notices:
// it is paid once per role per process, and only by the first read-only session
// a new account opens.
const standbyRoleWait = 2 * time.Second

// StandbyKnowsRole reports whether the standby has replayed a role yet, waiting
// briefly for it.
//
// Roles are cluster-wide and physically replicated, so a role the primary has
// is a role the standby has — a moment later. The gateway creates a per-user
// role on first use (EnsureUserRole), and a session that creates one and dials
// the standby in the same breath can arrive before the copy has it. The
// alternative to waiting is logging in as the shared role, which is what the
// caller does if this says no: on a read-only session that costs attribution
// and nothing else, because a role there cannot write and so has nothing to be
// attributed for.
func StandbyKnowsRole(role string) bool {
	deadline := time.Now().Add(standbyRoleWait)
	for {
		if haQuery(container("standby"),
			fmt.Sprintf("SELECT 1 FROM pg_roles WHERE rolname = %s", quoteLiteral(role))) == "1" {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// StandbyLag is how far behind the primary the standby's replayed data is, as
// Postgres reports it, and whether it could be asked at all.
//
// Taken from the primary rather than from the standby because the primary knows
// the difference: the standby can say which position it has replayed, but not
// what it is missing.
func StandbyLag() (string, bool) {
	lag := haQuery(PrimaryContainer(),
		"SELECT coalesce(replay_lag::text, '0') FROM pg_stat_replication WHERE application_name = "+
			quoteLiteral(StandbyName)+" LIMIT 1")
	if lag == "" {
		return "", false
	}
	return lag, true
}

// DescribeStandbyReads is the "=== reads ===" part of `ha status`: whether the
// copy may be read, how to reach it, and how far behind it is.
func DescribeStandbyReads() string {
	if err := standbyReadRefusal("main", primaryBranch(), ContainerState("standby"), IsStandbyNode()); err != nil {
		return "read-only sessions cannot be served here: " + err.Error()
	}
	s := fmt.Sprintf("read-only sessions may use %q instead of \"main\", and are answered by the\n"+
		"standby rather than the primary:\n  %s\n", StandbyReadName("main"),
		GatewayDSN(StandbyReadName("main"), ""))
	if lag, ok := StandbyLag(); ok {
		s += fmt.Sprintf("its data is %s behind the primary. ", lag)
	}
	return s + "A read there may be behind the primary;\nwrites are refused by Postgres itself, because the copy is in recovery."
}
