// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/license"
)

// Where the backups go, as `fox check` reports it.
//
// The default sends the write-ahead log archive and every base backup to the
// object store beside main, on the same disk — fine for a laptop, and wrong
// for anything holding data somebody would miss. This line is the only place
// the product says so unprompted, so what it says matters.
func TestBackupTargetLine(t *testing.T) {
	t.Run("the local store warns, and says what it costs", func(t *testing.T) {
		got := backupTargetLine(branch.Target{Kind: "local"}, nil)
		if got.state != stateWarn {
			t.Fatalf("state %d, want a warning", got.state)
		}
		// The consequence, not just the fact. "backups are local" is a
		// configuration note; "one disk failure takes the database and every
		// backup of it" is a reason to act.
		for _, want := range []string{"same disk", "every backup of it"} {
			if !strings.Contains(got.detail, want) {
				t.Errorf("detail %q does not mention %q", got.detail, want)
			}
		}
		// And the way out, which needs no new code.
		if !strings.Contains(got.fix, "backup target set") {
			t.Errorf("fix %q does not name the command", got.fix)
		}
	})

	t.Run("a remote target is fine, and is described", func(t *testing.T) {
		got := backupTargetLine(branch.Target{
			Kind: "s3", Bucket: "acme-fox-backups", Endpoint: "https://s3.eu-west-1.amazonaws.com",
			Region: "eu-west-1", AccessKey: "AKIA…",
		}, nil)
		if got.state != 0 {
			t.Fatalf("state %d, want ok: %s", got.state, got.detail)
		}
		if !strings.Contains(got.detail, "acme-fox-backups") {
			t.Errorf("detail %q does not name the bucket", got.detail)
		}
	})

	// A target file that cannot be read is not "assume local": backups would
	// go somewhere the owner did not choose, which is the one outcome this
	// check exists to prevent.
	t.Run("an unreadable target fails rather than guessing", func(t *testing.T) {
		got := backupTargetLine(branch.Target{}, errTargetForTest{})
		if got.state != stateFail {
			t.Fatalf("state %d, want a failure", got.state)
		}
		if !strings.Contains(got.detail, "backup-target.json") {
			t.Errorf("detail %q does not say which file", got.detail)
		}
	})
}

type errTargetForTest struct{}

func (errTargetForTest) Error() string {
	return "/home/a/.fox/backup-target.json: unexpected end of JSON input"
}

// What a commit means, and the one case where this line has to shout.
func TestDurabilityLine(t *testing.T) {
	never := func() bool { return false }
	met := func() bool { return true }

	t.Run("waiting for a standby nothing counts is a failure, not a warning", func(t *testing.T) {
		// The database looks hung from outside: every commit is waiting and
		// none will complete. This is the line somebody reads when that
		// happens, so it has to say so and carry the way out.
		got := durabilityLine(branch.HAState{Enabled: true, Sync: true, SyncActive: true}, never)
		if got.state != stateFail {
			t.Fatalf("state %d, want a failure", got.state)
		}
		for _, want := range []string{"every commit is waiting", "will not complete"} {
			if !strings.Contains(got.detail, want) {
				t.Errorf("detail %q does not mention %q", got.detail, want)
			}
		}
		if !strings.Contains(got.fix, "ha sync off") {
			t.Errorf("fix %q does not name the command that releases them", got.fix)
		}
		// And it says the escape hatch works *now*, which is the question
		// somebody staring at a stalled database actually has.
		if !strings.Contains(got.fix, "while they are waiting") {
			t.Errorf("fix %q does not say it works while commits are stalled", got.fix)
		}
	})

	t.Run("in effect and counted is fine, and names what it bought", func(t *testing.T) {
		got := durabilityLine(branch.HAState{Enabled: true, Sync: true, SyncActive: true}, met)
		if got.state != stateOK {
			t.Fatalf("state %d, want ok", got.state)
		}
		if !strings.Contains(got.detail, "zero data loss") {
			t.Errorf("detail %q does not say what it bought", got.detail)
		}
	})

	t.Run("asked for but not in effect warns, because the buyer thinks they have it", func(t *testing.T) {
		// The dangerous silence: somebody bought RPO zero, a failover took it
		// away, and nothing said so. Not a failure — the database is healthy.
		got := durabilityLine(branch.HAState{Enabled: false, Sync: true}, never)
		if got.state != stateWarn {
			t.Fatalf("state %d, want a warning", got.state)
		}
		if !strings.Contains(got.detail, "not in effect") {
			t.Errorf("detail %q does not say it is not in effect", got.detail)
		}
		if !strings.Contains(got.fix, "ha enable") {
			t.Errorf("fix %q does not name the way back", got.fix)
		}
	})

	t.Run("nobody asked, so say what the default costs", func(t *testing.T) {
		for _, c := range []struct {
			name string
			ha   branch.HAState
		}{
			{"with a standby", branch.HAState{Enabled: true}},
			{"without one", branch.HAState{}},
		} {
			got := durabilityLine(c.ha, never)
			if got.state != stateOK {
				t.Errorf("%s: state %d, want ok", c.name, got.state)
			}
			if !strings.Contains(got.detail, "never wait") {
				t.Errorf("%s: detail %q does not say commits never wait", c.name, got.detail)
			}
		}
	})

	t.Run("the quorum is only asked about when it decides the answer", func(t *testing.T) {
		// Asking Postgres costs a `docker exec psql`, and three of the four
		// cases do not need it.
		asked := 0
		counting := func() bool { asked++; return true }
		for _, ha := range []branch.HAState{{}, {Enabled: true}, {Sync: true}} {
			durabilityLine(ha, counting)
		}
		if asked != 0 {
			t.Errorf("Postgres was asked %d time(s) for a case that does not need it", asked)
		}
	})
}

// Who may copy the database. The warning case is the upgrade path: `ha enable`
// used to write a rule admitting any role from any address, that rule lives in
// the data directory, and a routine `fox update` has no reason to rewrite it.
func TestReplicationAccessLine(t *testing.T) {
	wide := func(string) bool { return true }
	narrow := func(string) bool { return false }

	t.Run("an older install's wide rule warns, and names what it costs", func(t *testing.T) {
		got := replicationAccessLine(branch.HAState{Enabled: true}, wide)
		if got.state != stateWarn {
			t.Fatalf("state %d, want a warning", got.state)
		}
		// The consequence, not the configuration: "pg_hba is wide" is a note,
		// "the credential that copies the database is the one that owns it" is
		// a reason to act.
		for _, want := range []string{"any role at any address", "the one that owns it"} {
			if !strings.Contains(got.detail, want) {
				t.Errorf("detail %q does not mention %q", got.detail, want)
			}
		}
		if !strings.Contains(got.fix, "ha enable") {
			t.Errorf("fix %q does not name what narrows it", got.fix)
		}
	})

	t.Run("a narrowed install says who may copy it and what they cannot do", func(t *testing.T) {
		got := replicationAccessLine(branch.HAState{Enabled: true}, narrow)
		if got.state != stateOK {
			t.Fatalf("state %d, want ok", got.state)
		}
		for _, want := range []string{branch.ReplicationRole, "can read none of it"} {
			if !strings.Contains(got.detail, want) {
				t.Errorf("detail %q does not mention %q", got.detail, want)
			}
		}
	})

	t.Run("no standby, so nothing may copy it, and pg_hba is not read", func(t *testing.T) {
		// Reading it costs a `docker exec`, and with no standby there is no
		// rule to judge.
		asked := 0
		counting := func(string) bool { asked++; return true }
		got := replicationAccessLine(branch.HAState{}, counting)
		if got.state != stateOK {
			t.Errorf("state %d, want ok", got.state)
		}
		if asked != 0 {
			t.Errorf("pg_hba was read %d time(s) with no standby to admit", asked)
		}
	})
}

// The licence line, and the clause it adds on a machine that is a standby for
// a primary elsewhere.
//
// `node join` says this once, at join time. Somebody who joined a month ago and
// has since let a licence lapse is in the state that matters, and this is where
// they would look — so the clause belongs on a line that is printed every run.
func TestLicenceLine(t *testing.T) {
	none := license.License{}
	active := license.License{ID: "LIC-1", Customer: "Acme"}

	t.Run("no licence on a standby names what a promotion would cost", func(t *testing.T) {
		got := licenceLine(true, true, none, license.Status{}, true)
		if got.state != stateWarn {
			t.Fatalf("state %d, want a warning", got.state)
		}
		for _, want := range []string{"this machine is a standby", "stop the paid features", "no grace period"} {
			if !strings.Contains(got.detail, want) {
				t.Errorf("detail %q does not mention %q", got.detail, want)
			}
		}
		// And what to ask for, since one licence can cover both nodes.
		if !strings.Contains(got.fix, "site licence") {
			t.Errorf("fix %q does not mention a site licence", got.fix)
		}
	})

	t.Run("no licence on a normal install is unchanged", func(t *testing.T) {
		// The existing judgement, which this must not have altered.
		got := licenceLine(true, false, none, license.Status{}, true)
		if got.state != stateWarn || got.detail != "none installed" {
			t.Errorf("a normal install's line changed: %d %q", got.state, got.detail)
		}
	})

	t.Run("a Standard build is still uninteresting, standby or not", func(t *testing.T) {
		for _, standby := range []bool{false, true} {
			got := licenceLine(false, standby, none, license.Status{}, true)
			if got.state != stateOK {
				t.Errorf("standby=%v: a Standard build was flagged", standby)
			}
		}
	})

	t.Run("a mismatched fingerprint on a standby says it survives promotion", func(t *testing.T) {
		// The correction to the plan's §3.1: a mismatch never lapses. The
		// obvious reading of "activated on a different machine" is that a
		// promotion will cost the paid features, and it will not.
		st := license.Status{State: license.Warning, Reason: "this licence was activated on a different machine",
			Action: "run `fox license rebind` to move it here"}
		got := licenceLine(true, true, active, st, false)
		if got.state != stateWarn {
			t.Fatalf("state %d, want a warning", got.state)
		}
		if !strings.Contains(got.detail, "still unlocks") || !strings.Contains(got.detail, "after a promotion") {
			t.Errorf("detail %q does not say the licence survives a promotion", got.detail)
		}
	})

	t.Run("the standby clause never changes the severity", func(t *testing.T) {
		// Being a standby makes a licence problem mean something extra, not
		// something milder or worse. The first version downgraded a lapsed
		// licence to a warning on a standby, which was backwards.
		lapsed := license.Status{State: license.Lapsed, Reason: "the licence expired", Action: "renew it"}
		for _, standby := range []bool{false, true} {
			if got := licenceLine(true, standby, active, lapsed, false); got.state != stateFail {
				t.Errorf("standby=%v: a lapsed licence is %d, want a failure", standby, got.state)
			}
		}
		// And the standby one still carries the consequence.
		got := licenceLine(true, true, active, lapsed, false)
		if !strings.Contains(got.detail, "standby") {
			t.Errorf("a lapsed licence on a standby does not say so: %q", got.detail)
		}
	})

	t.Run("an active licence is reported the same either way", func(t *testing.T) {
		st := license.Status{State: license.Active}
		a := licenceLine(true, false, active, st, false)
		b := licenceLine(true, true, active, st, false)
		if a.state != stateOK || b.state != stateOK || a.detail != b.detail {
			t.Errorf("an active licence differs on a standby:\n %q\n %q", a.detail, b.detail)
		}
	})
}

// `fox check` surviving the install it is run on.
//
// Every line here is a question put to something that may not be there, and
// one of them — the base-backup listing — used to be asked with no deadline at
// all. On a machine with no storage pool and no containers, `check` ran for
// over ten minutes and printed nothing: not an error, not the lines that had
// already answered, nothing. Both halves of that are the fault. A check that
// cannot answer has to say so, and the report must not wait for it.
func TestReportDoesNotWaitForAHangingCheck(t *testing.T) {
	hang := make(chan struct{}) // never closed: this check never answers
	t.Cleanup(func() { close(hang) })

	var out strings.Builder
	failed, warned := report(&out, []check{
		one("version", func() checkLine { return ok("version", "fox 1.2.3") }),
		one("backups", func() checkLine { <-hang; return ok("backups", "never reached") }),
		one("storage", func() checkLine { return fail("storage", "no branch storage pool found", "fox setup") }),
	}, 50*time.Millisecond)

	got := out.String()
	// The lines either side of the hang are the point: before this, one check
	// that never returned took the whole report with it.
	for _, want := range []string{"fox 1.2.3", "no branch storage pool found"} {
		if !strings.Contains(got, want) {
			t.Errorf("the report lost a line that had answered (%q):\n%s", want, got)
		}
	}
	// And the hanging one is named, with how long it was given, rather than
	// being silently missing from a report that otherwise looks complete.
	for _, want := range []string{"backups", "could not be determined in 50ms"} {
		if !strings.Contains(got, want) {
			t.Errorf("the report does not say %q:\n%s", want, got)
		}
	}
	// A question nobody could answer is not proof of a fault, so it must not
	// turn `fox check` into a non-zero exit for anybody scripting it.
	if failed != 1 || warned != 1 {
		t.Errorf("failed=%d warned=%d, want 1 failure (storage) and 1 warning (the hang)", failed, warned)
	}
}

// The lines are written as they resolve, not collected and printed at the end.
// Proved by a check that cannot finish until the line before it has been
// written: if the report were accumulated, that check would hang and be
// reported as undetermined.
func TestReportPrintsLinesAsTheyResolve(t *testing.T) {
	printed := make(chan struct{})
	w := &notifyWriter{on: "the first line", seen: printed}
	var out strings.Builder
	w.to = &out

	report(w, []check{
		one("version", func() checkLine { return ok("version", "the first line") }),
		one("storage", func() checkLine {
			select {
			case <-printed:
				return ok("storage", "saw the line before it")
			case <-time.After(2 * time.Second):
				return fail("storage", "the report was still being collected", "")
			}
		}),
	}, 5*time.Second)

	if !strings.Contains(out.String(), "saw the line before it") {
		t.Errorf("the second check did not see the first line printed:\n%s", out.String())
	}
}

// notifyWriter closes seen the first time a write contains on.
type notifyWriter struct {
	to   *strings.Builder
	on   string
	seen chan struct{}
	done bool
}

func (w *notifyWriter) Write(b []byte) (int, error) {
	n, err := w.to.Write(b)
	if !w.done && strings.Contains(string(b), w.on) {
		w.done = true
		close(w.seen)
	}
	return n, err
}

// How long one check may take, and the escape hatch for an install that is
// slow rather than stuck.
func TestCheckTimeoutSetting(t *testing.T) {
	t.Setenv("FOX_CHECK_TIMEOUT", "")
	if got := checkTimeout(); got != 10*time.Second {
		t.Errorf("unset gave %s, want 10s", got)
	}
	t.Setenv("FOX_CHECK_TIMEOUT", "90s")
	if got := checkTimeout(); got != 90*time.Second {
		t.Errorf("a 90s setting gave %s", got)
	}
	for _, off := range []string{"off", "0", "no"} {
		t.Setenv("FOX_CHECK_TIMEOUT", off)
		if got := checkTimeout(); got != 0 {
			t.Errorf("%q should wait for ever, got %s", off, got)
		}
	}
	// Nonsense keeps the default rather than becoming no deadline at all,
	// which is the one value that brings the original hang back.
	t.Setenv("FOX_CHECK_TIMEOUT", "soon")
	if got := checkTimeout(); got != 10*time.Second {
		t.Errorf("a bad value gave %s, want the default", got)
	}
}

// With no deadline the check is run on this goroutine and answers in full —
// the behaviour before this existed, kept for whoever wants to wait.
func TestRunCheckWithNoDeadlineStillAnswers(t *testing.T) {
	got := runCheck(one("version", func() checkLine { return ok("version", "answered") }), 0)
	if len(got) != 1 || got[0].detail != "answered" {
		t.Errorf("got %+v", got)
	}
}

// Each check carries the name its line is reported under, and that name is
// what a timed-out check is announced as — so a missing or duplicated one
// would make the report ambiguous exactly when it matters most.
func TestEveryCheckIsNamed(t *testing.T) {
	seen := map[string]bool{}
	for i, c := range checks() {
		if strings.TrimSpace(c.name) == "" {
			t.Errorf("check %d has no name", i)
		}
		if c.run == nil {
			t.Errorf("check %q has nothing to run", c.name)
		}
		if seen[c.name] {
			t.Errorf("two checks are called %q", c.name)
		}
		seen[c.name] = true
	}
	if len(seen) < 15 {
		t.Errorf("only %d checks; the list looks truncated", len(seen))
	}
}

// The two deadlines nest: a check's own shell-outs give up before the line's
// deadline does. The inner one is the only one that can report why and the
// only one that can remove the container it started, so it must not be the
// one that loses the race.
func TestProbeBudgetFitsInsideTheCheckDeadline(t *testing.T) {
	t.Setenv("FOX_CHECK_TIMEOUT", "")
	d := checkTimeout()
	p := probeBudget(d)
	if p <= 0 || p >= d {
		t.Errorf("probe budget %s against a line deadline of %s: it has to be shorter and still positive", p, d)
	}
	// A tightened line deadline tightens the probe with it.
	t.Setenv("FOX_CHECK_TIMEOUT", "4s")
	if got := probeBudget(checkTimeout()); got != 2*time.Second {
		t.Errorf("with a 4s line deadline the probe got %s", got)
	}
	// And "off" imposes nothing at either level, rather than quietly keeping a
	// deadline somebody asked to be rid of.
	t.Setenv("FOX_CHECK_TIMEOUT", "off")
	if got := probeBudget(checkTimeout()); got != 0 {
		t.Errorf("deadlines are off, but the probe still got %s", got)
	}
}

// Where anchors are kept, as `fox check` reports it (the expert review plan's
// G3): the default leaves them where the machine's administrator could rewrite
// them, and the line says so.
func TestAnchorTargetLine(t *testing.T) {
	remote := branch.Target{Kind: "s3", Bucket: "acme-backups", Endpoint: "https://s3.example", AccessKey: "AK1"}
	at := branch.AnchorTarget{Target: branch.Target{Kind: "s3", Bucket: "acme-anchors", Endpoint: "https://s3.example", AccessKey: "AK2"}, RetentionDays: 365}

	t.Run("none warns, names who could rewrite them, and the way out", func(t *testing.T) {
		got := anchorTargetLine(branch.AnchorTarget{}, false, nil, branch.Target{Kind: "local"}, branch.AnchorCopies{})
		if got.state != stateWarn || !strings.Contains(got.detail, "this machine only") || !strings.Contains(got.fix, "anchor-target set") {
			t.Errorf("%+v", got)
		}
		got = anchorTargetLine(branch.AnchorTarget{}, false, nil, remote, branch.AnchorCopies{})
		if got.state != stateWarn || !strings.Contains(got.detail, "backup bucket") {
			t.Errorf("with a backup target: %+v", got)
		}
	})
	t.Run("a target is fine, with its lock and retention", func(t *testing.T) {
		got := anchorTargetLine(at, true, nil, remote, branch.AnchorCopies{Total: 4})
		if got.state != stateOK || !strings.Contains(got.detail, "acme-anchors") || !strings.Contains(got.detail, "COMPLIANCE") || !strings.Contains(got.detail, "365 days") {
			t.Errorf("%+v", got)
		}
	})
	t.Run("copies waiting a short while are mentioned, not warned about", func(t *testing.T) {
		got := anchorTargetLine(at, true, nil, remote, branch.AnchorCopies{Total: 4, Waiting: 1, OldestWaiting: time.Minute})
		if got.state != stateOK || !strings.Contains(got.detail, "1 waiting") {
			t.Errorf("%+v", got)
		}
	})
	t.Run("copies stuck for a day warn: a gap is what a rewrite would want", func(t *testing.T) {
		got := anchorTargetLine(at, true, nil, remote, branch.AnchorCopies{Total: 4, Waiting: 2, OldestWaiting: 30 * time.Hour})
		if got.state != stateWarn || !strings.Contains(got.detail, "2 anchor(s) not copied") {
			t.Errorf("%+v", got)
		}
	})
	t.Run("an unreadable target fails", func(t *testing.T) {
		if got := anchorTargetLine(branch.AnchorTarget{}, false, errTargetForTest{}, remote, branch.AnchorCopies{}); got.state != stateFail {
			t.Errorf("%+v", got)
		}
	})
}

func TestParseWindow(t *testing.T) {
	for in, want := range map[string]int{"1h": 3600, "90m": 5400, "1d": 86400, "7d": 604800, "1m": 60} {
		if got, err := parseWindow(in); err != nil || got != want {
			t.Errorf("%s: %d %v", in, got, err)
		}
	}
	for _, bad := range []string{"30s", "8d", "x", "0"} {
		if _, err := parseWindow(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	if window(3600) != "hour" || window(1800) != "30 minutes" || window(172800) != "2 days" {
		t.Error("window names")
	}
}

// The pool's health and the disk under it.
//
// On 2026-10-26 the test VM's disk filled, ZFS suspended the pool its branches
// live on, and every postgres on it hung in the kernel for eight hours. The
// storage line said "29.5G free" throughout: that is the pool's own count, and a
// pool in a sparse file counts space its disk no longer has.
func TestPoolAndDiskLines(t *testing.T) {
	const gib = uint64(1) << 30
	full := branch.DiskSpace{Mount: "/", Size: 38 * gib, Avail: gib + gib/2, Holds: []string{branch.HoldsPool, branch.HoldsDocker}}
	roomy := branch.DiskSpace{Mount: "/", Size: 38 * gib, Avail: 24 * gib, Holds: []string{branch.HoldsPool, branch.HoldsDocker}}
	suspended := branch.PoolHealth{Driver: "zfs", State: "SUSPENDED", Free: 29 * gib, Backing: "/var/lib/dbpool-zpool.img"}

	t.Run("a suspended pool fails, says what that does, and how to get out", func(t *testing.T) {
		got := poolHealthLine(suspended, []branch.DiskSpace{full})
		if got.state != stateFail {
			t.Fatalf("state %d, want a failure", got.state)
		}
		if !strings.Contains(got.detail, "hang") {
			t.Errorf("detail %q does not say that everything hangs", got.detail)
		}
		// Space first: clearing a pool whose disk is still full suspends it again.
		for _, want := range []string{"free space on /", "volume prune", "zpool clear dbpool", "zpool status -v"} {
			if !strings.Contains(got.fix, want) {
				t.Errorf("fix %q does not mention %q", got.fix, want)
			}
		}
		if strings.Index(got.fix, "volume prune") > strings.Index(got.fix, "zpool clear") {
			t.Errorf("fix %q clears before freeing space", got.fix)
		}
		if strings.Contains(got.fix, "-a ") || strings.HasSuffix(got.fix, "-a") {
			t.Errorf("fix %q names a prune -a, which would take the object store's volume", got.fix)
		}
	})

	t.Run("…and with room on the disk, just how to clear it", func(t *testing.T) {
		got := poolHealthLine(suspended, []branch.DiskSpace{roomy})
		if got.state != stateFail || strings.Contains(got.fix, "free space") {
			t.Errorf("got %+v", got)
		}
	})

	t.Run("the other states", func(t *testing.T) {
		for _, c := range []struct {
			h    branch.PoolHealth
			want int
		}{
			{branch.PoolHealth{Driver: "zfs", State: "ONLINE"}, stateOK},
			{branch.PoolHealth{Driver: "zfs", State: "DEGRADED"}, stateWarn},
			{branch.PoolHealth{Driver: "zfs", State: "FAULTED"}, stateFail},
			{branch.PoolHealth{Driver: "zfs", State: "UNAVAIL"}, stateFail},
			{branch.PoolHealth{Driver: "btrfs", State: "mounted"}, stateOK},
			{branch.PoolHealth{Driver: "btrfs", State: "read-only"}, stateFail},
			{branch.PoolHealth{Driver: "btrfs", State: "not mounted"}, stateFail},
			// Not this line's to fail: the storage line already does.
			{branch.PoolHealth{Driver: "zfs", Missing: true, Err: "cannot open 'dbpool': no such pool"}, stateWarn},
			{branch.PoolHealth{Driver: "zfs", Err: "zpool did not finish within 5s"}, stateWarn},
		} {
			if got := poolHealthLine(c.h, nil); got.state != c.want {
				t.Errorf("%+v: state %d, want %d (%s)", c.h, got.state, c.want, got.detail)
			}
		}
	})

	t.Run("a nearly full disk under the pool fails, and says the pool's count is not the disk's", func(t *testing.T) {
		lines := diskLines([]branch.DiskSpace{full}, suspended, nil)
		if len(lines) != 1 || lines[0].state != stateFail {
			t.Fatalf("got %+v", lines)
		}
		for _, want := range []string{"1.5G free of 38.0G", "97% used", "the storage pool's file and Docker's images and volumes",
			"the pool counts 29.0G free, but its file can grow by only 1.5G more", "ZFS suspends it"} {
			if !strings.Contains(lines[0].detail, want) {
				t.Errorf("detail %q does not mention %q", lines[0].detail, want)
			}
		}
		if lines[0].name != "disk /" {
			t.Errorf("name %q", lines[0].name)
		}
	})

	t.Run("thresholds: a share or an amount, whichever says so first", func(t *testing.T) {
		for _, c := range []struct {
			size, avail uint64
			want        int
		}{
			{38 * gib, 24 * gib, stateOK},
			{38 * gib, 4 * gib, stateWarn},     // under 5G
			{1000 * gib, 90 * gib, stateWarn},  // under 10%
			{1000 * gib, 20 * gib, stateFail},  // under 3%
			{38 * gib, gib + gib/2, stateFail}, // under 2G
			{2000 * gib, 300 * gib, stateOK},   // plenty either way
		} {
			d := branch.DiskSpace{Mount: "/", Size: c.size, Avail: c.avail, Holds: []string{branch.HoldsDocker}}
			if got := diskLines([]branch.DiskSpace{d}, branch.PoolHealth{}, nil)[0].state; got != c.want {
				t.Errorf("%dG free of %dG: state %d, want %d", c.avail/gib, c.size/gib, got, c.want)
			}
		}
	})

	t.Run("plenty of room is one ok line per filesystem, with no note about the pool", func(t *testing.T) {
		lines := diskLines([]branch.DiskSpace{roomy}, branch.PoolHealth{Driver: "zfs", State: "ONLINE", Free: 29 * gib}, nil)
		if len(lines) != 1 || lines[0].state != stateOK || strings.Contains(lines[0].detail, "pool counts") {
			t.Errorf("got %+v", lines)
		}
	})

	t.Run("a disk that cannot be read is a warning, never a hang or a failure", func(t *testing.T) {
		lines := diskLines(nil, branch.PoolHealth{}, errors.New("asking Docker where it keeps its data: Cannot connect"))
		if len(lines) != 1 || lines[0].state != stateWarn || !strings.Contains(lines[0].detail, "Cannot connect") {
			t.Errorf("got %+v", lines)
		}
	})
}
