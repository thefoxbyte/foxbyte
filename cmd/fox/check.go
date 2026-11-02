// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/daemon"
	"github.com/thefoxbyte/foxbyte/internal/edition"
	"github.com/thefoxbyte/foxbyte/internal/license"
	"github.com/thefoxbyte/foxbyte/internal/version"
	"github.com/thefoxbyte/foxbyte/web"
)

// `fox check` — the install, diagnosing itself.
//
// Until now a half-working install was a conversation: the stack reports plenty
// through `fox status`, but nothing said which part was wrong or what to type
// next. Each check below answers one question, and a failure carries the single
// command that fixes it. Exit status is 1 if anything failed, so it is usable in
// a script, and warnings alone keep it 0.

// a check's outcome. warn is for something a person should know that does not
// make the install broken — a stale backup, no sample data.
type checkLine struct {
	name   string
	detail string
	fix    string
	state  int // 0 ok, 1 warn, 2 fail
}

const (
	stateOK = iota
	stateWarn
	stateFail
)

func ok(name, detail string) checkLine { return checkLine{name: name, detail: detail} }
func warn(name, detail, fix string) checkLine {
	return checkLine{name: name, detail: detail, fix: fix, state: stateWarn}
}
func fail(name, detail, fix string) checkLine {
	return checkLine{name: name, detail: detail, fix: fix, state: stateFail}
}

// a check: the lines it produces, and the name to put on a line if it does not
// produce them in time.
type check struct {
	name string
	run  func() []checkLine
}

func one(name string, f func() checkLine) check {
	return check{name, func() []checkLine { return []checkLine{f()} }}
}

func group(name string, f func() []checkLine) check { return check{name, f} }

// checks, in the order they are reported: roughly outside-in, from what this
// binary is to what is in the database.
func checks() []check {
	return []check{
		one("version", checkVersion),
		one("edition", checkEdition),
		one("licence", checkLicense),
		one("web console", checkConsoleEmbedded),
		one("storage", checkStorage),
		group("storage health", checkPoolAndDisk),
		one("main", checkMain),
		group("servers", checkServers),
		group("ports", checkPorts),
		one("API over TLS", checkAPI),
		one("API is closed", checkAPIClosed),
		one("blackbox", checkBlackbox),
		one("blackbox anchors", checkAnchors),
		one("anchor target", checkAnchorTarget),
		one("change feed", checkRealtime),
		one("durability", checkDurability),
		one("replication", checkReplicationAccess),
		one("backup target", checkBackupTarget),
		one("backups", checkBackups),
		one("restore proven", checkRestore),
		one("sample data", checkSampleData),
		one("docker volumes", checkVolumes),
	}
}

// EnvCheckTimeout tunes how long one check may take (a duration such as "30s"),
// or waits for ever with "off".
const EnvCheckTimeout = "CHECK_TIMEOUT"

// checkTimeout is how long to wait for one check. Seconds, not minutes: this
// command is run to find out why an install is not working, so every line has
// to arrive even when the thing behind it never answers.
func checkTimeout() time.Duration {
	v := strings.ToLower(strings.TrimSpace(brand.Getenv(EnvCheckTimeout)))
	switch v {
	case "":
		return 10 * time.Second
	case "off", "0", "false", "no":
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 10 * time.Second
	}
	return d
}

// probeBudget is how long a check's own shell-outs get, given the deadline on
// the line they belong to: half of it.
//
// The two deadlines have to nest rather than race. Whichever expires first is
// the one that gets to say what happened — and the inner one is the only one
// that can tidy up after itself: a check abandoned by the outer deadline leaves
// whatever it started running, which is how a `check` that was given up on left
// a Postgres container up behind it. With deadlines switched off, nothing is
// imposed here either.
func probeBudget(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return d / 2
}

// runCheck is c, given at most d to answer.
//
// The check runs in a goroutine and is abandoned rather than cancelled: it is
// a few shell-outs deep by then, each with its own deadline, and this process
// is about to exit anyway. What matters is that the report does not wait for
// it — a check that hangs now costs its own line and nothing else.
func runCheck(c check, d time.Duration) []checkLine {
	if d <= 0 {
		return c.run()
	}
	done := make(chan []checkLine, 1)
	go func() { done <- c.run() }()
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case ls := <-done:
		return ls
	case <-timer.C:
		// Deliberately a warning, not a failure: nothing was established either
		// way, and a `check` that exited 1 on a slow machine would be the wrong
		// lesson to teach anybody scripting it.
		return []checkLine{warn(c.name,
			fmt.Sprintf("could not be determined in %s — this says nothing about it either way", d),
			fmt.Sprintf("%s=1m %s check   — if this install is slow rather than stuck",
				brand.EnvName(EnvCheckTimeout), brand.CLI))}
	}
}

// report runs each check in turn and writes its lines to w as they resolve,
// returning how many failed and how many warned.
//
// Each line is written the moment it is known. They used to be collected into
// one slice and printed after the last check returned, which meant a single
// check that did not return held back the whole report: the twenty lines that
// had already answered — including the ones naming what was wrong — stayed
// invisible behind it, and `check` looked like a command that does nothing at
// all. A hang now costs the line it is on.
func report(w io.Writer, cs []check, d time.Duration) (failed, warned int) {
	for _, c := range cs {
		for _, l := range runCheck(c, d) {
			mark := "ok  "
			switch l.state {
			case stateWarn:
				mark, warned = "warn", warned+1
			case stateFail:
				mark, failed = "FAIL", failed+1
			}
			fmt.Fprintf(w, "%s  %-18s %s\n", mark, l.name, l.detail)
			if l.fix != "" {
				fmt.Fprintf(w, "      → %s\n", l.fix)
			}
		}
	}
	return failed, warned
}

func checkCmd(args []string) {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Printf("usage: %s check\n\nChecks this install and says what to do about anything wrong.\n", brand.CLI)
		return
	}
	failed, warned := report(os.Stdout, checks(), checkTimeout())
	fmt.Println()
	switch {
	case failed > 0:
		fmt.Printf("%d check(s) failed, %d warning(s).\n", failed, warned)
		os.Exit(1)
	case warned > 0:
		fmt.Printf("Everything essential is working, with %d warning(s).\n", warned)
	default:
		fmt.Println("Everything is working.")
	}
}

func checkVersion() checkLine {
	return ok("version", fmt.Sprintf("%s %s (newer releases: `%s update --check`)", brand.CLI, version.Version, brand.CLI))
}

// checkEdition says which edition is installed and whether its features are
// actually unlocked. An Enterprise build with no licence behaves exactly like
// the Standard one, which is correct but surprising if you just paid for it —
// so it is a warning with the command that fixes it, not a silent ok.
func checkEdition() checkLine {
	switch {
	case !edition.Enterprise:
		return ok("edition", "standard — Blackbox, guardrails and branching; paid features are not in this build")
	case len(edition.Available()) == 0:
		return warn("edition",
			"enterprise, but no licence is active — paid features are refused",
			fmt.Sprintf("%s license activate <file>", brand.CLI))
	default:
		var names []string
		for _, f := range edition.Available() {
			names = append(names, string(f))
		}
		return ok("edition", "enterprise — licensed: "+strings.Join(names, ", "))
	}
}

// checkLicense says what is wrong with the licence, which checkEdition cannot:
// "no licence is active" is the same sentence whether one expired last night,
// was issued for a machine that has since been rebuilt, or was never installed.
// Those have different ways out, and this is where a person looks for them.
//
// It reports the same Reason and Action the `fox license` commands print, from
// the same Status, so the two cannot drift into describing one licence two
// ways.
func checkLicense() checkLine {
	l, _, _, err := license.Load()
	if err == license.ErrNone {
		return licenceLine(edition.Enterprise, branch.IsStandbyNode(), license.License{}, license.Status{}, true)
	}
	if err != nil {
		return warn("licence", err.Error(), fmt.Sprintf("%s license show", brand.CLI))
	}
	return licenceLine(edition.Enterprise, branch.IsStandbyNode(), l, license.Install(), false)
}

// licenceLine is the judgement: what this install's licence is doing, and —
// when this machine is a standby for a primary elsewhere — what a promotion
// would do to it.
//
// The standby clause exists because `node join` says this once, at join time,
// and nothing said it again. Somebody who joined a month ago and has since let
// a licence lapse is in the state that matters, and `fox check` is where they
// would look. A licence is per-install state (~/.fox/license.json) and joining
// copies the primary's database, not its state directory, so an unlicensed
// standby is the default rather than an oversight.
//
// The standby clause adds the consequence and never changes the severity. An
// absent licence warns on any install and warns here; a lapsed one fails on any
// install and fails here. Being a standby does not make a licence problem
// milder or worse — it makes it mean something extra, which is that a promotion
// would stop the paid features on this machine as well.
//
// Pure, so each combination is read in a test rather than assembled on a
// machine that happens to be in that state.
func licenceLine(enterprise, standby bool, l license.License, st license.Status, none bool) checkLine {
	if none {
		if !enterprise {
			// A Standard build has nothing to unlock, so no licence is the
			// correct and uninteresting state rather than something to flag.
			return ok("licence", "not needed by the standard edition")
		}
		if standby {
			return warn("licence",
				"none installed, and this machine is a standby — a promotion would stop the paid "+
					"features here, with no grace period",
				fmt.Sprintf("%s license activate <file>   — or ask for a site licence, which covers both nodes",
					brand.CLI))
		}
		return warn("licence", "none installed",
			fmt.Sprintf("%s license activate <file>", brand.CLI))
	}
	switch st.State {
	case license.Active:
		return ok("licence", fmt.Sprintf("%s — %s, to %s", l.ID, l.Customer,
			l.NotAfter.UTC().Format("2 January 2006")))
	case license.Warning:
		if standby {
			// A warning is either an expiry inside the 14-day grace or a
			// fingerprint mismatch, and both unlock the paid features today.
			// Worth saying on a standby specifically, because the obvious
			// reading of "activated on a different machine" is that a promotion
			// will cost them, and it will not: the grace applies to expiry
			// only, so a mismatch never lapses. docs/FOX_HA_Plan.md §3.1
			// assumed otherwise and was corrected.
			return warn("licence", st.Reason+" — it still unlocks the paid features, here and after a promotion",
				st.Action)
		}
		return warn("licence", st.Reason, st.Action)
	default:
		// A lapsed or invalid licence is a failure on any install, and being a
		// standby does not make it less so: the clause adds the consequence,
		// it does not change the severity. Downgrading it here was the first
		// version of this, and it was backwards.
		if standby {
			return fail("licence",
				st.Reason+", and this machine is a standby — a promotion would stop the paid features here too",
				st.Action)
		}
		return fail("licence", st.Reason, st.Action)
	}
}

// The console is compiled into the binary with -tags embedui. Without it :8080
// serves the API and a blank page, which looks like a broken install.
func checkConsoleEmbedded() checkLine {
	if web.FS() == nil {
		return warn("web console", "not embedded in this build",
			"this is a development build; a released binary has the console in it")
	}
	return ok("web console", "embedded, served at https://localhost:8080")
}

// Storage is the copy-on-write engine branches are clones on. No figures means
// the pool is not there, which means the engine was never set up here.
func checkStorage() checkLine {
	s := branch.StorageInfo()
	if s.Used == "" && s.Avail == "" {
		return fail("storage", "no branch storage pool found", fmt.Sprintf("%s setup", brand.CLI))
	}
	return ok("storage", fmt.Sprintf("%s used, %s free", s.Used, s.Avail))
}

// The pool's health and the disk under it, which the storage line does not
// cover: a pool in a sparse file counts its whole size as free however full the
// disk holding that file is, and a full disk is how a pool gets suspended, after
// which everything on it hangs (internal/branch/poolhealth.go).
func checkPoolAndDisk() []checkLine {
	d := probeBudget(checkTimeout())
	h := branch.PoolHealthProbe(d)
	disks, err := branch.DiskSpaceProbe(d, h)
	return append([]checkLine{poolHealthLine(h, disks)}, diskLines(disks, h, err)...)
}

// Free space below these is a warning, and below the second pair a failure:
// whichever of the share and the absolute amount says so first. Both, because a
// share alone is too eager on a large disk and an amount alone is too late on a
// small one.
const (
	diskWarnPercent, diskFailPercent = 10, 3
	diskWarnBytes, diskFailBytes     = 5 << 30, 2 << 30
)

func diskState(d branch.DiskSpace) int {
	switch {
	case d.Avail < diskFailBytes || d.Avail*100 < d.Size*diskFailPercent:
		return stateFail
	case d.Avail < diskWarnBytes || d.Avail*100 < d.Size*diskWarnPercent:
		return stateWarn
	}
	return stateOK
}

func holdsPool(d branch.DiskSpace) bool {
	for _, h := range d.Holds {
		if h == branch.HoldsPool {
			return true
		}
	}
	return false
}

// diskFix names the safe cleanups: the anonymous volumes and dangling images
// nothing uses, and branches. Never `prune -a`, which would also take the object
// store's volume, holding every backup, whenever it is stopped.
const diskFix = "docker volume prune   and   docker image prune   (unused anonymous volumes and dangling images only; never -a), " +
	"and delete branches you no longer need"

func poolHealthLine(h branch.PoolHealth, disks []branch.DiskSpace) checkLine {
	const name = "pool health"
	if h.Missing {
		return warn(name, "there is no storage pool to check (see the storage line)", "")
	}
	if h.State == "" {
		return warn(name, "could not be read: "+h.Err, "")
	}
	clearCmd := "sudo zpool clear " + branch.Pool
	full := ""
	for _, d := range disks {
		if holdsPool(d) && diskState(d) == stateFail {
			full = d.Mount
		}
	}
	switch h.State {
	case "ONLINE", "mounted":
		return ok(name, fmt.Sprintf("%s (%s)", h.State, h.Driver))
	case "DEGRADED":
		return warn(name, "DEGRADED: a device in the pool has errors, though its data is still served",
			"sudo zpool status -v "+branch.Pool)
	case "SUSPENDED":
		fix := clearCmd + "   then   sudo zpool status -v " + branch.Pool + "   (it lists any file a failed write damaged)"
		if full != "" {
			fix = "free space on " + full + " first (" + diskFix + "), then: " + fix
		}
		return fail(name, "SUSPENDED after failed writes: every write to the pool waits, so main and every branch hang until it is cleared", fix)
	case "read-only":
		fix := "sudo dmesg | grep -i btrfs   (for why), then restart the machine"
		if full != "" {
			fix = "free space on " + full + " (" + diskFix + "), then: " + fix
		}
		return fail(name, "mounted read-only: btrfs does that after a failed write, and every write to a database now fails", fix)
	case "not mounted":
		return fail(name, "the btrfs image is not mounted, so no branch has its data", fmt.Sprintf("%s start", brand.CLI))
	}
	return fail(name, h.State+": the pool cannot be used", "sudo zpool status -v "+branch.Pool)
}

func diskLines(disks []branch.DiskSpace, h branch.PoolHealth, err error) []checkLine {
	if len(disks) == 0 {
		detail := "could not be determined"
		if err != nil {
			detail += ": " + firstLine(err.Error())
		}
		return []checkLine{warn("disk space", detail, "")}
	}
	var out []checkLine
	for _, d := range disks {
		name := "disk " + d.Mount
		used := 0
		if d.Size > 0 {
			used = int(100 - d.Avail*100/d.Size)
		}
		detail := fmt.Sprintf("%s free of %s (%d%% used), holding %s",
			branch.HumanBytes(d.Avail), branch.HumanBytes(d.Size), used, strings.Join(d.Holds, " and "))
		st := diskState(d)
		// The number the storage line shows is the pool's, and a pool in a
		// sparse file counts space its disk may no longer have.
		if st != stateOK && holdsPool(d) && h.Free > d.Avail {
			detail += fmt.Sprintf("; the pool counts %s free, but its file can grow by only %s more",
				branch.HumanBytes(h.Free), branch.HumanBytes(d.Avail))
		}
		switch st {
		case stateFail:
			why := "nearly full"
			if holdsPool(d) {
				why = "nearly full: once the pool's file cannot grow, the pool stops taking writes (ZFS suspends it) and everything on it hangs"
			}
			out = append(out, fail(name, why+" — "+detail, diskFix))
		case stateWarn:
			out = append(out, warn(name, "filling up — "+detail, diskFix))
		default:
			out = append(out, ok(name, detail))
		}
	}
	return out
}

// main has to be running and answering SQL; a container that is up but not
// accepting connections is the failure this catches.
func checkMain() checkLine {
	switch st := branch.ContainerState("main"); st {
	case "running":
	case "absent":
		return fail("main", "the primary container is not there", fmt.Sprintf("%s start", brand.CLI))
	default:
		return fail("main", "the primary is "+st, fmt.Sprintf("%s start", brand.CLI))
	}
	if _, err := branch.Query("main", "SELECT 1"); err != nil {
		return fail("main", "running, but not answering SQL: "+firstLine(err.Error()),
			fmt.Sprintf("%s logs api   and   %s start", brand.CLI, brand.CLI))
	}
	return ok("main", "running and answering SQL")
}

func checkServers() []checkLine {
	var out []checkLine
	for _, s := range []struct{ svc, label string }{
		{"controlplane", "control API"},
		{"gateway", "gateway (SQL)"},
		{"api", "agent API"},
	} {
		st := daemon.Status(s.svc)
		if strings.HasPrefix(st, "running") {
			out = append(out, ok(s.label, st))
			continue
		}
		out = append(out, fail(s.label, st, fmt.Sprintf("%s start   (then `%s logs %s`)", brand.CLI, brand.CLI, s.svc)))
	}
	return out
}

// A server can be alive and still not listening where clients look, so the ports
// are checked separately from the processes.
func checkPorts() []checkLine {
	var out []checkLine
	for _, p := range []struct{ port, label string }{
		{"8080", "port 8080"},
		{"6432", "port 6432"},
		{"8088", "port 8088"},
	} {
		addr := listenAddr(p.port)
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			out = append(out, fail(p.label, "nothing listening on "+addr, fmt.Sprintf("%s start", brand.CLI)))
			continue
		}
		_ = c.Close()
		out = append(out, ok(p.label, "listening on "+addr))
	}
	return out
}

// insecureClient talks to this install's own control plane. The certificate is
// self-signed on a local install, so verifying it would fail by design: what is
// being checked is that TLS is serving at all, not who signed it.
func insecureClient() *http.Client {
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // this install's own self-signed certificate
	}
}

// The API answering over TLS. /api/openapi.yaml is the one route outside the
// authenticated tree, so it says the server is serving without needing a key.
func checkAPI() checkLine {
	resp, err := insecureClient().Get("https://" + listenAddr("8080") + "/api/openapi.yaml")
	if err != nil {
		return fail("API over TLS", "no answer: "+firstLine(err.Error()),
			fmt.Sprintf("%s logs controlplane", brand.CLI))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fail("API over TLS", fmt.Sprintf("answered HTTP %d", resp.StatusCode),
			fmt.Sprintf("%s logs controlplane", brand.CLI))
	}
	return ok("API over TLS", "answering (certificate is self-signed on a local install)")
}

// The other half of that: everything under /api/ must refuse a caller with no
// credentials. A 401 here is the install working, and it is worth saying so —
// an API that answered would be the fault.
func checkAPIClosed() checkLine {
	resp, err := insecureClient().Get("https://" + listenAddr("8080") + "/api/status")
	if err != nil {
		return fail("API is closed", "no answer: "+firstLine(err.Error()),
			fmt.Sprintf("%s logs controlplane", brand.CLI))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		return fail("API is closed", fmt.Sprintf("an unauthenticated call got HTTP %d, not 401", resp.StatusCode),
			"this install is serving data without a key — do not expose it")
	}
	return ok("API is closed", "an unauthenticated call is refused (401)")
}

func checkBlackbox() checkLine {
	out, err := branch.LedgerVerify("main")
	if err != nil {
		return fail("blackbox", "cannot verify the record: "+firstLine(err.Error()),
			fmt.Sprintf("%s blackbox verify main", brand.CLI))
	}
	return ok("blackbox", firstLine(out))
}

// Where someone looks when anchors stop appearing.
//
// An install that upgrades into the gating keeps every anchor it has and keeps
// verifying them, but stops writing new ones — and nothing else would say so.
// It is reported as a fact rather than a warning, because nothing is wrong, and
// as a line rather than silence, because a capability that quietly disappeared
// is the single worst way to learn about an edition split.
func checkAnchors() checkLine {
	if edition.Has(edition.Anchors) {
		return ok("blackbox anchors", "on — new entries are anchored outside the database on a schedule")
	}
	// The same distinction requireFeature draws, because it is the same
	// question: one of these is a download and the other is a purchase, and a
	// line that blamed "the enterprise edition" for a missing licence would
	// send someone to reinstall a binary they already have.
	why := "not in the standard edition"
	if edition.Enterprise {
		why = "no licence covers them"
	}
	return ok("blackbox anchors", fmt.Sprintf("not written (%s); the record is still hash-chained "+
		"and checked, and anchors already written still verify", why))
}

// Where somebody looks when a change feed is costing something.
//
// Three separate facts, and they report differently because they lead
// different places: whether the databases are set up for a feed at all,
// whether this binary can serve one, and whether a slot is holding WAL that
// nothing is draining.
//
// The middle one matters most on an install that went back to Standard. The
// setting survives -- `realtime teardown` is deliberately in the free build so
// it can be undone -- but nothing can stream, and a database quietly paying
// extra WAL for a feature nobody can use is exactly the kind of thing an
// install should say out loud rather than leave to be discovered.
//
// The last is the one failure of this design that costs disk, so a slot is
// named with its branch and what it holds: "a slot is idle" is not something
// anybody can act on.
func checkRealtime() checkLine {
	keep := branch.WALKeepSize()
	if !branch.RealtimeOn() {
		return ok("change feed", "off — databases run at wal_level=replica, as they always have")
	}
	if !edition.Has(edition.Realtime) {
		// The same distinction requireFeature and checkAnchors draw: one of
		// these is a download and the other is a purchase.
		why := "not in the standard edition"
		if edition.Enterprise {
			why = "no licence covers it"
		}
		return warn("change feed", fmt.Sprintf("set up (wal_level=logical, %s of WAL per slot) but nothing can stream: %s", keep, why),
			fmt.Sprintf("%s realtime teardown", brand.CLI))
	}
	names, err := branch.RunningBranches()
	if err != nil {
		return ok("change feed", fmt.Sprintf("on (wal_level=logical, at most %s of WAL per slot)", keep))
	}
	var idle, lost, live []string
	for _, n := range names {
		slots, err := branch.RealtimeSlots(n)
		if err != nil {
			continue // a branch that cannot be asked is not a finding about slots
		}
		for _, s := range slots {
			switch {
			case s.Lost():
				lost = append(lost, n+"/"+s.Name)
			case s.Active:
				live = append(live, n)
			default:
				idle = append(idle, fmt.Sprintf("%s/%s holding %s", n, s.Name, humanBytes(s.WALBytes)))
			}
		}
	}
	switch {
	case len(lost) > 0:
		return warn("change feed", fmt.Sprintf("%d slot(s) fell past the %s budget and cannot be resumed from: %s",
			len(lost), keep, strings.Join(lost, ", ")),
			fmt.Sprintf("%s up   — sweeps them; their subscribers are told to resync", brand.CLI))
	case len(idle) > 0:
		return warn("change feed", fmt.Sprintf("on, with %d idle slot(s) kept for a subscriber that may not come back: %s",
			len(idle), strings.Join(idle, ", ")),
			fmt.Sprintf("%s realtime slots <branch> --drop <name>", brand.CLI))
	case len(live) > 0:
		return ok("change feed", fmt.Sprintf("streaming on %s (at most %s of WAL per slot)", strings.Join(live, ", "), keep))
	}
	return ok("change feed", fmt.Sprintf("on (wal_level=logical, at most %s of WAL per slot); nothing streaming", keep))
}

// Where the backups go, which is a different question from whether they are
// current — and the one with the larger consequence.
//
// By default the WAL archive and every base backup go to the object store the
// engine runs beside main, on the same disk. That is fine for a laptop and
// wrong for anything holding data somebody would miss: one disk or host
// failure takes the database and every backup of it at the same moment, and
// point-in-time restore has nothing to replay from.
//
// A warning rather than a failure. It is the right default for a fresh install
// to need no bucket, and a new user should not meet a red line before they
// have put anything in the database. It is also the single largest reduction
// in how much data an incident can cost, and it needs no new code to fix —
// which is why it is said on every `check` until it is done.
// checkReplicationAccess reports who may copy this database.
//
// It exists for the upgrade path. `ha enable` used to append `host replication
// all all` to the primary's pg_hba.conf — any role, from any address — and that
// line lives in the data directory, where a routine `fox update` has no reason
// to touch it. So an install whose HA was enabled by an older version keeps it
// until something rewrites the file, and the only thing that does is another
// `ha enable`. Nothing would have said so.
func checkReplicationAccess() checkLine {
	return replicationAccessLine(branch.HAInfo(), branch.ReplicationOpenToEveryone)
}

// replicationAccessLine is the judgement, given the state and a way to ask the
// primary. A function rather than a bool so pg_hba is only read in the one case
// that can need it, and so this is testable without a pool.
func replicationAccessLine(ha branch.HAState, wideOpen func(string) bool) checkLine {
	if !ha.Enabled {
		return ok("replication", "nothing may copy this database: no standby, and no rule admitting one")
	}
	if e, published := branch.CurrentExposure(); published {
		// Postgres on a network is the one thing the engine otherwise refuses
		// to do, so an install that does it should say so on every check —
		// not as a fault, but because an operator should never discover it.
		return ok("replication", fmt.Sprintf("%s, and %s can copy it from there and read none of it",
			branch.DescribeExposure(), branch.ReplicationRole)+
			exposureCaveat(e))
	}
	if wideOpen(branch.PrimaryContainer()) {
		return warn("replication",
			"the primary admits a replication connection from any role at any address — a rule an "+
				"older version wrote, and the credential that copies the database is the one that owns it",
			fmt.Sprintf("%s ha enable   — narrows it to the %s role, which can copy and cannot read",
				brand.CLI, branch.ReplicationRole))
	}
	return ok("replication", fmt.Sprintf("only %s may copy it, from this install's own network, and it "+
		"can read none of it", branch.ReplicationRole))
}

// exposureCaveat adds the one thing worth saying about a published primary that
// the summary does not: a range admits every machine on it.
func exposureCaveat(e branch.NodeExposure) string {
	if strings.HasSuffix(e.Peer, "/32") || strings.HasSuffix(e.Peer, "/128") {
		return ""
	}
	return " — note that " + e.Peer + " is a range, so any machine on it may try"
}

// checkDurability reports what a commit means, and shouts when commits cannot
// complete.
//
// The failing case is the reason this line exists: zero-data-loss mode in
// effect with nothing counted means every write is waiting and will wait
// forever, which from the outside looks like the database has hung. `fox check`
// is where somebody looks when that happens, and the one command that releases
// them has to be on the screen.
func checkDurability() checkLine { return durabilityLine(branch.HAInfo(), branch.SyncQuorumMet) }

// durabilityLine is the judgement, given the state and a way to ask whether the
// standby is actually counted. A function rather than a bool so the question is
// only put to Postgres in the one case that needs it — and so this is testable
// without a pool, which the state behind it is not.
func durabilityLine(ha branch.HAState, quorumMet func() bool) checkLine {
	switch {
	case ha.SyncActive && !quorumMet():
		return fail("durability",
			"zero-data-loss mode is on but no standby is being counted — every commit is waiting "+
				"and will not complete",
			fmt.Sprintf("%s ha sync off   — releases them; it works while they are waiting", brand.CLI))
	case ha.SyncActive:
		return ok("durability", fmt.Sprintf("zero data loss: a commit waits until %s has it on disk",
			branch.StandbyName))
	case ha.Sync:
		return warn("durability",
			"zero-data-loss mode was asked for but is not in effect — there is no standby to wait for, "+
				"so a lost machine still costs up to 60s of writes",
			fmt.Sprintf("%s ha enable   — then it comes back on its own", brand.CLI))
	case ha.Enabled:
		return ok("durability", "asynchronous replication: commits never wait, and a lost machine costs "+
			"up to 60s of writes")
	}
	return ok("durability", "single copy: commits never wait, and the WAL archive is the only second copy")
}

// Where anchors are kept, and whether the administrator of this machine could
// rewrite them (the expert review plan, G3). Read from the saved target and the
// marker files only: like the backup line, no container and no network.
func checkAnchorTarget() checkLine {
	a, ok, err := branch.CurrentAnchorTarget()
	bt, _ := branch.CurrentTarget()
	return anchorTargetLine(a, ok, err, bt, branch.CountAnchorCopies(branch.LockedSuffix))
}

// anchorTargetLine is the judgement, apart from reading the files.
func anchorTargetLine(a branch.AnchorTarget, set bool, err error, backup branch.Target, c branch.AnchorCopies) checkLine {
	fix := fmt.Sprintf("%s blackbox anchor-target set s3://bucket --endpoint <https-url> --access-key <key>", brand.CLI)
	if err != nil {
		return fail("anchor target", err.Error(), fmt.Sprintf("%s blackbox anchor-target show", brand.CLI))
	}
	if !set {
		where := "on this machine only"
		if backup.Remote() {
			where = "on this machine, with copies in the backup bucket under its default retention"
		}
		return warn("anchor target", "none: anchors are kept "+where+
			", so whoever administers this machine or holds the backup keys could rewrite them", fix)
	}
	detail := fmt.Sprintf("%s, each anchor locked in COMPLIANCE mode for %d days", a.Root(), a.RetentionDays)
	// An anchor waiting more than a day means the copying has stopped, and a
	// gap is exactly what someone rewriting history would want.
	if c.Waiting > 0 && c.OldestWaiting > 24*time.Hour {
		return warn("anchor target", fmt.Sprintf("%s; %d anchor(s) not copied there, the oldest for %s", detail, c.Waiting, c.OldestWaiting.Round(time.Hour)),
			fmt.Sprintf("%s blackbox anchor-target show", brand.CLI))
	}
	if c.Waiting > 0 {
		detail += fmt.Sprintf("; %d waiting to be copied", c.Waiting)
	}
	return ok("anchor target", detail)
}

func checkBackupTarget() checkLine { return backupTargetLine(branch.CurrentTarget()) }

// backupTargetLine is the judgement, separated from reading the file so it can
// be table-tested: the state directory is resolved once per process, so a test
// cannot redirect it, and the decision is the part worth holding still anyway.
func backupTargetLine(t branch.Target, err error) checkLine {
	if err != nil {
		return fail("backup target", err.Error(),
			fmt.Sprintf("%s backup target show", brand.CLI))
	}
	if !t.Remote() {
		return warn("backup target",
			"the local object store, on the same disk as main — one disk or host failure would take the database and every backup of it",
			fmt.Sprintf("%s backup target set s3://bucket --endpoint <https-url> --access-key <key>", brand.CLI))
	}
	// Whether that bucket has Object Lock is the next question and is not asked
	// here: answering it means starting a container and reaching the bucket over
	// the network, under a ten-minute deadline. `check` is run often and should
	// stay quick. A hang in it no longer makes every other line untrustworthy —
	// each check has a deadline and the lines print as they resolve — but a
	// line that costs a container and a network round trip is still the wrong
	// price for a question `backup target show` answers on demand, along with
	// the bucket's reachability.
	return ok("backup target", t.Describe())
}

// How current the backups are — the one line here that has to reach object
// storage to answer, and so the one that used to hang.
//
// With the install down and the backups in the local object store, there is
// nothing to list and no point waiting to discover that; with a remote bucket
// the listing is given seconds, not minutes. Either way a listing that cannot
// be made is reported as a listing that cannot be made. It is not reported as
// "no base backup yet": that sentence sends somebody to take a backup when they
// may already have a hundred, behind a store that is merely unreachable.
func checkBackups() checkLine {
	h := branch.CurrentBackupHealthProbe(probeBudget(checkTimeout()))
	switch {
	case h.Unknown:
		// The way out differs by where the backups are: a local store is this
		// install being down, a bucket that will not answer is credentials or a
		// network, and `backup list` is where its own error is printed in full.
		fix := fmt.Sprintf("%s start   (then `%s backup list`)", brand.CLI, brand.CLI)
		if h.Remote {
			fix = fmt.Sprintf("%s backup list   — prints the store's own error in full", brand.CLI)
		}
		return warn("backups", "could not be listed: "+h.Err, fix)
	case h.Newest == "":
		return warn("backups", "no base backup yet, so there is nothing to restore to",
			fmt.Sprintf("%s backup create", brand.CLI))
	case h.Stale:
		return warn("backups", fmt.Sprintf("newest is %dh old (schedule: %s) in %s", h.AgeHours, h.Schedule, h.Target),
			fmt.Sprintf("%s backup create", brand.CLI))
	}
	return ok("backups", fmt.Sprintf("newest %dh old (schedule: %s) in %s", h.AgeHours, h.Schedule, h.Target))
}

// Whether a restore has ever been proved to work, and when. A backup nothing has
// restored is a hope; this is the line that says which it is.
func checkRestore() checkLine {
	c, ran := branch.LastRestoreCheck() // not `ok`: that is the helper below
	if !ran {
		return warn("restore proven", "never checked on this install",
			fmt.Sprintf("%s backup verify", brand.CLI))
	}
	at, err := time.Parse(time.RFC3339, c.At)
	age := "at an unknown time"
	if err == nil {
		age = fmt.Sprintf("%dh ago", int(time.Since(at).Hours()))
	}
	if !c.OK {
		return fail("restore proven", fmt.Sprintf("the last check (%s) failed: %s", age, firstLine(c.Err)),
			fmt.Sprintf("%s backup verify", brand.CLI))
	}
	return ok("restore proven", fmt.Sprintf("yes, %s — restored from %s in %ds", age, c.BaseBackup, c.Seconds))
}

// Not a fault — but on a fresh install an empty main is usually a seed that did
// not run, and it is the difference between a console with something in it and a
// blank page.
func checkSampleData() checkLine {
	if branch.DemoOff() {
		return ok("sample data", "switched off ("+brand.EnvName("NO_DEMO")+")")
	}
	n, asked := branch.TableCountOK("main")
	if !asked {
		// Not "main has no tables": a stopped main answers the same way as an
		// empty one, and seeding a database that is not running is not the
		// thing to go and do about it.
		return warn("sample data", "main could not be asked what it holds",
			fmt.Sprintf("%s start", brand.CLI))
	}
	if n == 0 {
		return warn("sample data", "main has no tables", fmt.Sprintf("%s demo seed main", brand.CLI))
	}
	return ok("sample data", fmt.Sprintf("main has %d table(s)", n))
}

// Anonymous volumes left by branches removed before removeContainer passed -v.
// Only a warning: they cost disk and nothing else. The fix names prune without
// -a, which removes unused anonymous volumes and keeps every named one; with
// -a it would also take the object store's volume whenever that is stopped.
func checkVolumes() checkLine {
	n, err := branch.UnusedAnonymousVolumes()
	if err != nil {
		return warn("docker volumes", "Docker could not be asked: "+firstLine(err.Error()), "")
	}
	if n == 0 {
		return ok("docker volumes", "no unused anonymous volumes")
	}
	return warn("docker volumes",
		fmt.Sprintf("%d unused anonymous volume(s), most likely left by branches removed by an older version", n),
		"docker volume prune   — removes unused anonymous volumes only; named ones, the object store's included, are kept")
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return l
}
