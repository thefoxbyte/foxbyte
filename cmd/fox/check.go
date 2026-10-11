// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/tls"
	"fmt"
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

func checkCmd(args []string) {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Printf("usage: %s check\n\nChecks this install and says what to do about anything wrong.\n", brand.CLI)
		return
	}
	lines := []checkLine{
		checkVersion(),
		checkEdition(),
		checkLicense(),
		checkConsoleEmbedded(),
		checkStorage(),
		checkMain(),
	}
	lines = append(lines, checkServers()...)
	lines = append(lines, checkPorts()...)
	lines = append(lines, checkAPI(), checkAPIClosed(), checkBlackbox(), checkAnchors(), checkRealtime(),
		checkBackupTarget(), checkBackups(), checkRestore(), checkSampleData())

	failed, warned := 0, 0
	for _, l := range lines {
		mark := "ok  "
		switch l.state {
		case stateWarn:
			mark, warned = "warn", warned+1
		case stateFail:
			mark, failed = "FAIL", failed+1
		}
		fmt.Printf("%s  %-18s %s\n", mark, l.name, l.detail)
		if l.fix != "" {
			fmt.Printf("      → %s\n", l.fix)
		}
	}
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
		if edition.Enterprise {
			return warn("licence", "none installed",
				fmt.Sprintf("%s license activate <file>", brand.CLI))
		}
		// A Standard build has nothing to unlock, so no licence is the correct
		// and uninteresting state rather than something to flag.
		return ok("licence", "not needed by the standard edition")
	}
	if err != nil {
		return warn("licence", err.Error(), fmt.Sprintf("%s license show", brand.CLI))
	}
	st := license.Install()
	switch st.State {
	case license.Active:
		return ok("licence", fmt.Sprintf("%s — %s, to %s", l.ID, l.Customer,
			l.NotAfter.UTC().Format("2 January 2006")))
	case license.Warning:
		return warn("licence", st.Reason, st.Action)
	default:
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
	// here: answering it means starting a container and reaching the bucket
	// over the network, under a ten-minute deadline. `check` is run often and
	// should stay quick, and a hang in it would make every other line
	// untrustworthy. `backup target show` reaches the bucket and reports both
	// its reachability and its retention.
	return ok("backup target", t.Describe())
}

func checkBackups() checkLine {
	h := branch.CurrentBackupHealth()
	switch {
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
	n := branch.TableCount("main")
	if n == 0 {
		return warn("sample data", "main has no tables", fmt.Sprintf("%s demo seed main", brand.CLI))
	}
	return ok("sample data", fmt.Sprintf("main has %d table(s)", n))
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return l
}
