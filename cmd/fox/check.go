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
		checkConsoleEmbedded(),
		checkStorage(),
		checkMain(),
	}
	lines = append(lines, checkServers()...)
	lines = append(lines, checkPorts()...)
	lines = append(lines, checkAPI(), checkAPIClosed(), checkBlackbox(), checkBackups(), checkRestore(), checkSampleData())

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
