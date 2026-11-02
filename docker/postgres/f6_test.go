// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres_test

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// Every major the engine runs has a pinned pgAudit in the image, so an image
// built today is the image built tomorrow, and a new major cannot be added
// without one.
func TestEveryMajorHasAPinnedPgAudit(t *testing.T) {
	b, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	d := strings.ReplaceAll(string(b), "\r\n", "\n")
	for _, m := range branch.SupportedPGMajors {
		pin := regexp.MustCompile(`ARG PGAUDIT_VERSION_` + m + `=` + m + `\.[0-9]+-[0-9]+\.pgdg12\+[0-9]+\n`)
		if !pin.MatchString(d) {
			t.Errorf("no pinned pgAudit version for PostgreSQL %s (ARG PGAUDIT_VERSION_%s)", m, m)
		}
		if !strings.Contains(d, m+`) v="${PGAUDIT_VERSION_`+m+`}" ;;`) {
			t.Errorf("the pgAudit install does not use the pin for PostgreSQL %s", m)
		}
	}
	if !strings.Contains(d, `"postgresql-${PG_MAJOR}-pgaudit=${v}"`) {
		t.Error("pgAudit should be installed at its pinned version")
	}
}

// The log hook and the transaction line exist only when the library is
// preloaded: loaded on demand, as every install before audit loads it, the
// library must behave exactly as it did.
func TestAuditHooksOnlyWhenPreloaded(t *testing.T) {
	b, err := os.ReadFile("bb_identity/bb_identity.c")
	if err != nil {
		t.Fatal(err)
	}
	// A Windows checkout has CRLF line endings: .gitattributes pins LF for
	// scripts and the Dockerfile, not for C.
	c := strings.ReplaceAll(string(b), "\r\n", "\n")
	if !strings.Contains(c, "if (process_shared_preload_libraries_in_progress)\n\t\taudit_init();") {
		t.Error("audit_init should run only while shared_preload_libraries is being processed")
	}
	start := strings.Index(c, "audit_init(void)\n{")
	if start < 0 {
		t.Fatal("audit_init's definition was not found")
	}
	body := c[start:]
	end := strings.Index(body, "\n}")
	if end < 0 {
		t.Fatal("audit_init's body has no end")
	}
	body = body[:end]
	for _, hook := range []string{"\temit_log_hook = audit_emit_log;", "RegisterXactCallback(", "RegisterSubXactCallback("} {
		if n := strings.Count(c, hook); n != 1 {
			t.Errorf("%q appears %d times; it belongs in audit_init alone", hook, n)
		}
		if !strings.Contains(body, hook) {
			t.Errorf("%q is not inside audit_init", hook)
		}
	}
}
