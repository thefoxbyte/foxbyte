//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package hardening

import (
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// Every fix is for a check the report has; what could lock someone out or
// stop an application is not among them.
func TestFixesAreForRealChecks(t *testing.T) {
	ids := map[string]bool{}
	for _, id := range branch.HardeningCheckIDs() {
		ids[id] = true
	}
	for _, id := range Fixable() {
		if !ids[id] {
			t.Errorf("a fix for %q, which no check has", id)
		}
	}
	for _, never := range []string{"roles.superusers", "conn.trust", "conn.methods", "audit.on", "backup.offsite", "set.checksums"} {
		if _, ok := fixers[never]; ok {
			t.Errorf("%s is a person's to fix", never)
		}
	}
	if got := strings.Join(Fixable(), " "); !strings.Contains(got, "log.connections") || !strings.Contains(got, "roles.public_schema") {
		t.Fatalf("fixable: %s", got)
	}
}

// A check with no fix is offered none.
func TestPlanWithoutFix(t *testing.T) {
	if _, ok, err := plan("main", branch.HardeningCheck{ID: "roles.superusers", Status: branch.HardenFail}); ok || err != nil {
		t.Fatalf("offered a fix: %v %v", ok, err)
	}
}
