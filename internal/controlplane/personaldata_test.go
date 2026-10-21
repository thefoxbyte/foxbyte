// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// Where personal data sits is as sensitive as scanning for it: both are the
// branch owner's, and a route added under personal-data/ later cannot default
// to Use by being forgotten.
func TestPersonalDataNeedsManage(t *testing.T) {
	for _, c := range []struct {
		method, tail string
	}{
		{"GET", "personal-data"},
		{"POST", "personal-data/scan"},
		{"POST", "personal-data/findings/7/mark"},
	} {
		if got := needFor(c.method, c.tail); got != access.Manage {
			t.Errorf("%s %s: %v, want Manage", c.method, c.tail, got)
		}
	}
	if got := needFor("GET", "personal-database"); got != access.Use {
		t.Errorf("a tail that only starts with the same letters is not covered: %v", got)
	}
}

func TestScanSummaryKeepsNoValues(t *testing.T) {
	rep := branch.PIIReport{
		Scan:     &branch.PIIScan{ID: 3, Tables: 4, Columns: 9, Sample: 1000, Skipped: []branch.PIISkip{{Object: "public.f", Reason: "foreign"}}},
		Findings: []branch.PIIFinding{{Column: "aadhaar", Why: "12 of 12 sampled values …"}},
	}
	got := rep.Summary()
	if got != "scan 3: 4 table(s), 9 column(s), 1 skipped, sample 1000; 1 finding(s) in all" {
		t.Fatalf("summary: %q", got)
	}
	if strings.Contains(got, "aadhaar") {
		t.Fatal("the security log entry names no column")
	}
}
