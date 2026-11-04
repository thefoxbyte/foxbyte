// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// The export is Enterprise, and a period must run forwards.
func TestProduceAuditEvidenceRefuses(t *testing.T) {
	edition.SetEntitlement(nil)
	t.Cleanup(func() { edition.SetEntitlement(nil) })
	now := time.Now()
	if _, err := ProduceAuditEvidence(EvidenceOptions{Since: now.Add(-time.Hour)}); !errors.Is(err, ErrNotLicensed) {
		t.Fatalf("produced without a licence: %v", err)
	}
	if edition.Enterprise {
		edition.SetEntitlement(func(edition.Feature) bool { return true })
		old := buildAuditEvidence
		buildAuditEvidence = func(EvidenceOptions) (AuditEvidence, error) { return AuditEvidence{}, nil }
		t.Cleanup(func() { buildAuditEvidence = old })
		if _, err := ProduceAuditEvidence(EvidenceOptions{Since: now, Until: now.Add(-time.Hour)}); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("a period ending before it starts: %v", err)
		}
	}
}

// The period's records, by when they happened, whichever day collected them,
// and never with their text.
func TestAuditRecordsBetween(t *testing.T) {
	storeIn(t)
	settingsIn(t)
	seed(t, "2026-11-04", lineObject, lineTxn, lineError) // 10:00:01.5, 10:00:01.6, 10:00:02
	recs, err := AuditRecordsBetween(time.Date(2026, 11, 4, 10, 0, 1, 550e6, time.UTC), time.Date(2026, 11, 4, 10, 0, 2, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Kind != "transaction" {
		t.Fatalf("got %+v", recs)
	}
	all, _ := AuditRecordsBetween(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC))
	if len(all) != 3 {
		t.Fatalf("the whole period: %d records", len(all))
	}
	for _, r := range all {
		if r.Text != "" {
			t.Fatalf("a record with its text: %+v", r)
		}
	}
	if none, _ := AuditRecordsBetween(time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)); len(none) != 0 {
		t.Fatalf("records after the period: %d", len(none))
	}
}

// What the document says it covers and what it does not, as section 12 does.
func TestEvidenceStatements(t *testing.T) {
	not := strings.Join(EvidenceNotLogged, "\n")
	for _, want := range []string{"not marked", "SECURITY DEFINER", "superuser", "TRUNCATE", "continuous import"} {
		if !strings.Contains(not, want) {
			t.Errorf("not logged does not say %q", want)
		}
	}
	if s := EvidenceSummary(AuditEvidence{Period: EvidencePeriod{Since: "a", Until: "b"}, Activity: EvidenceActivity{Records: 3},
		Integrity: EvidenceIntegrity{ChainReport: ChainReport{Intact: true}}, Records: []AuditRecord{}}); s != "evidence for a to b: 3 record(s) in the period, chain intact, the records included" {
		t.Fatalf("summary: %q", s)
	}
}
