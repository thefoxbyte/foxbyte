// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"strings"
	"testing"
)

// fakePersonalData stands a branch's records in for the database, and says
// which edition the install is.
func fakePersonalData(t *testing.T, recs map[string]personalRecord, masking bool, maskedBranches ...string) {
	t.Helper()
	tempMaskFiles(t)
	oldRead, oldMask, oldScan, oldIs := readPersonalRecord, maskingAvailable, scanningAvailable, isMaskedBranch
	t.Cleanup(func() {
		readPersonalRecord, maskingAvailable, scanningAvailable, isMaskedBranch = oldRead, oldMask, oldScan, oldIs
	})
	readPersonalRecord = func(name string) (personalRecord, error) { return recs[name], nil }
	maskingAvailable = func() bool { return masking }
	scanningAvailable = func() bool { return masking }
	isMaskedBranch = func(name string) bool {
		for _, m := range maskedBranches {
			if m == name {
				return true
			}
		}
		return false
	}
}

func customers() personalRecord {
	// In the order the reader returns them: by place.
	return personalRecord{Scanned: true, Columns: []PersonalColumn{
		{Schema: "crm", Table: "leads", Column: "aadhaar", Category: "aadhaar"},
		{Schema: "public", Table: "customers", Column: "aadhaar", Category: "aadhaar"},
		{Schema: "public", Table: "customers", Column: "email", Category: "email", Mask: MaskHash},
		{Schema: "public", Table: "customers", Column: "pan", Category: "pan"},
	}}
}

// Only confirmed findings are personal data here. A suggested one is a
// question for a reviewer: warning on it would make every scan noise, and the
// change feed would refuse on it. The query is where that is decided.
func TestOnlyConfirmedFindingsCount(t *testing.T) {
	if !strings.Contains(confirmedPIISQL, "state = 'confirmed'") {
		t.Fatalf("the findings query does not keep to confirmed findings:\n%s", confirmedPIISQL)
	}
	// And nothing reads table data: the two records and nothing else.
	for _, q := range []string{confirmedPIISQL, maskRuleColumnsSQL, personalTablesSQL, anyScanSQL} {
		for _, rel := range []string{"FROM public.", "FROM customers", "TABLESAMPLE"} {
			if strings.Contains(q, rel) {
				t.Errorf("query reads table data (%s):\n%s", rel, q)
			}
		}
	}
}

func TestUnmaskedPersonalData(t *testing.T) {
	t.Run("an unmasked reader sees every confirmed column", func(t *testing.T) {
		fakePersonalData(t, map[string]personalRecord{"main": customers()}, true)
		s, err := UnmaskedPersonalData("main", "")
		if err != nil {
			t.Fatal(err)
		}
		if !s.Exposed() || s.Columns != 4 || s.NoRule != 3 {
			t.Fatalf("got %+v, want 4 columns, 3 without a rule", s)
		}
		if got := s.Counts(); got != "2 Aadhaar columns, 1 email column, 1 PAN column" {
			t.Errorf("counts %q", got)
		}
		if len(s.Examples) != 3 || s.Examples[0] != "crm.leads.aadhaar" || s.Examples[1] != "customers.aadhaar" {
			t.Errorf("examples %v: want three, public ones without their schema", s.Examples)
		}
	})

	t.Run("a masked account does not see the columns with a rule", func(t *testing.T) {
		fakePersonalData(t, map[string]personalRecord{"main": customers()}, true)
		if err := SaveMaskedAccounts([]MaskedAccount{{Email: "m@x.io"}}); err != nil {
			t.Fatal(err)
		}
		s, _ := UnmaskedPersonalData("main", "m@x.io")
		if s.Columns != 3 || s.ByCategory["email"] != 0 {
			t.Errorf("masked account: %+v, want the three columns with no rule", s)
		}
		// Its agent key reads as it does.
		if a, _ := UnmaskedPersonalData("main", AgentKeyRole("m@x.io")); a.Columns != 3 {
			t.Errorf("masked account's agent key: %d columns, want 3", a.Columns)
		}
		// An account nobody masked reads the rule's column as it is.
		if p, _ := UnmaskedPersonalData("main", "p@x.io"); p.Columns != 4 {
			t.Errorf("unmasked account: %d columns, want 4", p.Columns)
		}
	})

	t.Run("a masked branch holds the masks for everybody", func(t *testing.T) {
		fakePersonalData(t, map[string]personalRecord{"agent-a": customers()}, true, "agent-a")
		s, _ := UnmaskedPersonalData("agent-a", "")
		if s.Columns != 3 {
			t.Errorf("masked branch: %d columns, want the 3 with no rule", s.Columns)
		}
	})

	t.Run("everything masked is nothing to warn about", func(t *testing.T) {
		rec := personalRecord{Scanned: true, Columns: []PersonalColumn{{Table: "c", Column: "email", Category: "email", Mask: MaskHash}}}
		fakePersonalData(t, map[string]personalRecord{"agent-a": rec}, true, "agent-a")
		s, _ := UnmaskedPersonalData("agent-a", "")
		if s.Exposed() || s.Warning("agents using it", "") != "" {
			t.Errorf("all masked: %+v, %q", s, s.Warning("agents using it", ""))
		}
	})

	t.Run("never scanned is said, and is not no personal data", func(t *testing.T) {
		fakePersonalData(t, map[string]personalRecord{}, true)
		s, _ := UnmaskedPersonalData("dev", "")
		if s.Scanned || s.Exposed() {
			t.Fatalf("got %+v", s)
		}
		w := s.Warning("agents using it", "")
		for _, want := range []string{"never been scanned", "unmasked by default", "pii scan --branch dev"} {
			if !strings.Contains(w, want) {
				t.Errorf("warning %q does not say %q", w, want)
			}
		}
		// An agent's branch is made from main, so main is what to scan.
		if w := (UnmaskedSummary{Branch: "agent-x", ScanningAvailable: true}).Warning("", ""); !strings.Contains(w, "--branch main") {
			t.Errorf("agent branch: %q", w)
		}
	})

	t.Run("scanned with nothing confirmed says nothing", func(t *testing.T) {
		fakePersonalData(t, map[string]personalRecord{"main": {Scanned: true}}, true)
		s, _ := UnmaskedPersonalData("main", "")
		if w := s.Warning("agents using it", ""); w != "" {
			t.Errorf("warning %q for a branch with nothing confirmed", w)
		}
	})
}

// What the warning says to do depends on the edition: Enterprise names the
// commands; Standard says masking needs Enterprise, and does not offer a
// command it would refuse.
func TestPersonalDataWarningByEdition(t *testing.T) {
	t.Run("enterprise", func(t *testing.T) {
		fakePersonalData(t, map[string]personalRecord{"agent-a": customers()}, true)
		ws := PersonalDataWarnings("agent-a", "", "agents using it", "o@x.io")
		if len(ws) != 1 {
			t.Fatalf("warnings %v", ws)
		}
		for _, want := range []string{
			"this branch holds unmasked personal data: 2 Aadhaar columns, 1 email column, 1 PAN column",
			"(crm.leads.aadhaar, customers.aadhaar, customers.email, ...)",
			"agents using it see real values",
			"Masking (Enterprise) can hide them: fox mask rule crm.leads.aadhaar --branch main",
			"fox mask account o@x.io",
		} {
			if !strings.Contains(ws[0], want) {
				t.Errorf("warning %q does not say %q", ws[0], want)
			}
		}
	})
	t.Run("standard", func(t *testing.T) {
		fakePersonalData(t, map[string]personalRecord{"agent-a": customers()}, false)
		ws := PersonalDataWarnings("agent-a", "", "agents using it", "o@x.io")
		if len(ws) != 1 || !strings.Contains(ws[0], "masking needs FoxByte Enterprise") || strings.Contains(ws[0], "fox mask") {
			t.Errorf("standard warning %v", ws)
		}
		never := (UnmaskedSummary{Branch: "main"}).Warning("agents using it", "")
		if !strings.Contains(never, "Scanning and masking need FoxByte Enterprise") || strings.Contains(never, "fox pii scan") {
			t.Errorf("standard, never scanned: %q", never)
		}
	})
}
