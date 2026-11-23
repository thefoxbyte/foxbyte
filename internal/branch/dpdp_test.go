// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"bytes"
	"encoding/csv"
	"errors"
	"strings"
	"testing"
	"time"
)

func goodEntry() DPDPEntry {
	return DPDPEntry{
		Schema: "public", Table: "customers",
		Basis: "consent", Purpose: "  Delivering orders  ",
		Principals: []string{"child", "customer", "customer"},
		Keep:       DPDPKeep{Count: 3, Unit: "years", From: "last_contact", Reason: "purpose"},
	}
}

func TestCheckDPDPEntryTidies(t *testing.T) {
	e, err := CheckDPDPEntry(goodEntry())
	if err != nil {
		t.Fatal(err)
	}
	if e.Purpose != "Delivering orders" {
		t.Errorf("purpose not trimmed: %q", e.Purpose)
	}
	// Once each, in the vocabulary's order.
	if strings.Join(e.Principals, ",") != "customer,child" {
		t.Errorf("principals = %v, want [customer child]", e.Principals)
	}
}

func TestCheckDPDPEntryRefuses(t *testing.T) {
	for name, change := range map[string]func(*DPDPEntry){
		"no table":          func(e *DPDPEntry) { e.Table = "" },
		"unknown basis":     func(e *DPDPEntry) { e.Basis = "7j" },
		"no purpose":        func(e *DPDPEntry) { e.Purpose = "   " },
		"long purpose":      func(e *DPDPEntry) { e.Purpose = strings.Repeat("x", 1001) },
		"no one":            func(e *DPDPEntry) { e.Principals = nil },
		"unknown principal": func(e *DPDPEntry) { e.Principals = []string{"customer", "robot"} },
		"unknown unit":      func(e *DPDPEntry) { e.Keep.Unit = "weeks" },
		"negative":          func(e *DPDPEntry) { e.Keep.Count = -1 },
		"over a century":    func(e *DPDPEntry) { e.Keep.Count = 101 },
		"unknown start":     func(e *DPDPEntry) { e.Keep.From = "birthday" },
		"nothing kept":      func(e *DPDPEntry) { e.Keep.Count, e.Keep.From = 0, "collection" },
		"unknown reason":    func(e *DPDPEntry) { e.Keep.Reason = "habit" },
		"law with no name":  func(e *DPDPEntry) { e.Keep.Reason = "law" },
		"contract, no name": func(e *DPDPEntry) { e.Keep.Reason, e.Keep.Citation = "contract", "  " },
		"long citation":     func(e *DPDPEntry) { e.Keep.Reason, e.Keep.Citation = "law", strings.Repeat("x", 501) },
		"long note":         func(e *DPDPEntry) { e.Note = strings.Repeat("x", 1001) },
	} {
		e := goodEntry()
		change(&e)
		if _, err := CheckDPDPEntry(e); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s: err = %v, want ErrInvalidRequest", name, err)
		}
	}
	// Months allow more than years, by the unit.
	e := goodEntry()
	e.Keep.Count, e.Keep.Unit = 1200, "months"
	if _, err := CheckDPDPEntry(e); err != nil {
		t.Errorf("1200 months refused: %v", err)
	}
	// Until the purpose is served is 0 after it, for the purpose.
	e.Keep = DPDPKeep{Count: 0, Unit: "days", From: "purpose_served", Reason: "purpose"}
	if _, err := CheckDPDPEntry(e); err != nil {
		t.Errorf("until the purpose is served refused: %v", err)
	}
}

func TestDPDPKeepReads(t *testing.T) {
	for _, c := range []struct {
		k    DPDPKeep
		want string
	}{
		{DPDPKeep{0, "days", "purpose_served", "purpose", ""}, "until the purpose is served (s.8(7)(a))"},
		{DPDPKeep{1, "years", "account_closed", "contract", "MSA cl. 9"}, "1 year after the account is closed; a contract: MSA cl. 9"},
		{DPDPKeep{8, "years", "account_closed", "law", "PMLA s.12"}, "8 years after the account is closed; a law requires it: PMLA s.12"},
	} {
		if got := c.k.String(); got != c.want {
			t.Errorf("%+v reads %q, want %q", c.k, got, c.want)
		}
	}
}

func TestSplitDPDPPlace(t *testing.T) {
	for in, want := range map[string][3]string{
		"customers":           {"public", "customers", ""},
		"crm.customers":       {"crm", "customers", ""},
		"crm.customers.email": {"crm", "customers", "email"},
		" public.staff.dob ":  {"public", "staff", "dob"},
	} {
		s, tb, c, err := SplitDPDPPlace(in)
		if err != nil || [3]string{s, tb, c} != want {
			t.Errorf("%q = %q %q %q (%v), want %v", in, s, tb, c, err, want)
		}
	}
	for _, in := range []string{"", "a..b", "a.b.c.d", ".b"} {
		if _, _, _, err := SplitDPDPPlace(in); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%q accepted", in)
		}
	}
}

func finding(table, column, path, category, state string) PIIFinding {
	return PIIFinding{Schema: "public", Table: table, Column: column, Path: path, Category: category, State: state}
}

func TestBuildDPDPInventory(t *testing.T) {
	fs := []PIIFinding{
		finding("customers", "email", "", "email", PIIConfirmed),
		finding("customers", "aadhaar_no", "", "aadhaar", PIIConfirmed),
		finding("customers", "profile", "$.phone", "mobile", PIIConfirmed),
		finding("customers", "profile", "$.alt", "mobile", PIIConfirmed),
		finding("customers", "notes", "", "email", PIISuggested), // undecided: not in it
		finding("staff", "dob", "", "date_of_birth", PIIConfirmed),
		finding("staff", "dob", "", "child", PIIConfirmed),
		finding("staff", "pan", "", "pan", PIIRejected), // rejected: not in it
		finding("orders", "ship_to", "", "mobile", PIIConfirmed),
	}
	table := func(tb string) DPDPEntry {
		e := goodEntry()
		e.Table, e.Principals = tb, []string{"customer"}
		return e
	}
	kyc := table("customers")
	kyc.Column, kyc.Basis = "aadhaar_no", "7d"
	gone := table("customers")
	gone.Column = "notes" // only suggested there: no longer confirmed
	es := []DPDPEntry{table("customers"), kyc, table("staff"), gone, table("invoices")}

	inv := BuildDPDPInventory("main", fs, es)
	if len(inv.Tables) != 3 {
		t.Fatalf("tables = %d, want customers, orders, staff", len(inv.Tables))
	}
	cust, ord, staff := inv.Tables[0], inv.Tables[1], inv.Tables[2]
	if cust.Table != "customers" || ord.Table != "orders" || staff.Table != "staff" {
		t.Fatalf("order = %s %s %s", cust.Table, ord.Table, staff.Table)
	}
	by := map[string]DPDPColumn{}
	for _, c := range cust.Columns {
		by[c.Column] = c
	}
	if by["aadhaar_no"].By != "column" || by["aadhaar_no"].Override == nil || by["aadhaar_no"].Override.Basis != "7d" {
		t.Errorf("aadhaar_no = %+v, want its own entry", by["aadhaar_no"])
	}
	if by["email"].By != "table" || by["email"].Override != nil {
		t.Errorf("email = %+v, want the table's", by["email"])
	}
	if p := by["profile"]; strings.Join(p.Paths, ",") != "$.alt,$.phone" || strings.Join(p.Categories, ",") != "mobile" {
		t.Errorf("profile = %+v", p)
	}
	if _, in := by["notes"]; in {
		t.Error("an undecided finding's column is in the inventory")
	}
	if cust.Gaps != 0 || ord.Gaps != 1 || ord.Columns[0].By != "" {
		t.Errorf("gaps: customers %d, orders %d (%q)", cust.Gaps, ord.Gaps, ord.Columns[0].By)
	}
	if inv.GapColumns != 1 || inv.GapTables != 1 {
		t.Errorf("gap counts = %d columns, %d tables, want 1, 1", inv.GapColumns, inv.GapTables)
	}
	// staff.dob holds a child's data; staff's entry lists customers only.
	if len(staff.Notices) != 1 || !strings.Contains(staff.Notices[0], "dob") || !strings.Contains(staff.Notices[0], "s.9(1)") {
		t.Errorf("staff notices = %v", staff.Notices)
	}
	if len(staff.Columns) != 1 || strings.Join(staff.Columns[0].Categories, ",") != "child,date_of_birth" {
		t.Errorf("staff columns = %+v (the rejected pan is not personal data)", staff.Columns)
	}
	var stale []string
	for _, e := range inv.Stale {
		stale = append(stale, e.Where())
	}
	if strings.Join(stale, ",") != "public.customers.notes,public.invoices" {
		t.Errorf("stale = %v", stale)
	}
	if inv.Undecided != 1 || !strings.Contains(strings.Join(inv.Limits, " "), "1 finding(s) are undecided") {
		t.Errorf("undecided = %d, limits = %v", inv.Undecided, inv.Limits)
	}

	// Listing children clears the notice; nothing covering it, no notice
	// either (it is a gap, said once).
	kids := table("staff")
	kids.Principals = []string{"employee", "child"}
	if inv := BuildDPDPInventory("main", fs, []DPDPEntry{kids}); len(inv.Tables[2].Notices) != 0 {
		t.Errorf("notices with children listed = %v", inv.Tables[2].Notices)
	}
	if inv := BuildDPDPInventory("main", fs, nil); len(inv.Tables[2].Notices) != 0 || inv.GapColumns != 5 {
		t.Errorf("no entries: notices %v, gaps %d (want none, 5)", inv.Tables[2].Notices, inv.GapColumns)
	}
}

func TestBuildDPDPInventoryEmpty(t *testing.T) {
	inv := BuildDPDPInventory("b1", nil, nil)
	if inv.Tables == nil || inv.Stale == nil || len(inv.Limits) == 0 || len(inv.Vocabulary.Bases) != 10 {
		t.Errorf("empty inventory = %+v", inv)
	}
}

func TestWriteDPDPCSV(t *testing.T) {
	fs := []PIIFinding{
		finding("customers", "email", "", "email", PIIConfirmed),
		finding("orders", "ship_to", "", "mobile", PIIConfirmed),
	}
	e := goodEntry()
	e.Principals = []string{"customer"}
	e.Purpose = "=HYPERLINK(\"http://x\")"
	e.SetBy, e.SetAt = "dpo@example.com", time.Date(2026, 11, 24, 9, 0, 0, 0, time.UTC)
	var buf bytes.Buffer
	if err := WriteDPDPCSV(&buf, BuildDPDPInventory("main", fs, []DPDPEntry{e})); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || strings.Join(rows[0], ",") != strings.Join(DPDPCSVHeader, ",") {
		t.Fatalf("rows = %v", rows)
	}
	row := map[string]string{}
	for i, h := range rows[0] {
		row[h] = rows[1][i]
	}
	if row["covered_by"] != "table" || row["basis"] != "consent" || row["basis_label"] != "Consent (s.6)" ||
		row["set_at"] != "2026-11-24T09:00:00Z" || row["retention"] != "3 years after the person's last contact (s.8(8))" {
		t.Errorf("customers.email row = %v", row)
	}
	if !strings.HasPrefix(row["purpose"], "'=") {
		t.Errorf("a formula was written as one: %q", row["purpose"])
	}
	if rows[2][2] != "ship_to" || rows[2][4] != "none" || rows[2][5] != "" {
		t.Errorf("the gap's row = %v", rows[2])
	}
}

func TestDPDPEntrySummaryKeepsTheTextOut(t *testing.T) {
	e, _ := CheckDPDPEntry(goodEntry())
	e.Note = "secret note"
	s := e.Summary()
	if strings.Contains(s, "Delivering") || strings.Contains(s, "secret") {
		t.Errorf("the summary quotes free text: %q", s)
	}
	if s != "public.customers: basis consent, customer+child, kept 3 years after last_contact" {
		t.Errorf("summary = %q", s)
	}
}
