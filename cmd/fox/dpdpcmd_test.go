// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

func TestParseKeep(t *testing.T) {
	for in, want := range map[string]struct {
		n    int
		unit string
	}{
		"3y": {3, "years"}, "18m": {18, "months"}, "90d": {90, "days"}, "0": {0, "days"},
		"3 years": {3, "years"}, " 1 Year ": {1, "years"}, "6 months": {6, "months"}, "30 days": {30, "days"},
	} {
		n, u, err := parseKeep(in)
		if err != nil || n != want.n || u != want.unit {
			t.Errorf("%q = %d %s (%v), want %d %s", in, n, u, err, want.n, want.unit)
		}
	}
	for _, in := range []string{"", "3", "y", "3w", "three years", "-1y"} {
		if _, _, err := parseKeep(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestDPDPLine(t *testing.T) {
	f := func(table, column, cat string) branch.PIIFinding {
		return branch.PIIFinding{Schema: "public", Table: table, Column: column, Category: cat, State: branch.PIIConfirmed}
	}
	e := branch.DPDPEntry{Schema: "public", Table: "customers", Basis: "consent", Purpose: "orders",
		Principals: []string{"customer"}, Keep: branch.DPDPKeep{Count: 3, Unit: "years", From: "last_contact", Reason: "purpose"}}
	staff := e
	staff.Table = "staff"

	none := branch.BuildDPDPInventory("main", nil, nil)
	if l := dpdpLine(none, false); l.state != 0 || l.detail != "not in use" {
		t.Errorf("unlicensed, nothing recorded: %+v", l)
	}
	if l := dpdpLine(none, true); l.state != 0 || !strings.Contains(l.detail, "no confirmed personal data") {
		t.Errorf("licensed, nothing confirmed: %+v", l)
	}
	gaps := branch.BuildDPDPInventory("main", []branch.PIIFinding{f("customers", "email", "email"), f("orders", "ship_to", "mobile")}, []branch.DPDPEntry{e})
	if l := dpdpLine(gaps, true); l.state != 1 || !strings.Contains(l.detail, "1 column(s) in 1 table(s)") || !strings.Contains(l.fix, "dpdp inventory --gaps") {
		t.Errorf("a gap: %+v", l)
	}
	child := branch.BuildDPDPInventory("main", []branch.PIIFinding{f("staff", "dob", "child")}, []branch.DPDPEntry{staff})
	if l := dpdpLine(child, true); l.state != 1 || !strings.Contains(l.detail, "1 notice(s)") {
		t.Errorf("a child's data unlisted: %+v", l)
	}
	full := branch.BuildDPDPInventory("main", []branch.PIIFinding{f("customers", "email", "email")}, []branch.DPDPEntry{e})
	if l := dpdpLine(full, true); l.state != 0 || !strings.Contains(l.detail, "every confirmed column") {
		t.Errorf("all covered: %+v", l)
	}
	// Recorded under a licence since lapsed: still read, still warned.
	if l := dpdpLine(gaps, false); l.state != 1 {
		t.Errorf("lapsed licence with entries: %+v", l)
	}
}

func TestBranchAgeLine(t *testing.T) {
	if l := branchAgeLine(0, nil); l.state != 0 || !strings.Contains(l.detail, "no maximum set") {
		t.Errorf("off: %+v", l)
	}
	if l := branchAgeLine(90*24*time.Hour, nil); l.state != 0 || !strings.Contains(l.detail, "older than 90 days") {
		t.Errorf("none old: %+v", l)
	}
	yes := true
	l := branchAgeLine(90*24*time.Hour, []branch.BranchAge{{Branch: "agent-x", Days: 120, Personal: &yes}, {Branch: "dev", Days: 95}})
	if l.state != 1 || !strings.Contains(l.detail, "agent-x (120 days, with personal data), dev (95 days)") {
		t.Errorf("old: %+v", l)
	}
}
