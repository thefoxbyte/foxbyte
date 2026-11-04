// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// The tables to mark: a confirmed finding on a table whose writes are not
// audited, once each, whatever else is found there.
func TestUnmarkedPersonalTables(t *testing.T) {
	f := func(schema, table, state string) PIIFinding {
		return PIIFinding{Schema: schema, Table: table, Column: "c", State: state}
	}
	findings := []PIIFinding{
		f("public", "customers", PIIConfirmed),
		f("public", "customers", PIIConfirmed), // a second column: the table once
		f("public", "orders", PIIConfirmed),    // marked already
		f("public", "notes", PIISuggested),     // not decided
		f("public", "logs", PIIRejected),       // decided not personal
		f("crm", "leads", PIIConfirmed),
		f("public", "reads_only", PIIConfirmed), // reads marked, not writes: still to mark
	}
	marks := []AuditMark{
		{Schema: "public", Name: "orders", Writes: true},
		{Schema: "public", Name: "reads_only", Reads: true},
	}
	got := strings.Join(UnmarkedPersonalTables(findings, marks), " ")
	if got != "crm.leads public.customers public.reads_only" {
		t.Fatalf("got %q", got)
	}
	if UnmarkedPersonalTables(nil, marks) != nil {
		t.Fatal("tables with no findings")
	}
}

// An automatic mark adds writes and never takes reads off.
func TestMarkWritesSQL(t *testing.T) {
	sql := markWritesSQL(`'public.customers'::regclass`)
	for _, want := range []string{"GRANT INSERT, UPDATE, DELETE ON %s TO bb_audit", "TO bb_audit_read", "is not a table"} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q:\n%s", want, sql)
		}
	}
	if strings.Contains(sql, "REVOKE") || strings.Contains(sql, "SELECT ON %s TO bb_audit'") {
		t.Errorf("an automatic mark touches reads:\n%s", sql)
	}
}

// Marking every table is Enterprise; reading which are unmarked is not.
func TestMarkPersonalDataTablesIsEnterprise(t *testing.T) {
	edition.SetEntitlement(nil)
	t.Cleanup(func() { edition.SetEntitlement(nil) })
	if _, err := MarkPersonalDataTables("main", "cli:me"); !errors.Is(err, ErrNotLicensed) {
		t.Fatalf("marked without a licence: %v", err)
	}
}

// A SECURITY DEFINER function naming a marked table is a finding while audit
// is on, saying what it runs as and which tables.
func TestDefinerFindings(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	in := findingsInput{Now: now, AuditOn: true, State: auditState{LastRun: now.Format(time.RFC3339)},
		Definers: map[string][]DefinerFunc{
			"main": {{Function: "public.pay(integer)", Owner: "app_owner", Tables: []string{"public.orders", "public.payments"}}},
		}}
	fs := findingsFrom(in)
	if len(fs) != 1 || fs[0].Kind != "definer" || fs[0].Branch != "main" {
		t.Fatalf("findings: %+v", fs)
	}
	for _, want := range []string{"public.pay(integer)", "runs as app_owner", "public.orders, public.payments", "not in the audit log"} {
		if !strings.Contains(fs[0].Detail, want) {
			t.Errorf("missing %q: %s", want, fs[0].Detail)
		}
	}
	in.AuditOn = false
	for _, f := range findingsFrom(in) {
		if f.Kind == "definer" {
			t.Fatal("a definer finding with audit off, when nothing is audited anyway")
		}
	}
}

// The query leaves out the Blackbox's own functions and an extension's, and
// matches whole words, with the table name escaped for the pattern.
func TestDefinerSQL(t *testing.T) {
	for _, want := range []string{"p.prosecdef", "'bb'", "d.deptype = 'e'", `'\m' ||`, `|| '\M'`, "rolname = 'bb_audit'"} {
		if !strings.Contains(definerSQL, want) {
			t.Errorf("missing %q", want)
		}
	}
}
