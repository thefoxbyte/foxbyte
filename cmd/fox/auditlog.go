// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// `fox audit-log …` — pgAudit's log of who did what to the data (F6,
// docs/FOX_F6_Audit_Design.md). `fox audit` is the security log, which is
// FoxByte's own record of its accounts and keys; this is the databases'.
//
// Gate 1, step 1: turning it on and off, and seeing where it stands. Marking
// tables, reading the log and forwarding it come in later steps.
func auditLogCmd(args []string) error {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "status", "":
		return auditLogStatus()
	case "setup":
		return auditLogSetup(args[1:])
	case "off":
		return auditLogOff(args[1:])
	case "show":
		return auditLogShow(args[1:])
	case "verify":
		return auditLogVerify()
	case "collect":
		res, err := branch.CollectAudit()
		if err != nil {
			return err
		}
		fmt.Printf("%d record(s) collected; %d raw file(s) removed; %d day(s) past retention removed.\n", res.Records, res.Removed, res.Pruned)
		return nil
	case "tables":
		return auditLogTables(args[1:])
	case "table":
		return auditLogTable(args[1:])
	default:
		return fmt.Errorf("unknown: %s audit-log %s\n\n%s", brand.CLI, sub, auditLogUsage())
	}
}

func auditLogUsage() string {
	return fmt.Sprintf(`%[1]s audit-log status        whether the databases are audited, where the log is, and its space
%[1]s audit-log setup [--yes] turn it on (restarts main)
%[1]s audit-log off [--yes]   turn it off (restarts main)
%[1]s audit-log show [--branch b] [--table t] [--user u] [--since 1h|2026-11-04] [--limit n] [--errors] [--json]
                                                  the newest records: who did what to which object, how it ended, whom for
%[1]s audit-log verify                                check the records' hash chain
%[1]s audit-log tables [--branch b]                  the tables whose writes (and reads) are audited
%[1]s audit-log table <table> [--reads] [--branch b]  audit a table's writes, and with --reads its reads
%[1]s audit-log table <table> --off [--branch b]      stop auditing it`, brand.CLI)
}

func auditLogStatus() error {
	if !branch.AuditOn() {
		fmt.Printf("The audit log is off: no database runs pgAudit.\n\n"+
			"On, it records who changed the schema and roles, and who wrote to the\n"+
			"tables you mark, with no statement text and no values. It costs\n"+
			"capacity, more on busy tables, and turning it on restarts main.\n\n"+
			"Turn it on with: %s audit-log setup\n", brand.CLI)
		return pendingNote()
	}
	fmt.Printf("The audit log is on, in default mode: schema and role changes by everyone,\n" +
		"and writes to marked tables, with no statement text and no values.\n\n")
	fmt.Printf("  log      %s/<branch>, a week of hourly files\n", branch.AuditRoot())
	if s, err := branch.AuditUsage(); err == nil {
		if s.Quota > 0 {
			fmt.Printf("  space    %s of %s (%s)\n", humanBytes(s.Used), humanBytes(s.Quota), brand.EnvName("AUDIT_QUOTA"))
		} else {
			fmt.Printf("  space    %s, no quota on this storage\n", humanBytes(s.Used))
		}
	}
	if marks, err := branch.AuditMarks("main"); err == nil {
		fmt.Printf("  marked   %d table(s) on main (`%s audit-log tables`)\n", len(marks), brand.CLI)
	}
	fmt.Printf("  records  kept %d days (%s); `%s audit-log show` reads them\n", branch.AuditRetentionDays(), brand.EnvName("AUDIT_RETENTION_DAYS"), brand.CLI)
	fmt.Printf("\nForwarding to a SIEM is not in this version yet.\n")
	return pendingNote()
}

// pendingNote names the databases still running as they were before the last
// change: each picks it up when it next starts, and a suspended branch when it
// wakes.
func pendingNote() error {
	pending, err := branch.AuditPending()
	if err != nil || len(pending) == 0 {
		return nil
	}
	state := "without it"
	if !branch.AuditOn() {
		state = "with it still"
	}
	fmt.Printf("\nStill running %s, until each is next started: %s\n"+
		"A suspended branch picks the change up when it wakes; `%s stop` and then\n"+
		"`%s start` restarts them all now.\n", state, strings.Join(pending, ", "), brand.CLI, brand.CLI)
	return nil
}

// setup is the one way in, and says what it will do before it does it.
func auditLogSetup(args []string) error {
	if branch.AuditOn() {
		fmt.Println("Already on. Nothing to do.")
		return pendingNote()
	}
	if err := branch.AuditHAGuard("setup"); err != nil {
		return err
	}
	if !hasFlag(args, "--yes") {
		fmt.Printf("This turns on pgAudit, which main has to restart to load.\n"+
			"Connections drop for 5–15 seconds while it comes back; nothing is lost.\n\n"+
			"What it records: schema and role changes by everyone, and writes to the\n"+
			"tables you mark, with no statement text and no values. Errors reach the\n"+
			"server log as their code alone. The log is kept at %s, outside every\n"+
			"database, with at most %s (%s).\n\n"+
			"What it costs: capacity. With every statement audited, writes and reads\n"+
			"slowed by a fifth to a half on a busy server; mark only the tables that\n"+
			"need it.\n\n"+
			"Branches pick it up when they are next started, or woken.\n\n"+
			"Run again with --yes to go ahead.\n",
			branch.AuditRoot(), branch.AuditQuota(), brand.EnvName("AUDIT_QUOTA"))
		return nil
	}
	if err := branch.EnsureAuditImage(); err != nil {
		return err
	}
	if err := branch.PrepareAuditDir("main"); err != nil {
		return err
	}
	if err := branch.SetAuditOn(true); err != nil {
		return err
	}
	fmt.Println("Restarting main…")
	if err := branch.RestartPrimary(); err != nil {
		// Back as it was: a half-done setup would start every later branch
		// with settings main does not have.
		_ = branch.SetAuditOn(false)
		_ = branch.RestartPrimary()
		return fmt.Errorf("main did not come back with pgAudit, so audit stays off: %w", err)
	}
	if err := branch.EnsureAuditPolicy("main"); err != nil {
		return fmt.Errorf("main runs pgAudit, but its policy could not be set: %w\n"+
			"Run `%s audit-log setup` again to retry", err, brand.CLI)
	}
	// The standby is a primary in waiting: one left without it would promote
	// a primary that audits nothing.
	if err := branch.RestartStandby(); err != nil {
		fmt.Printf("\nThe HA standby could not be restarted, so it runs without pgAudit and a\n"+
			"failover would promote a primary that audits nothing: %v\n"+
			"Rebuild it with `%s ha enable`.\n", err, brand.CLI)
	}
	recordAuditChange(true)
	fmt.Printf("Done. `%s audit-log status` shows it.\n", brand.CLI)
	return pendingNote()
}

func auditLogOff(args []string) error {
	if !branch.AuditOn() {
		fmt.Println("Already off. Nothing to do.")
		return pendingNote()
	}
	if err := branch.AuditHAGuard("off"); err != nil {
		return err
	}
	if !hasFlag(args, "--yes") {
		fmt.Printf("This turns pgAudit off, which main has to restart to unload.\n"+
			"Connections drop for 5–15 seconds while it comes back; nothing is lost.\n\n"+
			"The log already kept stays where it is, at %s. Tables stay marked,\n"+
			"so turning it on again audits the same ones.\n\n"+
			"Run again with --yes to go ahead.\n", branch.AuditRoot())
		return nil
	}
	if err := branch.ResetAuditPolicy("main"); err != nil {
		return fmt.Errorf("taking the audit policy out of main: %w", err)
	}
	if err := branch.SetAuditOn(false); err != nil {
		return err
	}
	fmt.Println("Restarting main…")
	if err := branch.RestartPrimary(); err != nil {
		return fmt.Errorf("main did not come back: %w", err)
	}
	if err := branch.RestartStandby(); err != nil {
		fmt.Printf("\nThe HA standby could not be restarted, so it still runs pgAudit: %v\n"+
			"Rebuild it with `%s ha enable`.\n", err, brand.CLI)
	}
	recordAuditChange(false)
	fmt.Printf("Done. `%s audit-log status` shows it.\n", brand.CLI)
	return pendingNote()
}

// recordAuditChange puts it in the security log: who turned the record of who
// did what on or off is itself something an auditor asks.
func recordAuditChange(on bool) {
	s := openStore()
	defer s.Close()
	kind, detail := auth.EvAuditLogOff, "pgAudit off"
	if on {
		kind, detail = auth.EvAuditLogOn, "pgAudit on, default mode"
	}
	s.Audit(kind, cliActor(), "main", "", detail)
}

// tables lists a branch's marked tables.
func auditLogTables(args []string) error {
	b := optValue(args, "--branch")
	if b == "" {
		b = "main"
	}
	marks, err := branch.AuditMarks(b)
	if err != nil {
		return err
	}
	if len(marks) == 0 {
		fmt.Printf("No table on %s is marked. Schema and role changes are audited all the same.\n"+
			"Mark one with: %s audit-log table <table> [--reads] --branch %s\n", b, brand.CLI, b)
		return offNote()
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TABLE\tAUDITED")
	for _, m := range marks {
		fmt.Fprintf(w, "%s.%s\t%s\n", m.Schema, m.Name, branch.MarkWhat(m))
	}
	w.Flush()
	return offNote()
}

// offNote says that marks wait for audit to be on, which they do.
func offNote() error {
	if !branch.AuditOn() {
		fmt.Printf("\nThe audit log is off: marks take effect when it is turned on (`%s audit-log setup`).\n", brand.CLI)
	}
	return nil
}

// table marks one table, changes its mark, or takes it off.
func auditLogTable(args []string) error {
	b := optValue(args, "--branch")
	if b == "" {
		b = "main"
	}
	ps := positionals(args, "--branch")
	if len(ps) != 1 {
		return fmt.Errorf("usage: %s audit-log table <table> [--reads] [--off] [--branch b]", brand.CLI)
	}
	schema, table := splitTableName(ps[0])
	if schema == "" {
		schema = "public"
	}
	me := cliActor()
	if hasFlag(args, "--off") {
		if err := branch.UnmarkAudited(b, schema, table, me, "fox audit-log"); err != nil {
			return err
		}
		recordMark(me, b, fmt.Sprintf("stopped auditing %s.%s", schema, table))
		fmt.Printf("%s.%s on %s is no longer audited.\n", schema, table, b)
		return offNote()
	}
	reads := hasFlag(args, "--reads")
	if err := branch.MarkAudited(b, schema, table, reads, me, "fox audit-log"); err != nil {
		return err
	}
	what := branch.MarkWhat(branch.AuditMark{Writes: true, Reads: reads})
	recordMark(me, b, fmt.Sprintf("auditing %s of %s.%s", what, schema, table))
	fmt.Printf("%s.%s on %s: its %s are audited, by every login.\n", schema, table, b, what)
	if reads {
		fmt.Printf("Every read is a line in the log: on a busy table that costs more than writes do.\n")
	}
	return offNote()
}

func recordMark(actor, b, detail string) {
	s := openStore()
	defer s.Close()
	s.Audit(auth.EvAuditMarked, actor, b, "", detail)
}

// show reads the newest records, after collecting what is new.
func auditLogShow(args []string) error {
	if _, err := branch.CollectAudit(); err != nil {
		fmt.Fprintf(os.Stderr, "note: collecting what is new failed, so the newest lines may be missing: %v\n", err)
	}
	q := branch.AuditQuery{
		Branch: optValue(args, "--branch"),
		Table:  optValue(args, "--table"),
		Login:  optValue(args, "--user"),
		Limit:  50,
	}
	if v := optValue(args, "--limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return fmt.Errorf("--limit is a number of records, not %q", v)
		}
		q.Limit = n
	}
	if v := optValue(args, "--since"); v != "" {
		t, err := parseSince(v, time.Now())
		if err != nil {
			return err
		}
		q.Since = t
	}
	if hasFlag(args, "--errors") {
		q.Kinds = []string{"outcome"}
	}
	entries, err := branch.ReadAudit(q)
	if err != nil {
		return err
	}
	st := openStore()
	st.Audit(auth.EvAuditLogRead, cliActor(), q.Branch, "", fmt.Sprintf("%d record(s) via %s audit-log show", len(entries), brand.CLI))
	st.Close()
	if hasFlag(args, "--json") {
		enc := json.NewEncoder(os.Stdout)
		for _, e := range entries {
			if err := enc.Encode(e); err != nil {
				return err
			}
		}
		return nil
	}
	if len(entries) == 0 {
		fmt.Println("No record matches.")
		if !branch.AuditOn() {
			fmt.Printf("The audit log is off (`%s audit-log setup`).\n", brand.CLI)
		}
		return nil
	}
	printAuditEntries(os.Stdout, entries)
	return nil
}

// printAuditEntries is one line per statement: when, where, who, what, on
// which object, how its transaction ended, and whom it was for.
func printAuditEntries(out io.Writer, entries []branch.AuditEntry) {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIME\tBRANCH\tLOGIN\tWHAT\tOBJECT\tOUTCOME\tFOR")
	for _, e := range entries {
		t := e.Time
		if p, err := time.Parse(time.RFC3339Nano, e.Time); err == nil {
			t = p.Local().Format("2006-01-02 15:04:05")
		}
		what, outcome := e.Command, auditOutcome(e)
		if e.Kind == "outcome" {
			what = e.Outcome
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", t, e.Branch, dash(e.Login), what, dash(e.Object), outcome, auditForText(e.TxnFor))
	}
	w.Flush()
}

func auditOutcome(e branch.AuditEntry) string {
	switch {
	case e.Kind == "outcome":
		return e.SQLState
	case e.Error != "" && e.TxnOutcome != "":
		return strings.ToLower(e.TxnOutcome) + " (" + e.Error + ")"
	case e.TxnOutcome != "":
		return strings.ToLower(e.TxnOutcome)
	case e.Error != "":
		return "error " + e.Error
	}
	return "-"
}

func auditForText(f *branch.AuditFor) string {
	if f == nil || f.State == "" || f.State == "none" {
		return "-"
	}
	if f.State == "asserted" {
		return f.Actor + ", asserted by " + f.Issuer
	}
	return f.Actor + " (" + f.State + ")"
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// parseSince reads --since: a duration back from now (90m, 2h, 7d), or a date
// or time.
func parseSince(v string, now time.Time) (time.Time, error) {
	if strings.HasSuffix(v, "d") {
		if n, err := strconv.Atoi(strings.TrimSuffix(v, "d")); err == nil && n > 0 {
			return now.AddDate(0, 0, -n), nil
		}
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return now.Add(-d), nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, v, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("--since is a duration (90m, 2h, 7d) or a date (2026-11-04), not %q", v)
}

// verify checks the chain, after collecting what is new.
func auditLogVerify() error {
	if _, err := branch.CollectAudit(); err != nil {
		fmt.Fprintf(os.Stderr, "note: collecting what is new failed: %v\n", err)
	}
	rep, err := branch.VerifyAudit()
	if err != nil {
		return err
	}
	if rep.Intact {
		fmt.Printf("audit log intact: %d record(s), from record %d, each naming the one before it.\n", rep.Records, rep.First)
		return nil
	}
	fmt.Printf("audit log TAMPERED: %d record(s)\n", rep.Records)
	for _, p := range rep.Problems {
		fmt.Println("  problem:", p)
	}
	os.Exit(1)
	return nil
}
