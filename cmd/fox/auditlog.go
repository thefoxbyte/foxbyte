// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

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
	fmt.Printf("\nReading the log and forwarding it are not in this version yet.\n")
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
