//go:build enterprise

// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/thefoxbyte/foxbyte/enterprise/realtime"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// `fox realtime enable|disable|tables` — the paid half of the change feed.
//
// setup, teardown, status and slots are in the core, because someone who goes
// back to Standard must still be able to see and undo what they turned on.
// Choosing what to stream is the feature itself, so it lives here.
func realtimeEnterpriseCmd(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "enable":
		requireFeature(edition.Realtime)
		must(realtimeEnable(args[1:]))
	case "disable":
		requireFeature(edition.Realtime)
		must(realtimeDisable(args[1:]))
	case "tables":
		requireFeature(edition.Realtime)
		must(realtimeTables(args[1:]))
	case "doctor":
		requireFeature(edition.Realtime)
		must(realtimeDoctor(args[1:]))
	case "prepare":
		requireFeature(edition.Realtime)
		must(realtimePrepare(args[1:]))
	case "key":
		requireFeature(edition.Realtime)
		must(realtimeKey(args[1:]))
	case "url":
		requireFeature(edition.Realtime)
		must(realtimeURL(args[1:]))
	case "activity":
		requireFeature(edition.Realtime)
		must(realtimeActivity(args[1:]))
	default:
		return false
	}
	return true
}

func realtimeEnterpriseUsage() string {
	return fmt.Sprintf(`
%[1]s realtime enable <table> [--branch b] [--events insert,update,delete] [--replica-identity=full]
%[1]s realtime disable <table> [--branch b]
%[1]s realtime tables [--branch b]
%[1]s realtime doctor [--branch b]            what can stream, what needs changing, what cannot
%[1]s realtime prepare <table>|--all [--yes]  make a table ready, recorded in the Blackbox
%[1]s realtime url [branch]                  the connection string for an application
%[1]s realtime key create <branch>           mint a stream-only key, shown once
%[1]s realtime key ls [branch]
%[1]s realtime key revoke <id>
%[1]s realtime activity [branch] [--window 24h]  what staying warm has cost`, brand.CLI)
}

func realtimeEnable(args []string) error {
	schema, table, err := splitTable(args)
	if err != nil {
		return err
	}
	req := realtime.Request{
		Table:        realtime.Table{Schema: schema, Name: table},
		FullIdentity: hasFlag(args, "--replica-identity=full"),
	}
	if ev := optValue(args, "--events"); ev != "" {
		req.Events = strings.Split(ev, ",")
	}
	name := branchFlag(args)
	if err := realtime.Enable(name, req); err != nil {
		return err
	}
	fmt.Printf("Streaming %s.%s on %q (%s).\n", schema, table, name, strings.Join(req.EventList(), ", "))
	return nil
}

func realtimeDisable(args []string) error {
	schema, table, err := splitTable(args)
	if err != nil {
		return err
	}
	name := branchFlag(args)
	if err := realtime.Disable(name, schema, table); err != nil {
		return err
	}
	fmt.Printf("Stopped streaming %s.%s on %q.\n", schema, table, name)
	fmt.Println("Any REPLICA IDENTITY FULL stays: it was a change you asked for, it costs only")
	fmt.Println("WAL, and reverting it silently would be a second change you did not.")
	return nil
}

func realtimeTables(args []string) error {
	name := branchFlag(args)
	tables, err := branch.PublishedTables(name)
	if err != nil {
		return err
	}
	if len(tables) == 0 {
		fmt.Printf("Nothing is streamed on %q. Add a table with:\n  %s realtime enable <table>\n", name, brand.CLI)
		return nil
	}
	for _, t := range tables {
		fmt.Println(t)
	}
	return nil
}

// splitTable reads `schema.table` or a bare `table`, which means public.
func splitTable(args []string) (string, string, error) {
	raw := ""
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			raw = a
			break
		}
	}
	if raw == "" {
		return "", "", fmt.Errorf("which table? usage:%s", realtimeEnterpriseUsage())
	}
	if i := strings.LastIndex(raw, "."); i > 0 {
		return raw[:i], raw[i+1:], nil
	}
	return "public", raw, nil
}

func branchFlag(args []string) string {
	if b := optValue(args, "--branch"); b != "" {
		return b
	}
	return "main"
}

// `fox realtime doctor` — the whole branch, classified.
//
// The question an application asks before it adopts realtime is not "can this
// one table stream" but "how much of my database can". Answering it one
// refusal at a time is why the feature looks closed to anyone with more than a
// handful of tables.
func realtimeDoctor(args []string) error {
	name := branchFlag(args)
	verdicts, err := realtime.Survey(name, nil)
	if err != nil {
		return err
	}
	var streaming, ready, fixable, impossible int
	// One rule for what belongs to an application, shared with the realtime
	// API: two copies of a boundary drift, and this one decides whether a
	// subscriber can be offered the Blackbox.
	rows, system := realtime.Application(verdicts)
	for _, v := range rows {
		switch v.State {
		case realtime.Streaming:
			streaming++
		case realtime.Ready:
			ready++
		case realtime.Fixable:
			fixable++
		default:
			impossible++
		}
	}
	if len(rows) == 0 {
		fmt.Printf("No application tables on %q.\n", name)
		return nil
	}
	for _, v := range rows {
		mark := map[realtime.State]string{
			realtime.Streaming: "●", realtime.Ready: "○",
			realtime.Fixable: "!", realtime.Impossible: "x",
		}[v.State]
		detail := ""
		switch v.State {
		case realtime.Fixable:
			detail = fmt.Sprintf("%d change(s) needed", len(v.Fixes))
			if v.Costly() {
				detail += " — one of them has an ongoing cost"
			}
		case realtime.Impossible:
			detail = firstSentence(v.Reason)
		}
		fmt.Printf("  %s  %-40s %-14s %s\n", mark, v.Table.Qualified(), v.State, detail)
	}
	fmt.Printf("\n%d streaming · %d ready · %d need changes · %d cannot stream",
		streaming, ready, fixable, impossible)
	if system > 0 {
		fmt.Printf(" · %d system tables not listed", system)
	}
	fmt.Println()
	if fixable > 0 {
		fmt.Printf("\n%s realtime prepare --all        the free changes, on every table that needs them\n", brand.CLI)
		fmt.Printf("%s realtime prepare <table>      one table, including the ones with a cost\n", brand.CLI)
	}
	return nil
}

// `fox realtime prepare` — make a table ready, or say what it would take.
//
// A dry run by default. The statements are ordinary DDL and land in the
// Blackbox with the login behind them, which is the right outcome and also a
// reason not to run them because a flag was missing.
func realtimePrepare(args []string) error {
	name := branchFlag(args)
	apply := hasFlag(args, "--yes")

	if hasFlag(args, "--all") {
		verdicts, err := realtime.Survey(name, nil)
		if err != nil {
			return err
		}
		done, skipped, err := realtime.PrepareAll(name, verdicts, apply)
		if err != nil {
			return err
		}
		if len(done) == 0 && len(skipped) == 0 {
			fmt.Printf("Nothing to prepare on %q.\n", name)
			return nil
		}
		for _, v := range done {
			fmt.Printf("%s %s\n", map[bool]string{true: "prepared", false: "would prepare"}[apply], v.Table.Qualified())
			for _, f := range v.Fixes {
				fmt.Printf("    %s\n", f.SQL)
			}
		}
		if len(skipped) > 0 {
			fmt.Printf("\nLeft alone, because the only fix has an ongoing cost:\n")
			for _, v := range skipped {
				fmt.Printf("  %s\n", v.Table.Qualified())
				for _, f := range v.Fixes {
					if !f.Free() {
						fmt.Printf("      %s\n      %s\n", f.SQL, f.Cost)
					}
				}
			}
			fmt.Printf("\nRun `%s realtime prepare <table> --yes` for each one you want.\n", brand.CLI)
		}
		if !apply && len(done) > 0 {
			fmt.Printf("\nNothing was changed. Run again with --yes to apply.\n")
		}
		return nil
	}

	schema, table, err := splitTable(args)
	if err != nil {
		return err
	}
	v, err := realtime.Look(name, schema, table, nil)
	if err != nil {
		return err
	}
	switch v.State {
	case realtime.Streaming:
		fmt.Printf("%s is already streaming.\n", v.Table.Qualified())
		return nil
	case realtime.Ready:
		fmt.Printf("%s is ready; nothing to prepare.\n", v.Table.Qualified())
		return nil
	case realtime.Impossible:
		return errors.New(v.Reason)
	}

	fmt.Printf("%s needs %d change(s) before it can stream:\n\n", v.Table.Qualified(), len(v.Fixes))
	for _, f := range v.Fixes {
		fmt.Printf("  %s\n", f.SQL)
		fmt.Printf("      %s\n", f.Why)
		if !f.Free() {
			fmt.Printf("      cost: %s\n", f.Cost)
		}
	}
	for _, alt := range v.Alternatives {
		fmt.Printf("\n  instead: %s\n", alt)
	}
	if !apply {
		fmt.Printf("\nNothing was changed. Run again with --yes to apply.\n")
		return nil
	}
	if err := realtime.Prepare(name, v); err != nil {
		return err
	}
	fmt.Printf("\nDone, and recorded in the Blackbox. %s realtime enable %s\n", brand.CLI, v.Table.Qualified())
	return nil
}

// firstSentence keeps a one-line table readable when a reason runs long.
func firstSentence(s string) string {
	if i := strings.Index(s, ". "); i > 0 {
		return s[:i+1]
	}
	if len(s) > 90 {
		return s[:88] + "…"
	}
	return s
}
