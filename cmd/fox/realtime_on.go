//go:build enterprise

// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
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
	default:
		return false
	}
	return true
}

func realtimeEnterpriseUsage() string {
	return fmt.Sprintf(`
%[1]s realtime enable <table> [--branch b] [--events insert,update,delete] [--replica-identity=full]
%[1]s realtime disable <table> [--branch b]
%[1]s realtime tables [--branch b]`, brand.CLI)
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
