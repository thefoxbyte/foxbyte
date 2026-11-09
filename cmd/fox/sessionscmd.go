// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// sessionsCmd is `fox sessions` (point 12.5): who is connected to a branch and
// what each is running, a query cancelled, a session ended. From the machine,
// the operator sees every session; each signal is in the security log.
//
//	fox sessions [--branch b] [--json]
//	fox sessions cancel <pid> [--branch b]
//	fox sessions end <pid> [--branch b] [--yes]
func sessionsCmd(args []string) {
	b := maskBranch(args)
	if len(args) > 0 && (args[0] == "cancel" || args[0] == "end") {
		pidArg := firstPositional(args[1:], "--branch")
		if pidArg == "" {
			fmt.Printf("usage: %s sessions %s <pid> [--branch b]\n", brand.CLI, args[0])
			os.Exit(2)
		}
		pid, err := branch.ParsePID(pidArg)
		must(err)
		end := args[0] == "end"
		if end && !hasFlag(args, "--yes") {
			ss, err := branch.Sessions(b)
			must(err)
			for _, s := range ss {
				if s.PID == pid {
					fmt.Printf("This ends session %d on %s (%s, %s), rolling back what it has open:\n  %s\n\nRun again with --yes to go ahead.\n",
						pid, b, s.User, s.State, oneLine(s.Query, 120))
					return
				}
			}
			must(fmt.Errorf("there is no client session %d on %s", pid, b))
		}
		s, err := branch.SignalSession(b, pid, end, "")
		must(err)
		kind, what := auth.EvSessionCancel, "Cancelled the query of"
		if end {
			kind, what = auth.EvSessionEnd, "Ended"
		}
		recordMask(kind, b, fmt.Sprintf("%s session %d (%s)", strings.ToLower(what), pid, s.User))
		fmt.Printf("%s session %d on %s (%s).\n", what, pid, b, s.User)
		return
	}
	ss, err := branch.Sessions(b)
	must(err)
	if hasFlag(args, "--json") {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		must(enc.Encode(ss))
		return
	}
	if len(ss) == 0 {
		fmt.Printf("No client sessions on %s.\n", b)
		return
	}
	fmt.Printf("%-7s %-30s %-20s %-10s %s\n", "PID", "USER", "STATE", "FOR", "QUERY")
	for _, s := range ss {
		user := s.User
		if s.Engine {
			user += " (" + brand.Product + ")"
		}
		state := s.State
		if s.Wait != "" && s.State == "active" {
			state += ", waits"
		}
		if len(s.BlockedBy) > 0 {
			state += fmt.Sprintf(", blocked by %v", s.BlockedBy)
		}
		fmt.Printf("%-7d %-30s %-20s %-10s %s\n", s.PID, user, state, since(s.Since), oneLine(s.Query, 80))
	}
}

// maintainCmd is `fox maintain` (point 12.5): each table's upkeep, and a
// table vacuumed or analysed.
//
//	fox maintain [--branch b] [--table [schema.]t] [--json]
//	fox maintain vacuum|analyze|vacuum-analyze <[schema.]table> [--branch b]
func maintainCmd(args []string) {
	b := maskBranch(args)
	if len(args) > 0 && (args[0] == branch.MaintVacuum || args[0] == branch.MaintAnalyze || args[0] == branch.MaintVacuumAnalyze) {
		t := firstPositional(args[1:], "--branch")
		if t == "" {
			fmt.Printf("usage: %s maintain %s <[schema.]table> [--branch b]\n", brand.CLI, args[0])
			os.Exit(2)
		}
		schema, table := splitTableName(t)
		st, took, err := branch.Maintain(b, schema, table, args[0])
		must(err)
		recordMask(auth.EvMaintenance, b, fmt.Sprintf("%s of %s.%s", args[0], st.Schema, st.Table))
		fmt.Printf("%s of %s.%s on %s done in %s: %d rows, %d dead.\n", args[0], st.Schema, st.Table, b, took.Round(time.Millisecond), st.Live, st.Dead)
		return
	}
	schema, table := "", ""
	if t := optValue(args, "--table"); t != "" {
		schema, table = splitTableName(t)
	}
	ts, err := branch.TablesStats(b, schema, table)
	must(err)
	if hasFlag(args, "--json") {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		must(enc.Encode(ts))
		return
	}
	if len(ts) == 0 {
		fmt.Printf("No tables on %s.\n", b)
		return
	}
	fmt.Printf("%-36s %10s %10s  %-22s %-22s\n", "TABLE", "ROWS", "DEAD", "LAST VACUUM", "LAST ANALYZE")
	for _, t := range ts {
		fmt.Printf("%-36s %10d %10d  %-22s %-22s\n", t.Schema+"."+t.Table, t.Live, t.Dead, latest(t.LastVacuum, t.LastAutoVacuum), latest(t.LastAnalyze, t.LastAutoAnalyze))
	}
}

// latest is the later of a by-hand and an automatic run, saying which.
func latest(hand, auto string) string {
	switch {
	case hand == "" && auto == "":
		return "never"
	case auto > hand:
		return auto + " (auto)"
	}
	return hand
}

// since is how long ago an RFC 3339 time was, briefly.
func since(at string) string {
	t, err := time.Parse(time.RFC3339, at)
	if err != nil {
		return ""
	}
	return time.Since(t).Round(time.Second).String()
}
