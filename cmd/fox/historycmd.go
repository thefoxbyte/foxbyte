// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// historyCmd is `fox history` (points 8.1, 8.3): the SQL run from the console,
// the API, `fox sql` and `fox export`, kept per person for 90 days.
//
//	fox history [--branch b] [--limit n] [--json]   yours: what was run at this machine
//	fox history --user <email> [...]                a person's, for a request about their own data
//	fox history --people                            who has history, and how much
//	fox history purge [--user <email>]              delete yours, or a person's
//	fox history purge --everyone --yes              delete everybody's
//	fox history status | on | off                   the install's switch
//	fox history retention <days>                    how long it is kept (1–3650)
//
// Reading or deleting somebody else's history is the machine's operator acting
// for them, so it is recorded in the security log; your own is not an event.
func historyCmd(args []string) {
	sub := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	s := openStore()
	defer s.Close()
	me := cliActor()
	switch sub {
	case "":
		who := me
		if u := optValue(args, "--user"); u != "" {
			who = u
		}
		if hasFlag(args, "--people") {
			people, err := s.HistoryActors()
			must(err)
			printHistoryPeople(os.Stdout, people)
			return
		}
		n, _ := strconv.Atoi(optValue(args, "--limit"))
		h, err := s.History(who, auth.HistoryQuery{Branch: optValue(args, "--branch"), Limit: n})
		must(err)
		if who != me {
			s.Audit(auth.EvHistoryRead, me, who, "", fmt.Sprintf("%d entries, read at the machine", len(h)))
		}
		if hasFlag(args, "--json") {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			must(enc.Encode(h))
			return
		}
		printHistory(os.Stdout, h, who)
	case "purge":
		var n int64
		var err error
		switch {
		case hasFlag(args, "--everyone"):
			if !hasFlag(args, "--yes") {
				fmt.Fprintf(os.Stderr, "this deletes everybody's query history: run %s history purge --everyone --yes\n", brand.CLI)
				os.Exit(2)
			}
			n, err = s.PurgeAllHistory()
			must(err)
			s.Audit(auth.EvHistoryPurged, me, "*", "", fmt.Sprintf("%d entries, everybody's", n))
			fmt.Printf("Deleted %d entr%s: everybody's query history.\n", n, ies(n))
			return
		case optValue(args, "--user") != "":
			who := optValue(args, "--user")
			n, err = s.PurgeHistory(who)
			must(err)
			s.Audit(auth.EvHistoryPurged, me, who, "", fmt.Sprintf("%d entries, deleted at the machine", n))
			fmt.Printf("Deleted %d entr%s from %s's query history.\n", n, ies(n), who)
			return
		}
		n, err = s.PurgeHistory(me)
		must(err)
		s.Audit(auth.EvHistoryPurged, me, me, "", fmt.Sprintf("%d entries, their own", n))
		fmt.Printf("Deleted %d entr%s from your query history.\n", n, ies(n))
	case "status":
		set, err := s.HistorySettings()
		must(err)
		state := "on"
		if !set.Enabled {
			state = "off"
		}
		fmt.Printf("Query history is %s for this install, kept %d days.\n", state, set.RetentionDays)
		fmt.Println("It holds the SQL people ran from the console, the API, fox sql and fox export, and never a result.")
	case "on", "off":
		must(s.SetHistoryEnabled(sub == "on"))
		s.Audit(auth.EvHistorySettings, me, "", "", "history "+sub)
		if sub == "on" {
			fmt.Println("Query history is on.")
		} else {
			fmt.Println("Query history is off: nothing new is kept. What was kept stays until it expires or is purged.")
		}
	case "retention":
		if len(args) < 1 {
			fmt.Printf("usage: %s history retention <days>\n", brand.CLI)
			os.Exit(2)
		}
		d, err := strconv.Atoi(strings.TrimSuffix(args[0], "d"))
		if err != nil {
			must(fmt.Errorf("retention is a number of days, not %q", args[0]))
		}
		must(s.SetHistoryRetention(d))
		s.Audit(auth.EvHistorySettings, me, "", "", fmt.Sprintf("retention %d days", d))
		fmt.Printf("Query history is kept %d days; anything older was deleted.\n", d)
	default:
		fmt.Printf("usage: %s history [--branch b] [--limit n] [--json] [--user <email>] [--people] | purge | status | on | off | retention <days>\n", brand.CLI)
		os.Exit(2)
	}
}

// historyStore opens the store for recording, or returns nil: `fox sql` ran
// without the store before history existed, and keeping a statement must never
// be what makes it fail.
func historyStore() *auth.Store {
	s, err := auth.OpenFromEnv()
	if err != nil {
		return nil
	}
	return s
}

func ies(n int64) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// printHistory is a table to read: newest first, a statement on one line.
func printHistory(w io.Writer, h []auth.HistoryEntry, who string) {
	if len(h) == 0 {
		fmt.Fprintf(w, "No query history for %s.\n", who)
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tWHEN\tBRANCH\tFROM\tTOOK\tROWS\tRESULT\tSQL")
	for _, e := range h {
		res := "ok"
		if !e.OK {
			res = "error"
		}
		from := e.Source
		if e.Kind == "export" {
			from += " export"
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%dms\t%d\t%s\t%s\n", e.ID,
			time.UnixMilli(e.At).Format("2006-01-02 15:04:05"), e.Branch, from, e.DurationMS, e.Rows, res, oneLine(e.SQL, 80))
	}
	tw.Flush()
}

func printHistoryPeople(w io.Writer, people map[string]int) {
	if len(people) == 0 {
		fmt.Fprintln(w, "Nobody has any query history.")
		return
	}
	names := make([]string, 0, len(people))
	for n := range people {
		names = append(names, n)
	}
	sort.Strings(names)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "WHO\tENTRIES")
	for _, n := range names {
		fmt.Fprintf(tw, "%s\t%d\n", n, people[n])
	}
	tw.Flush()
}

// oneLine is a statement on one line, cut to n characters.
func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}
