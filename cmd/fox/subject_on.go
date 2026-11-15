//go:build enterprise

// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/thefoxbyte/foxbyte/enterprise/pii"
	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// subjectCmd is `fox subject find <value> [--category c] [--json]`: where one
// person's data appears, across main and the running branches, for an access
// or erasure request (docs/data-subject-requests.md). Read-only, and only in
// the columns a reviewer confirmed as personal data.
//
// It needs whoever runs the engine, as every `fox` command does, and the
// Enterprise licence, because it is built on personal-data discovery.
func subjectCmd(args []string) {
	ps := positionals(args, "--category")
	if len(ps) < 2 || ps[0] != "find" {
		fmt.Printf("usage: %s subject find <email|phone|aadhaar|…> [--category c] [--json]\n", brand.CLI)
		os.Exit(2)
	}
	requireFeature(edition.PersonalData)
	rep, err := pii.FindSubject(ps[1], pii.Category(optValue(args, "--category")), pii.PostgresSubjects{})
	must(err)
	// Who looked for a person is worth knowing; the value is not recorded.
	if s := historyStore(); s != nil {
		s.Audit(auth.EvSubjectSearched, cliActor(), "", "", rep.Summary())
		s.Close()
	}
	if hasFlag(args, "--json") {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		must(enc.Encode(rep))
		return
	}
	fmt.Printf("searched as %v: %d confirmed columns on %d branches\n", rep.Categories, rep.Columns, rep.Branches)
	if len(rep.Places) == 0 {
		fmt.Println("not found in any of them")
	} else {
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "BRANCH\tTABLE\tCOLUMN\tCATEGORY\tROWS")
		for _, p := range rep.Places {
			col := p.Column
			if p.Path != "" {
				col += " " + p.Path
			}
			fmt.Fprintf(tw, "%s\t%s.%s\t%s\t%s\t%d\n", p.Branch, p.Schema, p.Table, col, p.Category, p.Rows)
		}
		tw.Flush()
	}
	for _, l := range rep.Limits {
		fmt.Println("  limit:", l)
	}
}
