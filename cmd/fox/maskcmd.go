// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// maskCmd is `fox mask` (F5, point 4.6): masking personal data a reviewer
// confirmed, for the accounts an admin masks.
//
//	fox mask [status] [--branch b] [--json]
//	fox mask setup [--branch b] [--yes]                                   (Enterprise)
//	fox mask rule <[schema.]table.column> [rule] [--path $.a.b] [--branch b] [--yes]
//	fox mask rule <[schema.]table.column> --off [--path $.a.b] [--branch b]
//	fox mask account <email> [--off] [--yes]                              (Enterprise)
//
// Reading where masking stands is in every edition; setting it is Enterprise.
// Each setup, rule and account change is in the security log.
func maskCmd(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "setup":
			maskSetup(args[1:])
			return
		case "rule":
			maskRule(args[1:])
			return
		case "account":
			maskAccount(args[1:])
			return
		case "status":
			args = args[1:]
		}
	}
	st, err := branch.MaskingStatus(maskBranch(args))
	must(err)
	if hasFlag(args, "--json") {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		must(enc.Encode(st))
		return
	}
	printMaskStatus(st)
}

func maskBranch(args []string) string {
	if b := optValue(args, "--branch"); b != "" {
		return b
	}
	return "main"
}

func printMaskStatus(st branch.MaskStatus) {
	if !st.On {
		fmt.Printf("Masking: not set up on this install.\n")
		if st.Writes {
			fmt.Printf("  %s mask setup   explains what it does first\n", brand.CLI)
		} else {
			fmt.Printf("  Setting it up is in FoxByte Enterprise.\n")
		}
		return
	}
	fmt.Printf("Masking: on. Branch %s.\n", st.Branch)
	if len(st.Pending) > 0 {
		fmt.Printf("  Started before masking was set up, so not masking until they start again: %s\n", strings.Join(st.Pending, ", "))
	}
	fmt.Printf("\nRules (%d)\n", len(st.Rules))
	ready := map[string]bool{}
	for _, t := range st.Ready {
		ready[t] = true
	}
	for _, r := range st.Rules {
		view := r.Table
		if r.Schema != "public" {
			view = r.Schema + "__" + r.Table
		}
		state := "masked"
		if !ready[view] {
			state = "NOT MADE: a masked reader is refused the table"
		}
		fmt.Printf("  %-40s %-8s %-10s %s (%s, %s)\n", r.Where(), r.Rule, r.Category, state, r.By, r.At)
	}
	if len(st.Rules) == 0 {
		fmt.Printf("  none: %s mask rule <table.column> sets one on a confirmed finding\n", brand.CLI)
	}
	fmt.Printf("\nMasked accounts (%d), on every branch they do not own\n", len(st.Accounts))
	for _, a := range st.Accounts {
		fmt.Printf("  %-40s by %s at %s\n", a.Email, a.By, a.At)
	}
	if len(st.Accounts) == 0 {
		fmt.Printf("  none: nobody is masked until an admin masks them\n")
	}
}

// maskSetup sets masking up on a branch: the key if the install has none, the
// databases restarted to mount it, then the roles and grants.
func maskSetup(args []string) {
	requireFeature(edition.Masking)
	b := maskBranch(args)
	must(branch.MaskHAGuard())
	// Started before the key existed, or on an older image: it starts again.
	restart := branch.MaskNeedsRestart(b)
	if !hasFlag(args, "--yes") {
		fmt.Printf("This sets masking up on %s.\n\n"+
			"It makes the install's masking key if it has none: 32 random bytes in\n"+
			"%s, readable only by the database server and mounted read-only\n"+
			"into each database. FoxByte never reads it back and never shows it.\n\n"+
			"Then it makes, on %s, the masked readers' role, the schema their masks\n"+
			"are read from and their rights on the tables. Nobody is masked yet:\n"+
			"an admin masks accounts with `%s mask account`, and rules are set on\n"+
			"confirmed findings with `%s mask rule`, which says what each costs.\n",
			b, branch.MaskKeyDir(), b, brand.CLI, brand.CLI)
		if restart {
			fmt.Printf("\n%s restarts to mount the key: connections drop for 5–15 seconds\n"+
				"while it comes back, and nothing is lost.\n", b)
		}
		fmt.Printf("\nRun again with --yes to go ahead.\n")
		return
	}
	must(branch.EnsureMaskImage())
	must(branch.EnsureMaskKey("default"))
	if restart {
		fmt.Printf("Restarting %s…\n", b)
		if err := branch.RestartForMask(b); err != nil {
			must(fmt.Errorf("%s did not come back with the key: %w", b, err))
		}
		if b == "main" {
			// The standby is a primary in waiting: one without the key would
			// promote a primary whose masked readers see nothing.
			if err := branch.RestartStandby(); err != nil {
				fmt.Printf("The HA standby could not be restarted, so it has no key: %v\n"+
					"Rebuild it with `%s ha enable`.\n", err, brand.CLI)
			}
		}
	}
	must(branch.SetupMasking(b, cliActor()))
	recordMask(auth.EvMaskSetup, b, "masking set up on "+b)
	fmt.Printf("Done. `%s mask --branch %s` shows it.\n", brand.CLI, b)
}

// maskRule sets a rule, or takes one off. Before a rule is set it says what
// it costs (design, decision 9).
func maskRule(args []string) {
	requireFeature(edition.Masking)
	ps := positionals(args, "--branch", "--path")
	if len(ps) < 1 || len(ps) > 2 {
		fmt.Fprintf(os.Stderr, "usage: %s mask rule <[schema.]table.column> [%s] [--path $.a.b] [--branch b] [--yes]\n"+
			"       %s mask rule <[schema.]table.column> --off [--path $.a.b] [--branch b]\n",
			brand.CLI, strings.Join(branch.MaskRules, "|"), brand.CLI)
		os.Exit(2)
	}
	schema, table, column, err := splitColumn(ps[0])
	must(err)
	b, path := maskBranch(args), optValue(args, "--path")
	where := branch.MaskRule{Schema: schema, Table: table, Column: column, Path: path}.Where()
	if hasFlag(args, "--off") {
		must(branch.DropMaskRule(b, schema, table, column, path, cliActor()))
		recordMask(auth.EvMaskRule, b, fmt.Sprintf("rule taken off %s on %s", where, b))
		fmt.Printf("Done: %s is no longer masked on %s.\n", where, b)
		return
	}
	r := branch.MaskRule{Schema: schema, Table: table, Column: column, Path: path, By: cliActor()}
	if len(ps) == 2 {
		r.Rule = ps[1]
		must(branch.CheckMaskRule(r.Rule, ""))
	}
	if !hasFlag(args, "--yes") {
		rule := r.Rule
		if rule == "" {
			rule = "the default for its category"
		}
		fmt.Printf("This masks %s on %s, as %s, for every masked account.\n\n", where, b, rule)
		fmt.Print(branch.MaskCost(r.Rule, path))
		fmt.Printf("\nRun again with --yes to set it.\n")
		return
	}
	must(branch.SetMaskRule(b, r))
	recordMask(auth.EvMaskRule, b, fmt.Sprintf("rule %s set on %s on %s", orDefault(r.Rule), where, b))
	fmt.Printf("Done. `%s mask --branch %s` shows it.\n", brand.CLI, b)
}

func orDefault(rule string) string {
	if rule == "" {
		return "(the category's default)"
	}
	return rule
}

// splitColumn reads [schema.]table.column.
func splitColumn(s string) (schema, table, column string, err error) {
	parts := strings.Split(s, ".")
	switch len(parts) {
	case 2:
		schema, table, column = "public", parts[0], parts[1]
	case 3:
		schema, table, column = parts[0], parts[1], parts[2]
	default:
		return "", "", "", fmt.Errorf("a column is named [schema.]table.column, not %q", s)
	}
	for _, p := range []string{schema, table, column} {
		if p == "" {
			return "", "", "", fmt.Errorf("a column is named [schema.]table.column, not %q", s)
		}
	}
	return schema, table, column, nil
}

// maskAccount masks an account, or unmasks it. Their sessions on running
// branches end, so each next connection sees the change.
func maskAccount(args []string) {
	requireFeature(edition.Masking)
	ps := positionals(args)
	if len(ps) != 1 {
		fmt.Fprintf(os.Stderr, "usage: %s mask account <email> [--off] [--yes]\n", brand.CLI)
		os.Exit(2)
	}
	email, off := strings.ToLower(ps[0]), hasFlag(args, "--off")
	if !hasFlag(args, "--yes") {
		if off {
			fmt.Printf("This unmasks %s: they see real values again on every branch.\n", email)
		} else {
			fmt.Printf("This masks %s on every branch they do not own: they read the masks of\n"+
				"marked tables, ordinary tables as they are, and cannot write to marked\n"+
				"tables. An admin is never masked.\n", email)
		}
		fmt.Printf("Their open sessions end, so the next one sees the change.\n\nRun again with --yes to go ahead.\n")
		return
	}
	must(branch.MaskAccount(email, cliActor(), off))
	what := "masked"
	if off {
		what = "unmasked"
	}
	recordMask(auth.EvMaskAccount, "", what+" "+email)
	fmt.Printf("Done: %s is %s.\n", email, what)
}

func recordMask(kind, b, detail string) {
	if s := openStore(); s != nil {
		s.Audit(kind, cliActor(), b, "", detail)
		s.Close()
	}
}
