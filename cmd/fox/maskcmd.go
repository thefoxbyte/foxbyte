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
//	fox mask key [status] [--json]
//	fox mask key create|rotate|drop <domain> [--yes]                      (Enterprise)
//	fox mask key use <domain> --table [schema.]table [--branch b] [--yes] (Enterprise)
//	fox mask unmask <email> --branch b [--off] [--yes]                    (Enterprise)
//	fox mask lookups [--branch b] [--limit n] [--json]
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
		case "key":
			maskKey(args[1:])
			return
		case "unmask":
			maskUnmask(args[1:])
			return
		case "lookups":
			maskLookups(args[1:])
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
	fmt.Printf("\nMasked accounts (%d), on every branch, their own included\n", len(st.Accounts))
	for _, a := range st.Accounts {
		fmt.Printf("  %-40s by %s at %s\n", a.Email, a.By, a.At)
	}
	if len(st.Accounts) == 0 {
		fmt.Printf("  none: nobody is masked until an admin masks them\n")
	}
	fmt.Printf("\nUnmask on %s (%d): real values, every read of a marked table audited\n", st.Branch, len(st.Unmasks))
	for _, g := range st.Unmasks {
		fmt.Printf("  %-40s by %s at %s\n", g.Email, g.By, g.At)
	}
	if len(st.Unmasks) > 0 && !st.AuditOn {
		fmt.Printf("  The audit log is off, so their reads are not being logged: %s audit-log on\n", brand.CLI)
	}
	fmt.Printf("\nLookups on %s: %d recorded (%s mask lookups --branch %s)\n", st.Branch, len(st.Lookups), brand.CLI, st.Branch)
	// The paths around the masks (step 4).
	if len(st.Closed) > 0 {
		fmt.Printf("\nClosed to masked accounts on %s (%d): they would read real values through these\n", st.Branch, len(st.Closed))
		for _, c := range st.Closed {
			why := "a view reading a masked column"
			if c.Kind == "refs" {
				why = "a foreign key into a masked column: writing it would say which values are there"
			}
			fmt.Printf("  %-40s %s taken: %s\n", c.Relation, c.Privs, why)
		}
	}
	if len(st.Definers) > 0 {
		fmt.Printf("\nDefiner functions a masked account can run that read masked tables (%d): each can return real values\n", len(st.Definers))
		for _, d := range st.Definers {
			fmt.Printf("  %-40s runs as %s, names %s\n", d.Function, d.Owner, strings.Join(d.Tables, ", "))
		}
		fmt.Printf("  Take EXECUTE from PUBLIC on each (REVOKE EXECUTE ON FUNCTION … FROM PUBLIC), or make it SECURITY INVOKER.\n")
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
			fmt.Printf("This masks %s on every branch, their own included: they read the\n"+
				"masks of marked tables, ordinary tables as they are, and cannot write to\n"+
				"marked tables. Their agent keys read the same. An admin is never masked.\n", email)
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

// maskKey is `fox mask key` (step 2): the install's key domains, and rotating
// a key. Reading is in every edition; changing a key is Enterprise and in the
// security log. The keys themselves are never shown.
func maskKey(args []string) {
	sub := "status"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	if sub == "status" {
		st, err := branch.MaskKeysState()
		must(err)
		if hasFlag(args, "--json") {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			must(enc.Encode(st))
			return
		}
		printMaskKeys(st)
		return
	}
	requireFeature(edition.Masking)
	ps := positionals(args, "--branch", "--table")
	usage := func() {
		fmt.Fprintf(os.Stderr, "usage: %[1]s mask key [status] [--json]\n"+
			"       %[1]s mask key create|rotate|drop <domain> [--yes]\n"+
			"       %[1]s mask key use <domain> --table [schema.]table [--branch b] [--yes]\n", brand.CLI)
		os.Exit(2)
	}
	if len(ps) != 1 {
		usage()
	}
	domain, yes := ps[0], hasFlag(args, "--yes")
	switch sub {
	case "create":
		must(branch.CheckMaskDomain(domain))
		if !yes {
			fmt.Printf("This makes a key domain, %s: a key of its own, 32 random bytes beside the\n"+
				"default key in %s, never read back and never shown.\n\n"+
				"Tables put under it (`%s mask key use %s --table …`) hash apart from every\n"+
				"other domain's, so their masks cannot be joined with them: for data that must\n"+
				"never be matched up, such as two tenants'. Joins work within one domain.\n\n"+
				"Run again with --yes to make it.\n", domain, branch.MaskKeyDir(), brand.CLI, domain)
			return
		}
		must(branch.CreateMaskDomain(domain, cliActor()))
		recordMask(auth.EvMaskKey, "", "key domain "+domain+" made")
		fmt.Printf("Done: key domain %s made.\n", domain)
	case "rotate":
		k, ok := branch.MaskKeyFor(domain)
		if !ok {
			must(fmt.Errorf("the install has no key domain %q (`%s mask key` lists them)", domain, brand.CLI))
		}
		if !yes {
			fmt.Printf("This rotates the key of domain %s (key %d).\n\n", domain, max(k.Gen, 1))
			fmt.Print(branch.MaskRotateCost(domain))
			st, err := branch.MaskKeysState()
			must(err)
			for _, u := range st.Keys {
				if u.Domain != domain {
					continue
				}
				var keyed []string
				for _, t := range u.Tables {
					if t.Keyed {
						keyed = append(keyed, t.Branch+": "+t.Schema+"."+t.Table)
					}
				}
				fmt.Printf("\nWritten again (%d tables on running branches)\n", len(keyed))
				for _, t := range keyed {
					fmt.Printf("  %s\n", t)
				}
				if u.Pending {
					fmt.Printf("\nA rotation of %s was cut short: this carries it on with the key it made.\n", domain)
				}
			}
			if len(st.Stopped) > 0 {
				fmt.Printf("\nNot running, so not rotated: %s. Their tables in %s keep masks made\n"+
					"under the old key until `%s mask setup --branch <name>` once each starts;\n"+
					"`%s mask key` names them.\n", strings.Join(st.Stopped, ", "), domain, brand.CLI, brand.CLI)
			}
			fmt.Printf("\nRun again with --yes to rotate it.\n")
			return
		}
		must(branch.RotateMaskKey(domain, cliActor(), func(s string) { fmt.Println("  " + s) }))
		recordMask(auth.EvMaskKey, "", "key of domain "+domain+" rotated")
		fmt.Printf("Done: %s's key is rotated, and the old one deleted.\n", domain)
	case "drop":
		if !yes {
			fmt.Printf("This deletes key domain %s and its key. It is refused while a table on\n"+
				"any branch uses it, or while a branch stopped since it was made, whose tables\n"+
				"cannot be read.\n\n"+
				"Run again with --yes to delete it.\n", domain)
			return
		}
		must(branch.DropMaskDomain(domain, cliActor()))
		recordMask(auth.EvMaskKey, "", "key domain "+domain+" deleted")
		fmt.Printf("Done: key domain %s deleted.\n", domain)
	case "use":
		t := optValue(args, "--table")
		if t == "" {
			usage()
		}
		schema, table := "public", t
		if i := strings.Index(t, "."); i >= 0 {
			schema, table = t[:i], t[i+1:]
		}
		b := maskBranch(args)
		if !yes {
			fmt.Printf("This puts %s.%s's masks on %s under key domain %s.\n\n"+
				"Only that table's hashed and faked masks are written again, under %s's key;\n"+
				"masked readers read the old ones until it is done. Its masks then join only\n"+
				"with tables in %s.\n\nRun again with --yes to go ahead.\n", schema, table, b, domain, domain, domain)
			return
		}
		must(branch.UseMaskDomain(b, schema, table, domain, cliActor()))
		recordMask(auth.EvMaskKey, b, fmt.Sprintf("%s.%s on %s put under key domain %s", schema, table, b, domain))
		fmt.Printf("Done: %s.%s on %s is under key domain %s.\n", schema, table, b, domain)
	default:
		usage()
	}
}

func printMaskKeys(st branch.MaskKeysStatus) {
	if len(st.Keys) == 0 {
		fmt.Printf("Masking keys: none. `%s mask setup` makes the install's first.\n", brand.CLI)
		return
	}
	fmt.Printf("Masking keys (%d). The keys are never shown.\n", len(st.Keys))
	for _, k := range st.Keys {
		made := k.Made
		if made == "" {
			made = "before key records were kept"
		}
		fmt.Printf("\n  %s: key %d, made %s", k.Domain, max(k.Gen, 1), made)
		if k.By != "" {
			fmt.Printf(" by %s", k.By)
		}
		if k.Rotated != "" {
			fmt.Printf("; rotated %s by %s", k.Rotated, k.RotBy)
		}
		fmt.Println()
		if k.Next {
			fmt.Printf("    A ROTATION WAS CUT SHORT: `%s mask key rotate %s --yes` finishes it.\n", brand.CLI, k.Domain)
		}
		for _, t := range k.Tables {
			what := "partial or empty only, no key"
			if t.Keyed {
				what = fmt.Sprintf("under key %d", max(t.Gen, 1))
			}
			fmt.Printf("    %s: %s.%s, %s\n", t.Branch, t.Schema, t.Table, what)
		}
		if len(k.Tables) == 0 {
			fmt.Printf("    no table on a running branch\n")
		}
		for _, t := range k.Stale {
			fmt.Printf("    MADE UNDER AN OLDER KEY: %s: %s.%s; `%s mask setup --branch %s` makes them again\n",
				t.Branch, t.Schema, t.Table, brand.CLI, t.Branch)
		}
	}
	if len(st.Stopped) > 0 {
		fmt.Printf("\nNot running, so not read: %s\n", strings.Join(st.Stopped, ", "))
	}
}

// maskUnmask gives a masked account unmask on a branch, or takes it. There it
// sees real values, and every read it makes of a marked table is audited.
func maskUnmask(args []string) {
	requireFeature(edition.Masking)
	ps := positionals(args, "--branch")
	b := optValue(args, "--branch")
	if len(ps) != 1 || b == "" {
		fmt.Fprintf(os.Stderr, "usage: %s mask unmask <email> --branch b [--off] [--yes]\n", brand.CLI)
		os.Exit(2)
	}
	email, off := strings.ToLower(ps[0]), hasFlag(args, "--off")
	if !hasFlag(args, "--yes") {
		if off {
			fmt.Printf("This takes unmask on %s from %s: they read masks there again.\n", b, email)
		} else {
			fmt.Printf("This lets %s see real values on %s, as its owner does.\n\n"+
				"Every read they make there of a marked table is audited: their role's audit\n"+
				"role becomes %s, which only a superuser can change, so the audit log\n"+
				"records those reads, and theirs only. It is listed in the access review.\n",
				email, b, branch.AuditReadRole)
			if !branch.AuditOn() {
				fmt.Printf("\nThe audit log is off, so their reads are not logged until `%s audit-log on`.\n", brand.CLI)
			}
		}
		fmt.Printf("Their open sessions on %s end, so the next one sees the change.\n\nRun again with --yes to go ahead.\n", b)
		return
	}
	must(branch.Unmask(email, b, cliActor(), off))
	what := "given unmask on " + b
	if off {
		what = "no longer unmasked on " + b
	}
	recordMask(auth.EvMaskUnmask, b, email+" "+what)
	fmt.Printf("Done: %s is %s.\n", email, what)
}

// maskLookups lists a branch's lookups: who, when, which column, how many
// rows found. Never the value looked up, which is not kept.
func maskLookups(args []string) {
	b := maskBranch(args)
	n := 100
	if v := optValue(args, "--limit"); v != "" {
		if _, err := fmt.Sscan(v, &n); err != nil {
			must(fmt.Errorf("--limit is a number, not %q", v))
		}
	}
	ls, err := branch.Lookups(b, n)
	must(err)
	if hasFlag(args, "--json") {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		must(enc.Encode(ls))
		return
	}
	fmt.Printf("Lookups on %s (%d, newest first). The values looked up are not kept.\n", b, len(ls))
	for _, l := range ls {
		fmt.Printf("  %s  %-36s %s.%s  found %d\n", l.At, l.Who, l.Table, l.Column, l.Found)
	}
	if len(ls) == 0 {
		fmt.Printf("  none: a masked account looks a person up with SELECT * FROM %s.find('table', 'column', 'value')\n", branch.MaskSchema)
	}
}
