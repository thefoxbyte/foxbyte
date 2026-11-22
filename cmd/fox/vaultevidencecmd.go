// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// The vault's evidence and the customer's declarations (point 13, step 13.4b):
//
//	fox vault evidence [--kind k] [--since 90d|2026-08-01] [--entries] [--json]
//	fox vault declare --kind k                      (what the kind asks to be declared)
//	fox vault declare --kind k ITEM "what is true" | ITEM --withdraw
//	fox vault declarations [--kind k] [--all] [--json]
//
// The operator's, on the machine; over the API, admins only.

const vaultEvidenceUsage = `usage:
  fox vault evidence [--kind KIND] [--since 90d|2026-08-01] [--entries] [--json]
  fox vault declare --kind KIND [ITEM "STATEMENT" | ITEM --withdraw]
  fox vault declarations [--kind KIND] [--all] [--json]
`

func vaultEvidence(args []string) {
	st := openStore()
	if st == nil {
		must(fmt.Errorf("the install's store could not be opened, and the evidence reads it"))
	}
	defer st.Close()
	o := branch.VaultEvidenceOptions{Kind: optValue(args, "--kind"), Entries: hasFlag(args, "--entries"), By: cliActor()}
	if v := optValue(args, "--since"); v != "" {
		t, err := parseSince(v, time.Now())
		must(err)
		o.Since = t
	}
	ev, err := branch.VaultEvidenceFor(st, o)
	must(err)
	if hasFlag(args, "--json") {
		printJSON(ev)
		return
	}
	printVaultEvidence(os.Stdout, ev)
}

func printVaultEvidence(w io.Writer, ev *branch.VaultEvidence) {
	fmt.Fprintf(w, "Vault evidence, %s, by %s; activity since %s.\n", ev.Generated, ev.By, ev.Since[:10])
	tok := fmt.Sprintf("%s %s, serial %s", ev.Token.Maker, ev.Token.Model, ev.Token.Serial)
	if ev.Token.Software {
		tok += " (the software token: not UIDAI-compliant, trials and testing only)"
	}
	fmt.Fprintf(w, "Token: %s.\n", tok)
	chain := "the chain holds"
	if ev.Log.BrokenAt != 0 {
		chain = fmt.Sprintf("THE CHAIN BREAKS AT ENTRY %d", ev.Log.BrokenAt)
	}
	fmt.Fprintf(w, "Access log: %d entries, %s; against the security log: %s.\n", ev.Log.Entries, chain, ev.Log.Anchor.Note)
	for _, k := range ev.Kinds {
		fmt.Fprintf(w, "\n%s: %d record(s); rules: %s\n", k.Kind, k.Records, dash(k.Rules))
		if len(k.Rows) == 0 {
			fmt.Fprintln(w, "  No rules are mapped for this kind, so there is nothing to judge; its keys and activity are in --json.")
			continue
		}
		fmt.Fprintf(w, "  %d met, %d not met, %d open (waiting for a declaration), %d not applicable.\n",
			k.Summary[branch.VaultMet], k.Summary[branch.VaultNotMet], k.Summary[branch.VaultOpen], k.Summary[branch.VaultNotApplicable])
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "\n  PARA\tVERDICT\tWHOSE\tREQUIREMENT")
		for _, r := range k.Rows {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", r.Para, strings.ToUpper(r.Verdict), r.Whose, clip(r.Requirement, 80))
		}
		_ = tw.Flush()
		var why []string
		for _, r := range k.Rows {
			for _, c := range r.Checks {
				if !c.OK {
					why = append(why, fmt.Sprintf("  %s: %s: %s", r.Para, c.What, c.Detail))
				}
			}
			if r.Verdict == branch.VaultOpen || r.Verdict == branch.VaultNotMet {
				have := map[string]bool{}
				for _, d := range r.Declared {
					have[d.Item] = true
				}
				for _, it := range r.Items {
					if !have[it] {
						why = append(why, fmt.Sprintf("  %s: not declared: %s (%s vault declare --kind %s %s \"…\")", r.Para, it, brand.CLI, k.Kind, it))
					}
				}
			}
		}
		if len(why) > 0 {
			fmt.Fprintln(w, "\n  What keeps a rule from being met:")
			for _, l := range why {
				fmt.Fprintln(w, l)
			}
		}
		var decl []string
		for _, r := range k.Rows {
			for _, d := range r.Declared {
				decl = append(decl, fmt.Sprintf("  %s %s: %q, declared by %s on %s", r.Para, d.Item, d.Value, d.DeclaredBy, d.DeclaredAt.Format("2006-01-02")))
			}
		}
		if len(decl) > 0 {
			fmt.Fprintln(w, "\n  Declared by the customer (not checked by FoxByte):")
			for _, l := range uniq(decl) {
				fmt.Fprintln(w, l)
			}
		}
		if len(k.Branches) > 0 {
			fmt.Fprintln(w, "\n  Branches, by their latest Aadhaar exposure report:")
			for _, b := range k.Branches {
				state := "clean"
				if b.Flag != "" {
					state = b.Flag
				}
				ran := "never"
				if b.Ran != nil {
					ran = b.Ran.Local().Format("2006-01-02")
				}
				fmt.Fprintf(w, "    %s (scanned %s): %s\n", b.Branch, ran, state)
			}
		}
	}
	fmt.Fprintln(w, "\nWhat this cannot show:")
	for _, l := range ev.Limits {
		fmt.Fprintf(w, "  - %s\n", l)
	}
	fmt.Fprintf(w, "\nThe whole document, for an auditor: %s vault evidence --json [--entries] > evidence.json\n", brand.CLI)
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func vaultDeclare(args []string) {
	kind := optValue(args, "--kind")
	if kind == "" {
		fmt.Fprintf(os.Stderr, "--kind is needed\n\n%s", vaultEvidenceUsage)
		os.Exit(2)
	}
	pos := positionals(args, "--kind")
	items := branch.VaultDeclItems(kind)
	if len(pos) == 0 {
		if len(items) == 0 {
			fmt.Printf("The %s kind has no rules mapped, so there is nothing to declare.\n", kind)
			return
		}
		fmt.Printf("What %s's rules ask you to declare (para, item, what to state):\n\n", kind)
		for _, it := range items {
			fmt.Printf("  %-5s %-17s %s\n", it.Para, it.Item, it.Asks)
		}
		fmt.Printf("\n%s vault declare --kind %s ITEM \"what is true\"; %s vault declarations lists what is declared.\n", brand.CLI, kind, brand.CLI)
		return
	}
	item, value := pos[0], strings.Join(pos[1:], " ")
	withdraw := hasFlag(args, "--withdraw")
	if withdraw == (value != "") {
		fmt.Fprintf(os.Stderr, "give the item a statement, or --withdraw it\n\n%s", vaultEvidenceUsage)
		os.Exit(2)
	}
	st := openStore()
	if st == nil {
		must(fmt.Errorf("the install's store could not be opened, and declarations are kept there"))
	}
	defer st.Close()
	d, err := branch.DeclareVault(st, kind, item, value, cliActor(), "")
	must(err)
	if withdraw {
		fmt.Printf("Withdrawn: %s %s is open again in the evidence.\n", kind, item)
		return
	}
	fmt.Printf("Declared: %s %s, by %s. The evidence shows it as declared, not checked.\n", kind, d.Item, d.DeclaredBy)
}

func vaultDeclarations(args []string) {
	st := openStore()
	if st == nil {
		must(fmt.Errorf("the install's store could not be opened"))
	}
	defer st.Close()
	kind := optValue(args, "--kind")
	ds, err := st.VaultDeclarations(kind, hasFlag(args, "--all"))
	must(err)
	if hasFlag(args, "--json") {
		printJSON(ds)
		return
	}
	if hasFlag(args, "--all") {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "WHEN\tKIND\tITEM\tBY\tSTATEMENT")
		for _, d := range ds {
			v := d.Value
			if v == "" {
				v = "(withdrawn)"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", d.DeclaredAt.Local().Format("2006-01-02 15:04"), d.Kind, d.Item, d.DeclaredBy, v)
		}
		_ = w.Flush()
		return
	}
	kinds := []string{kind}
	if kind == "" {
		kinds = []string{"aadhaar"}
	}
	byItem := map[string]auth.VaultDeclaration{}
	for _, d := range ds {
		byItem[d.Kind+"/"+d.Item] = d
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "KIND\tPARA\tITEM\tSTATEMENT\tBY\tWHEN")
	for _, k := range kinds {
		for _, it := range branch.VaultDeclItems(k) {
			d, ok := byItem[k+"/"+it.Item]
			if !ok {
				fmt.Fprintf(w, "%s\t%s\t%s\t(not declared)\t-\t-\n", k, it.Para, it.Item)
				continue
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", k, it.Para, it.Item, clip(d.Value, 60), d.DeclaredBy, d.DeclaredAt.Local().Format("2006-01-02"))
		}
	}
	_ = w.Flush()
}
