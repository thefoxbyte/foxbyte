// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// adminCmd handles `fox admin grant|revoke <email> [--branch <name>]` and
// `fox admin list [--branch <name>]`.
//
// Members of db_admin may override the destructive-DDL guardrail with
// SET bb.allow_destructive=on; other users cannot. Roles live inside each
// branch's Postgres, so without --branch a change is applied to main (which new
// branches inherit) and to every running branch.
func adminCmd(args []string) {
	if len(args) == 0 {
		adminUsage()
	}
	sub, rest := args[0], args[1:]
	branches, err := adminScope(optValue(rest, "--branch"))
	must(err)

	failed := false
	switch sub {
	case "grant", "revoke":
		email := firstPositional(rest, "--branch")
		if email == "" {
			adminUsage()
		}
		u, ok := openStore().UserByEmail(email)
		if !ok {
			must(fmt.Errorf("no such user: %s (create it with: fox user create %s)", email, email))
		}
		done := map[string]string{"grant": "granted db_admin to", "revoke": "revoked db_admin from"}[sub]
		for _, b := range branches {
			if sub == "grant" {
				err = branch.GrantAdmin(b, u.Email)
			} else {
				err = branch.RevokeAdmin(b, u.Email)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "  %s: %v\n", b, err)
				failed = true
				continue
			}
			fmt.Printf("  %s: %s %s\n", b, done, u.Email)
		}
	case "list":
		for _, b := range branches {
			names, err := branch.ListAdmins(b)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  %s: %v\n", b, err)
				failed = true
				continue
			}
			list := strings.Join(names, ", ")
			if list == "" {
				list = "(none — only superusers may override)"
			}
			fmt.Printf("  %s: %s\n", b, list)
		}
	default:
		adminUsage()
	}
	if failed {
		os.Exit(1)
	}
}

func adminUsage() {
	fmt.Println("usage: fox admin grant <email> [--branch <name>]\n" +
		"       fox admin revoke <email> [--branch <name>]\n" +
		"       fox admin list [--branch <name>]")
	os.Exit(2)
}

// adminScope resolves which branches an admin change applies to: the named
// branch, or main plus every running branch.
func adminScope(named string) ([]string, error) {
	if named != "" {
		return []string{named}, nil
	}
	running, err := branch.RunningBranches()
	if err != nil {
		return nil, err
	}
	if len(running) == 0 || running[0] != "main" {
		return nil, fmt.Errorf("main is not running — start FoxByte first (fox start)")
	}
	return running, nil
}

// ledgerUpgradeCmd handles `fox ledger upgrade [branch|--all]`: re-applies the
// current Blackbox definition (idempotent). main is also upgraded on every
// `fox start`; existing branches keep the definition they were cloned with until
// upgraded here.
func ledgerUpgradeCmd(args []string) {
	branches := []string{"main"}
	if len(args) > 0 && args[0] == "--all" {
		running, err := branch.RunningBranches()
		must(err)
		branches = running
	} else if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		branches = []string{args[0]}
	}
	failed := false
	for _, b := range branches {
		if err := branch.InstallLedger(b); err != nil {
			fmt.Fprintf(os.Stderr, "  %s: %v\n", b, err)
			failed = true
			continue
		}
		if err := branch.EnsureLedgerV2(b); err != nil {
			fmt.Fprintf(os.Stderr, "  %s: %v\n", b, err)
			failed = true
			continue
		}
		fmt.Printf("  %s: ledger up to date (including 2.0 capture)\n", b)
	}
	if failed {
		os.Exit(1)
	}
}

// optValue returns the value following flag in args, or "".
func optValue(args []string, flag string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag {
			return args[i+1]
		}
	}
	return ""
}

// firstPositional returns the first argument that is neither a flag nor the value
// of one of valueFlags.
func firstPositional(args []string, valueFlags ...string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			for _, f := range valueFlags {
				if a == f {
					i++ // skip the flag's value
					break
				}
			}
			continue
		}
		return a
	}
	return ""
}
