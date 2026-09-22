// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

// ledgerV2Cmd handles the Blackbox 2.0 subcommands of `fox ledger`:
//
//	fox ledger checkpoint [branch]   anchor new entries outside the database
//	fox ledger integrity [branch]    check the ledger against its anchors
//	fox ledger export [branch]       every entry as JSON lines (--format jsonl)
//	fox ledger entries [branch]      newest entries with their ids (--limit N)
//	fox ledger sessions [branch]     agent sessions: agent, task, parent session (--limit N)
//	fox ledger diff <a> <b>          schema changes on each branch since they split (--json)
//	fox ledger branch-before <id>    a new branch of main as it was just before entry <id>
//	fox ledger anchor-key            the public key anchors are signed with
//
// It returns false for anything else, leaving the existing subcommands untouched.
func ledgerV2Cmd(args []string) bool {
	if len(args) == 0 {
		return false
	}
	name := "main"
	if len(args) > 1 && !strings.HasPrefix(args[1], "-") {
		name = args[1]
	}
	switch args[0] {
	case "checkpoint":
		a, path, err := branch.Checkpoint(name)
		must(err)
		if a == nil {
			fmt.Printf("%s: nothing new to checkpoint\n", name)
			return true
		}
		fmt.Printf("checkpoint #%d on %s: ledger ids %d–%d (%d entries)\n", a.CheckpointID, name, a.FromID, a.ToID, a.EntryCount)
		fmt.Printf("  root   %s\n", a.MerkleRoot)
		fmt.Printf("  anchor %s\n", path)
		if a.KeyID != "" {
			fmt.Printf("  signed by key %s\n", a.KeyID)
		}
	case "anchor-key":
		// The public key a verifier needs to prove anchors are genuine. Give it
		// to whoever audits; keep the private key where the databases cannot
		// reach it (FOX_ANCHOR_KEY).
		pub, path, err := branch.AnchorPublicKey()
		must(err)
		fmt.Print(string(ledger.EncodePublicKey(pub)))
		fmt.Fprintf(os.Stderr, "saved at %s — verify with: fox-verify … --pubkey %s\n", path, path)
	case "integrity":
		rep, err := branch.Integrity(name)
		must(err)
		fmt.Println(rep.Summary())
		if !rep.Intact {
			os.Exit(1)
		}
	case "export":
		if f := optValue(args, "--format"); f != "" && f != "jsonl" {
			must(fmt.Errorf("unsupported export format %q (supported: jsonl)", f))
		}
		must(branch.ExportLedger(name, os.Stdout))
	case "entries":
		limit := 50
		if v := optValue(args, "--limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				limit = n
			}
		}
		if name = firstPositional(args[1:], "--limit"); name == "" {
			name = "main"
		}
		entries, err := branch.LedgerEntries(name, limit)
		must(err)
		fmt.Println(branch.FormatLedgerEntries(entries))
	case "sessions":
		limit := 50
		if v := optValue(args, "--limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				limit = n
			}
		}
		if name = firstPositional(args[1:], "--limit"); name == "" {
			name = "main"
		}
		ss, err := branch.AgentSessions(name, limit)
		must(err)
		fmt.Println(branch.FormatAgentSessions(ss))
	case "diff":
		diffCmd(args[1:])
	case "branch-before":
		branchBeforeCmd(args[1:])
	default:
		return false
	}
	return true
}

// branchBeforeCmd: fox ledger branch-before <entry-id> [--branch main] [--as name]
func branchBeforeCmd(args []string) {
	id := firstPositional(args, "--branch", "--as")
	entryID, err := strconv.ParseInt(id, 10, 64)
	if id == "" || err != nil || entryID <= 0 {
		fmt.Println("usage: fox ledger branch-before <entry-id> [--branch main] [--as <new-branch>]")
		os.Exit(2)
	}
	src := optValue(args, "--branch")
	if src == "" {
		src = "main"
	}
	fmt.Printf("Branching %s from just before ledger entry %d (base backup + WAL replay — this can take a few minutes)…\n", src, entryID)
	res, err := branch.BranchBeforeEntry(src, entryID, optValue(args, "--as"), func(format string, a ...any) {
		fmt.Printf("  "+format+"\n", a...)
	})
	must(err)
	fmt.Printf("branch %q is ready (%ds): %s as it was just before entry %d\n", res.Branch, res.Seconds, res.Source, res.EntryID)
	fmt.Printf("  excluded   %s %s\n", res.CommandTag, res.Object)
	fmt.Printf("  target     %s %s (base backup %s)\n", res.TargetKind, res.Target, res.BaseBackup)
	fmt.Printf("  connect    postgresql://dbadmin:<api-key>@localhost:6432/%s?sslmode=require\n", res.Branch)
}
