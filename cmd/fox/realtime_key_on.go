//go:build enterprise

// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/thefoxbyte/foxbyte/enterprise/realtime"
	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// `fox realtime key` and `fox realtime url` — how an application is given the
// change feed.
//
// The output is one connection string, because that is how every other database
// is configured: a value an application puts in an environment variable, not an
// endpoint plus a header plus a branch name that all have to agree.

// realtimeKey dispatches `fox realtime key create|ls|revoke`.
func realtimeKey(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: %s realtime key create <branch> [--name n] | ls [branch] | revoke <id>", brand.CLI)
	}
	switch args[0] {
	case "create", "new":
		return realtimeKeyCreate(args[1:])
	case "ls", "list":
		return realtimeKeyList(args[1:])
	case "revoke", "rm":
		return realtimeKeyRevoke(args[1:])
	}
	return fmt.Errorf("unknown: %s realtime key %s", brand.CLI, args[0])
}

func realtimeKeyCreate(args []string) error {
	var name, branchName, sslmode string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--name" && i+1 < len(args):
			name = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--name="):
			name = strings.TrimPrefix(args[i], "--name=")
		case args[i] == "--sslmode" && i+1 < len(args):
			sslmode = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--sslmode="):
			sslmode = strings.TrimPrefix(args[i], "--sslmode=")
		case strings.HasPrefix(args[i], "--"):
			return fmt.Errorf("unknown flag %q", args[i])
		case branchName == "":
			branchName = args[i]
		default:
			return fmt.Errorf("unexpected argument %q", args[i])
		}
	}
	if branchName == "" {
		return fmt.Errorf("which branch? usage: %s realtime key create <branch> [--name n]", brand.CLI)
	}
	// Refused for a branch that does not exist, rather than minting a key that
	// can never work. A credential that authenticates and then 404s is the
	// hardest kind of mistake to read from the application's side.
	if !branch.Exists(branchName) {
		return fmt.Errorf("no branch %q", branchName)
	}
	dsn, err := realtimeDSN(branchName, sslmode)
	if err != nil {
		return err
	}

	store := openStore()
	defer store.Close()
	uid, err := realtimeKeyOwner(store, branchName)
	if err != nil {
		return err
	}
	secret, info, err := store.CreateRealtimeKey(uid, name, branchName)
	if err != nil {
		return err
	}
	store.Audit(auth.EvRealtimeKeyCreated, "", branchName, "", "key "+info.ID+" ("+info.Name+")")

	dsn.Key = secret
	fmt.Printf("Realtime key %s for branch %q.\n\n", info.ID, branchName)
	fmt.Println("  " + dsn.String())
	fmt.Println()
	fmt.Println("This is the only time the key is shown — it is stored hashed. Put it")
	fmt.Printf("somewhere an application reads secrets from, not in source control.\n\n")
	fmt.Println("It subscribes to this branch's change feed and can do nothing else:")
	fmt.Println("  • not the control plane (/api/ refuses it)")
	fmt.Println("  • not SQL through the Gateway (refused by kind)")
	fmt.Println("  • not another branch's feed")
	fmt.Printf("\nRevoke it with `%s realtime key revoke %s`.\n", brand.CLI, info.ID)
	return nil
}

// realtimeKeyOwner decides which account a key belongs to.
//
// The branch's owner when it has one, so the key appears in the listing of the
// person whose branch it is; otherwise any account, which is what an engine-made
// branch already does for its gateway key. The owner decides only who can see
// and revoke the key — a realtime key carries no account access of its own.
func realtimeKeyOwner(store *auth.Store, branchName string) (int64, error) {
	if uid, ok := store.BranchOwner(branchName); ok {
		return uid, nil
	}
	if uid, ok := store.AnyUserID(); ok {
		return uid, nil
	}
	return 0, fmt.Errorf("this install has no account yet — make one with `%s user create <email>`", brand.CLI)
}

func realtimeKeyList(args []string) error {
	want := ""
	if len(args) > 0 {
		want = args[0]
	}
	store := openStore()
	defer store.Close()
	uid, ok := store.AnyUserID()
	if !ok {
		fmt.Println("no accounts, so no keys")
		return nil
	}
	keys, err := store.ListKeys(uid)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tBRANCH\tPREFIX\tCREATED")
	n := 0
	for _, k := range keys {
		if k.Kind != auth.KindRealtime {
			continue // ordinary account and gateway keys are `fox key ls`
		}
		if want != "" && k.Scope != want {
			continue
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s…\t%s\n", k.ID, k.Name, k.Scope, k.Prefix,
			time.Unix(k.Created, 0).Format("2006-01-02 15:04"))
		n++
	}
	_ = w.Flush()
	if n == 0 {
		if want != "" {
			fmt.Printf("no realtime keys for branch %q\n", want)
		} else {
			fmt.Println("no realtime keys")
		}
	}
	return nil
}

func realtimeKeyRevoke(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("which key? usage: %s realtime key revoke <id>", brand.CLI)
	}
	id := args[0]
	store := openStore()
	defer store.Close()
	uid, ok := store.AnyUserID()
	if !ok {
		return fmt.Errorf("this install has no account yet")
	}
	if err := store.RevokeKey(uid, id); err != nil {
		return err
	}
	store.Audit(auth.EvRealtimeKeyRevoked, "", "", "", "key "+id)
	fmt.Printf("Revoked %s. A subscriber using it is refused on its next connection.\n", id)
	return nil
}

// realtimeURL is `fox realtime url <branch>`: the connection string without a
// key, for putting in documentation or a deployment template where the secret
// comes from somewhere else.
func realtimeURL(args []string) error {
	var branchName, sslmode string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--sslmode" && i+1 < len(args):
			sslmode = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--sslmode="):
			sslmode = strings.TrimPrefix(args[i], "--sslmode=")
		case strings.HasPrefix(args[i], "--"):
			return fmt.Errorf("unknown flag %q", args[i])
		case branchName == "":
			branchName = args[i]
		default:
			return fmt.Errorf("unexpected argument %q", args[i])
		}
	}
	if branchName == "" {
		branchName = "main"
	}
	if !branch.Exists(branchName) {
		return fmt.Errorf("no branch %q", branchName)
	}
	dsn, err := realtimeDSN(branchName, sslmode)
	if err != nil {
		return err
	}
	fmt.Println(dsn.String())
	fmt.Printf("\nAdd a key with `%s realtime key create %s`.\n", brand.CLI, branchName)
	return nil
}

// realtimeDSN builds the connection string for this install.
//
// sslmode defaults to require, which is what a default install actually serves:
// the control plane presents a self-signed certificate, so the connection is
// encrypted and its identity is not verifiable. Saying verify-full there would
// hand out a DSN that fails to connect.
func realtimeDSN(branchName, sslmode string) (realtime.DSN, error) {
	d := realtime.DSN{Host: listenAddr("8080"), Branch: branchName, SSL: realtime.SSLRequire}
	if sslmode != "" {
		d.SSL = realtime.SSLMode(sslmode)
		// Round-tripped rather than range-checked here, so there is one list of
		// valid modes and it lives with the parser.
		if _, err := realtime.ParseDSN(d.String()); err != nil {
			return realtime.DSN{}, err
		}
	}
	return d, nil
}

// realtimeActivity is `fox realtime activity [branch] [--window 24h]`: what
// staying warm has cost, and whether anything used it.
//
// The question this answers is one the product could not answer before. A
// subscribed branch is never suspended — that is the promise the feed makes —
// so it runs, and runs, and nothing anywhere said for how long or to what end.
func realtimeActivity(args []string) error {
	branchName, window := "main", 24*time.Hour
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--window" && i+1 < len(args):
			d, err := time.ParseDuration(args[i+1])
			if err != nil || d <= 0 {
				return fmt.Errorf("--window %q is not a duration such as 1h or 24h", args[i+1])
			}
			window = d
			i++
		case strings.HasPrefix(args[i], "--window="):
			d, err := time.ParseDuration(strings.TrimPrefix(args[i], "--window="))
			if err != nil || d <= 0 {
				return fmt.Errorf("--window %q is not a duration such as 1h or 24h", args[i])
			}
			window = d
		case strings.HasPrefix(args[i], "--"):
			return fmt.Errorf("unknown flag %q", args[i])
		default:
			branchName = args[i]
		}
	}
	if !branch.Exists(branchName) {
		return fmt.Errorf("no branch %q", branchName)
	}

	store := openStore()
	defer store.Close()

	// A reading is taken now, so a first run has something to say rather than
	// only "wait five minutes". It is the same reading the meter takes.
	realtime.MeterOnce(store, nil, 0)

	rep, err := realtime.Activity(store, branchName, window, nil)
	if err != nil {
		return err
	}

	fmt.Printf("%s\n\n", rep.Cost())
	if m := rep.Measured; m != nil {
		fmt.Printf("  over the last %s (%d readings)\n", m.Over, m.Samples)
		// Transactions, said as transactions. Without pg_stat_statements —
		// which is not loaded, and loading it costs a restart — this is what
		// Postgres counts, and calling it "queries" would be a number somebody
		// bills from and a word that is not true.
		fmt.Printf("  %d transactions (%.0f/day), %d rows returned\n",
			m.Transactions, m.PerDay, m.RowsReturned)
	}
	if rep.Warm {
		fmt.Printf("  %d of %d subscribers attached", rep.Subscribers, realtime.MaxSubscribers())
		if rep.PeakSubs > rep.Subscribers {
			fmt.Printf(" (%d at most so far)", rep.PeakSubs)
		}
		fmt.Printf("\n  %d table(s) streaming, %d events delivered since the control plane started\n",
			rep.Tables, rep.EventsNow)
	}
	for _, s := range rep.Slots {
		state := "idle"
		if s.Active {
			state = "streaming"
		}
		if s.Status == "lost" {
			state = "lost"
		}
		fmt.Printf("  %-34s %-9s holding %s", s.Slot, state, humanBytes(s.HeldBytes))
		if s.SafeBytes > 0 {
			fmt.Printf(", %s before it is dropped", humanBytes(s.SafeBytes))
		}
		fmt.Println()
	}
	for _, n := range rep.Notes {
		fmt.Printf("\n  note: %s\n", n)
	}
	// The judgement, last and as a suggestion. The engine will not suspend a
	// branch somebody is subscribed to, so this is a person's decision to make.
	if rep.Idle(2 * time.Hour) {
		fmt.Printf("\nNothing has used this branch in that time while it stayed warm. If that is a\n"+
			"forgotten subscriber, `%s realtime slots %s` shows what is holding it.\n", brand.CLI, branchName)
	}
	return nil
}
