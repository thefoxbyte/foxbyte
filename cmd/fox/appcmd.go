// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// appCmd is `fox app`: the applications that may say which of their users a
// transaction acts for (application identity, F1).
//
//	fox app [list] [--json]
//	fox app show <name> [--json]
//	fox app register <name> --account <email> [--key <file>|-] [--kid k] [--max-life 5m] [--on-invalid none|refuse]
//	fox app key add <name> --key <file>|- [--kid k]
//	fox app key revoke <name> <kid> [--compromised-since <time>|now]
//	fox app remove <name>
//
// An application is registered against the account whose key its connections
// use, with the public half of a key only it holds. It then calls
// bb.act_for($1) with a short-lived token signed by that key, and the
// Blackbox records each change as made by the account and for the user the
// token names. At this machine the operator is an admin already, as for
// `fox user list`.
func appCmd(args []string) {
	sub := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	s := historyStore()
	if s == nil {
		must(fmt.Errorf("the account store could not be opened"))
	}
	defer s.Close()
	me := cliActor()
	switch sub {
	case "list":
		apps, err := s.Apps()
		must(err)
		id, err := s.InstallID()
		must(err)
		if hasFlag(args, "--json") {
			printJSON(map[string]any{"install_id": id, "apps": apps})
			return
		}
		printApps(os.Stdout, apps, id)
		printReadiness(os.Stdout)
	case "show":
		name := oneArg(args, "show <name>")
		a, err := s.App(name)
		must(appErr(err, name))
		id, err := s.InstallID()
		must(err)
		if hasFlag(args, "--json") {
			printJSON(map[string]any{"install_id": id, "app": a})
			return
		}
		printApp(os.Stdout, a, id)
		printReadiness(os.Stdout)
	case "register":
		name := oneArg(args, "register <name> --account <email> [--key <file>|-]")
		life := time.Duration(0)
		if v := optValue(args, "--max-life"); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				must(fmt.Errorf("--max-life is a duration such as 5m, not %q", v))
			}
			life = d
		}
		a, err := s.RegisterApp(name, optValue(args, "--account"), life, optValue(args, "--on-invalid"))
		must(err)
		s.Audit(auth.EvAppRegistered, me, a.Name, "", fmt.Sprintf("account %s, tokens live at most %ds, an invalid one: %s", a.Account, a.MaxLife, a.OnInvalid))
		fmt.Printf("Registered %s: its tokens are accepted from %s's own logins.\n", a.Name, a.Account)
		if optValue(args, "--key") != "" {
			addKey(s, me, a.Name, args)
		} else {
			fmt.Printf("It has no key yet: %s app key add %s --key <public key file>\n", brand.CLI, a.Name)
		}
		syncApps()
	case "key":
		if len(args) == 0 {
			must(fmt.Errorf("usage: %s app key add <name> --key <file>|- | revoke <name> <kid> [--compromised-since <time>|now]", brand.CLI))
		}
		switch args[0] {
		case "add":
			name := oneArg(args[1:], "key add <name> --key <file>|-")
			if _, err := s.App(name); err != nil {
				must(appErr(err, name))
			}
			addKey(s, me, name, args[1:])
			syncApps()
		case "revoke":
			ps := positionals(args[1:], "--compromised-since")
			if len(ps) != 2 {
				must(fmt.Errorf("usage: %s app key revoke <name> <kid> [--compromised-since <time>|now]", brand.CLI))
			}
			var since *time.Time
			if v := optValue(args, "--compromised-since"); v != "" {
				t, err := parseWhen(v)
				must(err)
				since = &t
			}
			must(appErr(s.RevokeAppKey(ps[0], ps[1], since), ps[0]))
			detail := "key " + ps[1] + " revoked"
			if since != nil {
				detail += ", reported compromised since " + since.UTC().Format(time.RFC3339)
			}
			s.Audit(auth.EvAppKeyRevoked, me, ps[0], "", detail)
			fmt.Printf("Key %s of %s is revoked: its tokens are refused from the next transaction.\n", ps[1], ps[0])
			if since != nil {
				fmt.Printf("Records asserted with it since %s are shown as \"key reported compromised\".\n", since.Local().Format("2 Jan 2006 15:04 MST"))
			}
			syncApps()
		default:
			must(fmt.Errorf("unknown: %s app key %s (add or revoke)", brand.CLI, args[0]))
		}
	case "remove":
		name := oneArg(args, "remove <name>")
		must(appErr(s.RemoveApp(name), name))
		s.Audit(auth.EvAppRemoved, me, name, "", "")
		fmt.Printf("Removed %s: its tokens are refused from the next transaction. What it asserted stays in the Blackbox, under its name.\n", name)
		syncApps()
	default:
		fmt.Fprintf(os.Stderr, "usage: %s app [list|show|register|key|remove] (see %s help)\n", brand.CLI, brand.CLI)
		os.Exit(2)
	}
}

// addKey reads --key (a file, or - for stdin) and adds it.
func addKey(s *auth.Store, me, name string, args []string) {
	src := optValue(args, "--key")
	if src == "" {
		must(fmt.Errorf("--key names the public key's file, or - to read it from stdin"))
	}
	var b []byte
	var err error
	if src == "-" {
		b, err = io.ReadAll(io.LimitReader(os.Stdin, 64<<10))
	} else {
		b, err = os.ReadFile(src)
	}
	must(err)
	pub, err := auth.ParsePublicKey(b)
	must(err)
	k, err := s.AddAppKey(name, optValue(args, "--kid"), pub)
	must(appErr(err, name))
	s.Audit(auth.EvAppKeyAdded, me, name, "", "key "+k.Kid)
	fmt.Printf("Added key %s to %s. Its tokens carry \"kid\":%q in their header.\n", k.Kid, name, k.Kid)
}

// syncApps copies the change into every running branch at once, and says
// where it could not. A suspended branch gets it when it is woken.
func syncApps() {
	failed := branch.SyncIdentityAll()
	names := make([]string, 0, len(failed))
	for n := range failed {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(os.Stderr, "warning: %s: %v (it is copied there when the branch is next woken or restarted)\n", n, failed[n])
	}
}

func oneArg(args []string, usage string) string {
	ps := positionals(args, "--account", "--key", "--kid", "--max-life", "--on-invalid", "--compromised-since")
	if len(ps) != 1 {
		must(fmt.Errorf("usage: %s app %s", brand.CLI, usage))
	}
	return ps[0]
}

func appErr(err error, name string) error {
	if errors.Is(err, auth.ErrAppNotFound) {
		return fmt.Errorf("no application %q is registered (%s app list)", name, brand.CLI)
	}
	return err
}

// parseWhen reads a moment: now, an RFC 3339 time, or a date (midnight UTC).
func parseWhen(v string) (time.Time, error) {
	if v == "now" {
		return time.Now(), nil
	}
	for _, f := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.Parse(f, v); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("--compromised-since is now, a date (2026-10-22) or a time (2026-10-22T09:30:00Z), not %q", v)
}

func printApps(w io.Writer, apps []auth.App, installID string) {
	fmt.Fprintf(w, "Tokens for this install name \"aud\":%q.\n", installID)
	if len(apps) == 0 {
		fmt.Fprintf(w, "No application is registered. Register one with %s app register <name> --account <email> --key <file>.\n", brand.CLI)
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tACCOUNT\tKEYS\tTOKEN LIFE\tINVALID TOKEN")
	for _, a := range apps {
		active := 0
		for _, k := range a.Keys {
			if k.Active() {
				active++
			}
		}
		acct := a.Account
		if acct == "" {
			acct = "(account deleted)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%d active, %d revoked\t%s\t%s\n", a.Name, acct, active, len(a.Keys)-active,
			time.Duration(a.MaxLife)*time.Second, invalidWord(a.OnInvalid))
	}
	tw.Flush()
}

func printApp(w io.Writer, a auth.App, installID string) {
	acct := a.Account
	if acct == "" {
		acct = "(account deleted: nothing can assert for it)"
	}
	fmt.Fprintf(w, "%s\n  account:        %s (its own logins only; not its agent keys)\n", a.Name, acct)
	fmt.Fprintf(w, "  token life:     at most %s from iat to exp\n", time.Duration(a.MaxLife)*time.Second)
	fmt.Fprintf(w, "  invalid token:  %s\n", invalidWord(a.OnInvalid))
	fmt.Fprintf(w, "  tokens name:    {\"iss\":%q, \"aud\":%q, \"sub\":\"<user>\", \"iat\":…, \"exp\":…}\n", a.Name, installID)
	fmt.Fprintf(w, "                  header {\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"kid\":\"<key id>\"}; optional claims: tenant, branch\n")
	fmt.Fprintf(w, "  then, in each transaction: SELECT bb.act_for($1), with the token as the parameter\n")
	if len(a.Keys) == 0 {
		fmt.Fprintf(w, "  keys:           none yet (%s app key add %s --key <file>)\n", brand.CLI, a.Name)
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  KEY ID\tADDED\tSTATE")
	for _, k := range a.Keys {
		state := "active"
		if k.Revoked != nil {
			state = "revoked " + time.Unix(*k.Revoked, 0).Format("2 Jan 2006 15:04")
		}
		if k.CompromisedSince != nil {
			state += ", reported compromised since " + time.Unix(*k.CompromisedSince, 0).Format("2 Jan 2006 15:04")
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", k.Kid, time.Unix(k.Created, 0).Format("2 Jan 2006"), state)
	}
	tw.Flush()
}

func invalidWord(onInvalid string) string {
	if onInvalid == "refuse" {
		return "the transaction is refused"
	}
	return "the change is recorded for nobody, with the reason"
}

// printReadiness names the running branches that cannot check a token yet,
// and what fixes each.
func printReadiness(w io.Writer) {
	r, err := branch.IdentityReadiness()
	if err != nil {
		return // the engine is not running: nothing to say about its branches
	}
	var notReady []string
	for _, n := range sortedKeys(r) {
		switch v := r[n]; v {
		case "checked":
		case "unavailable":
			notReady = append(notReady, fmt.Sprintf("%s (its container predates the image that checks tokens: %s stop, then %s start)", n, brand.CLI, brand.CLI))
		case "not installed":
			notReady = append(notReady, fmt.Sprintf("%s (%s ledger upgrade %s)", n, brand.CLI, n))
		default:
			notReady = append(notReady, n+" ("+v+")")
		}
	}
	if len(notReady) > 0 {
		fmt.Fprintf(w, "Not ready to check tokens: %s.\n", strings.Join(notReady, "; "))
	}
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
