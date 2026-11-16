// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// Who may change main (audit LIVE-1):
//
//	fox access main-write                 the mode, and who may change main
//	fox access main-write all|granted     set it (granted lists who loses write first)
//	fox access write grant|revoke <email> one account's write on main
//	fox access list                       every account, and whether it may change main
//
// At this machine the operator is an admin already, as for `fox admin`. Each
// change is in the security log, its intent first (auth.BeginPrivileged).

func mainWriteUsage() string {
	return fmt.Sprintf("       %[1]s access main-write [all|granted]\n"+
		"       %[1]s access write grant|revoke <email>\n"+
		"       %[1]s access list\n", brand.CLI)
}

// mainAdmins asks main who is an admin, or says why it cannot.
func mainAdmins() []string {
	names, err := branch.ListAdmins("main")
	if err != nil {
		fmt.Fprintf(os.Stderr, "  (main could not be asked who is an admin: %v)\n", firstLine(err.Error()))
		return nil
	}
	return names
}

func mainWriteCmd(args []string) {
	s := openStore()
	defer s.Close()
	switch args[0] {
	case "list":
		v, err := access.ViewMainWrite(s, mainAdmins())
		must(err)
		printMainWrite(os.Stdout, v)
	case "main-write":
		mode := firstPositional(args[1:])
		if mode == "" {
			v, err := access.ViewMainWrite(s, mainAdmins())
			must(err)
			printMainWrite(os.Stdout, v)
			return
		}
		mode = strings.ToLower(mode)
		if mode != auth.MainWriteAll && mode != auth.MainWriteGranted {
			fmt.Fprint(os.Stderr, "usage:\n"+mainWriteUsage())
			os.Exit(2)
		}
		before, err := access.ViewMainWrite(s, mainAdmins())
		must(err)
		if mode == auth.MainWriteGranted && before.Mode == auth.MainWriteAll {
			fmt.Print(loseWriteWarning(before.LoseInGranted))
		}
		act, err := s.BeginPrivileged(auth.EvMainWriteModeStarted, auth.EvMainWriteModeSet, auth.EvMainWriteModeFailed,
			cliActor(), "main", "", "mode "+mode)
		must(err)
		err = s.SetMainWriteMode(mode)
		if err == nil {
			err = branch.ApplyMainWrite()
		}
		act.Done(err, "mode "+mode)
		must(err)
		fmt.Printf("main write: %s\n", describeMainWriteMode(mode))
	case "write":
		sub, email := "", ""
		if len(args) > 1 {
			sub = args[1]
		}
		if len(args) > 2 {
			email = strings.ToLower(strings.TrimSpace(args[2]))
		}
		if (sub != "grant" && sub != "revoke") || email == "" {
			fmt.Fprint(os.Stderr, "usage:\n"+mainWriteUsage())
			os.Exit(2)
		}
		u, ok := s.UserByEmail(email)
		if !ok {
			must(fmt.Errorf("no such user: %s", email))
		}
		started, done, failed := auth.EvMainWriteGrantStarted, auth.EvMainWriteGranted, auth.EvMainWriteGrantFailed
		if sub == "revoke" {
			started, done, failed = auth.EvMainWriteRevokeStarted, auth.EvMainWriteRevoked, auth.EvMainWriteRevokeFailed
		}
		act, err := s.BeginPrivileged(started, done, failed, cliActor(), u.Email, "", "branch main")
		must(err)
		if sub == "grant" {
			err = s.GrantMainWrite(u.ID, cliActor())
		} else {
			_, err = s.RevokeMainWrite(u.ID)
		}
		if err == nil {
			err = branch.ApplyMainWriteFor(u.Email)
		}
		act.Done(err, "branch main")
		must(err)
		mode, _ := s.MainWriteMode()
		verb := map[string]string{"grant": "may now change main", "revoke": "may no longer change main"}[sub]
		note := ""
		if mode == auth.MainWriteAll {
			note = fmt.Sprintf(" once main is in mode granted (it is in mode all: every account may; `%s access main-write granted`)", brand.CLI)
		}
		fmt.Printf("  %s %s%s\n", u.Email, verb, note)
	}
}

func describeMainWriteMode(mode string) string {
	if mode == auth.MainWriteAll {
		return "all: every account may change data on main"
	}
	return "granted: only admins and accounts granted write may change main; everyone else reads it"
}

// loseWriteWarning is what switching to "granted" takes away, said before it
// is done.
func loseWriteWarning(lose []string) string {
	if len(lose) == 0 {
		return "Every account is an admin or granted write: nobody loses write on main.\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Warning: %d account(s) will lose write on main, and their open sessions there end:\n", len(lose))
	for _, e := range lose {
		fmt.Fprintf(&b, "  %s\n", e)
	}
	fmt.Fprintf(&b, "Give one back with: %s access write grant <email>\n", brand.CLI)
	return b.String()
}

func printMainWrite(w io.Writer, v access.MainWriteView) {
	fmt.Fprintf(w, "main write: %s\n\n", describeMainWriteMode(v.Mode))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "EMAIL\tMAY CHANGE MAIN\tWHY")
	for _, a := range v.Accounts {
		why := "-"
		switch {
		case a.Admin:
			why = "admin"
		case a.Granted:
			why = "granted"
		case v.Mode == auth.MainWriteAll:
			why = "mode all"
		}
		yes := "no (reads)"
		if a.Writes {
			yes = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", a.Email, yes, why)
	}
	tw.Flush()
	if v.Mode == auth.MainWriteAll {
		fmt.Fprintf(w, "\nTo make main read-only for accounts not granted write: %s access main-write granted\n", brand.CLI)
	}
}
