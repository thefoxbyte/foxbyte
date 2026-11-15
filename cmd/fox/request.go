// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// `fox request` — review a branch's schema changes, then apply them.
//
// From this machine the operator is whoever has the shell, so the CLI does not
// ask who is approving: it records the decision as the local CLI's. Over the API
// the approver is the signed-in account, and must be one that may manage the
// target (internal/access).

func requestCmd(args []string) {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "list":
		requestListCmd(args[1:])
	case "show":
		requestShowCmd(args[1:])
	case "approve":
		// Approving applies the change; rejecting below does not, and stays
		// free so a request left pending when an install changed edition can
		// be closed rather than stranded.
		requireFeature(edition.Promotion)
		requestDecideCmd(args[1:], auth.RequestApproved)
	case "reject":
		requestDecideCmd(args[1:], auth.RequestRejected)
	default:
		fmt.Printf("usage: %[1]s request list [--open] [--target <branch>]\n"+
			"       %[1]s request show <id>\n"+
			"       %[1]s request approve <id> [--note \"…\"]\n"+
			"       %[1]s request reject <id> [--note \"…\"]\n\n"+
			"Make one with: %[1]s branch request <source> [--to <target>] [--include-data]\n", brand.CLI)
		os.Exit(2)
	}
}

// branchRequestCmd is `fox branch request <source> [--to <target>]`.
func branchRequestCmd(args []string) {
	requireFeature(edition.Promotion)
	source := firstPositional(args, "--to")
	if source == "" {
		fmt.Printf("usage: %s branch request <source> [--to <target>] [--include-data]\n", brand.CLI)
		os.Exit(2)
	}
	target := optValue(args, "--to")
	if target == "" {
		target = "main"
	}
	s := openStore()
	defer s.Close()
	history, err := branch.RequestHistory(s, source, target)
	must(err)
	// Data changes stay on the source unless asked for by name.
	plan, err := branch.BuildRequest(source, target, history, branch.RequestOptions{IncludeData: hasFlag(args, "--include-data")})
	must(err)
	rec, err := branch.NewRequest(source, target, plan)
	must(err)
	c, existing, err := s.OpenChangeRequest(auth.CLIUser, rec)
	must(err)
	if existing {
		fmt.Print(branch.FormatRequest(c, plan.Entries))
		fmt.Printf("Request #%d is already open for exactly these changes, so no new one was made. Review it, then:\n  %s request approve %d\n",
			c.ID, brand.CLI, c.ID)
		return
	}
	s.Audit(auth.EvChangeRequested, cliActor(), fmt.Sprintf("request #%d: %s → %s", c.ID, source, target), "",
		branch.RequestedDetail(plan))
	fmt.Print(branch.FormatRequest(c, plan.Entries))
	fmt.Printf("Nothing has been applied to %s yet. Review it, then:\n  %s request approve %d\n",
		target, brand.CLI, c.ID)
}

func requestListCmd(args []string) {
	status := ""
	if hasFlag(args, "--open") {
		status = auth.RequestOpen
	}
	s := openStore()
	defer s.Close()
	list, err := s.ChangeRequests(status, optValue(args, "--target"))
	must(err)
	if len(list) == 0 {
		fmt.Printf("No change requests. Make one with `%s branch request <source>`.\n", brand.CLI)
		return
	}
	for _, c := range list {
		fmt.Println(branch.RequestSummary(c))
	}
}

func requestShowCmd(args []string) {
	c, s := requestByArg(args, "show")
	defer s.Close()
	entries, err := branch.UnmarshalEntries(c.Entries)
	must(err)
	fmt.Print(branch.FormatRequest(c, entries))
}

func requestDecideCmd(args []string, decision string) {
	c, s := requestByArg(args, strings.TrimSuffix(decision, "d"))
	defer s.Close()
	entries, err := branch.UnmarshalEntries(c.Entries)
	must(err)

	// The intents are written before the claim, which is the decision: one
	// that cannot be written stops it (auth.BeginPrivileged).
	note := optValue(args, "--note")
	decided, err := s.BeginPrivileged(auth.EvChangeDecideStarted, auth.EvChangeDecided, auth.EvChangeDecideFailed,
		cliActor(), fmt.Sprintf("request #%d %s", c.ID, decision), "", note)
	must(err)
	var applying *auth.Privileged
	if decision == auth.RequestApproved {
		applying, err = s.BeginPrivileged(auth.EvChangeApplyStarted, auth.EvChangeApplied, auth.EvChangeApplyFailed,
			cliActor(), fmt.Sprintf("request #%d: %s → %s", c.ID, c.Source, c.Target), "",
			fmt.Sprintf("%d statement(s)", len(entries)))
		if err != nil {
			decided.Done(err, "not decided")
			must(err)
		}
	}
	claimed, err := s.ClaimChangeRequest(c.ID, auth.CLIUser, decision, note)
	if err != nil {
		decided.Done(err, "not decided")
		applying.Done(err, "not applied")
	}
	if errors.Is(err, auth.ErrRequestDecided) {
		must(fmt.Errorf("request #%d was already %s by %s", c.ID, c.Status, c.DecidedBy))
	}
	must(err)

	if decision == auth.RequestRejected {
		decided.Done(nil, claimed.Note)
		fmt.Printf("Request #%d rejected. %s is unchanged.\n", c.ID, c.Target)
		return
	}

	fmt.Printf("Applying %d statement(s) to %s …\n", len(entries), c.Target)
	n, applyErr, recordErr := branch.ApplyClaimed(s, claimed, "the local CLI")
	if recordErr != nil {
		fmt.Fprintf(os.Stderr, "warning: recording the outcome of request #%d: %v\n"+
			"(%s keeps its own record; the next request from %s reconciles from it)\n", c.ID, recordErr, c.Target, c.Source)
	}
	applying.Done(applyErr, fmt.Sprintf("%d statement(s) applied to %s", n, c.Target))
	decided.Done(nil, fmt.Sprintf("%d statement(s) applied to %s", n, c.Target))
	if errors.Is(applyErr, branch.ErrAlreadyApplied) {
		must(fmt.Errorf("%w — nothing was run again, and request #%d is now recorded as applied (%d statement(s))", applyErr, c.ID, n))
	}
	must(applyErr)
	fmt.Printf("Applied %d statement(s) to %s. Each one is in %s's Blackbox, attributed to whoever wrote it:\n  %s blackbox %s\n",
		n, c.Target, c.Target, brand.CLI, c.Target)
}

// requestByArg reads the id argument and loads the request. The caller closes
// the store.
func requestByArg(args []string, verb string) (auth.ChangeRequest, *auth.Store) {
	if len(args) == 0 {
		fmt.Printf("usage: %s request %s <id>\n", brand.CLI, verb)
		os.Exit(2)
	}
	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil || id <= 0 {
		must(fmt.Errorf("%q is not a request id — list them with `%s request list`", args[0], brand.CLI))
	}
	s := openStore()
	c, err := s.ChangeRequest(id)
	if err != nil {
		s.Close()
		must(err)
	}
	return c, s
}
