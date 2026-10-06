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
			"Make one with: %[1]s branch request <source> [--to <target>]\n", brand.CLI)
		os.Exit(2)
	}
}

// branchRequestCmd is `fox branch request <source> [--to <target>]`.
func branchRequestCmd(args []string) {
	requireFeature(edition.Promotion)
	source := firstPositional(args, "--to")
	if source == "" {
		fmt.Printf("usage: %s branch request <source> [--to <target>]\n", brand.CLI)
		os.Exit(2)
	}
	target := optValue(args, "--to")
	if target == "" {
		target = "main"
	}
	s := openStore()
	defer s.Close()
	history, err := s.ApprovedRequestsFrom(source, target)
	must(err)
	entries, forkAfter, err := branch.BuildRequest(source, target, history)
	must(err)
	snapshot, err := branch.MarshalEntries(entries)
	must(err)
	c, err := s.CreateChangeRequest(auth.CLIUser, source, target, forkAfter, snapshot)
	must(err)
	s.Audit(auth.EvChangeRequested, cliActor(), fmt.Sprintf("request #%d: %s → %s", c.ID, source, target), "",
		fmt.Sprintf("%d statement(s)", len(entries)))
	fmt.Print(branch.FormatRequest(c, entries))
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

	claimed, err := s.ClaimChangeRequest(c.ID, auth.CLIUser, decision, optValue(args, "--note"))
	if errors.Is(err, auth.ErrRequestDecided) {
		must(fmt.Errorf("request #%d was already %s by %s", c.ID, c.Status, c.DecidedBy))
	}
	must(err)

	if decision == auth.RequestRejected {
		s.Audit(auth.EvChangeDecided, cliActor(), fmt.Sprintf("request #%d rejected", c.ID), "", claimed.Note)
		fmt.Printf("Request #%d rejected. %s is unchanged.\n", c.ID, c.Target)
		return
	}

	fmt.Printf("Applying %d statement(s) to %s …\n", len(entries), c.Target)
	n, applyErr := branch.ApplyRequest(c.ID, c.Target, "the local CLI", entries)
	failure := ""
	if applyErr != nil {
		failure = applyErr.Error()
	}
	if err := s.FinishChangeRequest(c.ID, n, failure); err != nil {
		fmt.Fprintf(os.Stderr, "warning: recording the outcome of request #%d: %v\n", c.ID, err)
	}
	s.Audit(auth.EvChangeDecided, cliActor(), fmt.Sprintf("request #%d approved", c.ID), "",
		fmt.Sprintf("%d statement(s) applied to %s", n, c.Target))
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
