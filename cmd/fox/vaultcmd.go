// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// vaultCmd is `fox vault` (point 13, step 13.1): the install's vault for
// sensitive values, Aadhaar first.
//
//	fox vault [status] [--json]
//	fox vault setup [--yes] [--hsm-dir d --hsm-lib l --token t --pin-file f [--hsm-env N=V ...]]
//	fox vault kinds [--json]
//	fox vault tokenise --kind k [--format opaque|legacy] <value>... | -
//	fox vault find --kind k <value>... | -
//	fox vault detokenise --kind k --purpose "why" <reference key>... | -
//
// The CLI is the operator's, on the machine: it reaches the vault service
// directly, and each call is in the security log with the vault's log head.
// Detokenising is the operator's only, until admins can grant it (13.2).
func vaultCmd(args []string) {
	requireFeature(edition.Vault)
	sub := "status"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "status":
		vaultStatus(args)
	case "setup":
		vaultSetup(args)
	case "kinds":
		vaultKinds(args)
	case "tokenise", "tokenize", "find", "detokenise", "detokenize":
		vaultCall(strings.Replace(sub, "z", "s", 1), args)
	default:
		fmt.Fprintf(os.Stderr, "unknown vault command %q\n\n%s", sub, vaultUsage)
		os.Exit(2)
	}
}

const vaultUsage = `usage:
  fox vault [status] [--json]
  fox vault setup [--yes] [--hsm-dir DIR --hsm-lib LIB --token LABEL --pin-file FILE [--hsm-env NAME=VALUE ...]]
  fox vault kinds [--json]
  fox vault tokenise --kind KIND [--format opaque|legacy] VALUE... | -
  fox vault find --kind KIND VALUE... | -
  fox vault detokenise --kind KIND --purpose "WHY" REF... | -
`

func vaultSetup(args []string) {
	o := branch.VaultSetupOptions{
		HSMDir:  optValue(args, "--hsm-dir"),
		HSMLib:  optValue(args, "--hsm-lib"),
		Token:   optValue(args, "--token"),
		PINFile: optValue(args, "--pin-file"),
	}
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--hsm-env" {
			o.HSMEnv = append(o.HSMEnv, args[i+1])
		}
	}
	hsm := o.HSMDir != "" || o.HSMLib != "" || o.PINFile != ""
	if !hasFlag(args, "--yes") {
		fmt.Printf("This sets up the install's vault (point 13): the one place it keeps\n" +
			"sensitive values, Aadhaar first, each encrypted inside an HSM.\n\n" +
			"It makes two containers: the vault database, on a network of its own\n" +
			"with no route out, which admits only the vault service; and the vault\n" +
			"service, which talks to the HSM and answers only this engine, on a\n" +
			"socket in the state directory.\n\n")
		if hsm {
			fmt.Printf("The keys are made in the HSM you named (%s in %s, token %q),\n"+
				"and never leave it.\n", o.HSMLib, o.HSMDir, o.Token)
		} else {
			fmt.Printf("No HSM is named, so the keys are made in FoxByte's own software\n" +
				"token. That is for trials and testing: UIDAI requires an HSM for\n" +
				"Aadhaar, so the vault says \"not UIDAI-compliant\" for Aadhaar until it\n" +
				"is set up with one (--hsm-dir, --hsm-lib, --token, --pin-file).\n")
		}
		fmt.Printf("\nRun again with --yes to go ahead.\n")
		return
	}
	c, err := branch.VaultSetup(o)
	must(err)
	how := "FoxByte's own software token (not UIDAI-compliant: trials and testing only)"
	if c.HSM != nil {
		how = fmt.Sprintf("the HSM's token %q (%s)", c.Token, c.HSM.Lib)
	}
	recordVault(auth.EvVaultSetup, "", "set up with "+how+", subnet "+c.Subnet)
	fmt.Printf("Done: the vault is set up and running, with %s.\n", how)
	fmt.Printf("See it with `%s vault status`; its kinds with `%s vault kinds`.\n", brand.CLI, brand.CLI)
}

func recordVault(kind, subject, detail string) {
	if s := openStore(); s != nil {
		s.Audit(kind, cliActor(), subject, "", detail)
		s.Close()
	}
}

// vaultServiceStatus is the part of the service's status the CLI shows.
type vaultServiceStatus struct {
	Token struct {
		Label, Maker, Model, Serial string
		Software                    bool
	} `json:"token"`
	Kinds []struct {
		Name        string `json:"name"`
		Prefix      string `json:"prefix"`
		Compliant   string `json:"compliant"`
		Records     int64  `json:"records"`
		HSMRequired bool   `json:"hsm_required"`
		Keys        []struct {
			Label            string `json:"label"`
			Role             string `json:"role"`
			Current          bool   `json:"current"`
			Destroyed        bool   `json:"destroyed"`
			Uses             int64  `json:"uses"`
			Records          int64  `json:"records"`
			Sensitive        bool   `json:"sensitive"`
			Extractable      bool   `json:"extractable"`
			NeverExtractable bool   `json:"never_extractable"`
			Local            bool   `json:"local"`
		} `json:"keys"`
	} `json:"kinds"`
	Log struct {
		Entries  int64  `json:"entries"`
		BrokenAt int64  `json:"broken_at"`
		Head     string `json:"head"`
	} `json:"log"`
}

func vaultStatus(args []string) {
	st, err := branch.VaultStatus(openStore())
	must(err)
	if hasFlag(args, "--json") {
		b, _ := json.MarshalIndent(st, "", "  ")
		fmt.Println(string(b))
		return
	}
	if !st.SetUp {
		fmt.Printf("The vault is not set up on this install.\nSet it up with `%s vault setup`.\n", brand.CLI)
		return
	}
	c := st.Config
	token := "FoxByte's own software token"
	if c.HSM != nil {
		token = "the HSM in " + c.HSM.Dir
	}
	fmt.Printf("The vault: set up %s, with %s.\n", c.SetUpAt.Format("2 Jan 2006"), token)
	fmt.Printf("  Database   %s (%s)\n", runningWord(st.Database), c.DBAddr)
	fmt.Printf("  Service    %s (%s)\n", runningWord(st.Service), c.SvcAddr)
	if st.StatusErr != "" {
		fmt.Printf("\nThe service did not answer: %s\n", st.StatusErr)
		return
	}
	var s vaultServiceStatus
	if err := json.Unmarshal(st.Status, &s); err != nil {
		must(err)
	}
	fmt.Printf("  Token      %q: %s %s, serial %s\n\n", s.Token.Label, s.Token.Maker, s.Token.Model, s.Token.Serial)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "KIND\tPREFIX\tRECORDS\tCOMPLIANT")
	for _, k := range s.Kinds {
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\n", k.Name, k.Prefix, k.Records, k.Compliant)
	}
	_ = w.Flush()
	fmt.Println()
	w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "KEY\tROLE\tRECORDS\tUSES\tPROTECTED")
	for _, k := range s.Kinds {
		for _, key := range k.Keys {
			prot := "destroyed"
			switch {
			case key.Destroyed:
			case key.Sensitive && !key.Extractable && key.NeverExtractable && key.Local:
				prot = "made in the token, never extractable"
			default:
				prot = "NOT protected: it can leave the token"
			}
			role := key.Role
			if key.Current {
				role += " (current)"
			}
			fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\n", key.Label, role, key.Records, key.Uses, prot)
		}
	}
	_ = w.Flush()
	fmt.Println()
	if s.Log.BrokenAt == 0 {
		fmt.Printf("Access log: %d entries; the chain holds.\n", s.Log.Entries)
	} else {
		fmt.Printf("Access log: %d entries; THE CHAIN BREAKS at entry %d.\n", s.Log.Entries, s.Log.BrokenAt)
	}
	if st.Anchor.Holds {
		fmt.Printf("Against the security log: %s.\n", st.Anchor.Note)
	} else {
		fmt.Printf("Against the security log: DOES NOT HOLD: %s.\n", st.Anchor.Note)
	}
}

func runningWord(b bool) string {
	if b {
		return "running"
	}
	return "STOPPED"
}

func vaultKinds(args []string) {
	ks, err := branch.VaultKinds()
	must(err)
	if hasFlag(args, "--json") {
		b, _ := json.MarshalIndent(ks, "", "  ")
		fmt.Println(string(b))
		return
	}
	for _, k := range ks {
		fmt.Printf("%s (reference keys %s…)\n", k.Name, k.Prefix)
		fmt.Printf("  accepts:  %s\n", k.Check)
		if k.Legacy != "" {
			fmt.Printf("  legacy:   %s\n", k.Legacy)
		} else {
			fmt.Printf("  legacy:   none\n")
		}
		if k.Rules != "" {
			fmt.Printf("  rules:    %s", k.Rules)
			if k.HSMRequired {
				fmt.Printf(" (an HSM is required)")
			}
			fmt.Println()
		} else {
			fmt.Printf("  rules:    none mapped\n")
		}
	}
}

// vaultCall is tokenise, find and detokenise. Values and reference keys come
// as arguments, or one a line on standard input after "-", so a number need
// not sit in the shell's history.
func vaultCall(path string, args []string) {
	kind := optValue(args, "--kind")
	if kind == "" {
		fmt.Fprintf(os.Stderr, "--kind is needed: one of the kinds `%s vault kinds` lists\n", brand.CLI)
		os.Exit(2)
	}
	items := positionals(args, "--kind", "--format", "--purpose")
	if len(items) == 1 && items[0] == "-" {
		items = nil
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			if l := strings.TrimRight(sc.Text(), "\r"); l != "" {
				items = append(items, l)
			}
		}
		must(sc.Err())
	}
	if len(items) == 0 {
		fmt.Fprintf(os.Stderr, "nothing to %s: give values (or reference keys), or - to read them one a line\n", path)
		os.Exit(2)
	}
	req := map[string]any{"kind": kind}
	if path == "detokenise" {
		purpose := strings.TrimSpace(optValue(args, "--purpose"))
		if purpose == "" {
			fmt.Fprintln(os.Stderr, "--purpose is needed: why the values are read back, which the vault's log and the security log keep")
			os.Exit(2)
		}
		req["refs"], req["purpose"] = items, purpose
	} else {
		req["values"] = items
		if f := optValue(args, "--format"); f != "" {
			req["format"] = f
		}
	}
	body, _ := json.Marshal(req)
	st := openStore()
	if st != nil {
		defer st.Close()
	}
	reply, code, err := branch.VaultCall(st, cliActor(), "", path, body)
	must(err)
	var r struct {
		Refs    []string `json:"refs"`
		New     []bool   `json:"new"`
		Values  []string `json:"values"`
		Results []string `json:"results"`
		Error   string   `json:"error"`
	}
	if err := json.Unmarshal(reply, &r); err != nil {
		must(fmt.Errorf("the vault answered %d: %s", code, strings.TrimSpace(string(reply))))
	}
	if code != 200 {
		must(errors.New(r.Error))
	}
	missing := 0
	for i := range r.Results {
		res := r.Results[i]
		switch {
		case res != "done":
			missing++
			fmt.Printf("(%s)\n", res)
		case path == "detokenise":
			fmt.Println(r.Values[i])
		case path == "tokenise" && i < len(r.New) && r.New[i]:
			fmt.Printf("%s\tnew\n", r.Refs[i])
		default:
			fmt.Println(r.Refs[i])
		}
	}
	if missing > 0 {
		fmt.Fprintf(os.Stderr, "%d of %d were not %s\n", missing, len(r.Results), map[string]string{
			"tokenise": "taken: they fail the kind's check", "find": "in the vault", "detokenise": "read: see the line for each"}[path])
		os.Exit(1)
	}
}
