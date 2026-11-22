// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// Rotating a kind's keys, and deleting or updating values under their
// reference keys (point 13, step 13.4; design, sections 6 and 12):
//
//	fox vault rotate --kind k [--key data|index] [--yes]
//	fox vault delete --kind k --purpose "why" REF... | - [--yes]
//	fox vault update --kind k --purpose "why" REF...   (the new values on stdin, one a line, in order)
//
// The operator's, on the machine; over the API, admins only. A new value is
// never taken on the command line, where the shell's history would keep it.

const vaultKeysUsage = `usage:
  fox vault rotate --kind KIND [--key data|index] [--yes]
  fox vault delete --kind KIND --purpose "WHY" REF... | - [--yes]
  fox vault update --kind KIND --purpose "WHY" REF...   (new values on stdin, one a line, in order)
`

type vaultReplyCLI struct {
	Refs    []string `json:"refs"`
	Results []string `json:"results"`
	Error   string   `json:"error"`
}

// vaultChange makes one call that changes the vault, as the operator, and
// returns the service's reply, exiting on a refusal.
func vaultChange(path string, req map[string]any) vaultReplyCLI {
	body, _ := json.Marshal(req)
	st := openStore()
	if st != nil {
		defer st.Close()
	}
	reply, code, err := branch.VaultCall(st, cliActor(), "", path, body)
	must(err)
	var r vaultReplyCLI
	if err := json.Unmarshal(reply, &r); err != nil {
		must(fmt.Errorf("the vault answered %d: %s", code, strings.TrimSpace(string(reply))))
	}
	if code != 200 {
		must(errors.New(r.Error))
	}
	return r
}

func vaultKindArg(args []string) string {
	kind := optValue(args, "--kind")
	if kind == "" {
		fmt.Fprintf(os.Stderr, "--kind is needed: one of the kinds `%s vault kinds` lists\n\n%s", brand.CLI, vaultKeysUsage)
		os.Exit(2)
	}
	return kind
}

func vaultPurposeArg(args []string, what string) string {
	purpose := strings.TrimSpace(optValue(args, "--purpose"))
	if purpose == "" {
		fmt.Fprintf(os.Stderr, "--purpose is needed: why the values are %s, which the vault's log and the security log keep\n", what)
		os.Exit(2)
	}
	return purpose
}

// stdinLines reads stdin, one item a line, blank lines skipped.
func stdinLines() []string {
	var out []string
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		if l := strings.TrimRight(sc.Text(), "\r"); l != "" {
			out = append(out, l)
		}
	}
	must(sc.Err())
	return out
}

func vaultRotate(args []string) {
	kind := vaultKindArg(args)
	key := optValue(args, "--key")
	if key == "" {
		key = "data"
	}
	if key != "data" && key != "index" {
		fmt.Fprintf(os.Stderr, "--key is data or index, not %q\n", key)
		os.Exit(2)
	}
	if !hasFlag(args, "--yes") {
		if key == "data" {
			fmt.Printf("This makes a new data key for %s in the HSM, encrypts every %s record\n"+
				"again under it, in batches, while the vault keeps answering, then destroys\n"+
				"the old key in the HSM. Values deleted or updated before now, still in the\n"+
				"vault database's backups, can then never be read again: that is how they\n"+
				"are shredded.\n\n", kind, kind)
		} else {
			fmt.Printf("This makes a new index key for %s in the HSM, indexes every %s record\n"+
				"again under it, in batches, while the vault keeps answering (a value is\n"+
				"found under the old key or the new one meanwhile), then destroys the old\n"+
				"key in the HSM. Reference keys do not change.\n\n", kind, kind)
		}
		fmt.Println("Run again with --yes to go ahead.")
		return
	}
	r := vaultChange("rotate", map[string]any{"kind": kind, "key": key})
	for _, res := range r.Results {
		fmt.Println(res)
	}
}

func vaultDelete(args []string) {
	kind := vaultKindArg(args)
	purpose := vaultPurposeArg(args, "deleted")
	refs := positionals(args, "--kind", "--purpose")
	if len(refs) == 1 && refs[0] == "-" {
		refs = stdinLines()
	}
	if len(refs) == 0 {
		fmt.Fprintf(os.Stderr, "nothing to delete: give reference keys, or - to read them one a line\n\n%s", vaultKeysUsage)
		os.Exit(2)
	}
	if !hasFlag(args, "--yes") {
		fmt.Printf("This deletes %d %s value(s) from the vault. Their reference keys then answer\n"+
			"\"not found\" to everyone, wherever they are kept. The ciphertexts stay in the\n"+
			"vault database's backups, readable with the current data key, until the next\n"+
			"`%s vault rotate --kind %s` destroys it.\n\n"+
			"Run again with --yes to go ahead.\n", len(refs), kind, brand.CLI, kind)
		return
	}
	r := vaultChange("delete", map[string]any{"kind": kind, "refs": refs, "purpose": purpose})
	gone := 0
	for i, res := range r.Results {
		if res == "done" {
			gone++
			continue
		}
		fmt.Printf("%s\t(%s)\n", refs[i], res)
	}
	fmt.Printf("%d of %d deleted.\n", gone, len(refs))
	if gone < len(refs) {
		os.Exit(1)
	}
}

func vaultUpdate(args []string) {
	kind := vaultKindArg(args)
	purpose := vaultPurposeArg(args, "updated")
	refs := positionals(args, "--kind", "--purpose")
	if len(refs) == 0 {
		fmt.Fprintf(os.Stderr, "nothing to update: give the reference keys, and their new values on stdin\n\n%s", vaultKeysUsage)
		os.Exit(2)
	}
	values := stdinLines()
	if len(values) != len(refs) {
		fmt.Fprintf(os.Stderr, "%d reference key(s) and %d new value(s) on stdin: give one value a line, in the keys' order\n", len(refs), len(values))
		os.Exit(2)
	}
	r := vaultChange("update", map[string]any{"kind": kind, "refs": refs, "values": values, "purpose": purpose})
	done := 0
	for i, res := range r.Results {
		switch {
		case res == "done" || res == "unchanged":
			done++
			fmt.Printf("%s\t%s\n", refs[i], res)
		case i < len(r.Refs) && r.Refs[i] != "":
			fmt.Printf("%s\t(%s: %s)\n", refs[i], res, r.Refs[i])
		default:
			fmt.Printf("%s\t(%s)\n", refs[i], res)
		}
	}
	if done < len(refs) {
		fmt.Fprintf(os.Stderr, "%d of %d were not updated: see the line for each\n", len(refs)-done, len(refs))
		os.Exit(1)
	}
}
