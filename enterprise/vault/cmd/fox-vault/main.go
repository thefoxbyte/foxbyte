//go:build enterprise && cgo && linux

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

// Command fox-vault is the vault service (point 13,
// docs/FOX_P13_Vault_Design.md). Gate 0, the prototype: `serve` is the
// service; `bench`, `gen`, `migrate`, `status` and `call` are what the
// prototype's suite measures and checks it with.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "bench":
		err = bench(os.Args[2:])
	case "gen":
		err = gen(os.Args[2:])
	case "migrate":
		err = migrate(os.Args[2:])
	case "status":
		err = status(os.Args[2:])
	case "call":
		err = callCmd(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "fox-vault:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: fox-vault serve|bench|gen|migrate|status|call [flags]")
	os.Exit(2)
}

func readSecret(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := string(b)
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	if s == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return s, nil
}
