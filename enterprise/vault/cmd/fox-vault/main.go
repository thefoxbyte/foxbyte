//go:build enterprise && cgo && linux

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

// Command fox-vault is the vault service (point 13,
// docs/FOX_P13_Vault_Design.md). Gate 0, the prototype: `serve` is the
// service; `bench`, `gen`, `migrate`, `status` and `call` are what the
// prototype's suite measures and checks it with.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/thefoxbyte/foxbyte/enterprise/vault/hsm"
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
	case "init-token":
		err = initToken(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "fox-vault:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: fox-vault serve|init-token|status|call|bench|gen|migrate [flags]")
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

// initToken makes FoxByte's own software token, its PINs read from files so
// they never reach a command line. A token already made is left as it is.
func initToken(args []string) error {
	fs := flag.NewFlagSet("init-token", flag.ExitOnError)
	lib := fs.String("pkcs11-lib", "/usr/lib/softhsm/libsofthsm2.so", "the PKCS#11 library")
	label := fs.String("token", "fox-vault", "the token's label")
	pinFile := fs.String("pin-file", "/etc/fox-vault/secret/pin", "the user's PIN")
	soPinFile := fs.String("so-pin-file", "/etc/fox-vault/secret/so-pin", "the security officer's PIN")
	_ = fs.Parse(args)
	pin, err := readSecret(*pinFile)
	if err != nil {
		return err
	}
	so, err := readSecret(*soPinFile)
	if err != nil {
		return err
	}
	err = hsm.InitToken(*lib, *label, so, pin)
	if errors.Is(err, hsm.ErrTokenExists) {
		fmt.Printf("the token %q exists already\n", *label)
		return nil
	}
	if err == nil {
		fmt.Printf("made the token %q\n", *label)
	}
	return err
}
