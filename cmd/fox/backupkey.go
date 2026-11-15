// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"

	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/secrets"
)

// allowInsecureHTTP is the escape hatch for a plain-HTTP bucket on another
// machine. --allow-http is the flag's old name, still accepted so a script
// written for it keeps working; either one is warned about when it is used.
func allowInsecureHTTP(args []string) bool {
	return hasFlag(args, "--allow-insecure-http") || hasFlag(args, "--allow-http")
}

// targetSetOptions reads `backup target set`'s flags.
func targetSetOptions(args []string) (branch.TargetOptions, error) {
	o := branch.TargetOptions{AllowInsecureHTTP: allowInsecureHTTP(args)}
	on, off := hasFlag(args, "--encrypt"), hasFlag(args, "--no-encrypt")
	switch {
	case on && off:
		return o, errors.New("--encrypt and --no-encrypt cannot both be given")
	case on:
		o.Encrypt = branch.EncryptOn
	case off:
		o.Encrypt = branch.EncryptOff
	}
	return o, nil
}

// backupKeyCmd is `fox backup key export|import`: the key the backups in a
// remote bucket are encrypted with. It is kept on this machine and never in
// the bucket, so a lost machine loses it unless it was exported first.
//
// Only the CLI has it, and the CLI at this machine is its operator, as for
// `fox user list`: whoever can run it can read the key file anyway. No API
// route returns the key.
func backupKeyCmd(args []string) {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "export":
		k, err := secrets.BackupKey()
		if errors.Is(err, secrets.ErrNoBackupKey) {
			must(fmt.Errorf("no backup key on this machine: one is made when a remote backup target is set with encryption"))
		}
		must(err)
		fmt.Fprintf(os.Stderr, "This key decrypts every backup in the bucket (key id %s).\n", secrets.BackupKeyID(k))
		fmt.Fprintln(os.Stderr, "Keep it somewhere that is neither this machine nor the bucket: a password manager or a sealed record.")
		fmt.Fprintln(os.Stderr, "Lose it and the backups are lost; let someone else have it and they can read them.")
		fmt.Println(k)
	case "import":
		fmt.Fprint(os.Stderr, "backup key: ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		must(secrets.ImportBackupKey(line, hasFlag(args, "--replace")))
		k, _ := secrets.BackupKey()
		fmt.Printf("backup key installed (key id %s)\n", secrets.BackupKeyID(k))
		if t, err := branch.CurrentTarget(); err == nil {
			if p := t.KeyProblem(); p != nil {
				fmt.Fprintln(os.Stderr, "warning:", p)
			}
		}
	default:
		fmt.Printf("usage: %[1]s backup key export | %[1]s backup key import [--replace]   (the key is read from stdin)\n", brand.CLI)
		os.Exit(2)
	}
}
