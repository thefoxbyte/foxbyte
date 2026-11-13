//go:build !(enterprise && cgo && linux)

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

// Command fox-vault is the vault service (point 13). It talks PKCS#11, a C
// interface, so it is built with cgo and the enterprise tag, on Linux, into
// the vault's own image; never into `fox`. This stub is what any other build
// gets, so `go build ./...` and `go vet ./...` pass everywhere, macOS and
// Windows included.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "fox-vault is built with -tags enterprise and cgo, into the vault's image")
	os.Exit(2)
}
