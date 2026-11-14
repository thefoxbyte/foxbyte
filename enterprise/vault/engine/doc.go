// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

// Package engine connects the vault to the engine (point 13): it installs
// the vault's client and kinds as internal/branch's Vaulter. It is a package
// of its own so the vault service, which imports enterprise/vault, never
// carries the engine.
package engine

// Untagged, so `go build ./...` succeeds without `-tags enterprise`. See
// enterprise/doc.go.
