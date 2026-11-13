// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

// Command fox-vault is the vault service (point 13,
// docs/FOX_P13_Vault_Design.md). The real service is built with cgo and the
// enterprise tag on Linux, into the vault's image; any other build gets the
// stub that says so (stub.go).
package main

// Untagged, so every build sees the package. See enterprise/doc.go.
