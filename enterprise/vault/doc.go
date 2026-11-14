// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

// Package vault is the vault's own logic, without the HSM (point 13,
// docs/FOX_P13_Vault_Design.md): its kinds, reference keys, the access log's
// chain, and the protocol between the engine and the vault service, with a
// client for it. The HSM side is enterprise/vault/hsm (cgo), and the service
// is enterprise/vault/cmd/fox-vault.
//
// Gate 0, the prototype: what is here is what the prototype measures, and
// Gate 1 builds on it.
package vault

// Untagged, so `go build ./...` succeeds without `-tags enterprise`. See
// enterprise/doc.go.
