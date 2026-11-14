// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

// Package hsm is the vault's side of PKCS#11 (point 13, design section 6):
// a token's sessions, the keys made inside it, and the calls that encrypt,
// decrypt, index and draw random bytes there. It needs cgo, because PKCS#11
// libraries are C, so it is built only into the vault service, on Linux,
// never into `fox`.
package hsm

// Untagged, so `go build ./...` succeeds without `-tags enterprise` or cgo.
// See enterprise/doc.go.
