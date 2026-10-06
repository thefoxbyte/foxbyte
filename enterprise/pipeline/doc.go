// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package pipeline

// This file carries no build tag so that `go build ./...` and `go vet ./...`
// succeed without `-tags enterprise` — the same reason enterprise/doc.go and
// web/embed_stub.go exist. Everything with behaviour in it is tagged, and in a
// Standard build this package compiles to nothing at all.
