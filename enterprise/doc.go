// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

// Package enterprise is the root of the paid edition. See LICENSE in this
// directory: this code is source-available, not open source, and is not covered
// by the AGPL that applies to the rest of the repository.
//
// This file carries no build tag so that `go build ./...` and `go vet ./...`
// succeed without `-tags enterprise`, for the same reason web/embed_stub.go
// exists. Everything with behaviour in it is tagged.
package enterprise
