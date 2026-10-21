// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

// Package pii finds personal data in a branch: column names and sampled
// values, recognised by shape and, where an identifier has one, by its check
// digit. Point 4.1 of the review plan.
package pii

// Untagged, so `go build ./...` succeeds without `-tags enterprise`. See
// enterprise/doc.go.
