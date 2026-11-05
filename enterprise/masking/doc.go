// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

// Package masking makes masks (F5, point 7): rules set on confirmed marks,
// kept in shadow tables by triggers, read through views by masked readers.
package masking

// Untagged, so `go build ./...` succeeds without `-tags enterprise`. See
// enterprise/doc.go.
