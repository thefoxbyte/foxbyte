// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

// Package auditevidence builds the audit log's evidence export (F6 Gate 1,
// step 6b): what the audit log covered over a period, what it did not, and
// whether its records are intact, anchored and delivered.
package auditevidence

// Untagged, so `go build ./...` succeeds without `-tags enterprise`. See
// enterprise/doc.go.
