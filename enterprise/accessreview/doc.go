// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

// Package accessreview builds the access review report (point 4.8): every
// account, what it can reach and with which credentials, who may override the
// guardrails where, and who has gone quiet.
package accessreview

// Untagged, so `go build ./...` succeeds without `-tags enterprise`. See
// enterprise/doc.go.
