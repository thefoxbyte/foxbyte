// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

// Package dpdp is the DPDP compliance manager (point 11). Its first part is
// the personal-data inventory (11.1): setting and removing the entries that
// say, for each table holding confirmed personal data, its basis under the
// DPDP Act, its purpose, whose data it is and how long it is kept. Reading
// the inventory is in internal/branch, free in every edition.
package dpdp

// Untagged, so `go build ./...` succeeds without `-tags enterprise`. See
// enterprise/doc.go.
