// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

// Package idcheck is the Aadhaar check with nothing else attached: digits,
// Verhoeff, and the rule the PII scanner calls Aadhaar. The vault service
// (point 13) builds on it so that its binary carries no part of the engine;
// enterprise/pii keeps its own, and a test holds the two to the same answers.
package idcheck

// Untagged, so `go build ./...` succeeds without `-tags enterprise`. See
// enterprise/doc.go.
