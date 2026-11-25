//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package pii

// What an erasure request (F4, enterprise/dpdp) needs of finding a person:
// the same reading of a value, and the same comparison in SQL, as
// `fox subject find` uses, so a request erases exactly the rows a search
// counts.

// SubjectMatches reads a value as every category it could be, or as only
// that one when only is set.
func SubjectMatches(value string, only Category) []SubjectMatch { return subjectMatches(value, only) }

// SubjectSQL is the SQL expression a stored value x is compared in, for c.
func SubjectSQL(c Category, x string) string { return subjectSQL(c, x) }

// IsCategory reports whether c is a category the recognisers know.
func IsCategory(c string) bool {
	for _, r := range recognisers {
		if string(r.cat) == c {
			return true
		}
	}
	return false
}
