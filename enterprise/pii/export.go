//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package pii

// The scanner's checks, for the vault (point 13): a vault kind refuses what the
// scanner would not call its category, and a vault's legacy reference keys are
// made to fail the same check, so the two can never disagree.

// IsAadhaar reports whether s is an Aadhaar number by the scanner's rule: 12
// digits once spaces and hyphens are removed, the first 2 to 9, passing the
// Verhoeff check.
func IsAadhaar(s string) bool { return isAadhaar(s) }

// Digits removes the separators people type into numbers (spaces, hyphens),
// and reports whether what is left is all digits.
func Digits(s string) (string, bool) { return digits(s) }

// VerhoeffDigit is the check digit that, appended to d (digits only), makes the
// whole pass the Verhoeff check.
func VerhoeffDigit(d string) byte {
	inv := [10]int{0, 4, 3, 2, 1, 5, 6, 7, 8, 9}
	c := 0
	for i := 0; i < len(d); i++ {
		c = verhoeffD[c][verhoeffP[(i+1)%8][int(d[len(d)-1-i]-'0')]]
	}
	return byte('0' + inv[c])
}
