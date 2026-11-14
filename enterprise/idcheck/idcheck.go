//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package idcheck

import "strings"

// Digits removes the separators people type into numbers (spaces, hyphens),
// and reports whether what is left is all digits.
func Digits(s string) (string, bool) {
	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		switch {
		case r == ' ' || r == '-':
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			return "", false
		}
	}
	return b.String(), b.Len() > 0
}

// Verhoeff's tables, as UIDAI uses them for Aadhaar's last digit.
var (
	vd = [10][10]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
		{2, 3, 4, 0, 1, 7, 8, 9, 5, 6}, {3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
		{4, 0, 1, 2, 3, 9, 5, 6, 7, 8}, {5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
		{6, 5, 9, 8, 7, 1, 0, 4, 3, 2}, {7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
		{8, 7, 6, 5, 9, 3, 2, 1, 0, 4}, {9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
	}
	vp = [8][10]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
		{5, 8, 0, 3, 7, 9, 6, 1, 4, 2}, {8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
		{9, 4, 5, 3, 1, 2, 6, 8, 7, 0}, {4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
		{2, 7, 9, 3, 8, 0, 6, 4, 1, 5}, {7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
	}
	vinv = [10]int{0, 4, 3, 2, 1, 5, 6, 7, 8, 9}
)

// Verhoeff reports whether d, all digits, passes the Verhoeff check.
func Verhoeff(d string) bool {
	c := 0
	for i := 0; i < len(d); i++ {
		c = vd[c][vp[i%8][int(d[len(d)-1-i]-'0')]]
	}
	return c == 0
}

// VerhoeffDigit is the check digit that, appended to d (digits only), makes
// the whole pass the Verhoeff check.
func VerhoeffDigit(d string) byte {
	c := 0
	for i := 0; i < len(d); i++ {
		c = vd[c][vp[(i+1)%8][int(d[len(d)-1-i]-'0')]]
	}
	return byte('0' + vinv[c])
}

// IsAadhaar is the scanner's rule: 12 digits once spaces and hyphens are
// removed, the first 2 to 9, passing the Verhoeff check.
func IsAadhaar(s string) bool {
	d, ok := Digits(s)
	return ok && len(d) == 12 && d[0] >= '2' && Verhoeff(d)
}
