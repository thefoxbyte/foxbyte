//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package pii

import (
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/enterprise/idcheck"
)

// The vault (point 13) checks Aadhaar with enterprise/idcheck, the scanner
// with its own code. They must never disagree: a value the vault refuses the
// scanner would call Aadhaar, or the other way round, would let a number
// through one or the other.
func TestIDCheckAgreesWithTheScanner(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	cases := []string{"", " ", "-", "2", "234123412346", "1234 1234 1234", "2341-2341-2346", "23412341234", "2341234123460", "abcd", "２３４１"}
	for i := 0; i < 200000; i++ {
		n := 10 + r.IntN(5)
		var b strings.Builder
		for j := 0; j < n; j++ {
			switch x := r.IntN(30); {
			case x == 0:
				b.WriteByte(' ')
			case x == 1:
				b.WriteByte('-')
			case x == 2:
				b.WriteByte('x')
			default:
				b.WriteByte(byte('0' + r.IntN(10)))
			}
		}
		cases = append(cases, b.String())
		// And numbers made to pass, so both sides of the check are exercised.
		d := make([]byte, 11)
		d[0] = byte('2' + r.IntN(8))
		for j := 1; j < 11; j++ {
			d[j] = byte('0' + r.IntN(10))
		}
		cases = append(cases, string(d)+string(VerhoeffDigit(string(d))))
	}
	passed := 0
	for _, c := range cases {
		if isAadhaar(c) != idcheck.IsAadhaar(c) {
			t.Fatalf("%q: the scanner says %v, idcheck %v", c, isAadhaar(c), idcheck.IsAadhaar(c))
		}
		if a, aok := digits(c); true {
			b, bok := idcheck.Digits(c)
			if a != b || aok != bok {
				t.Fatalf("%q: digits differ", c)
			}
		}
		if isAadhaar(c) {
			passed++
		}
	}
	if passed < 200000 {
		t.Fatalf("only %d cases passed the check: the made-to-pass ones are not exercising it", passed)
	}
	for i := 0; i < 1000; i++ {
		d := make([]byte, 11)
		for j := range d {
			d[j] = byte('0' + r.IntN(10))
		}
		if VerhoeffDigit(string(d)) != idcheck.VerhoeffDigit(string(d)) {
			t.Fatalf("%s: check digits differ", d)
		}
	}
}
