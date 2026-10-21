//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package pii

import (
	"errors"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

func TestMask(t *testing.T) {
	for _, c := range []struct {
		cat     Category
		in, out string
	}{
		{Aadhaar, "2345 6789 0124", "XXXX XXXX 0124"},
		{Aadhaar, "234567890124", "XXXXXXXX0124"},
		{Mobile, "+91 98765 43210", "+XX XXXXX X3210"},
		{Card, "4111-1111-1111-1111", "XXXX-XXXX-XXXX-1111"},
		{PAN, "ABCPE1234F", "XXXXXX234F"},
		{Email, "a.person@example.com", "a***@example.com"},
		{UPI, "person@okhdfc", "p***@okhdfc"},
		{Birth, "1990-05-17", "1990-XX-XX"},
		{Child, "2015-01-01", "2015-XX-XX"},
		{IP, "10.0.0.1", "10.0.X.X"},
		{IP, "192.168.1.20/32", "192.168.X.X"},
		{IP, "2001:db8::1", "2001:X:X:X"},
		{VoterID, "ABC", "XXX"},                 // too short to show any of it
		{Email, "not an email", "XXX XX Xmail"}, // no @: masked like anything else
	} {
		if got := Mask(c.cat, c.in); got != c.out {
			t.Errorf("Mask(%s, %q) = %q, want %q", c.cat, c.in, got, c.out)
		}
	}
}

// Whatever comes in, at most four of its letters and digits come out (an
// email's first letter and domain, a date's year and an address's network are
// the stated exceptions, tested above).
func TestMaskShowsAtMostFour(t *testing.T) {
	for _, v := range []string{aadhaars(1)[0], "4111111111111111", "ABCPE1234F", "27AAPFU0939F1ZV", "J8369854",
		"MH12AB1234", "something long enough to be free text, which is cut short and masked all the same, really"} {
		got := Mask(PAN, v)
		shown := 0
		for _, r := range got {
			if (unicode.IsLetter(r) || unicode.IsDigit(r)) && r != 'X' {
				shown++
			}
		}
		if shown > 4 {
			t.Errorf("Mask(%q) = %q shows %d characters", v, got, shown)
		}
		if strings.Contains(got, v) {
			t.Errorf("Mask(%q) returned the value", v)
		}
	}
}

func TestRecogniserFor(t *testing.T) {
	today = func() time.Time { return time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC) }
	defer func() { today = func() time.Time { return time.Now().UTC() } }()
	if !recogniserFor(Aadhaar)(aadhaars(1)[0]) || recogniserFor(Aadhaar)("123") {
		t.Fatal("aadhaar")
	}
	if !recogniserFor(Child)("2015-01-01") || recogniserFor(Child)("1990-01-01") {
		t.Fatal("child is a date of birth less than 18 years ago")
	}
	if recogniserFor("no-such-category")("anything") {
		t.Fatal("an unknown category matches nothing")
	}
}

func TestReadErrorSaysWhatToDoAndNoValue(t *testing.T) {
	f := branch.PIIFinding{Schema: "public", Table: "customers", Column: "aadhaar_no"}
	denied := readError(&pgconn.PgError{Code: "42501", Message: "permission denied for table customers"}, f)
	if !errors.Is(denied, branch.ErrCannotReadLocation) || !strings.Contains(denied.Error(), "public.customers.aadhaar_no") {
		t.Fatalf("permission: %v", denied)
	}
	gone := readError(&pgconn.PgError{Code: "42703"}, f)
	if !errors.Is(gone, branch.ErrNoFinding) {
		t.Fatalf("a dropped column: %v", gone)
	}
	other := readError(&pgconn.PgError{Code: "22P02", Message: `invalid input syntax: "234567890124"`}, f)
	if strings.Contains(other.Error(), "234567890124") || !strings.Contains(other.Error(), "22P02") {
		t.Fatalf("other: %v", other)
	}
}
