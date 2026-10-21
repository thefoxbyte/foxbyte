//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package pii

import (
	"net"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// Category names a kind of personal data. The values are stored in
// bb.pii_findings and returned by the API, so they do not change.
type Category string

const (
	Aadhaar  Category = "aadhaar"
	PAN      Category = "pan"
	GSTIN    Category = "gstin"
	Mobile   Category = "mobile"
	Card     Category = "card"
	Email    Category = "email"
	UPI      Category = "upi"
	IFSC     Category = "ifsc"
	Passport Category = "passport"
	VoterID  Category = "voter_id"
	Vehicle  Category = "vehicle_registration"
	Birth    Category = "date_of_birth"
	IP       Category = "ip_address"
	// Child is not recognised by itself: it is the dates of birth that make a
	// person under 18, whose data DPDP treats separately (verifiable parental
	// consent).
	Child Category = "child"
)

// strength is how much a value's shape says by itself.
type strength int

const (
	// weak: a common shape (a date, seven digits after a letter) that only
	// means personal data when the column's name says so too.
	weak strength = iota
	// format: a shape particular enough to mean it alone (an email address),
	// with no check digit to confirm it.
	format
	// checked: a check digit or checksum the value passes. It shows the value
	// is well-formed, not that it was issued, or whose it is.
	checked
)

// recogniser is one category: the column names that suggest it, the values
// that look like it, and how far a value alone can be trusted.
type recogniser struct {
	cat   Category
	str   strength
	value func(string) bool
	// name reports whether a column's name, split into lower-case words,
	// suggests the category.
	name func(words []string) bool
	// rule is what a match means, in a sentence a reviewer reads.
	rule string
	// types are the type categories (pg_type.typcategory) whose values are
	// checked: S strings, N numbers, D dates and times, I network addresses.
	types string
}

var recognisers = []recogniser{
	{Aadhaar, checked, isAadhaar, hasAny("aadhaar", "aadhar", "adhaar", "aadhaarno", "uidai"),
		"12 digits, the first 2 to 9, passing the Verhoeff check", "SN"},
	{PAN, format, isPAN, hasWordWith("pan", "", "no", "num", "number", "card"),
		"5 letters, 4 digits and a letter, the fourth a holder type", "S"},
	{GSTIN, checked, isGSTIN, hasAny("gstin", "gst", "gstno", "gstn"),
		"15 characters: a state code, a PAN, and a check character that matches", "S"},
	{Mobile, format, isMobile, hasAny("mobile", "phone", "msisdn", "whatsapp", "telephone", "cellphone", "mob"),
		"10 digits starting 6 to 9, with or without +91", "SN"},
	{Card, checked, isCard, cardName,
		"13 to 19 digits passing the Luhn check", "SN"},
	{Email, format, isEmail, hasAny("email", "mail", "emailid"),
		"an email address", "S"},
	{UPI, format, isUPI, hasAny("upi", "vpa", "upiid"),
		"a UPI ID: a handle, @, and a provider", "S"},
	{IFSC, format, isIFSC, hasAny("ifsc", "ifsccode"),
		"4 letters, 0, and 6 letters or digits", "S"},
	{Passport, weak, isPassport, hasAny("passport", "passportno"),
		"a letter and 7 digits, the shape of an Indian passport number", "S"},
	{VoterID, weak, isVoterID, hasAny("voter", "voterid", "epic"),
		"3 letters and 7 digits, the shape of a voter ID (EPIC)", "S"},
	{Vehicle, weak, isVehicle, hasAny("vehicle", "vehicleno", "numberplate", "rcno"),
		"a state code, a district number, letters and 4 digits", "S"},
	{Birth, weak, isBirthDate, hasAny("dob", "birth", "birthday", "birthdate", "dateofbirth"),
		"a date between 1900 and today", "SD"},
	{IP, format, isIP, hasAny("ip", "ipaddr", "ipaddress", "ipv4", "ipv6"),
		"an IPv4 or IPv6 address", "SI"},
}

// --- column names ------------------------------------------------------------

// words splits a column name into lower-case words: customer_aadhaar_no,
// customerAadhaarNo and "Customer Aadhaar No" all give customer, aadhaar, no.
func words(name string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	rs := []rune(name)
	for i, r := range rs {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
		case unicode.IsUpper(r) && i > 0 && unicode.IsLower(rs[i-1]):
			flush()
			cur = append(cur, r)
		case unicode.IsDigit(r) && i > 0 && unicode.IsLetter(rs[i-1]),
			unicode.IsLetter(r) && i > 0 && unicode.IsDigit(rs[i-1]):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return out
}

// hasAny matches a name with one of the words, or whose words run together
// into one of them (date_of_birth is dateofbirth).
func hasAny(want ...string) func([]string) bool {
	return func(ws []string) bool {
		joined := strings.Join(ws, "")
		for _, w := range want {
			if joined == w {
				return true
			}
			for _, x := range ws {
				if x == w {
					return true
				}
			}
		}
		return false
	}
}

// hasWordWith matches a word that is ambiguous alone (pan is also part of
// "company") when it is a whole word, followed by one of the given words ("" for
// nothing after it).
func hasWordWith(word string, next ...string) func([]string) bool {
	return func(ws []string) bool {
		for i, x := range ws {
			if x != word {
				continue
			}
			after := ""
			if i+1 < len(ws) {
				after = ws[i+1]
			}
			for _, n := range next {
				if after == n {
					return true
				}
			}
		}
		return strings.Join(ws, "") == word+"card" || strings.Join(ws, "") == word+"no"
	}
}

func cardName(ws []string) bool {
	joined := strings.Join(ws, "")
	for _, j := range []string{"cardnumber", "cardno", "cardnum", "ccnumber", "ccnum", "ccno", "creditcard", "debitcard", "cardpan"} {
		if strings.Contains(joined, j) {
			return true
		}
	}
	return false
}

// --- values ------------------------------------------------------------------

// digits removes the separators people type into numbers (spaces, hyphens), and
// reports whether what is left is all digits.
func digits(s string) (string, bool) {
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

// Verhoeff, as UIDAI uses it for Aadhaar's last digit.
var (
	verhoeffD = [10][10]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
		{2, 3, 4, 0, 1, 7, 8, 9, 5, 6}, {3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
		{4, 0, 1, 2, 3, 9, 5, 6, 7, 8}, {5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
		{6, 5, 9, 8, 7, 1, 0, 4, 3, 2}, {7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
		{8, 7, 6, 5, 9, 3, 2, 1, 0, 4}, {9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
	}
	verhoeffP = [8][10]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
		{5, 8, 0, 3, 7, 9, 6, 1, 4, 2}, {8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
		{9, 4, 5, 3, 1, 2, 6, 8, 7, 0}, {4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
		{2, 7, 9, 3, 8, 0, 6, 4, 1, 5}, {7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
	}
)

func verhoeff(d string) bool {
	c := 0
	for i := 0; i < len(d); i++ {
		c = verhoeffD[c][verhoeffP[i%8][int(d[len(d)-1-i]-'0')]]
	}
	return c == 0
}

func isAadhaar(s string) bool {
	d, ok := digits(s)
	return ok && len(d) == 12 && d[0] >= '2' && verhoeff(d)
}

func luhn(d string) bool {
	sum := 0
	for i := 0; i < len(d); i++ {
		n := int(d[len(d)-1-i] - '0')
		if i%2 == 1 {
			if n *= 2; n > 9 {
				n -= 9
			}
		}
		sum += n
	}
	return sum%10 == 0
}

func isCard(s string) bool {
	d, ok := digits(s)
	return ok && len(d) >= 13 && len(d) <= 19 && d[0] >= '2' && d[0] <= '6' && luhn(d)
}

// A PAN's fourth letter says who holds it: P a person, C a company, H a Hindu
// undivided family, F a firm, A an association of persons, T a trust, B a body
// of individuals, L a local authority, J an artificial juridical person, G a
// government body.
var panRE = regexp.MustCompile(`^[A-Z]{3}[ABCFGHJLPT][A-Z][0-9]{4}[A-Z]$`)

func isPAN(s string) bool { return panRE.MatchString(strings.ToUpper(strings.TrimSpace(s))) }

var gstinRE = regexp.MustCompile(`^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$`)

const base36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

func isGSTIN(s string) bool {
	g := strings.ToUpper(strings.TrimSpace(s))
	if !gstinRE.MatchString(g) || !isPAN(g[2:12]) {
		return false
	}
	// A state or union territory code, 01 to 38, or 97 and 99 for the
	// codes GSTN gives other kinds of registration.
	state := int(g[0]-'0')*10 + int(g[1]-'0')
	if !(state >= 1 && state <= 38 || state == 97 || state == 99) {
		return false
	}
	sum := 0
	for i := 0; i < 14; i++ {
		v := strings.IndexByte(base36, g[i]) * (i%2 + 1)
		sum += v/36 + v%36
	}
	return base36[(36-sum%36)%36] == g[14]
}

func isMobile(s string) bool {
	t := strings.TrimSpace(s)
	t = strings.NewReplacer("(", "", ")", "").Replace(t)
	t = strings.TrimPrefix(t, "+")
	d, ok := digits(t)
	if !ok {
		return false
	}
	switch {
	case len(d) == 12 && strings.HasPrefix(d, "91"):
		d = d[2:]
	case len(d) == 11 && d[0] == '0':
		d = d[1:]
	}
	return len(d) == 10 && d[0] >= '6'
}

var (
	emailRE = regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}$`)
	// A UPI ID's provider has no dot, which is what tells one from an email.
	upiRE      = regexp.MustCompile(`^[A-Za-z0-9.\-_]{2,256}@[A-Za-z][A-Za-z0-9]{1,63}$`)
	ifscRE     = regexp.MustCompile(`^[A-Z]{4}0[A-Z0-9]{6}$`)
	passportRE = regexp.MustCompile(`^[A-PR-WY][1-9][0-9] ?[0-9]{4}[1-9]$`)
	voterRE    = regexp.MustCompile(`^[A-Z]{3}[0-9]{7}$`)
	vehicleRE  = regexp.MustCompile(`^([A-Z]{2})[0-9]{1,2}[A-Z]{0,3}[0-9]{4}$`)
)

func isEmail(s string) bool { return len(s) <= 254 && emailRE.MatchString(strings.TrimSpace(s)) }
func isUPI(s string) bool   { return upiRE.MatchString(strings.TrimSpace(s)) }
func isIFSC(s string) bool  { return ifscRE.MatchString(strings.ToUpper(strings.TrimSpace(s))) }
func isPassport(s string) bool {
	return passportRE.MatchString(strings.ToUpper(strings.TrimSpace(s)))
}
func isVoterID(s string) bool { return voterRE.MatchString(strings.ToUpper(strings.TrimSpace(s))) }

// The codes a registration starts with: the states and union territories.
var vehicleStates = map[string]bool{}

func init() {
	for _, c := range strings.Fields("AN AP AR AS BR CG CH DD DL DN GA GJ HP HR JH JK KA KL LA LD MH ML MN MP MZ NL OD OR PB PY RJ SK TN TR TS UK UP WB") {
		vehicleStates[c] = true
	}
}

func isVehicle(s string) bool {
	// Written with spaces or hyphens anywhere (MH 12 AB 1234, DL-3C-AB-1234).
	t := strings.NewReplacer(" ", "", "-", "").Replace(strings.ToUpper(strings.TrimSpace(s)))
	m := vehicleRE.FindStringSubmatch(t)
	return m != nil && vehicleStates[m[1]]
}

// birthDate reads the date at the start of a value: a date column's text form,
// or a timestamp's.
func birthDate(s string) (time.Time, bool) {
	t := strings.TrimSpace(s)
	if len(t) < 10 {
		return time.Time{}, false
	}
	d, err := time.Parse("2006-01-02", t[:10])
	return d, err == nil
}

// today is replaced by the tests, which need an age to stay the same.
var today = func() time.Time { return time.Now().UTC() }

func isBirthDate(s string) bool {
	d, ok := birthDate(s)
	return ok && d.Year() >= 1900 && !d.After(today())
}

// minor reports a date of birth less than 18 years ago.
func minor(s string) bool {
	d, ok := birthDate(s)
	return ok && isBirthDate(s) && d.AddDate(18, 0, 0).After(today())
}

func isIP(s string) bool {
	t := strings.TrimSpace(s)
	if i := strings.IndexByte(t, '/'); i > 0 { // inet's text form carries a mask
		t = t[:i]
	}
	return net.ParseIP(t) != nil
}
