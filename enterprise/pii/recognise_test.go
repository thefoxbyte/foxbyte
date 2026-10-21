//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package pii

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Every identifier here is synthetic: made to pass its check, never a real
// person's. The helpers append the check digit the way the issuer does.

func verhoeffDigit(d string) string {
	inv := [10]int{0, 4, 3, 2, 1, 5, 6, 7, 8, 9}
	c := 0
	for i := 0; i < len(d); i++ {
		c = verhoeffD[c][verhoeffP[(i+1)%8][int(d[len(d)-1-i]-'0')]]
	}
	return d + fmt.Sprint(inv[c])
}

func luhnDigit(d string) string {
	for x := 0; x <= 9; x++ {
		if luhn(d + fmt.Sprint(x)) {
			return d + fmt.Sprint(x)
		}
	}
	panic("no Luhn digit")
}

func gstinWith(first14 string) string {
	for _, c := range base36 {
		if isGSTIN(first14 + string(c)) {
			return first14 + string(c)
		}
	}
	panic("no GSTIN check character")
}

func TestHelpersMakeValidNumbers(t *testing.T) {
	if !verhoeff(verhoeffDigit("23456789012")) {
		t.Fatal("verhoeffDigit does not make a Verhoeff-valid number")
	}
	if !luhn(luhnDigit("411111111111111")) {
		t.Fatal("luhnDigit does not make a Luhn-valid number")
	}
	// A well-known published test vector: 2363 is the Verhoeff example.
	if !verhoeff("2363") || verhoeff("2364") {
		t.Fatal("Verhoeff disagrees with its published example")
	}
}

func TestRecognisers(t *testing.T) {
	today = func() time.Time { return time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC) }
	defer func() { today = func() time.Time { return time.Now().UTC() } }()

	aadhaar := verhoeffDigit("23456789012")
	bad := aadhaar[:11] + fmt.Sprint((int(aadhaar[11]-'0')+1)%10)
	gstin := gstinWith("27AAPFU0939F1Z")
	card := luhnDigit("411111111111111")

	for _, c := range []struct {
		name string
		fn   func(string) bool
		yes  []string
		no   []string
	}{
		{"aadhaar", isAadhaar,
			[]string{aadhaar, aadhaar[:4] + " " + aadhaar[4:8] + " " + aadhaar[8:], aadhaar[:4] + "-" + aadhaar[4:8] + "-" + aadhaar[8:]},
			[]string{bad, "1" + aadhaar[1:], aadhaar[:11], aadhaar + "0", "abcd" + aadhaar[4:], ""}},
		{"pan", isPAN,
			[]string{"ABCPE1234F", "abcpe1234f", "AAACB1234C"},
			[]string{"ABCXE1234F", "ABCPE12345", "AB1PE1234F", "ABCPE1234"}},
		{"gstin", isGSTIN,
			[]string{gstin, strings.ToLower(gstin)},
			[]string{gstin[:14] + nextBase36(gstin[14]), "00" + gstin[2:], "27AAXFU0939F1Z" + gstin[14:], gstin[:13] + "Y" + gstin[14:]}},
		{"mobile", isMobile,
			[]string{"9876543210", "+91 98765 43210", "+919876543210", "09876543210", "(+91) 98765-43210"},
			[]string{"5876543210", "987654321", "98765432101", "+1 9876543210", "abc9876543"}},
		{"card", isCard,
			[]string{card, card[:4] + " " + card[4:8] + " " + card[8:12] + " " + card[12:]},
			[]string{card[:15] + fmt.Sprint((int(card[15]-'0')+1)%10), "0" + card[1:], luhnDigit("41111111111"), "1" + card[1:]}},
		{"email", isEmail,
			[]string{"a.person@example.com", "x+y@mail.example.co.in"},
			[]string{"a.person@example", "no at sign", "a@b.c", "person@okhdfc"}},
		{"upi", isUPI,
			[]string{"person@okhdfc", "98765.43210@ybl"},
			[]string{"a.person@example.com", "@ybl", "x@1bank"}},
		{"ifsc", isIFSC,
			[]string{"HDFC0001234", "sbin0A1B2C3"},
			[]string{"HDFC1001234", "HDF00001234", "HDFC000123"}},
		{"passport", isPassport,
			[]string{"J8369854", "j8369854", "A12 34567"},
			[]string{"Q8369854", "J0369854", "J836985", "J83698540"}},
		{"voter", isVoterID,
			[]string{"ABC1234567"},
			[]string{"AB1234567", "ABC123456", "1BC1234567"}},
		{"vehicle", isVehicle,
			[]string{"MH12AB1234", "MH 12 AB 1234", "DL-3C-AB-1234", "KA011234"},
			[]string{"XX12AB1234", "MH12AB123", "MH12ABCD1234"}},
		{"birth", isBirthDate,
			[]string{"1990-05-17", "2015-01-01 00:00:00+00", "1900-01-01"},
			[]string{"1899-12-31", "2027-01-01", "17/05/1990", "not a date"}},
		{"ip", isIP,
			[]string{"10.0.0.1", "192.168.1.20/32", "2001:db8::1"},
			[]string{"10.0.0", "300.1.1.1", "host.example.com"}},
	} {
		for _, v := range c.yes {
			if !c.fn(v) {
				t.Errorf("%s: %q should be recognised", c.name, v)
			}
		}
		for _, v := range c.no {
			if c.fn(v) {
				t.Errorf("%s: %q should not be recognised", c.name, v)
			}
		}
	}
	if !minor("2015-01-01") || minor("2008-10-20") || !minor("2008-10-22") {
		t.Error("minor should be a date of birth less than 18 years before today")
	}
}

func nextBase36(c byte) string {
	i := strings.IndexByte(base36, c)
	return string(base36[(i+1)%36])
}

func TestWords(t *testing.T) {
	for in, want := range map[string][]string{
		"customer_aadhaar_no": {"customer", "aadhaar", "no"},
		"customerAadhaarNo":   {"customer", "aadhaar", "no"},
		"Customer Aadhaar No": {"customer", "aadhaar", "no"},
		"ipv4":                {"ipv", "4"},
		"PAN":                 {"pan"},
		"email2":              {"email", "2"},
	} {
		if got := words(in); !reflect.DeepEqual(got, want) {
			t.Errorf("words(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNames(t *testing.T) {
	named := func(col string) []Category {
		var out []Category
		for _, r := range recognisers {
			if r.name(words(col)) {
				out = append(out, r.cat)
			}
		}
		return out
	}
	for col, want := range map[string][]Category{
		"aadhaar_no":    {Aadhaar},
		"pan":           {PAN},
		"pan_number":    {PAN},
		"company":       nil, // contains "pan", but not as a word
		"panel_id":      nil,
		"gstin":         {GSTIN},
		"mobile_no":     {Mobile},
		"phone":         {Mobile},
		"card_number":   {Card},
		"cardNo":        {Card},
		"discard_count": nil,
		"email":         {Email},
		"e_mail":        {Email},
		"upi_id":        {UPI},
		"ifsc_code":     {IFSC},
		"passport_no":   {Passport},
		"voter_id":      {VoterID},
		"vehicle_no":    {Vehicle},
		"dob":           {Birth},
		"date_of_birth": {Birth},
		"ip_address":    {IP},
		"ipv4":          nil, // split into ipv and 4; "ipv4" joined is a name
		"shipping":      nil,
	} {
		got := named(col)
		if col == "ipv4" {
			want = []Category{IP}
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("name %q suggests %v, want %v", col, got, want)
		}
	}
}
