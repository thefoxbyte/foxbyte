//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package pii

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/enterprise/vault"
)

// Synthetic numbers (aadA, aadB) and made-up keys: an opaque one and a legacy
// one, each shaped as the vault makes them. The opaque one is plainly a
// placeholder, so no secret scanner reads it as a credential.
var keyOpaque = "AR" + strings.Repeat("7", 26)

const keyLegacy = "100000000042"

// keys answers every number with its key in refs, as a text column does.
func keys(refs map[string]string) keyFor {
	return func(d string, _ bool) (string, bool, string) {
		k, ok := refs[d]
		if !ok {
			return "", false, leftNoKey
		}
		return k, false, ""
	}
}

func TestAadhaarSpansAgreeWithTheReport(t *testing.T) {
	for _, s := range []string{
		"", "no number", aadA, spaced(aadA), "a " + aadA + " and " + spaced(aadB) + " and " + aadA,
		"card 4" + aadA + "123", aadA[:4] + "-" + aadA[4:8] + "-" + aadA[8:], "+91" + aadA, aadA + "5",
	} {
		var got []string
		seen := map[string]bool{}
		for _, sp := range aadhaarSpans(s) {
			if !seen[sp.digits] {
				got = append(got, sp.digits)
				seen[sp.digits] = true
			}
			if d := sp.digits; len(d) != 12 {
				t.Errorf("%q: span %q", s, d)
			}
		}
		if want := findAadhaar(s); !reflect.DeepEqual(got, want) {
			t.Errorf("%q: spans %v, the report finds %v", s, got, want)
		}
	}
}

func TestRewriteText(t *testing.T) {
	refs := map[string]string{aadA: keyOpaque, aadB: keyLegacy}
	cases := []struct {
		in, want string
		n        int
		left     map[string]int
	}{
		{aadA, keyOpaque, 1, nil},
		{spaced(aadA), keyOpaque, 1, nil},
		{"KYC done, aadhaar " + spaced(aadA) + ", ok", "KYC done, aadhaar " + keyOpaque + ", ok", 1, nil},
		{aadA + "/" + aadB + "/" + aadA, keyOpaque + "/" + keyLegacy + "/" + keyOpaque, 3, nil},
		{"no number here", "no number here", 0, nil},
		{"card 4" + aadA + "123", "card 4" + aadA + "123", 0, nil},
	}
	for _, c := range cases {
		got, n, left := rewriteText(c.in, keys(refs))
		if got != c.want || n != c.n || len(left) != len(c.left) {
			t.Errorf("rewriteText(%q) = %q, %d, %v; want %q, %d", c.in, got, n, left, c.want, c.n)
		}
	}
	got, n, left := rewriteText(aadA+", "+aadB, keys(map[string]string{aadA: keyOpaque}))
	if got != keyOpaque+", "+aadB || n != 1 || left[leftNoKey] != 1 {
		t.Errorf("a number with no key is left, and counted: %q %d %v", got, n, left)
	}
}

func TestRewriteJSON(t *testing.T) {
	refs := map[string]string{aadA: keyOpaque, aadB: keyLegacy}
	isLegacy := func(k string) bool { return k == keyLegacy }
	// As a JSON column's: a legacy key replaces a JSON number as a number;
	// any other key replaces it as a string.
	key := func(d string, jsonNumber bool) (string, bool, string) {
		k, ok := refs[d]
		if !ok {
			return "", false, leftNoKey
		}
		return k, jsonNumber && !isLegacy(k), ""
	}
	cases := []struct {
		name, in, want string
		n              int
	}{
		{"a string value", `{"aadhaar": "` + spaced(aadA) + `"}`, `{"aadhaar": "` + keyOpaque + `"}`, 1},
		{"inside text", `{"note":"verified ` + aadA + ` today"}`, `{"note":"verified ` + keyOpaque + ` today"}`, 1},
		{"a number, opaque key", `{"id": ` + aadA + `}`, `{"id": "` + keyOpaque + `"}`, 1},
		{"a number, legacy key", `{"id":` + aadB + `,"n":2}`, `{"id":` + keyLegacy + `,"n":2}`, 1},
		{"a key of an object", `{"` + aadA + `": true}`, `{"` + keyOpaque + `": true}`, 1},
		{"arrays, layout kept", "[\n  " + aadB + ",\n  \"" + aadA + "\"\n]", "[\n  " + keyLegacy + ",\n  \"" + keyOpaque + "\"\n]", 2},
		{"escapes elsewhere in the string", `{"a":"line\n` + aadA + ` \"q\""}`, `{"a":"line\n` + keyOpaque + ` \"q\""}`, 1},
		{"nothing to replace", `{"a":[1,2.5,-3e4,"x"],"b":null,"c":true}`, `{"a":[1,2.5,-3e4,"x"],"b":null,"c":true}`, 0},
	}
	for _, c := range cases {
		got, n, left, ok := rewriteJSON(c.in, key)
		if !ok || got != c.want || n != c.n || len(left) != 0 {
			t.Errorf("%s: rewriteJSON(%s) = %s, %d, %v, %v; want %s, %d", c.name, c.in, got, n, left, ok, c.want, c.n)
		}
		if !json.Valid([]byte(got)) {
			t.Errorf("%s: %s is not JSON", c.name, got)
		}
	}
	got, n, left, ok := rewriteJSON(`{"x": `+aadA+`.5}`, key)
	if !ok || got != `{"x": `+aadA+`.5}` || n != 0 || left[leftInNumber] != 1 {
		t.Errorf("a number inside a longer JSON number is left, and said so: %s %d %v %v", got, n, left, ok)
	}
	if _, _, _, ok := rewriteJSON(`{"x": `+aadA, key); ok {
		t.Error("a value that is not JSON is not rewritten")
	}
	got, _, _, _ = rewriteJSON(`{"a":"<`+aadA+`> & é"}`, key)
	if got != `{"a":"<`+keyOpaque+`> & é"}` || !json.Valid([]byte(got)) {
		t.Errorf("an escaped string rewritten is written back without HTML escapes: %s", got)
	}
}

func TestKeyInAColumn(t *testing.T) {
	kind, _ := vault.KindOf("aadhaar")
	refs := map[string]string{aadA: keyOpaque, aadB: keyLegacy}
	text := &migCol{}
	narrow := &migCol{legacy: true}
	doc := &migCol{json: true}
	cases := []struct {
		name       string
		c          *migCol
		d          string
		jsonNumber bool
		key        string
		quote      bool
		why        string
	}{
		{"text takes an opaque key", text, aadA, false, keyOpaque, false, ""},
		{"text takes a legacy key", text, aadB, false, keyLegacy, false, ""},
		{"a bigint takes a legacy key", narrow, aadB, false, keyLegacy, false, ""},
		{"a bigint cannot take an opaque one", narrow, aadA, false, "", false, leftOpaque},
		{"a JSON number: a legacy key as a number", doc, aadB, true, keyLegacy, false, ""},
		{"a JSON number: an opaque key as a string", doc, aadA, true, keyOpaque, true, ""},
		{"JSON text: as it is", doc, aadA, false, keyOpaque, false, ""},
		{"a number with no key", text, verhoeffDigit("55555555555"), false, "", false, leftNoKey},
	}
	for _, c := range cases {
		k, q, why := c.c.keyIn(kind, refs)(c.d, c.jsonNumber)
		if k != c.key || q != c.quote || why != c.why {
			t.Errorf("%s: %q %v %q", c.name, k, q, why)
		}
	}
}

func TestNeedsLegacy(t *testing.T) {
	text, narrow, doc := &migCol{}, &migCol{legacy: true}, &migCol{json: true}
	for _, c := range []struct {
		c          *migCol
		format     string
		jsonNumber bool
		want       bool
	}{
		{text, "", false, false}, {narrow, "", false, true}, {doc, "", true, true}, {doc, "", false, false},
		{text, "legacy", false, true}, {narrow, "opaque", false, false},
	} {
		if got := c.c.needsLegacy(c.format, c.jsonNumber); got != c.want {
			t.Errorf("needsLegacy(%+v, %q, %v) = %v", *c.c, c.format, c.jsonNumber, got)
		}
	}
}

func TestOpaqueKeyLen(t *testing.T) {
	kind, _ := vault.KindOf("aadhaar")
	if len(keyOpaque) != opaqueKeyLen || !kind.IsRef(keyOpaque) || kind.IsLegacy(keyOpaque) {
		t.Errorf("an opaque key is %d characters, as the vault makes them", opaqueKeyLen)
	}
	if !kind.IsLegacy(keyLegacy) {
		t.Error("the test's legacy key is shaped as the vault makes them")
	}
}
