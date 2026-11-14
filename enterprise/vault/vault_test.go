//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package vault

import (
	"crypto/rand"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/enterprise/idcheck"
)

func rnd(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// A synthetic number passes the scanner's own check, and so the kind's.
func TestSyntheticAadhaarPassesTheCheck(t *testing.T) {
	k, _ := KindOf("aadhaar")
	for i := 0; i < 2000; i++ {
		v, err := SyntheticAadhaar(rnd)
		if err != nil {
			t.Fatal(err)
		}
		if !idcheck.IsAadhaar(v) {
			t.Fatalf("%s fails the scanner's check", v)
		}
		if _, err := k.Accept(v); err != nil {
			t.Fatalf("%s refused: %v", v, err)
		}
	}
}

func TestAadhaarKindAcceptsAndRefuses(t *testing.T) {
	k, _ := KindOf("aadhaar")
	v, _ := SyntheticAadhaar(rnd)
	spaced := v[:4] + " " + v[4:8] + "-" + v[8:]
	n, err := k.Accept(spaced)
	if err != nil || n != v {
		t.Fatalf("spaced %q: got %q, %v; want %q", spaced, n, err, v)
	}
	bad := v[:11] + string('0'+(v[11]-'0'+1)%10)
	for _, s := range []string{bad, "123412341234", "0" + v[1:], v + "1", "abcd", ""} {
		if _, err := k.Accept(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

// The legacy format can never pass the Aadhaar check: a person or the
// scanner can never take a reference key for a number.
func TestAadhaarLegacyNeverPassesTheCheck(t *testing.T) {
	k, _ := KindOf("aadhaar")
	seen := map[string]bool{}
	for i := 0; i < 20000; i++ {
		r, err := k.NewRef(FormatLegacy, rnd)
		if err != nil {
			t.Fatal(err)
		}
		if len(r) != 12 || r[0] != '1' || !k.IsRef(r) {
			t.Fatalf("%q is not 12 digits starting with 1", r)
		}
		if idcheck.IsAadhaar(r) {
			t.Fatalf("%q passes the Aadhaar check", r)
		}
		if _, err := k.Accept(r); err == nil {
			t.Fatalf("the kind accepts its own reference key %q", r)
		}
		seen[r] = true
	}
	if len(seen) < 19990 {
		t.Fatalf("only %d distinct of 20000", len(seen))
	}
}

func TestOpaqueRefs(t *testing.T) {
	for _, k := range Kinds() {
		seen := map[string]bool{}
		for i := 0; i < 5000; i++ {
			r, err := k.NewRef(FormatOpaque, rnd)
			if err != nil {
				t.Fatal(err)
			}
			if len(r) != 28 || !strings.HasPrefix(r, k.Prefix) || !k.IsRef(r) {
				t.Fatalf("%s: %q", k.Name, r)
			}
			if strings.ContainsAny(r[2:], "ILOU") {
				t.Fatalf("%q is not Crockford base32", r)
			}
			seen[r] = true
		}
		if len(seen) != 5000 {
			t.Fatalf("%s: a repeat in 5000", k.Name)
		}
	}
	a, _ := KindOf("aadhaar")
	x, _ := KindOf("text")
	r, _ := x.NewRef(FormatOpaque, rnd)
	if a.IsRef(r) {
		t.Fatalf("a text reference key %q passes as an Aadhaar one", r)
	}
}

// Every bit of the random bytes reaches the key: two draws differing in the
// last used bit differ in the key.
func TestOpaqueRefUsesItsBits(t *testing.T) {
	zero := func(n int) ([]byte, error) { return make([]byte, n), nil }
	one := func(n int) ([]byte, error) {
		b := make([]byte, n)
		b[16] = 0x40 // bit 130 of 136, the last one used
		return b, nil
	}
	a, _ := opaqueRef("AR", zero)
	b, _ := opaqueRef("AR", one)
	if a == b {
		t.Fatalf("the 130th bit is lost: %s", a)
	}
	if a != "AR"+strings.Repeat("0", 26) {
		t.Fatalf("all zero bytes gave %s", a)
	}
}

func TestTextKindHasNoLegacyFormat(t *testing.T) {
	k, _ := KindOf("text")
	if _, err := k.NewRef(FormatLegacy, rnd); err == nil {
		t.Fatal("the text kind made a legacy reference key")
	}
	if _, err := k.Accept("any value at all"); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"", "a\x00b", string([]byte{0xff, 0xfe}), strings.Repeat("x", 4097)} {
		if _, err := k.Accept(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	if k.HSMRequired || k.Rules != "" {
		t.Fatal("the text kind claims rules it does not have")
	}
}

func TestAADBindsKindAndRef(t *testing.T) {
	if string(AAD("aadhaar", "ARX")) == string(AAD("text", "ARX")) || string(AAD("aadhaar", "AR1")) == string(AAD("aadhaar", "AR2")) {
		t.Fatal("associated data does not tell kinds or reference keys apart")
	}
	if string(AAD("a", "bc")) == string(AAD("ab", "c")) {
		t.Fatal("associated data runs kind and reference key together")
	}
}

func chain(n int) []Entry {
	var out []Entry
	prev := Genesis
	for i := 1; i <= n; i++ {
		e := Entry{Seq: int64(i), AtMicro: int64(1000 + i), Actor: "a", Action: "find", Kind: "aadhaar", Refs: []string{"AR1"}, N: 1, Result: "done 1"}
		e.Prev = prev
		e.Hash = e.Sum(prev)
		prev = e.Hash
		out = append(out, e)
	}
	return out
}

func TestLogChain(t *testing.T) {
	if b := Verify(chain(5)); b != 0 {
		t.Fatalf("a good chain broke at %d", b)
	}
	c := chain(5)
	c[2].Purpose = "changed"
	if b := Verify(c); b != 3 {
		t.Fatalf("a changed entry: broke at %d, want 3", b)
	}
	c = chain(5)
	c = append(c[:1], c[2:]...)
	if b := Verify(c); b != 3 {
		t.Fatalf("a deleted entry: broke at %d, want 3", b)
	}
	// Fields are length-prefixed: moving a character between two fields
	// changes the hash.
	a := Entry{Seq: 1, Actor: "ab", Action: "c"}
	b := Entry{Seq: 1, Actor: "a", Action: "bc"}
	if string(a.Sum(Genesis)) == string(b.Sum(Genesis)) {
		t.Fatal("two different entries hash the same")
	}
}
