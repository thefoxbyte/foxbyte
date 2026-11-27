//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package dpdp

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// A value is read as fox subject find reads it, and kept only as its last
// four characters.
func TestReadValues(t *testing.T) {
	ms, refs, err := readValues([]branch.ErasureValue{
		{Value: " Asha@Example.com "},
		{Category: "mobile", Value: "+91 98765 43210"},
		{Value: "asha@example.com"}, // the same person's same value again
	})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(ms["email"], "asha@example.com") || !contains(ms["mobile"], "9876543210") {
		t.Fatalf("matches = %v", ms)
	}
	if len(refs) != 2 {
		t.Fatalf("refs = %+v, want the two values once each", refs)
	}
	for _, r := range refs {
		if strings.Contains(r.Last4, "asha") || len([]rune(r.Last4)) != 4 {
			t.Errorf("a ref keeps %q", r.Last4)
		}
	}
	for name, vs := range map[string][]branch.ErasureValue{
		"no shape":         {{Value: "hello there"}},
		"unknown category": {{Category: "shoe-size", Value: "9"}},
		"nothing":          {{Value: "   "}},
	} {
		if _, _, err := readValues(vs); !errors.Is(err, branch.ErrInvalidRequest) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// What is kept never says more than it should of a short value.
	if got := last4("ab12cd"); got != "cd" {
		t.Errorf("last4 of a short value = %q", got)
	}
	if got := last4("9876543210"); got != "3210" {
		t.Errorf("last4 = %q", got)
	}
}

// Every value at a path the scanner names is cleared, and nothing else.
func TestClearJSONPaths(t *testing.T) {
	doc := `{"name":"Asha","contact":{"email":"asha@example.com","phone":9876543210,"ok":true},` +
		`"items":[{"email":"a@x.in","sku":"Q1"},{"email":"b@x.in","sku":"Q2"}],"odd key":{"pan":"ABCDE1234F"},"tags":["x","y"]}`
	got, err := clearJSONPaths(doc, []string{"$.contact.email", "$.contact.phone", "$.items[*].email", `$."odd key".pan`, "$.missing.path"})
	if err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"asha@example.com", "9876543210", "a@x.in", "b@x.in", "ABCDE1234F"} {
		if strings.Contains(got, gone) {
			t.Errorf("%s is still in %s", gone, got)
		}
	}
	for _, kept := range []string{`"name":"Asha"`, `"sku":"Q1"`, `"sku":"Q2"`, `"ok":true`, `"tags":["x","y"]`} {
		if !strings.Contains(got, kept) {
			t.Errorf("%s was lost: %s", kept, got)
		}
	}
	// An array of scalars at the top, and a document that is one value.
	if got, _ := clearJSONPaths(`["a@x.in", 5, {"k": 1}]`, []string{"$[*]"}); got != `[null,null,{"k":1}]` {
		t.Errorf("top array: %s", got)
	}
	if got, _ := clearJSONPaths(`"asha@example.com"`, []string{"$"}); got != "null" {
		t.Errorf("a scalar document: %s", got)
	}
	// Large numbers stay as they are written.
	if got, _ := clearJSONPaths(`{"n": 234567890124, "e": "x"}`, []string{"$.e"}); got != `{"e":null,"n":234567890124}` {
		t.Errorf("number: %s", got)
	}
	if _, err := clearJSONPaths(`{`, []string{"$.a"}); err == nil {
		t.Error("a broken document was cleared")
	}
	for _, bad := range []string{"a.b", "$.", `$."open`, "$x"} {
		if _, err := parsePath(bad); err == nil {
			t.Errorf("the path %q was read", bad)
		}
	}
}

// A refused delete stops the rows deleted; a column that cannot be cleared
// stops the rows cleared; neither is shown against the other.
func TestProblemsFor(t *testing.T) {
	ps := []string{
		"3 row(s) of public.orders refer to the rows this deletes through orders_fk, which refuses a delete (RESTRICT or NO ACTION): …",
		"phone is NOT NULL with no default, so it cannot be cleared: …",
		"something else entirely",
	}
	if got := problemsFor(ps, branch.ErasureActDelete); len(got) != 2 || strings.Contains(strings.Join(got, ""), "cannot be cleared") {
		t.Errorf("delete: %v", got)
	}
	if got := problemsFor(ps, branch.ErasureActCascade); len(got) != 2 {
		t.Errorf("cascade: %v", got)
	}
	if got := problemsFor(ps, branch.ErasureActClear); len(got) != 2 || strings.Contains(strings.Join(got, ""), "rows this deletes") {
		t.Errorf("clear: %v", got)
	}
	if got := problemsFor(ps, branch.ErasureActKeep); len(got) != 0 {
		t.Errorf("keep: %v", got)
	}
}

func TestRewriteMax(t *testing.T) {
	for v, want := range map[string]int64{"": 1 << 30, "500M": 500 << 20, "2G": 2 << 30, "4096": 4096, "lots": 1 << 30, "-1": 1 << 30} {
		t.Setenv(rewriteMaxEnv, v)
		if got := rewriteMax(); got != want {
			t.Errorf("%q: %d, want %d", v, got, want)
		}
	}
}

// What a law requires kept records its citation and, once the event's date
// is given, when it ends.
func TestException(t *testing.T) {
	e := &branch.DPDPEntry{Keep: branch.DPDPKeep{Count: 5, Unit: "years", From: "account_closed", Reason: "law", Citation: "PML Rules, Rule 10"}}
	x := exception(e, "aadhaar_no", map[string]string{"account_closed": "2025-03-31"})
	if x.Ends == nil || x.Ends.Format("2006-01-02") != "2030-03-31" || !strings.Contains(x.Text, "PML Rules, Rule 10") || !strings.Contains(x.Text, "ends 31 March 2030") {
		t.Errorf("with the date: %+v", x)
	}
	x = exception(e, "", nil)
	if x.Ends != nil || !strings.Contains(x.Text, "the table is kept") || !strings.Contains(x.Text, "not known until") {
		t.Errorf("without it: %+v", x)
	}
}

// Postgres's DETAIL can quote a row's values; an error is told by where.
func TestReadErrDropsTheDetail(t *testing.T) {
	err := readErr(errors.New(`ERROR: duplicate key value violates unique constraint "x" DETAIL: Key (email)=(asha@example.com) already exists.`))
	if strings.Contains(err.Error(), "asha") {
		t.Errorf("the value is in the error: %v", err)
	}
}

// A statement's text is searched for each value as it was given and in its
// normalised forms, once each, never for a string too short to mean anything.
func TestTextForms(t *testing.T) {
	values := []branch.ErasureValue{{Value: " Asha@Example.com "}, {Category: "mobile", Value: "+91 98765 43210"}, {Value: "ab1"}}
	ms := matchSet{"email": {"asha@example.com"}, "mobile": {"9876543210"}}
	got := strings.Join(textForms(values, ms), "|")
	if got != "Asha@Example.com|+91 98765 43210|asha@example.com|9876543210" && got != "Asha@Example.com|+91 98765 43210|9876543210" {
		t.Errorf("forms = %q", got)
	}
	for _, f := range textForms(values, ms) {
		if f == "ab1" {
			t.Error("a three-character string is searched for")
		}
	}
}

// A row's key as the Aadhaar exposure report writes it, from the erasure's.
func TestAadhaarRowKey(t *testing.T) {
	for _, c := range []struct {
		cols []string
		key  string
		want string
		ok   bool
	}{
		{[]string{"id"}, `["42"]`, "id=42", true},
		{[]string{"a", "b"}, `["1", "x"]`, "(a, b)=(1, x)", true},
		{[]string{"a", "b"}, `["1", null]`, "(a, b)=(1, NULL)", true},
		{nil, ``, "", false},
		{[]string{"id"}, `[null]`, "", false},
		{[]string{"id"}, `["1", "2"]`, "", false},
	} {
		got, ok := aadhaarRowKey(c.cols, c.key)
		if got != c.want || ok != c.ok {
			t.Errorf("%v %s: %q %v", c.cols, c.key, got, ok)
		}
	}
}

// A row is found by the key main's erasure kept however it was printed: the
// store keeps keys compacted, PostgreSQL prints a composite key with spaces,
// so the two are compared as JSON, never as text.
func TestKeyMatchComparesAsJSON(t *testing.T) {
	r := &relInfo{keyCols: []string{"tenant", "id"}}
	if got := keyMatch(r, "x"); got != `jsonb_build_array(x."tenant"::text, x."id"::text) = ANY($1::jsonb[])` {
		t.Fatalf("keyMatch: %s", got)
	}
	// The keys as main's result keeps them, once stored: compacted.
	raw, _ := json.Marshal(struct {
		Keys []json.RawMessage `json:"keys"`
	}{[]json.RawMessage{json.RawMessage(`["7", "x"]`)}})
	if !strings.Contains(string(raw), `["7","x"]`) {
		t.Fatalf("the store's form of a key changed, so this test no longer shows why: %s", raw)
	}
}

// A clear applied again sets what the request's plan said, read back from
// the columns as it kept them (F4 step 4).
func TestReapplySets(t *testing.T) {
	rel := &relInfo{cols: map[string]colInfo{
		"email":  {typ: "text"},
		"status": {typ: "text", notNull: true, hasDefault: true},
		"code":   {typ: "character varying(8)", notNull: true},
		"prefs":  {typ: "jsonb"},
	}}
	d, err := reapplySets(rel, []branch.ErasureColumn{
		{Column: "email", To: "NULL"}, {Column: "status", To: "DEFAULT"}, {Column: "code", To: strconv.Quote("XXXX")},
		{Column: "prefs", Path: "$.contact.mobile", To: "null at the path"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, s := range d.sets {
		a := ""
		if s.arg != nil {
			a = "=" + *s.arg
		}
		got = append(got, s.col+":"+s.expr+a)
	}
	if strings.Join(got, ",") != "email:NULL,status:DEFAULT,code:$character varying(8)=XXXX" || len(d.paths["prefs"]) != 1 || d.paths["prefs"][0] != "$.contact.mobile" {
		t.Fatalf("sets %v, paths %v", got, d.paths)
	}
	if _, err := reapplySets(rel, []branch.ErasureColumn{{Column: "phone", To: "NULL"}}); err == nil {
		t.Fatal("a column the copy does not have was not said")
	}
	if _, err := reapplySets(rel, []branch.ErasureColumn{{Column: "email", To: "something else"}}); err == nil {
		t.Fatal("a clear it cannot read was not refused")
	}
}
