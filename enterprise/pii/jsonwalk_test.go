//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package pii

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func pathsOf(ps []jsonPath) map[string][]string {
	m := map[string][]string{}
	for _, p := range ps {
		m[p.path+" ("+p.name+")"] = p.values
	}
	return m
}

func TestWalkJSON(t *testing.T) {
	docs := []string{
		`{"customer": {"phone": "+91 98765 43210", "aadhaar": 234567890124}, "items": [{"email": "a@example.com"}, {"email": "b@example.org"}], "ok": true}`,
		`{"customer": {"phone": null}, "odd key": "x", "tags": ["vip", "new"]}`,
		`"just a string"`,
		`not json`,
	}
	ps, truncated, bad := walkJSON(docs, "profile")
	if truncated || bad != 1 {
		t.Fatalf("truncated %v, bad %d", truncated, bad)
	}
	want := map[string][]string{
		"$ (profile)":                  {"just a string"},
		"$.customer.aadhaar (aadhaar)": {"234567890124"}, // a number keeps its digits
		"$.customer.phone (phone)":     {"+91 98765 43210"},
		`$."odd key" (odd key)`:        {"x"},
		"$.items[*].email (email)":     {"a@example.com", "b@example.org"},
		"$.tags[*] (tags)":             {"vip", "new"},
	}
	got := pathsOf(ps)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("paths:\n got %v\nwant %v", got, want)
	}
	// Sorted, so a result is the same each time.
	for i := 1; i < len(ps); i++ {
		if ps[i-1].path > ps[i].path {
			t.Fatalf("not sorted: %q before %q", ps[i-1].path, ps[i].path)
		}
	}
}

func TestWalkJSONBounds(t *testing.T) {
	// A document keyed by IDs makes a path per key: bounded.
	doc := "{"
	for i := 0; i < maxPaths+50; i++ {
		if i > 0 {
			doc += ","
		}
		doc += fmt.Sprintf(`"k%d": "v"`, i)
	}
	doc += "}"
	ps, truncated, _ := walkJSON([]string{doc}, "c")
	if !truncated || len(ps) != maxPaths {
		t.Fatalf("got %d paths, truncated %v", len(ps), truncated)
	}
	// Deeper than maxDepth is not walked.
	deep := ""
	for i := 0; i < maxDepth+5; i++ {
		deep += `{"a":`
	}
	deep += `"bottom"`
	for i := 0; i < maxDepth+5; i++ {
		deep += "}"
	}
	if ps, _, _ := walkJSON([]string{deep}, "c"); len(ps) != 0 {
		t.Fatalf("a value deeper than %d levels was walked: %v", maxDepth, ps)
	}
}

func TestJSONPathsClassify(t *testing.T) {
	var docs []string
	for _, a := range aadhaars(6) {
		docs = append(docs, fmt.Sprintf(`{"kyc": {"aadhaar_no": "%s", "status": "ok"}, "contact": {"mobile": "98765%05d"}}`, a, len(docs)))
	}
	ps, _, _ := walkJSON(docs, "profile")
	got := map[string]Category{}
	for _, p := range ps {
		for _, s := range Classify(p.name, "S", p.values) {
			got[p.path] = s.Category
		}
	}
	want := map[string]Category{"$.kyc.aadhaar_no": Aadhaar, "$.contact.mobile": Mobile}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// The marker for a document too large to read travels through Postgres text,
// which cannot hold a NUL (the first version had one, and every table with a
// JSON column failed to read), and must never parse as a document.
func TestTooLargeMarker(t *testing.T) {
	for _, r := range tooLarge {
		if r < 0x20 {
			t.Fatalf("the marker holds a control character %U", r)
		}
	}
	if json.Valid([]byte(tooLarge)) {
		t.Fatal("the marker parses as JSON")
	}
}

func TestReadFailureNamesTheKindNotTheValue(t *testing.T) {
	err := &pgconn.PgError{Code: "22P02", Message: `invalid input syntax for type integer: "234567890124"`}
	if got := readFailure(err); got != "it could not be read (SQLSTATE 22P02)" {
		t.Fatalf("got %q", got)
	}
}
