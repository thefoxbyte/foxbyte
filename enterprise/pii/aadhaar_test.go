//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package pii

import (
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
)

// Synthetic numbers only: eleven digits chosen here, and the twelfth computed
// to pass the check.
var (
	aadA = verhoeffDigit("23456789012")
	aadB = verhoeffDigit("98765432109")
)

func spaced(d string) string { return d[:4] + " " + d[4:8] + " " + d[8:] }

func TestFindAadhaar(t *testing.T) {
	bad := aadA[:11] + string(rune('0'+(int(aadA[11]-'0')+1)%10))
	cases := []struct {
		in   string
		want []string
	}{
		{aadA, []string{aadA}},
		{"Aadhaar " + spaced(aadA) + ", verified", []string{aadA}},
		{"id " + aadA[:4] + "-" + aadA[4:8] + "-" + aadA[8:] + ".", []string{aadA}},
		{aadA + " and " + spaced(aadB) + " and " + aadA, []string{aadA, aadB}}, // each once
		{"num:" + aadA + ".00", []string{aadA}},                                // a numeric's decimals end it
		{bad, nil},                                                             // the check digit fails
		{"1" + aadA[1:], nil},                                                  // Aadhaar never starts with 0 or 1
		{"9" + aadA, nil},                                                      // inside a longer number
		{aadA + "7", nil},                                                      // inside a longer number
		// A space between digits joins them (a card's or a phone's groups),
		// so a number run on after "+91 " reads as part of a longer one.
		{"+91 " + aadA, nil},
		{"4111 " + spaced(aadA), nil}, // a card's groups run on
		{spaced(aadA) + " 1234", nil}, // and on
		{"", nil},
	}
	for _, c := range cases {
		if got := findAadhaar(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("findAadhaar(%q) = %v, want %v", c.in, findAadhaar(c.in), c.want)
		}
	}
}

// The database's filter must pass on every value the check keeps, or a
// number is lost before it is looked at.
func TestShapeFilterCoversTheCheck(t *testing.T) {
	for _, v := range []string{aadA, spaced(aadA), aadA[:4] + "-" + aadA[4:8] + "-" + aadA[8:], aadA[:4] + " " + aadA[4:]} {
		if len(findAadhaar(v)) == 1 && !shapeRE.MatchString(v) {
			t.Errorf("%q is kept by the check but not passed by the filter", v)
		}
	}
	if shapePG != shapeRE.String() {
		t.Errorf("the database's filter %q and the check's %q differ", shapePG, shapeRE.String())
	}
}

func TestWalkExposure(t *testing.T) {
	doc := `{"kyc": {"aadhaar": "` + spaced(aadA) + `", "pan": "ABCPE1234F"},
		"notes": ["called", "said ` + aadB + `"],
		"by_id": {"` + aadA + `": {"name": "x", "uid": ` + aadB + `}},
		"status": true}`
	hits, ok := walkExposure(doc)
	if !ok {
		t.Fatal("a JSON document did not parse")
	}
	want := []docHit{
		{"$.by_id.*", aadA},     // a key holding the number: found, and the path does not keep it
		{"$.by_id.*.uid", aadB}, // and what is under it
		{"$.kyc.aadhaar", aadA},
		{"$.notes[*]", aadB},
	}
	if !reflect.DeepEqual(hits, want) {
		t.Errorf("walkExposure = %v, want %v", hits, want)
	}
	for _, h := range hits {
		if strings.ContainsAny(h.path, "0123456789") {
			t.Errorf("a path keeps digits: %q", h.path)
		}
	}
	if _, ok := walkExposure("{not json"); ok {
		t.Error("a broken document parsed")
	}
}

func TestSafeKey(t *testing.T) {
	for in, want := range map[string]string{
		"aadhaar": "$.aadhaar",
		"line 2":  `$."line 2"`,
		// Eight digits across hyphens: hidden too. A path that loses a date
		// is a smaller loss than one that keeps a number.
		"2024-11-12":    "$.*",
		"order_1234567": `$.order_1234567`,
		aadA:            "$.*",
		spaced(aadA):    "$.*",
	} {
		if got := safeKey("$", in); got != want {
			t.Errorf("safeKey(%q) = %q, want %q", in, safeKey("$", in), want)
		}
	}
}

func TestRowKeySQL(t *testing.T) {
	tb := table{schema: "public", name: "t", kind: "r"}
	if got, keyless := rowKeySQL(tb, []string{"id"}); got != `'id=' || "id"::text` || keyless {
		t.Errorf("one column: %s %v", got, keyless)
	}
	got, _ := rowKeySQL(tb, []string{"a", "b"})
	if got != `'(a, b)=(' || coalesce("a"::text, 'NULL') || ', ' || coalesce("b"::text, 'NULL') || ')'` {
		t.Errorf("two columns: %s", got)
	}
	if got, keyless := rowKeySQL(tb, nil); got != "'ctid=' || ctid::text" || !keyless {
		t.Errorf("no key: %s %v", got, keyless)
	}
	tb.kind = "p"
	if got, _ := rowKeySQL(tb, nil); !strings.Contains(got, "tableoid::regclass") {
		t.Errorf("a partitioned table's position names its partition: %s", got)
	}
}

func TestExposureGroupsAndCaps(t *testing.T) {
	e := newExposure()
	var none pgtype.Timestamptz
	notes := colKey{"public", "tickets", "notes", ""}
	cust := colKey{"public", "customers", "aadhaar", ""}
	e.add(cust, "id=1", none, []string{aadA})
	e.add(cust, "id=2", none, []string{aadB})
	e.add(notes, "id=9", none, []string{aadA, aadB})
	e.add(notes, "id=9", none, []string{aadA}) // the same place again
	if len(e.places) != 4 {
		t.Fatalf("places = %d, want 4", len(e.places))
	}
	// One person per number, across tables.
	if e.person[0] != e.person[2] || e.person[1] != e.person[3] || e.person[0] == e.person[1] {
		t.Errorf("persons = %v", e.person)
	}
	if e.places[2].last4 != aadA[8:] {
		t.Errorf("a place keeps the last four digits, got %q", e.places[2].last4)
	}
	if st := e.cols[notes]; st.numbers != 3 || st.rows != 2 || st.listed != 2 {
		t.Errorf("notes: %+v", *st)
	}

	// Past a column's cap, numbers are counted and not kept.
	e = newExposure()
	big := colKey{"public", "big", "uid", ""}
	for i := 0; i < maxListedPerColumn+5; i++ {
		e.add(big, "id="+strconv.Itoa(i), none, []string{aadA})
	}
	st := e.cols[big]
	if st.listed != maxListedPerColumn || !st.capped || st.numbers != int64(maxListedPerColumn+5) {
		t.Errorf("capped column: %+v", *st)
	}
	if lim := strings.Join(exposureLimits(e, exposureStats{}, false), " "); !strings.Contains(lim, "places are kept for a column") {
		t.Errorf("a capped run does not say so: %s", lim)
	}
}

// Nothing a run keeps may hold a full number.
func TestExposureKeepsNoNumber(t *testing.T) {
	e := newExposure()
	var none pgtype.Timestamptz
	hits, _ := walkExposure(`{"by": {"` + aadA + `": "` + aadB + `"}}`)
	for _, h := range hits {
		e.add(colKey{"public", "docs", "body", h.path}, "id=1", none, []string{h.number})
	}
	for _, p := range e.places {
		all := p.schema + p.table + p.column + p.path + p.row + p.last4
		for _, n := range []string{aadA, aadB} {
			if strings.Contains(all, n) || strings.Contains(all, n[:8]) {
				t.Errorf("a place keeps a number: %+v", p)
			}
		}
	}
}
