// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

// The console renders whatever pgx decoded a column into. For several types
// that is a byte array or a struct, and the JSON form of those is useless to
// read: a uuid arrived as "[195,64,152,78,…]" — the bug this fixes — and an
// interval as {"Microseconds":7200000000,…}.
func TestCellRendersPostgresTypes(t *testing.T) {
	m := pgtype.NewMap()
	uuid := [16]byte{0xc3, 0x40, 0x98, 0x4e, 0x87, 0xbf, 0x40, 0x06, 0xa0, 0x13, 0x72, 0xac, 0xa6, 0xfc, 0x7d, 0x77}

	cases := []struct {
		name string
		v    any
		oid  uint32
		want any
	}{
		{"uuid", uuid, pgtype.UUIDOID, "c340984e-87bf-4006-a013-72aca6fc7d77"},
		{"bytea", []byte{0x01, 0x02}, pgtype.ByteaOID, `\x0102`},
		{"interval", pgtype.Interval{Days: 1, Microseconds: 7200000000, Valid: true}, pgtype.IntervalOID, "1 day 02:00:00"},
		{"time of day", pgtype.Time{Microseconds: 45296000000, Valid: true}, pgtype.TimeOID, "12:34:56.000000"},
		{"inet", netip.MustParsePrefix("192.168.1.1/32"), pgtype.InetOID, "192.168.1.1/32"},
		{"macaddr", net.HardwareAddr{0x08, 0x00, 0x2b, 0x01, 0x02, 0x03}, pgtype.MacaddrOID, "08:00:2b:01:02:03"},

		// Types that already rendered well keep rendering exactly as before.
		{"text", "hello", pgtype.TextOID, "hello"},
		{"int", int32(42), pgtype.Int4OID, int32(42)},
		{"bool", true, pgtype.BoolOID, true},
		{"null", nil, pgtype.TextOID, nil},
		{"numeric", mustNumeric(t, "1234.5678"), pgtype.NumericOID, "1234.5678"},
		{"jsonb object", map[string]any{"a": float64(1)}, pgtype.JSONBOID, `{"a":1}`},
		{"int array", []any{int32(1), int32(2), int32(3)}, pgtype.Int4ArrayOID, `[1,2,3]`},
		{"text array", []any{"a", "b"}, pgtype.TextArrayOID, `["a","b"]`},

		// An array of a type that needs rendering: each element by its own type,
		// rather than a list of lists of numbers.
		{"uuid array", []any{uuid}, pgtype.UUIDArrayOID, `["c340984e-87bf-4006-a013-72aca6fc7d77"]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := cell(c.v, c.oid, m)
			if got != c.want {
				t.Errorf("cell(%#v) = %#v, want %#v", c.v, got, c.want)
			}
		})
	}
}

// A timestamp keeps the RFC 3339 form the UI parses.
func TestCellTimestamp(t *testing.T) {
	ts := time.Date(2026, 9, 18, 1, 52, 7, 691280000, time.UTC)
	if got := cell(ts, pgtype.TimestamptzOID, pgtype.NewMap()); got != "2026-09-18T01:52:07.69128Z" {
		t.Errorf("cell(timestamp) = %#v", got)
	}
}

// An unknown OID, or no type map at all, must not lose the value: the console
// falls back to what it showed before.
func TestCellUnknownType(t *testing.T) {
	uuid := [16]byte{0x01}
	if got := cell(uuid, 0, nil); got == nil || got == "" {
		t.Errorf("a uuid with no type map should still render something, got %#v", got)
	}
	// pgx hands back []byte for a type it has no codec for (a custom enum or
	// domain arrives as the bytes of its text form), so only a real bytea column
	// is hex-encoded -- these stay readable, as they were before.
	if got := cell([]byte("active"), 999999, pgtype.NewMap()); got != "active" {
		t.Errorf("an unknown type's text should stay readable, got %#v", got)
	}
}

func mustNumeric(t *testing.T, s string) pgtype.Numeric {
	t.Helper()
	var n pgtype.Numeric
	if err := n.Scan(s); err != nil {
		t.Fatalf("numeric %q: %v", s, err)
	}
	return n
}

// A json or jsonb array is JSON whole, its objects not cells of their own
// (point 12.4: an EXPLAIN plan is one).
func TestCellJSONArray(t *testing.T) {
	m := pgtype.NewMap()
	v := []any{map[string]any{"a": float64(1)}, "x"}
	for _, oid := range []uint32{pgtype.JSONOID, pgtype.JSONBOID} {
		if got := cell(v, oid, m); got != `[{"a":1},"x"]` {
			t.Errorf("oid %d: %#v", oid, got)
		}
	}
	if got := cell(float64(2), pgtype.JSONBOID, m); got != float64(2) {
		t.Errorf("a json number changed: %#v", got)
	}
}
