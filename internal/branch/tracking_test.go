// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"strings"
	"testing"
)

func TestCheckTrackOptions(t *testing.T) {
	if err := CheckTrackOptions(DefaultTrackOptions); err != nil {
		t.Fatal(err)
	}
	if err := CheckTrackOptions(TrackOptions{By: "who"}); err != nil {
		t.Fatalf("one column is enough: %v", err)
	}
	for _, o := range []TrackOptions{
		{},
		{Created: "x", Updated: "x"},
		{Created: strings.Repeat("c", 64)},
	} {
		if err := CheckTrackOptions(o); err == nil {
			t.Errorf("%+v accepted", o)
		}
	}
}

// One transaction, the person named for the Blackbox, and the override only
// for turning tracking off.
func TestTrackSQL(t *testing.T) {
	on := trackSQL("ada@x.com", "console", "SELECT 1;", false)
	if !strings.HasPrefix(on, "BEGIN;\n") || !strings.HasSuffix(on, "COMMIT;\n") {
		t.Fatalf("not one transaction:\n%s", on)
	}
	if !strings.Contains(on, "set_config('bb.actor', 'ada@x.com', true)") || strings.Contains(on, "allow_destructive") {
		t.Fatalf("%s", on)
	}
	if off := trackSQL("o'brien", "fox track", "SELECT 1;", true); !strings.Contains(off, "SET LOCAL bb.allow_destructive = on;") ||
		!strings.Contains(off, "'o''brien'") {
		t.Fatalf("%s", off)
	}
}

func TestTableRef(t *testing.T) {
	if got := tableRef("", "Order's"); got != "format('%I.%I', 'public', 'Order''s')::regclass" {
		t.Fatal(got)
	}
	if got := tableRef("shop", "x"); got != "format('%I.%I', 'shop', 'x')::regclass" {
		t.Fatal(got)
	}
}

func TestPsqlError(t *testing.T) {
	for in, want := range map[string]string{
		"psql:<stdin>:3: ERROR:  column created_at of public.x is date, and tracking keeps timestamp with time zone there\nCONTEXT: …": "column created_at of public.x is date, and tracking keeps timestamp with time zone there",
		"ERROR:  relation \"nope\" does not exist\n": "relation \"nope\" does not exist",
		"something else": "something else",
	} {
		if got := psqlError(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}
