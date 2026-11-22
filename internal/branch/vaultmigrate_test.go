// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func col(where string, skipped string, left int64) VaultMigrateColumn {
	p := strings.SplitN(where, ".", 3)
	return VaultMigrateColumn{Schema: p[0], Table: p[1], Column: p[2], Skipped: skipped, Left: left}
}

func TestRehearsalFor(t *testing.T) {
	reports := []VaultMigration{ // newest first, as the store lists them
		{ID: 9, Columns: []VaultMigrateColumn{col("public.kyc.aadhaar", "", 3), col("public.notes.body", "", 0)}},
		{ID: 7, Columns: []VaultMigrateColumn{col("public.kyc.aadhaar", "", 0)}},
		{ID: 5, Columns: []VaultMigrateColumn{col("public.cards.doc", "", 0)}},
	}
	ids, err := rehearsalFor([]VaultMigrateColumn{col("public.kyc.aadhaar", "", 0), col("public.notes.body", "", 0)}, reports)
	if err != nil || !reflect.DeepEqual(ids, []int64{7, 9}) {
		t.Fatalf("each column from the newest run that moved it clean: %v %v", ids, err)
	}
	_, err = rehearsalFor([]VaultMigrateColumn{col("public.kyc.aadhaar", "", 0), col("public.other.x", "", 0)}, reports)
	if !errors.Is(err, ErrVaultRehearsal) || !strings.Contains(err.Error(), "public.other.x") || strings.Contains(err.Error(), "public.kyc.aadhaar,") {
		t.Fatalf("a column no branch moved is named: %v", err)
	}
	ids, err = rehearsalFor([]VaultMigrateColumn{col("public.nokey.x", "the table has no primary key", 0)}, reports)
	if err != nil || len(ids) != 0 {
		t.Fatalf("a column main would skip needs no rehearsal: %v %v", ids, err)
	}
	_, err = rehearsalFor([]VaultMigrateColumn{col("public.cards.doc", "", 0)}, []VaultMigration{
		{ID: 3, Columns: []VaultMigrateColumn{col("public.cards.doc", "it is part of a foreign key", 0)}},
	})
	if !errors.Is(err, ErrVaultRehearsal) {
		t.Fatal("a column a branch skipped was not rehearsed:", err)
	}
}

func TestVaultMigrationClean(t *testing.T) {
	m := VaultMigration{State: "done", Columns: []VaultMigrateColumn{col("public.a.b", "", 0)}}
	if !m.Clean() {
		t.Error("a finished run with every column moved and nothing left is clean")
	}
	for name, x := range map[string]VaultMigration{
		"a preview":          {Dry: true, State: "done", Columns: m.Columns},
		"failed":             {State: "failed", Columns: m.Columns},
		"nothing planned":    {State: "done"},
		"a number left":      {State: "done", Columns: []VaultMigrateColumn{col("public.a.b", "", 1)}},
		"a column not moved": {State: "done", Columns: []VaultMigrateColumn{col("public.a.b", "", 0), col("public.a.c", "no primary key", 0)}},
	} {
		if x.Clean() {
			t.Errorf("%s is not clean", name)
		}
	}
	s := VaultMigration{ID: 4, Branch: "b", Distinct: 2, Made: 1, Reused: 1, Columns: []VaultMigrateColumn{{Replaced: 5}}}.Summary()
	if !strings.Contains(s, "migration 4 on b") || !strings.Contains(s, "1 key(s) made, 1 reused; 5 row(s) rewritten, 0 left") {
		t.Errorf("summary: %s", s)
	}
	if s := (VaultMigration{ID: 4, Branch: "b", Dry: true}).Summary(); !strings.HasPrefix(s, "preview 4") || strings.Contains(s, "made") {
		t.Errorf("a preview's summary: %s", s)
	}
}

func TestParseVaultColumnAndFormat(t *testing.T) {
	for in, want := range map[string]string{"kyc.aadhaar": "public.kyc.aadhaar", " app.kyc.aadhaar ": "app.kyc.aadhaar"} {
		if got, err := parseVaultColumn(in); err != nil || got != want {
			t.Errorf("parseVaultColumn(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "aadhaar", "a..b", "a.b.c.d", ".b.c"} {
		if _, err := parseVaultColumn(bad); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("parseVaultColumn(%q) is refused: %v", bad, err)
		}
	}
	for in, want := range map[string]string{"": "", "Opaque": "opaque", "legacy": "legacy"} {
		if got, err := CheckVaultFormat(in); err != nil || got != want {
			t.Errorf("CheckVaultFormat(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := CheckVaultFormat("hash"); !errors.Is(err, ErrInvalidRequest) {
		t.Error("a format that is neither is refused")
	}
}
