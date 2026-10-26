// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

func TestIdentityDataSQL(t *testing.T) {
	revoked, since := int64(1_700_000_100), int64(1_700_000_000)
	st := identityState{
		installID: "install-0123456789abcdef0123",
		apps: []auth.App{
			{Name: "shop", Account: "shop@example.com", MaxLife: 300, OnInvalid: "none", Keys: []auth.AppKey{
				{Kid: "k1", PublicKey: strings.Repeat("ab", 32)},
				{Kid: "k0", PublicKey: strings.Repeat("cd", 32), Revoked: &revoked, CompromisedSince: &since},
			}},
			{Name: "o'brien", Account: "ob@example.com", MaxLife: 60, OnInvalid: "refuse", Keys: []auth.AppKey{
				{Kid: "x", PublicKey: strings.Repeat("ef", 32)},
			}},
			// Its account was deleted: nothing can log in as it, so it is not copied.
			{Name: "orphan", Account: "", MaxLife: 300, OnInvalid: "none", Keys: []auth.AppKey{
				{Kid: "z", PublicKey: strings.Repeat("01", 32)},
			}},
		},
	}
	sql := identityDataSQL("feature-x", st)
	for _, want := range []string{
		"IF to_regclass('bb_f1.install') IS NULL OR to_regclass('bb.app_issuers') IS NULL THEN RETURN; END IF;",
		"VALUES (1, 'install-0123456789abcdef0123', 'feature-x')",
		"DELETE FROM bb.app_issuers;",
		"VALUES ('shop', 'k1', 'shop@example.com', decode('" + strings.Repeat("ab", 32) + "', 'hex'), make_interval(secs => 300), 'none', NULL, NULL);",
		"VALUES ('shop', 'k0', 'shop@example.com', decode('" + strings.Repeat("cd", 32) + "', 'hex'), make_interval(secs => 300), 'none', to_timestamp(1700000100), to_timestamp(1700000000));",
		"VALUES ('o''brien', 'x', 'ob@example.com', decode('" + strings.Repeat("ef", 32) + "', 'hex'), make_interval(secs => 60), 'refuse', NULL, NULL);",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("the SQL should contain\n  %s\ngot:\n%s", want, sql)
		}
	}
	if strings.Contains(sql, "orphan") {
		t.Error("an application whose account is gone was copied")
	}
	// The delete and the inserts are one block, so a branch never has half.
	if strings.Count(sql, "DO $id$") != 1 || !strings.HasSuffix(strings.TrimSpace(sql), "$id$;") {
		t.Errorf("not one block:\n%s", sql)
	}
}

// A promoted standby serves main, and its tokens name main.
func TestIdentityBranch(t *testing.T) {
	for in, want := range map[string]string{"main": "main", "standby": "main", "feature-x": "feature-x"} {
		if got := identityBranch(in); got != want {
			t.Errorf("identityBranch(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseAsserted(t *testing.T) {
	m := parseAsserted("shop|k1|12|2|1792659600\nshop|k0|0|1|1792600000\n\nmalformed|line\n")
	if a := m[[2]string{"shop", "k1"}]; a.Records != 12 || a.Sessions != 2 || a.Last.Unix() != 1792659600 {
		t.Errorf("shop k1: %+v", a)
	}
	if a := m[[2]string{"shop", "k0"}]; a.Records != 0 || a.Sessions != 1 {
		t.Errorf("shop k0: %+v", a)
	}
	if len(m) != 2 {
		t.Errorf("a malformed line was read: %v", m)
	}
}
