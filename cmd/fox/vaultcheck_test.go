// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

func vaultState(t *testing.T, software bool, brokenAt int64, holds bool) *branch.VaultState {
	t.Helper()
	st := map[string]any{
		"token": map[string]any{"software": software},
		"kinds": []map[string]any{{"name": "aadhaar", "hsm_required": true, "rules": "UIDAI Circular No. 14 of 2025"}, {"name": "text"}},
		"log":   map[string]any{"entries": 12, "broken_at": brokenAt},
	}
	b, _ := json.Marshal(st)
	return &branch.VaultState{SetUp: true, Database: true, Service: true, Status: b, Anchor: branch.VaultAnchor{Holds: holds, Note: "entry 9 was cut off its end"}}
}

func names(ls []checkLine) string {
	var out []string
	for _, l := range ls {
		out = append(out, l.name+"="+[]string{"ok", "warn", "fail"}[l.state])
	}
	return strings.Join(out, " ")
}

func TestVaultCheckLines(t *testing.T) {
	now := time.Now()
	stopped := vaultState(t, false, 0, true)
	stopped.Service = false
	if got := names(vaultLines(stopped, nil, now)); got != "vault=fail" {
		t.Errorf("stopped: %s", got)
	}
	if got := names(vaultLines(vaultState(t, false, 0, true), nil, now)); got != "vault log=ok" {
		t.Errorf("a vault on an HSM, all well: %s", got)
	}
	ls := vaultLines(vaultState(t, true, 0, true), nil, now)
	if got := names(ls); got != "vault log=ok vault token=warn" || !strings.Contains(ls[1].detail, "aadhaar") {
		t.Errorf("the software token holding Aadhaar: %s", got)
	}
	if got := names(vaultLines(vaultState(t, false, 7, true), nil, now)); got != "vault log=fail" {
		t.Errorf("a broken chain: %s", got)
	}
	ls = vaultLines(vaultState(t, false, 0, false), nil, now)
	if got := names(ls); got != "vault log=fail" || !strings.Contains(ls[0].detail, "cut off") {
		t.Errorf("a head the log no longer holds: %s %+v", got, ls)
	}
}
