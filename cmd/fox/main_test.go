// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"strings"
	"testing"
	"time"
)

// The help must say what `blackbox revert` really does (a point-in-time restore
// of main), not promise to revert a branch; and list `ha failback`.
func TestUsageDescribesRevertAndFailback(t *testing.T) {
	if strings.Contains(usage, "revert of a branch") {
		t.Error("usage still claims revert reverts a branch")
	}
	for _, want := range []string{"Point-in-time restore of main", "ha failback"} {
		if !strings.Contains(usage, want) {
			t.Errorf("usage lacks %q", want)
		}
	}
}

func TestAddrFlag(t *testing.T) {
	if got := addrFlag([]string{"--addr", ":9999"}, ":6432"); got != ":9999" {
		t.Errorf("addrFlag = %q, want :9999", got)
	}
	if got := addrFlag(nil, ":6432"); got != ":6432" {
		t.Errorf("addrFlag default = %q, want :6432", got)
	}
	if got := addrFlag([]string{"--addr"}, ":6432"); got != ":6432" {
		t.Errorf("addrFlag dangling = %q, want default", got)
	}
}

func TestDurFlag(t *testing.T) {
	if got := durFlag([]string{"--idle", "90s"}, "--idle", 2*time.Minute); got != 90*time.Second {
		t.Errorf("durFlag = %v, want 90s", got)
	}
	if got := durFlag(nil, "--idle", 2*time.Minute); got != 2*time.Minute {
		t.Errorf("durFlag default = %v, want 2m", got)
	}
	if got := durFlag([]string{"--idle", "nonsense"}, "--idle", time.Minute); got != time.Minute {
		t.Errorf("durFlag invalid = %v, want fallback 1m", got)
	}
}

func TestRestoreArg(t *testing.T) {
	if got := restoreArg([]string{"--to", "latest"}); got != "latest" {
		t.Errorf("restoreArg(--to latest) = %q", got)
	}
	if got := restoreArg([]string{"2026-01-01 00:00:00+00"}); got != "2026-01-01 00:00:00+00" {
		t.Errorf("restoreArg(bare) = %q", got)
	}
	if got := restoreArg(nil); got != "" {
		t.Errorf("restoreArg(empty) = %q, want ''", got)
	}
	if got := restoreArg([]string{"--to"}); got != "" {
		t.Errorf("restoreArg(dangling) = %q, want ''", got)
	}
}
