//go:build enterprise

// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "testing"

// The value of a flag is never taken for the table, wherever the flag sits.
func TestRealtimeEnableReadsTheTableAndColumns(t *testing.T) {
	for _, args := range [][]string{
		{"orders", "--columns", "id,note"},
		{"--columns", "id,note", "orders"},
		{"--columns=id,note", "--branch", "dev", "orders"},
	} {
		schema, table, err := splitTable(args)
		if err != nil || schema != "public" || table != "orders" {
			t.Errorf("%v: %s.%s, %v", args, schema, table, err)
		}
		if got := flagValue(args, "--columns"); got != "id,note" {
			t.Errorf("%v: --columns = %q", args, got)
		}
	}
}
