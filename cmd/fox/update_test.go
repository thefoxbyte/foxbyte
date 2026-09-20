// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"github.com/foxbyte/foxbyte/internal/host"
)

func TestParseUpdateArgs(t *testing.T) {
	cases := []struct {
		args []string
		want host.UpdateOptions
	}{
		{nil, host.UpdateOptions{}},
		{[]string{"--check"}, host.UpdateOptions{Check: true}},
		{[]string{"-y"}, host.UpdateOptions{Yes: true}},
		{[]string{"--yes", "--version", "v0.9.0"}, host.UpdateOptions{Yes: true, Version: "v0.9.0"}},
		{[]string{"--version=0.9"}, host.UpdateOptions{Version: "0.9"}},
	}
	for _, c := range cases {
		got, err := parseUpdateArgs(c.args)
		if err != nil || got != c.want {
			t.Errorf("parseUpdateArgs(%q) = %+v, %v; want %+v", c.args, got, err, c.want)
		}
	}
	for _, bad := range [][]string{{"--version"}, {"--version", "--yes"}, {"--version", "banana"}, {"now"}} {
		if _, err := parseUpdateArgs(bad); err == nil {
			t.Errorf("parseUpdateArgs(%q) accepted", bad)
		}
	}
}
