// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "testing"

func TestServicesListenOnLoopbackByDefault(t *testing.T) {
	t.Setenv("FOX_LISTEN", "")
	if got := listenAddr("8080"); got != "127.0.0.1:8080" {
		t.Errorf("default = %q, want 127.0.0.1:8080", got)
	}
	t.Setenv("FOX_LISTEN", "0.0.0.0")
	if got := listenAddr("6432"); got != "0.0.0.0:6432" {
		t.Errorf("FOX_LISTEN=0.0.0.0 gave %q", got)
	}
	t.Setenv("FOX_LISTEN", "::")
	if got := listenAddr("8088"); got != "[::]:8088" {
		t.Errorf("FOX_LISTEN=:: gave %q", got)
	}
}
