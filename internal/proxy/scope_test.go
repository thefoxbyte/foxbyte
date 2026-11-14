// SPDX-License-Identifier: AGPL-3.0-or-later

package proxy

import (
	"path/filepath"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

func TestScopedKeyRefusalIsLogged(t *testing.T) {
	s, err := auth.Open(auth.Config{DBPath: filepath.Join(t.TempDir(), "t.db"), WebOrigin: "http://x", SignupOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	old := authStore
	authStore = s
	t.Cleanup(func() { authStore = old })

	noteScopedRefusal(auth.User{Email: "a@b.co"}, "dev", "main", "203.0.113.9")
	evs, err := s.SecurityEvents(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].Kind != auth.EvDenied || evs[0].Actor != "a@b.co" || evs[0].Subject != "main" {
		t.Fatalf("events: %+v", evs)
	}
	if evs[0].Detail != "scoped key for dev" {
		t.Fatalf("detail %q", evs[0].Detail)
	}
}
