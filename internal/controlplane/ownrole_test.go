// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A signed-in user whose own role cannot be had is refused, never run as the
// shared role, where the name on the record would be a setting the user's SQL
// can change (G1). The engine's own reads, with no user, are not affected.
func TestConsoleRefusesWithoutOwnRole(t *testing.T) {
	old := ensureUserRole
	ensureUserRole = func(branchName, email string) error { return errors.New("role creation failed") }
	t.Cleanup(func() { ensureUserRole = old })
	_, err := openSession(context.Background(), "127.0.0.1:1", queryAs{Branch: "main", Actor: "alice@example.com"})
	if !errors.Is(err, errNoOwnRole) || !strings.Contains(err.Error(), "does not fall back to the shared role") ||
		!strings.Contains(err.Error(), "role creation failed") {
		t.Fatalf("refusal: %v", err)
	}
	res := runQuery("127.0.0.1:1", "SELECT 1", queryAs{Branch: "main", Actor: "alice@example.com"})
	if msg, _ := res["error"].(string); !strings.Contains(msg, "could not log you in as your own role") {
		t.Errorf("the console is told why: %v", res)
	}
}
