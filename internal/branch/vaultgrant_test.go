// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

// Who may call over the API (design, section 9).
func TestVaultAuthorize(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	st := store(t)
	admin := VaultCaller{Email: "admin@x.com", Admin: true}
	kyc := VaultCaller{Email: "kyc@x.com"}

	// An admin puts values in and finds keys without a grant…
	if id, err := vaultAuthorize(st, admin, "tokenise", "aadhaar", 3); err != nil || id != 0 {
		t.Fatalf("an admin's tokenise: %d, %v", id, err)
	}
	// …but reads nothing back by being one.
	if _, err := vaultAuthorize(st, admin, "detokenise", "aadhaar", 1); !errors.Is(err, ErrVaultForbidden) {
		t.Fatalf("an admin's detokenise without a grant: %v", err)
	}
	// Anyone else needs a grant for either.
	if _, err := vaultAuthorize(st, kyc, "find", "aadhaar", 1); !errors.Is(err, ErrVaultForbidden) || !strings.Contains(err.Error(), "use grant") {
		t.Fatalf("a find without a grant: %v", err)
	}
	g, _ := st.GrantVault("kyc@x.com", "aadhaar", auth.VaultDetokenise, 5, nil, "admin@x.com")
	if id, err := vaultAuthorize(st, kyc, "detokenise", "aadhaar", 2); err != nil || id != g.ID {
		t.Fatalf("a holder's detokenise: %d, %v", id, err)
	}
	// A grant on one kind is not a grant on another, nor use.
	if _, err := vaultAuthorize(st, kyc, "detokenise", "text", 1); !errors.Is(err, ErrVaultForbidden) {
		t.Fatalf("another kind: %v", err)
	}
	if _, err := vaultAuthorize(st, kyc, "tokenise", "aadhaar", 1); !errors.Is(err, ErrVaultForbidden) {
		t.Fatalf("detokenise is not use: %v", err)
	}
	// The limit an hour, counted in values.
	_ = st.RecordVaultUse(g.ID, 4)
	if _, err := vaultAuthorize(st, kyc, "detokenise", "aadhaar", 1); err != nil {
		t.Fatalf("the fifth value is within 5 an hour: %v", err)
	}
	if _, err := vaultAuthorize(st, kyc, "detokenise", "aadhaar", 2); !errors.Is(err, ErrVaultLimit) || !strings.Contains(err.Error(), "4 were used") {
		t.Fatalf("the sixth and seventh are not: %v", err)
	}
	// An unknown call is refused as such.
	if _, err := vaultAuthorize(st, kyc, "entries", "aadhaar", 1); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("entries over the API: %v", err)
	}
	// Deleting, updating and rotating are for admins, whatever an account
	// holds (13.4).
	_, _ = st.GrantVault("kyc@x.com", "aadhaar", auth.VaultUse, 100, nil, "admin@x.com")
	for _, p := range []string{"delete", "update", "rotate"} {
		if _, err := vaultAuthorize(st, kyc, p, "aadhaar", 1); !errors.Is(err, ErrVaultForbidden) || !strings.Contains(err.Error(), "for admins") {
			t.Fatalf("%s by a grant holder: %v", p, err)
		}
		if id, err := vaultAuthorize(st, admin, p, "aadhaar", 1); err != nil || id != 0 {
			t.Fatalf("%s by an admin: %d, %v", p, id, err)
		}
	}
}

func TestParseVaultExpiry(t *testing.T) {
	now := time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)
	for in, want := range map[string]time.Time{
		"30d":        now.Add(30 * 24 * time.Hour),
		"12h":        now.Add(12 * time.Hour),
		"2026-12-31": time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	} {
		got, err := ParseVaultExpiry(in, now)
		if err != nil || got == nil || !got.Equal(want) {
			t.Errorf("%s: got %v, %v; want %v", in, got, err, want)
		}
	}
	if got, err := ParseVaultExpiry("", now); got != nil || err != nil {
		t.Errorf("no expiry: %v, %v", got, err)
	}
	for _, bad := range []string{"0d", "-3d", "3w", "d", "2026-11-01", "tomorrow", "1.5d"} {
		if _, err := ParseVaultExpiry(bad, now); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
