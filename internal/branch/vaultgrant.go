// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// Who may call the vault over the API (point 13, step 13.2; design, section
// 9). The operator, on the machine, calls through VaultCall directly; every
// call over the API comes through VaultCallAs, which decides first:
//
//   - tokenise and find: an admin, or an account holding use on the kind;
//   - detokenise: only an account holding detokenise on the kind. Being an
//     admin is not enough: an admin who needs a value grants it to themselves,
//     which is itself recorded and reviewed. A masked account never reads
//     values back, whatever it holds;
//   - each grant within its limit an hour, counted in values.
//
// A refusal is in the security log as vault.refused, never as vault.call, so
// the head check (vault.go) reads only calls the vault saw.

// ErrVaultForbidden is a call the caller has no grant for.
var ErrVaultForbidden = errors.New("not allowed")

// ErrVaultLimit is a grant's limit an hour reached.
var ErrVaultLimit = errors.New("limit reached")

// VaultCaller is who calls over the API.
type VaultCaller struct {
	Email string
	Admin bool
	IP    string
	// Actor is who the vault knows the call by, when not Email: a migration
	// run's own name (point 13.3).
	Actor string
}

// VaultCallAs is a call over the API: decided by the caller's grants, passed
// to the vault, and counted against the grant it used.
func VaultCallAs(st *auth.Store, c VaultCaller, path string, body []byte) ([]byte, int, error) {
	if err := requireVault(); err != nil {
		return nil, 0, err
	}
	var req vaultRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, 0, fmt.Errorf("%w: the body is not a vault request", ErrInvalidRequest)
	}
	n := len(req.Values) + len(req.Refs)
	grant, err := vaultAuthorize(st, c, path, req.Kind, n)
	if err != nil {
		st.Audit(auth.EvVaultRefused, c.Email, req.Kind, c.IP, fmt.Sprintf("%s, %d: %v", path, n, err))
		return nil, 0, err
	}
	reply, code, err := VaultCallActor(st, c.Email, c.Actor, c.IP, path, body)
	if err == nil && grant != 0 && code == 200 {
		if uerr := st.RecordVaultUse(grant, n); uerr != nil {
			return nil, 0, fmt.Errorf("counting the call against its grant: %w", uerr)
		}
	}
	return reply, code, err
}

func vaultAuthorize(st *auth.Store, c VaultCaller, path, kind string, n int) (int64, error) {
	if st == nil {
		return 0, fmt.Errorf("%w: the install's store is not open", ErrVaultForbidden)
	}
	perm := auth.VaultUse
	switch path {
	case "tokenise", "find":
	case "detokenise":
		perm = auth.VaultDetokenise
	default:
		return 0, fmt.Errorf("%w: no vault call %q", ErrInvalidRequest, path)
	}
	if perm == auth.VaultDetokenise && IsMaskedAccount(c.Email) {
		return 0, fmt.Errorf("%w: a masked account never reads values back from the vault", ErrVaultForbidden)
	}
	g, err := st.HeldVaultGrant(c.Email, kind, perm)
	if errors.Is(err, auth.ErrNoVaultGrant) {
		if perm == auth.VaultUse && c.Admin {
			return 0, nil // admins put values in and find keys without a grant
		}
		if perm == auth.VaultDetokenise {
			return 0, fmt.Errorf("%w: reading %s values back needs a detokenise grant on %s, given by an admin (an admin grants it to themselves too)", ErrVaultForbidden, kind, kind)
		}
		return 0, fmt.Errorf("%w: putting %s values in, or finding their keys, needs a use grant on %s, given by an admin", ErrVaultForbidden, kind, kind)
	}
	if err != nil {
		return 0, err
	}
	if g.UsedLastHour+n > g.PerHour {
		return 0, fmt.Errorf("%w: the grant allows %d %s an hour, and %d were used in the last hour", ErrVaultLimit, g.PerHour, vaultPlural(g.PerHour, "value", "values"), g.UsedLastHour)
	}
	return g.ID, nil
}

// VaultGrantOptions is a grant's terms.
type VaultGrantOptions struct {
	Email, Kind, Permission string
	PerHour                 int
	Expires                 *time.Time
}

// GrantVault gives a grant, after checking the kind exists, the account
// exists, and that detokenise does not go to a masked account.
func GrantVault(st *auth.Store, o VaultGrantOptions, by, ip string) (auth.VaultGrant, error) {
	if err := requireFeature(edition.Vault); err != nil {
		return auth.VaultGrant{}, err
	}
	if !auth.ValidVaultPermission(o.Permission) {
		return auth.VaultGrant{}, fmt.Errorf("%w: a grant is use or detokenise, not %q", ErrInvalidRequest, o.Permission)
	}
	ks, err := VaultKinds()
	if err != nil {
		return auth.VaultGrant{}, err
	}
	known := false
	for _, k := range ks {
		known = known || k.Name == o.Kind
	}
	if !known {
		return auth.VaultGrant{}, fmt.Errorf("%w: no kind %q (%s vault kinds lists them)", ErrInvalidRequest, o.Kind, brand.CLI)
	}
	email := strings.ToLower(strings.TrimSpace(o.Email))
	if _, ok := st.UserByEmail(email); !ok {
		return auth.VaultGrant{}, fmt.Errorf("%w: there is no account %s", ErrInvalidRequest, email)
	}
	if o.Permission == auth.VaultDetokenise && IsMaskedAccount(email) {
		return auth.VaultGrant{}, fmt.Errorf("%w: %s is masked, and a masked account never reads values back from the vault", ErrInvalidRequest, email)
	}
	g, err := st.GrantVault(email, o.Kind, o.Permission, o.PerHour, o.Expires, by)
	if err != nil {
		return g, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	st.Audit(auth.EvVaultGrant, by, email, ip, vaultGrantText("granted", g))
	return g, nil
}

// RevokeVault ends a grant.
func RevokeVault(st *auth.Store, id int64, by, ip string) (auth.VaultGrant, error) {
	if err := requireFeature(edition.Vault); err != nil {
		return auth.VaultGrant{}, err
	}
	g, err := st.RevokeVaultGrant(id, by)
	if errors.Is(err, auth.ErrNoVaultGrant) {
		return g, fmt.Errorf("%w: no grant %d that still holds", ErrInvalidRequest, id)
	}
	if err != nil {
		return g, err
	}
	st.Audit(auth.EvVaultGrant, by, g.Email, ip, vaultGrantText("revoked", g))
	return g, nil
}

func vaultGrantText(what string, g auth.VaultGrant) string {
	s := fmt.Sprintf("%s grant %d: %s on %s, %d an hour", what, g.ID, g.Permission, g.Kind, g.PerHour)
	if g.Expires != nil {
		s += ", until " + g.Expires.Format(time.RFC3339)
	}
	return s
}

// VaultGrantUnused is how long a grant may go unused before `fox check`
// says so.
const VaultGrantUnused = 90 * 24 * time.Hour

// ParseVaultExpiry reads a grant's expiry: a number of days or hours from
// now ("30d", "12h"), or a date ("2026-12-31", the end of that day UTC). ""
// is no expiry.
func ParseVaultExpiry(s string, now time.Time) (*time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if n := len(s); n > 1 && (s[n-1] == 'd' || s[n-1] == 'h') {
		var v int
		if _, err := fmt.Sscanf(s[:n-1], "%d", &v); err == nil && v > 0 && fmt.Sprint(v) == s[:n-1] {
			d := time.Duration(v) * time.Hour
			if s[n-1] == 'd' {
				d *= 24
			}
			t := now.Add(d).UTC()
			return &t, nil
		}
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		t = t.Add(24*time.Hour - time.Second).UTC()
		if !t.After(now) {
			return nil, fmt.Errorf("%w: %s has passed", ErrInvalidRequest, s)
		}
		return &t, nil
	}
	return nil, fmt.Errorf("%w: an expiry is days or hours from now (30d, 12h) or a date (2026-12-31), not %q", ErrInvalidRequest, s)
}
