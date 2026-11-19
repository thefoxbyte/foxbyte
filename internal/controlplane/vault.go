// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// registerVault is the vault's API (point 13): its state, kinds, grants and
// access log for admins (13.1, 13.2); tokenising and finding values for admins
// and holders of a use grant on the kind; reading values back only for holders
// of a detokenise grant on it, within its limit an hour, never a masked
// account and never an admin by being one (branch.VaultCallAs). Setting the
// vault up is the operator's (`fox vault setup`).
func registerVault(mux *http.ServeMux) {
	gate := func(w http.ResponseWriter, r *http.Request) bool {
		if !requireFeature(w, edition.Vault) {
			return false
		}
		if !isAdmin(r) {
			writeErr(w, 403, errors.New("the vault is for admins"))
			return false
		}
		return true
	}

	mux.HandleFunc("GET /api/vault", func(w http.ResponseWriter, r *http.Request) {
		if !gate(w, r) {
			return
		}
		st, err := branch.VaultStatus(secLog)
		if err != nil {
			vaultFail(w, err)
			return
		}
		writeJSON(w, 200, st)
	})

	mux.HandleFunc("GET /api/vault/kinds", func(w http.ResponseWriter, r *http.Request) {
		if !gate(w, r) {
			return
		}
		ks, err := branch.VaultKinds()
		if err != nil {
			vaultFail(w, err)
			return
		}
		writeJSON(w, 200, ks)
	})

	call := func(path string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !requireFeature(w, edition.Vault) {
				return
			}
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
			if err != nil {
				writeErr(w, 400, errors.New("the body is too large: at most 4 MB a call"))
				return
			}
			u, _ := auth.UserFrom(r.Context())
			caller := branch.VaultCaller{Email: u.Email, Admin: isAdmin(r), IP: remoteIP(r)}
			reply, code, err := branch.VaultCallAs(secLog, caller, path, body)
			if err != nil {
				vaultFail(w, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_, _ = w.Write(reply)
		}
	}
	mux.HandleFunc("POST /api/vault/tokenise", call("tokenise"))
	mux.HandleFunc("POST /api/vault/find", call("find"))
	mux.HandleFunc("POST /api/vault/detokenise", call("detokenise"))

	// What the caller may do: any signed-in account, so the console can show a
	// grant holder their part of the vault.
	mux.HandleFunc("GET /api/vault/mine", func(w http.ResponseWriter, r *http.Request) {
		if !requireFeature(w, edition.Vault) {
			return
		}
		u, _ := auth.UserFrom(r.Context())
		out := map[string]any{"set_up": branch.VaultSetUp(), "admin": isAdmin(r), "grants": []auth.VaultGrant{}, "kinds": []branch.VaultKind{}}
		gs, err := secLog.VaultGrantsOf(u.Email)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		if gs != nil {
			out["grants"] = gs
		}
		if len(gs) > 0 || isAdmin(r) {
			if ks, err := branch.VaultKinds(); err == nil {
				out["kinds"] = ks
			}
		}
		writeJSON(w, 200, out)
	})

	mux.HandleFunc("GET /api/vault/grants", func(w http.ResponseWriter, r *http.Request) {
		if !gate(w, r) {
			return
		}
		gs, err := secLog.VaultGrants(r.URL.Query().Get("all") == "1")
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		if gs == nil {
			gs = []auth.VaultGrant{}
		}
		writeJSON(w, 200, gs)
	})

	mux.HandleFunc("POST /api/vault/grants", func(w http.ResponseWriter, r *http.Request) {
		if !gate(w, r) {
			return
		}
		var b struct {
			Email      string `json:"email"`
			Kind       string `json:"kind"`
			Permission string `json:"permission"`
			PerHour    int    `json:"per_hour"`
			Expires    string `json:"expires"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&b); err != nil {
			writeErr(w, 400, errors.New("the body must be JSON: email, kind, permission (use or detokenise), per_hour, expires"))
			return
		}
		exp, err := branch.ParseVaultExpiry(b.Expires, time.Now())
		if err != nil {
			vaultFail(w, err)
			return
		}
		u, _ := auth.UserFrom(r.Context())
		g, err := branch.GrantVault(secLog, branch.VaultGrantOptions{Email: b.Email, Kind: b.Kind, Permission: b.Permission, PerHour: b.PerHour, Expires: exp}, u.Email, remoteIP(r))
		if err != nil {
			vaultFail(w, err)
			return
		}
		writeJSON(w, 201, g)
	})

	mux.HandleFunc("DELETE /api/vault/grants/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !gate(w, r) {
			return
		}
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeErr(w, 400, errors.New("a grant is named by its number"))
			return
		}
		u, _ := auth.UserFrom(r.Context())
		g, err := branch.RevokeVault(secLog, id, u.Email, remoteIP(r))
		if err != nil {
			vaultFail(w, err)
			return
		}
		writeJSON(w, 200, g)
	})

	mux.HandleFunc("GET /api/vault/log", func(w http.ResponseWriter, r *http.Request) {
		if !gate(w, r) {
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
		b, err := branch.VaultLog(limit, before)
		if err != nil {
			vaultFail(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	})
}

func vaultFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, branch.ErrVaultNotSetUp):
		writeErr(w, 409, err)
	case errors.Is(err, branch.ErrInvalidRequest):
		writeErr(w, 400, err)
	case errors.Is(err, branch.ErrNotLicensed), errors.Is(err, branch.ErrVaultForbidden):
		writeErr(w, 403, err)
	case errors.Is(err, branch.ErrVaultLimit):
		writeErr(w, 429, err)
	default:
		writeErr(w, 500, err)
	}
}
