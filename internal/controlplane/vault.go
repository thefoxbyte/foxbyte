// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"errors"
	"io"
	"net/http"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// registerVault is the vault's API (point 13, step 13.1): its state and kinds,
// and tokenising and finding values, for admins. Detokenising is refused
// here until admins can grant it (13.2): the operator does it on the machine,
// and the design's rule stands that nobody reads values back by being an
// admin. Setting the vault up is the operator's (`fox vault setup`).
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
			if !gate(w, r) {
				return
			}
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
			if err != nil {
				writeErr(w, 400, errors.New("the body is too large: at most 4 MB a call"))
				return
			}
			u, _ := auth.UserFrom(r.Context())
			reply, code, err := branch.VaultCall(secLog, u.Email, remoteIP(r), path, body)
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
	mux.HandleFunc("POST /api/vault/detokenise", func(w http.ResponseWriter, r *http.Request) {
		if !gate(w, r) {
			return
		}
		writeErr(w, 403, errors.New("reading values back needs a detokenise grant, which admins give once the vault's permissions arrive; "+
			"until then only the operator can, on the machine: "+brand.CLI+" vault detokenise"))
	})
}

func vaultFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, branch.ErrVaultNotSetUp):
		writeErr(w, 409, err)
	case errors.Is(err, branch.ErrInvalidRequest):
		writeErr(w, 400, err)
	case errors.Is(err, branch.ErrNotLicensed):
		writeErr(w, 403, err)
	default:
		writeErr(w, 500, err)
	}
}
