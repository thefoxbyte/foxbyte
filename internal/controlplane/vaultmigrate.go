// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// Moving a branch's Aadhaar numbers into the vault over HTTP (point 13, step
// 13.3).
//
//	POST /api/branches/{name}/personal-data/aadhaar/migrate     {"columns": [...], "format": "", "dryRun": true}
//	GET  /api/branches/{name}/personal-data/aadhaar/migrations  the branch's runs, newest first
//	GET  /api/vault/orphans                                     keys made on branches now gone (admins)
//	POST /api/vault/orphans/delete                              {"run": id}, or every run's (admins)
//
// Under personal-data, so Manage on the branch (its owner, or an admin). A
// preview needs only that. Moving needs a use grant on Aadhaar too, unless the
// caller is an admin, and its calls count against the grant. Main is moved
// only by an admin, and only once a branch made from main has moved the same
// columns with nothing left (branch.MigrateToVault).
func registerVaultMigrate(mux *http.ServeMux) {
	fail := func(w http.ResponseWriter, err error) {
		if errors.Is(err, branch.ErrVaultRehearsal) {
			writeErr(w, 409, err)
			return
		}
		vaultFail(w, err)
	}
	mux.HandleFunc("POST /api/branches/{name}/personal-data/aadhaar/migrate", func(w http.ResponseWriter, r *http.Request) {
		if !requireFeature(w, edition.Vault) {
			return
		}
		var body struct {
			Columns []string `json:"columns"`
			Format  string   `json:"format"`
			DryRun  bool     `json:"dryRun"`
		}
		if r.ContentLength != 0 {
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
				writeErr(w, 400, errors.New(`the body must be JSON: {"columns": ["schema.table.column", ...], "format": "opaque"|"legacy", "dryRun": true}`))
				return
			}
		}
		name := r.PathValue("name")
		u, _ := auth.UserFrom(r.Context())
		admin := isAdmin(r)
		if name == "main" && !admin && !body.DryRun {
			writeErr(w, 403, errors.New("main's numbers are moved into the vault by an admin"))
			return
		}
		if !admin && !body.DryRun {
			if _, err := secLog.HeldVaultGrant(u.Email, branch.VaultMigrateKind, auth.VaultUse); err != nil {
				msg := fmt.Sprintf("moving numbers into the vault needs a use grant on %s, given by an admin", branch.VaultMigrateKind)
				secLog.Audit(auth.EvVaultRefused, u.Email, branch.VaultMigrateKind, remoteIP(r), "migrate on "+name+": "+msg)
				writeErr(w, 403, errors.New(msg))
				return
			}
		}
		if _, err := branch.EnsureRunning(name); err != nil {
			writeErr(w, 404, err)
			return
		}
		caller := branch.VaultCaller{Email: u.Email, Admin: admin, IP: remoteIP(r)}
		m, err := branch.MigrateToVault(secLog, name, branch.VaultMigrateOptions{
			Actor: u.Email, IP: remoteIP(r), Columns: body.Columns, Format: body.Format, DryRun: body.DryRun,
			Call: func(vaultActor, path string, b []byte) ([]byte, int, error) {
				c := caller
				c.Actor = vaultActor
				return branch.VaultCallAs(secLog, c, path, b)
			},
		})
		if err != nil {
			if m.ID == 0 {
				fail(w, err)
				return
			}
			// The run is kept, with how far it got: a refusal before anything
			// was written (main not rehearsed) is a 409, anything else the
			// report with its error.
			code := 500
			switch {
			case errors.Is(err, branch.ErrVaultRehearsal):
				code = 409
			case errors.Is(err, branch.ErrVaultForbidden):
				code = 403
			case errors.Is(err, branch.ErrVaultLimit):
				code = 429
			case errors.Is(err, branch.ErrInvalidRequest):
				code = 400
			}
			writeJSON(w, code, map[string]any{"error": err.Error(), "migration": m})
			return
		}
		writeJSON(w, 200, m)
	})
	mux.HandleFunc("GET /api/branches/{name}/personal-data/aadhaar/migrations", func(w http.ResponseWriter, r *http.Request) {
		if !requireFeature(w, edition.Vault) {
			return
		}
		ms, err := branch.VaultMigrations(secLog, r.PathValue("name"), 50)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, ms)
	})
	admins := func(w http.ResponseWriter, r *http.Request) bool {
		if !requireFeature(w, edition.Vault) {
			return false
		}
		if !isAdmin(r) {
			writeErr(w, 403, errors.New("the vault is for admins"))
			return false
		}
		return true
	}
	mux.HandleFunc("GET /api/vault/orphans", func(w http.ResponseWriter, r *http.Request) {
		if !admins(w, r) {
			return
		}
		orphans, err := branch.VaultOrphans(secLog)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, orphans)
	})
	mux.HandleFunc("POST /api/vault/orphans/delete", func(w http.ResponseWriter, r *http.Request) {
		if !admins(w, r) {
			return
		}
		var body struct {
			Run int64 `json:"run"`
		}
		if r.ContentLength != 0 {
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&body); err != nil || body.Run < 0 {
				writeErr(w, 400, errors.New(`the body must be JSON: {"run": a migration's number}, or empty for every run's orphaned keys`))
				return
			}
		}
		u, _ := auth.UserFrom(r.Context())
		res, err := branch.DeleteVaultOrphans(secLog, u.Email, remoteIP(r), body.Run)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, res)
	})
}
