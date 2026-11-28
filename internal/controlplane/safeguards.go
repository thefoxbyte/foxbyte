// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// registerSafeguards serves the safeguards evidence (point 11.4, Rule 6),
// admins only: the document and the declarations it needs. Producing it and
// declaring are Enterprise (the dpdp feature); reading the declarations is
// free.
func registerSafeguards(mux *http.ServeMux, store *auth.Store) {
	admin := func(w http.ResponseWriter, r *http.Request) (string, bool) {
		if !isAdmin(r) {
			writeErr(w, 403, fmt.Errorf("the safeguards evidence is for admins"))
			return "", false
		}
		u, _ := auth.UserFrom(r.Context())
		return u.Email, true
	}
	fail := func(w http.ResponseWriter, err error) {
		switch {
		case errors.Is(err, branch.ErrNotLicensed):
			writeErr(w, 403, err)
		case errors.Is(err, branch.ErrSafeguardItem), errors.Is(err, auth.ErrVaultDeclaration):
			writeErr(w, 400, err)
		default:
			writeErr(w, 500, err)
		}
	}
	mux.HandleFunc("GET /api/dpdp/evidence", func(w http.ResponseWriter, r *http.Request) {
		by, ok := admin(w, r)
		if !ok {
			return
		}
		ev, err := branch.SafeguardsEvidenceFor(store, branch.SafeguardsOptions{By: by, Access: access.SafeguardAccessOf(store)})
		if err != nil {
			fail(w, err)
			return
		}
		if r.URL.Query().Get("download") == "1" {
			w.Header().Set("Content-Disposition", `attachment; filename="safeguards-evidence.json"`)
		}
		writeJSON(w, 200, ev)
	})
	mux.HandleFunc("GET /api/dpdp/declarations", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := admin(w, r); !ok {
			return
		}
		ds, err := branch.SafeguardDeclarations(store)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": branch.SafeguardItems(), "declarations": ds})
	})
	// {item, value}; an empty value withdraws the declaration.
	mux.HandleFunc("POST /api/dpdp/declarations", func(w http.ResponseWriter, r *http.Request) {
		by, ok := admin(w, r)
		if !ok {
			return
		}
		var b struct {
			Item  string `json:"item"`
			Value string `json:"value"`
		}
		if err := decode(r, &b); err != nil {
			writeErr(w, 400, err)
			return
		}
		d, err := branch.DeclareSafeguard(store, b.Item, b.Value, by)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 201, d)
	})
}
