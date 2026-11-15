// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/host"
	"github.com/thefoxbyte/foxbyte/internal/update"
)

// Switching edition from the console (the Upgrade modal's Install button).
//
// The engine switches itself: the control plane starts `fox upgrade`'s own path
// as a detached job (host.StartEditionSwitch) and reports on it, from the file
// that job keeps, so the control plane that comes back on the other edition can
// still say how it went. Present in both editions: it is how one leaves
// Standard, and what it knows of Enterprise is a file name and a licence URL.

// startEditionSwitch begins the switch; a variable so tests start nothing.
var startEditionSwitch = host.StartEditionSwitch

// readEditionSwitch reports on it; a variable for the same reason.
var readEditionSwitch = host.ReadEditionSwitch

// registerEditionPublic mounts the one public answer: which edition this
// engine is. fox on a Mac or a Windows PC asks it before every command, to
// notice an engine switched from the console (host.SyncLauncherEdition), so it
// is outside the /api/ sign-in gate, like the API description. It says the
// edition and nothing else.
func registerEditionPublic(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/edition", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"edition": update.ThisEdition()})
	})
}

func registerEditionSwitch(mux *http.ServeMux, store *auth.Store) {
	mux.HandleFunc("POST /api/edition/switch", func(w http.ResponseWriter, r *http.Request) {
		if !isAdmin(r) {
			writeErr(w, 403, fmt.Errorf("only an admin may change the edition"))
			return
		}
		var body struct {
			Edition       string `json:"edition"`
			AcceptLicense bool   `json:"accept_license"`
		}
		if err := decode(r, &body); err != nil {
			writeErr(w, 400, err)
			return
		}
		// Moving to Enterprise means running software under another licence;
		// the console asks for it to be ticked, and so does this.
		if body.Edition == update.EditionEnterprise && !body.AcceptLicense {
			writeErr(w, 400, fmt.Errorf("accept the %s to install it: %s", "FoxByte Enterprise License", host.EnterpriseLicenseURL()))
			return
		}
		u, _ := auth.UserFrom(r.Context())
		detail := "to " + body.Edition
		if body.Edition == update.EditionEnterprise {
			detail += ", Enterprise License accepted"
		}
		// Intent first, and no switch without it (auth.BeginPrivileged). The
		// success keeps its kind, edition.switch_started.
		act, err := store.BeginPrivileged(auth.EvEditionSwitchAsked, auth.EvEditionSwitch, auth.EvEditionSwitchFailed,
			u.Email, "", remoteIP(r), detail)
		if err != nil {
			writeErr(w, 503, err)
			return
		}
		err = startEditionSwitch(body.Edition, u.Email)
		act.Done(err, detail)
		switch {
		case errors.Is(err, host.ErrSameEdition), errors.Is(err, host.ErrSwitchRunning):
			writeErr(w, 409, err)
			return
		case err != nil:
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, 202, map[string]string{"state": "running", "edition": body.Edition})
	})

	mux.HandleFunc("GET /api/edition/switch", func(w http.ResponseWriter, r *http.Request) {
		if !isAdmin(r) {
			writeErr(w, 403, fmt.Errorf("only an admin may see the edition switch"))
			return
		}
		s, ok := readEditionSwitch()
		if !ok {
			writeJSON(w, 200, map[string]string{"state": "none", "edition": update.ThisEdition()})
			return
		}
		writeJSON(w, 200, s)
	})
}
