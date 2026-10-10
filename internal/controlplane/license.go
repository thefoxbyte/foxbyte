// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
	"github.com/thefoxbyte/foxbyte/internal/host"
	"github.com/thefoxbyte/foxbyte/internal/license"
)

// GET /api/license — what this engine's entitlement is, and why.
//
// /api/status already says which edition this build is and which features are
// usable. This says what a person needs in order to act: whether a licence is
// installed at all, what is wrong with it if anything, and what would fix it —
// the same Reason and Action the CLI prints, from the same Status, so the
// console and `fox license show` cannot describe one licence two ways.
//
// It reports what *this process* is honouring (license.Installed), not a fresh
// read of the file. A console that showed a licence activated five minutes ago
// as active, while the running engine was still refusing the features, would be
// worse than showing nothing.
//
// Two tiers, by design. Every signed-in user sees the state, the expiry and the
// wording, because every user may hit a locked page and deserves to know why.
// Who bought the licence and which machine it is tied to are the account's
// details rather than the product's, so they are for admins.
func registerLicense(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/license", func(w http.ResponseWriter, r *http.Request) {
		st := license.Installed()
		out := map[string]any{
			"edition":  edition.Name(),
			"present":  st.Present(),
			"state":    st.State.Code(),
			"unlocks":  st.Unlocks(),
			"features": featureNames(),
			"reason":   st.Reason,
			"action":   st.Action,
		}
		// A Standard build has no licence to describe and needs none: saying so
		// plainly is what lets the console show paid features locked with an
		// explanation rather than an error.
		if !st.Present() {
			if edition.Enterprise {
				out["reason"] = "no licence is installed"
				out["action"] = "run `" + brand.CLI + " license activate <file>`"
			}
			writeJSON(w, 200, out)
			return
		}
		l := st.License
		if !l.NotAfter.IsZero() {
			out["expires"] = l.NotAfter.UTC().Format(time.RFC3339)
		}
		if isAdmin(r) {
			out["id"] = l.ID
			out["customer"] = l.Customer
			// What the licence *names*, as against what this build can serve.
			// They differ when a licence is newer than the binary, and the
			// difference is the thing support asks about first.
			out["licensed"] = l.Features
			out["issuedAt"] = l.IssuedAt.UTC().Format(time.RFC3339)
			out["issuedFor"] = l.Fingerprint
			out["boundTo"] = st.BoundTo
			out["rebinds"] = st.Rebinds
		}
		writeJSON(w, 200, out)
	})

	// POST /api/license — activate a licence from the console.
	//
	// The CLI has done this since licensing landed, and it is the wrong place
	// for the person who needs it: somebody meets a locked feature in the
	// console, and the way out was a terminal, a file on disk and a command
	// they had to be told. Now it is a paste box on the page the lock points
	// at.
	//
	// Admin only. This changes what the whole engine will serve, which is not
	// a decision a branch's user makes.
	mux.HandleFunc("POST /api/license", func(w http.ResponseWriter, r *http.Request) {
		if !isAdmin(r) {
			writeErr(w, 403, fmt.Errorf("only an admin may activate a licence"))
			return
		}
		var body struct {
			License string `json:"license"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, fmt.Errorf("could not read the request: %w", err))
			return
		}
		text := strings.TrimSpace(body.License)
		if text == "" {
			writeErr(w, 400, fmt.Errorf("paste the licence you were sent"))
			return
		}
		var l license.License
		if err := json.Unmarshal([]byte(text), &l); err != nil {
			writeErr(w, 400, fmt.Errorf("that is not a licence: it should be the JSON you were sent, pasted whole"))
			return
		}
		pub, err := license.PublicKey()
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		// A forgery is refused outright and nothing is written. Everything else
		// — expired, bound to another machine — installs with the state saying
		// so, because those are states a real customer is in and each has a
		// different way out. The same rule as `fox license activate`, and it
		// has to be: two ways in that disagree about what is acceptable would
		// be a way around one of them.
		if err := license.CheckSignature(l, pub); err != nil {
			writeErr(w, 400, fmt.Errorf("%w — nothing was installed", err))
			return
		}
		// Bound to whatever it was issued for, not to this machine. Binding on
		// activation would make the mismatch warning unreachable and the rebind
		// record meaningless.
		if err := license.Save(l, l.Fingerprint, 0); err != nil {
			writeErr(w, 500, err)
			return
		}
		// Honoured by this process at once. The entitlement is otherwise read
		// once at startup, and an activation that needed a restart before the
		// console would show it working is most of the friction this endpoint
		// exists to remove.
		st := license.Install()

		u, _ := auth.UserFrom(r.Context())
		secLog.Audit(auth.EvLicenseActivated, u.Email, l.ID, remoteIP(r),
			fmt.Sprintf("%s for %s, via the console", l.ID, l.Customer))

		out := map[string]any{
			"activated": l.ID,
			"customer":  l.Customer,
			"edition":   edition.Name(),
			"state":     st.State.Code(),
			"unlocks":   st.Unlocks(),
			"reason":    st.Reason,
			"action":    st.Action,
			"notes":     activationNotes(st),
		}
		writeJSON(w, 200, out)
	})
}

// activationNotes says what is still left to do, and only when it is.
//
// Two things this endpoint cannot finish on its own, each true in a different
// deployment:
//
//   - The Gateway and the Agent API are separate processes that read the
//     entitlement when they start. The control plane now honours the licence;
//     they will not until they are restarted.
//   - On macOS and Windows the engine runs inside a VM and this process is in
//     it, while `fox license` deliberately runs on the host — the fingerprint
//     has to be read there, because recreating the VM is an ordinary repair
//     and a licence that moved with it would be rebound by a routine fix.
//     There is no channel from here back to the host, so the host's copy is
//     not written: rebuilding the VM would lose this, and `fox license show`
//     on the host will say there is none.
//
// Said rather than hidden. A licence that works until the next repair, with
// nothing having mentioned it, is the kind of surprise that arrives months
// later with no way to connect it to this moment.
func activationNotes(st license.Status) []string {
	var notes []string
	if st.Unlocks() {
		notes = append(notes,
			"The control plane is honouring this now. Restart the engine so the Gateway and the Agent API do too.")
	}
	if host.InGuest() {
		notes = append(notes,
			"This engine runs inside a VM, and only the VM's copy was written. Run `"+brand.CLI+
				" license activate <file>` on your computer as well, or rebuilding the VM will lose it.")
	}
	return notes
}
