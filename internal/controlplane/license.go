// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"net/http"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
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
}
