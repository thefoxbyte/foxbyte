// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// The access review report over HTTP (point 4.8).
//
//	GET /api/access-review?dormant=90                          the report, as JSON
//	GET /api/access-review?dormant=90&format=csv&section=keys  one of its tables, as CSV
//
// Admins only: it lists every account and credential on the install. Each
// report produced is in the security log.
func registerAccessReview(mux *http.ServeMux, store *auth.Store) {
	mux.HandleFunc("GET /api/access-review", func(w http.ResponseWriter, r *http.Request) {
		if !requireFeature(w, edition.AccessReview) {
			return
		}
		if !isAdmin(r) {
			writeErr(w, 403, errors.New("only an admin may produce the access review"))
			return
		}
		q := r.URL.Query()
		o := access.ReviewOptions{}
		if v := q.Get("dormant"); v != "" {
			// 0 asked for is refused, not taken as "the default": a
			// report for a window nobody chose is not the one they asked for.
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				writeErr(w, 400, fmt.Errorf("dormant is 1 to 3650 days, not %q", v))
				return
			}
			o.DormantDays = n
		}
		rep, err := access.ProduceReview(store, o)
		switch {
		case err == nil:
		case errors.Is(err, access.ErrBadReview):
			writeErr(w, 400, err)
			return
		default:
			writeErr(w, 500, err)
			return
		}
		u, _ := auth.UserFrom(r.Context())
		if secLog != nil {
			secLog.Audit(auth.EvAccessReviewed, u.Email, "", remoteIP(r), rep.LogLine())
		}
		switch q.Get("format") {
		case "", "json":
			writeJSON(w, 200, rep)
		case "csv":
			section := q.Get("section")
			if section == "" {
				section = "accounts"
			}
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
			w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="access-review-%s-%s.csv"`,
				rep.Generated.Format("2006-01-02"), section))
			if err := rep.CSV(section, w); err != nil {
				// Nothing has been written for an unknown section: the
				// header row is the first write.
				w.Header().Set("Content-Type", "application/json")
				w.Header().Del("Content-Disposition")
				writeErr(w, 400, err)
			}
		default:
			writeErr(w, 400, fmt.Errorf("format is json or csv, not %q", q.Get("format")))
		}
	})
}
