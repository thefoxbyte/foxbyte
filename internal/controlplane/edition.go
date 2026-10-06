// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"fmt"
	"net/http"

	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// featureNames is the paid features this engine can currently serve, as plain
// strings for /api/status. Always a list, never null: the console iterates it,
// and an empty list is the honest answer for a Standard build.
func featureNames() []string {
	out := []string{}
	for _, f := range edition.Available() {
		out = append(out, string(f))
	}
	return out
}

// requireFeature answers the request and returns false when this engine may not
// serve f.
//
// 403 rather than 404: unlike a branch the caller may not reach, there is
// nothing to hide here — the route exists, the edition and the licensed
// features are already on /api/status, and pretending the endpoint is absent
// would leave a console unable to tell "not available to you" from "your engine
// is too old". And not 500: nothing failed.
func requireFeature(w http.ResponseWriter, f edition.Feature) bool {
	if edition.Has(f) {
		return true
	}
	writeErr(w, 403, fmt.Errorf("%s is part of %s Enterprise, and this is the %s edition — see GET /api/license",
		edition.Describe(f), brand.Product, edition.Name()))
	return false
}
