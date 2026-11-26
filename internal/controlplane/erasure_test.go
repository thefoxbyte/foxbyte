// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"net/http/httptest"
	"testing"
)

// An erasure request erases and rewrites main and every branch in one call:
// it has an export's hour to write its answer, not a request's five minutes.
func TestErasureRoutesHaveTheLongBudget(t *testing.T) {
	for _, c := range []struct {
		method, path string
		want         kind
	}{
		{"POST", "/api/dpdp/erasures", kindExport},
		{"POST", "/api/dpdp/erasures/7/apply", kindExport},
		{"POST", "/api/v1/dpdp/erasures/7/branches/dev/remake", kindExport},
		{"GET", "/api/dpdp/erasures/7", kindNormal},
	} {
		if got := routeKind(httptest.NewRequest(c.method, c.path, nil)); got != c.want {
			t.Errorf("%s %s: %v, want %v", c.method, c.path, got, c.want)
		}
	}
}
