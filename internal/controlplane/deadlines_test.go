// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"net/http/httptest"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/httpx"
)

// Each route gets the budget that fits it, by either spelling of its path:
// an upload a long read, a stream no overall write deadline, an export a long
// one, and everything else the short ordinary budget.
func TestRouteBudgets(t *testing.T) {
	t.Setenv("FOX_HTTP_TIMEOUT", "")
	t.Setenv("FOX_UPLOAD_TIMEOUT", "")
	t.Setenv("FOX_EXPORT_TIMEOUT", "")
	b := routeBudgets()
	normal := httpx.Budget{Read: httpx.DefaultRequestTimeout, Write: httpx.DefaultRequestTimeout}
	for _, c := range []struct {
		method, path string
		want         httpx.Budget
	}{
		{"POST", "/api/import/file", httpx.Budget{Read: httpx.DefaultUploadTimeout}},
		{"POST", "/api/v1/import/file", httpx.Budget{Read: httpx.DefaultUploadTimeout}},
		{"POST", "/api/import", httpx.Budget{Read: httpx.DefaultRequestTimeout}},
		{"POST", "/api/pipelines/7/run", httpx.Budget{Read: httpx.DefaultRequestTimeout}},
		{"GET", "/api/branches/dev/realtime", httpx.Budget{Read: httpx.DefaultRequestTimeout}},
		{"GET", realtimeAPIPrefix + "/branches/dev/stream", httpx.Budget{Read: httpx.DefaultRequestTimeout}},
		{"POST", "/api/branches/dev/export", httpx.Budget{Read: httpx.DefaultRequestTimeout, Write: httpx.DefaultExportTimeout}},
		{"GET", "/api/v1/branches/dev/ledger/export", httpx.Budget{Read: httpx.DefaultRequestTimeout, Write: httpx.DefaultExportTimeout}},
		{"POST", "/api/branches/dev/query", normal},
		{"GET", "/api/status", normal},
		{"GET", "/api/import", normal},
	} {
		if got := b(httptest.NewRequest(c.method, c.path, nil)); got != c.want {
			t.Errorf("%s %s: %+v, want %+v", c.method, c.path, got, c.want)
		}
	}
}

func TestUploadSpelledEitherWay(t *testing.T) {
	for _, p := range []string{"/api/import/file", "/api/v1/import/file"} {
		if !isUpload(httptest.NewRequest("POST", p, nil)) {
			t.Errorf("%s is the upload route, with its own body cap", p)
		}
	}
}
