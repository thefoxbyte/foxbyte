// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckBranchName(t *testing.T) {
	reached := false
	h := checkBranchName(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	for path, want := range map[string]int{
		"/api/branches/dev":               200,
		"/api/branches/dev/suspend":       200,
		"/api/branches":                   200,
		"/api/branches/x%2F..%2Fmain":     400, // one segment that decodes to a path
		"/api/branches/main%40for-x":      400, // a ZFS snapshot of main
		"/api/branches/-rf/ledger/verify": 400,
		"/api/branches/%2E%2E/impact":     400,
		"/api/status":                     200,
	} {
		reached = false
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("DELETE", path, nil))
		got := w.Code
		if reached {
			got = 200
		}
		if got != want {
			t.Errorf("%s: %d, want %d", path, got, want)
		}
	}
}

func TestPipelineSourceMustBeAConnectionString(t *testing.T) {
	for src, ok := range map[string]bool{
		"postgres://u@h/db": true, "mysql://u@h/db": true, "mongodb+srv://h/db": true,
		"":                            false,
		"/home/fox/.fox/secrets.json": false,
		"secrets.json":                false,
		"../../etc/passwd.csv":        false,
		"file:///home/fox/.fox/x.sql": false,
	} {
		if err := checkPipelineSource(src); (err == nil) != ok {
			t.Errorf("checkPipelineSource(%q) = %v, want ok=%v", src, err, ok)
		}
	}
}
