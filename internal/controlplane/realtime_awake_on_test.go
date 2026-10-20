//go:build enterprise

// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A realtime handler that reads a branch's database runs only once the branch
// is up: a suspended branch is resumed first, and one that cannot be is
// answered as missing, without the handler running.
func TestAwakeResumesBeforeTheHandler(t *testing.T) {
	old := ensureRunning
	t.Cleanup(func() { ensureRunning = old })

	var order []string
	ensureRunning = func(name string) (string, error) { order = append(order, "resume "+name); return "addr", nil }
	h := awake(func(w http.ResponseWriter, r *http.Request, name string) {
		order = append(order, "handle "+name)
		w.WriteHeader(299)
	})
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest("GET", "/", nil), "rtidle")
	if w.Code != 299 || len(order) != 2 || order[0] != "resume rtidle" || order[1] != "handle rtidle" {
		t.Fatalf("%d %v", w.Code, order)
	}

	order = nil
	ensureRunning = func(name string) (string, error) { return "", errors.New(`branch "gone" does not exist`) }
	w = httptest.NewRecorder()
	h(w, httptest.NewRequest("GET", "/", nil), "gone")
	if w.Code != 404 || len(order) != 0 {
		t.Fatalf("%d %v", w.Code, order)
	}
}
