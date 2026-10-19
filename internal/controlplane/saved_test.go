// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"net/http"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

func savedServer(t *testing.T) (*auth.Store, func(key, method, path, body string) (int, map[string]any), map[string]string) {
	t.Helper()
	s, call, k := historyServer(t)
	// historyServer mounts only history; saved queries sit beside it.
	mux := http.NewServeMux()
	registerHistory(mux, s)
	registerSavedQueries(mux, s)
	h := s.Authn(mux)
	_ = call
	return s, func(key, method, path, body string) (int, map[string]any) {
		return serve(t, h, key, method, path, body)
	}, k
}

// Saved queries over the API: the caller's own, a name used once, and the
// answers a client can act on.
func TestSavedQueryRoutes(t *testing.T) {
	_, call, k := savedServer(t)
	code, q := call(k["alice"], "POST", "/api/saved-queries", `{"name":"big","sql":"SELECT * FROM orders WHERE total > 100"}`)
	if code != 201 || q["name"] != "big" {
		t.Fatalf("save: %d %v", code, q)
	}
	id := itoa(int64(q["id"].(float64)))
	if code, _ := call(k["alice"], "POST", "/api/saved-queries", `{"name":"big","sql":"SELECT 2"}`); code != 409 {
		t.Fatalf("the same name again: %d, want 409", code)
	}
	if code, _ := call(k["alice"], "POST", "/api/saved-queries", `{"name":"","sql":"SELECT 2"}`); code != 400 {
		t.Fatalf("no name: %d, want 400", code)
	}
	if _, out := call(k["bob"], "GET", "/api/saved-queries", ""); len(out["queries"].([]any)) != 0 {
		t.Fatalf("bob sees alice's: %v", out)
	}
	for _, m := range []string{"PUT", "DELETE"} {
		if code, _ := call(k["bob"], m, "/api/saved-queries/"+id, `{"name":"bob's"}`); code != 404 {
			t.Errorf("bob %s alice's: %d, want 404", m, code)
		}
	}
	if code, out := call(k["alice"], "PUT", "/api/saved-queries/"+id, `{"name":"orders over 100"}`); code != 200 || out["name"] != "orders over 100" {
		t.Fatalf("rename: %d %v", code, out)
	}
	if _, out := call(k["alice"], "GET", "/api/saved-queries?q=TOTAL", ""); len(out["queries"].([]any)) != 1 {
		t.Fatalf("search: %v", out)
	}
	if code, _ := call(k["alice"], "DELETE", "/api/saved-queries/"+id, ""); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := call(k["alice"], "DELETE", "/api/saved-queries/"+id, ""); code != 404 {
		t.Fatalf("delete again: %d", code)
	}
}

// Search and the failed filter reach the store from the query string.
func TestHistorySearchRoute(t *testing.T) {
	s, call, k := savedServer(t)
	for _, e := range []auth.HistoryEntry{
		{Actor: "alice@x.com", Branch: "main", Source: "api", SQL: "SELECT * FROM orders", OK: true},
		{Actor: "alice@x.com", Branch: "main", Source: "api", SQL: "SELECT * FROM orderz", Error: "no such table"},
		{Actor: "alice@x.com", Branch: "main", Source: "api", SQL: "SELECT 1", OK: true},
	} {
		s.RecordQuery(e)
	}
	if _, out := call(k["alice"], "GET", "/api/history?q=ORDER", ""); len(out["entries"].([]any)) != 2 {
		t.Fatalf("q: %v", out)
	}
	if _, out := call(k["alice"], "GET", "/api/history?q=order&failed=1", ""); len(out["entries"].([]any)) != 1 {
		t.Fatalf("failed: %v", out)
	}
}
