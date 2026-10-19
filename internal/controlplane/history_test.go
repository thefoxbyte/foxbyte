// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

// historyServer is the history routes behind real sign-in, with alice's and
// bob's keys and the admin's.
func historyServer(t *testing.T) (*auth.Store, func(key, method, path, body string) (int, map[string]any), map[string]string) {
	t.Helper()
	s, admin, alice, bob := withACL(t)
	mux := http.NewServeMux()
	registerHistory(mux, s)
	h := s.Authn(mux)
	keys := map[string]string{}
	for name, u := range map[string]auth.User{"admin": admin, "alice": alice, "bob": bob} {
		k, _, _ := s.CreateAPIKey(u.ID, "t")
		keys[name] = k
	}
	call := func(key, method, path, body string) (int, map[string]any) {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+key)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		out := map[string]any{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	return s, call, keys
}

// Over the API a person reads and deletes their own history and nothing else,
// an admin included.
func TestHistoryRoutesAreYourOwn(t *testing.T) {
	s, call, k := historyServer(t)
	for _, e := range []auth.HistoryEntry{
		{Actor: "alice@x.com", Branch: "main", Source: "api", SQL: "SELECT 'alice'", OK: true},
		{Actor: "bob@x.com", Branch: "main", Source: "api", SQL: "SELECT 'bob'", OK: true},
	} {
		if _, err := s.RecordQuery(e); err != nil {
			t.Fatal(err)
		}
	}
	code, out := call(k["alice"], "GET", "/api/history", "")
	es, _ := out["entries"].([]any)
	if code != 200 || len(es) != 1 || es[0].(map[string]any)["sql"] != "SELECT 'alice'" {
		t.Fatalf("alice: %d %v", code, out)
	}
	if _, out := call(k["admin"], "GET", "/api/history", ""); len(out["entries"].([]any)) != 0 {
		t.Fatalf("an admin read others' history over the API: %v", out)
	}
	if _, out := call(k["admin"], "GET", "/api/history?user=alice@x.com", ""); len(out["entries"].([]any)) != 0 {
		t.Fatalf("?user= reached alice's history: %v", out)
	}
	bobs, _ := s.History("bob@x.com", auth.HistoryQuery{})
	id := bobs[0].ID
	if code, _ := call(k["alice"], "DELETE", "/api/history/"+itoa(id), ""); code != 404 {
		t.Fatalf("alice deleting bob's entry: %d, want 404", code)
	}
	if code, _ := call(k["bob"], "DELETE", "/api/history/"+itoa(id), ""); code != 204 {
		t.Fatalf("bob deleting his own: %d", code)
	}
	code, out = call(k["alice"], "DELETE", "/api/history", "")
	if code != 200 || out["deleted"] != float64(1) {
		t.Fatalf("alice purging hers: %d %v", code, out)
	}
	ev, _ := s.RecentSecurityEvents(20)
	found := false
	for _, e := range ev {
		if e.Kind == auth.EvHistoryPurged && e.Actor == "alice@x.com" && e.Subject == "alice@x.com" {
			found = true
			if strings.Contains(e.Detail, "SELECT") {
				t.Fatalf("the security log holds SQL: %q", e.Detail)
			}
		}
	}
	if !found {
		t.Fatal("the purge is not in the security log")
	}
}

// Anyone can turn their own history off; only an admin can switch the
// install's or change its retention.
func TestHistorySettingsRoutes(t *testing.T) {
	s, call, k := historyServer(t)
	code, out := call(k["alice"], "GET", "/api/history/settings", "")
	if code != 200 || out["enabled"] != true || out["retention_days"] != float64(90) || out["mine"] != true || out["admin"] != false {
		t.Fatalf("%d %v", code, out)
	}
	if code, out = call(k["alice"], "PUT", "/api/history/settings", `{"mine":false}`); code != 200 || out["mine"] != false {
		t.Fatalf("alice turning hers off: %d %v", code, out)
	}
	if !s.HistoryOptedOut("alice@x.com") || s.HistoryOptedOut("bob@x.com") {
		t.Fatal("the switch reached the wrong person")
	}
	for _, body := range []string{`{"enabled":false}`, `{"retention_days":7}`} {
		if code, _ := call(k["alice"], "PUT", "/api/history/settings", body); code != 403 {
			t.Errorf("alice %s: %d, want 403", body, code)
		}
	}
	if set, _ := s.HistorySettings(); !set.Enabled || set.RetentionDays != 90 {
		t.Fatalf("a refused change applied: %+v", set)
	}
	if code, out = call(k["admin"], "PUT", "/api/history/settings", `{"enabled":false,"retention_days":30}`); code != 200 || out["enabled"] != false || out["retention_days"] != float64(30) {
		t.Fatalf("admin: %d %v", code, out)
	}
	if code, _ := call(k["admin"], "PUT", "/api/history/settings", `{"retention_days":0}`); code != 400 {
		t.Fatalf("retention 0: %d", code)
	}
	if code, _ := call(k["alice"], "PUT", "/api/history/settings", `not json`); code != 400 {
		t.Fatalf("a body that is not JSON: %d", code)
	}
}

// What history keeps of a run: the rows across every statement, and the
// first failure.
func TestQueryOutcome(t *testing.T) {
	one := map[string]any{"rows": [][]any{{1}, {2}}, "results": []map[string]any{{"rows": [][]any{{1}, {2}}}}}
	if n, e := queryOutcome(one); n != 2 || e != "" {
		t.Fatalf("%d %q", n, e)
	}
	script := map[string]any{"error": "boom", "results": []map[string]any{
		{"rows": [][]any{{1}}}, {"rows": [][]any{}, "error": "boom"},
	}}
	if n, e := queryOutcome(script); n != 1 || e != "boom" {
		t.Fatalf("%d %q", n, e)
	}
	if n, e := queryOutcome(map[string]any{"error": "no such table"}); n != 0 || e != "no such table" {
		t.Fatalf("%d %q", n, e)
	}
	o := SQLOutput{Results: []SQLResult{{Rows: [][]any{{1}, {2}}}, {Error: "x"}}}
	if n, err := o.Outcome(); n != 2 || err == nil || err.Error() != "x" {
		t.Fatalf("%d %v", n, err)
	}
}

// The console's own reads say so, and a request that does not say is a query
// someone ran.
func TestRequestSource(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer k")
	if auth.RequestSource(r) != "api" {
		t.Fatal("a key is the API")
	}
	r.AddCookie(&http.Cookie{Name: "dbengine_session", Value: "x"})
	if auth.RequestSource(r) != "console" {
		t.Fatal("a session is the console")
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }
