// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// requestsServer is the change-request routes over a temp store, with
// admin@x.com as the admin. It returns the store, its file, and a caller that
// sends a request as the admin.
func requestsServer(t *testing.T) (*auth.Store, string, func(method, path, body string) *httptest.ResponseRecorder) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "a.db")
	s, err := auth.Open(auth.Config{DBPath: path, WebOrigin: "http://x"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	admin, _ := s.CreateUser("admin@x.com", "password1")
	old, oldLog := acl, secLog
	acl, secLog = access.NewWith(s, func(e string) bool { return e == "admin@x.com" }), s
	t.Cleanup(func() { acl, secLog = old, oldLog })
	key, _, _ := s.CreateAPIKey(admin.ID, "t")
	mux := http.NewServeMux()
	registerRequests(mux, s)
	h := s.Authn(mux)
	return s, path, func(method, p, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, p, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+key)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
}

func entitlePromotion(t *testing.T) {
	t.Helper()
	if !edition.Enterprise {
		t.Skip("a Standard build cannot entitle promotion")
	}
	edition.SetEntitlement(func(f edition.Feature) bool { return f == edition.Promotion })
	t.Cleanup(func() { edition.SetEntitlement(nil) })
}

func kinds(t *testing.T, s *auth.Store) []string {
	t.Helper()
	evs, err := s.SecurityEvents(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range evs {
		if strings.HasPrefix(e.Kind, "branch.change_") {
			out = append(out, e.Kind)
		}
	}
	return out
}

func openRequest(t *testing.T, s *auth.Store) auth.ChangeRequest {
	t.Helper()
	c, _, err := s.OpenChangeRequest(auth.CLIUser, auth.NewChangeRequest{Source: "dev", Target: "main",
		Entries: `[{"id":1,"command":"CREATE TABLE","object":"public.t","sql":"CREATE TABLE t ()"}]`, EntryKey: "1"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRejectingWritesIntentAndOutcome(t *testing.T) {
	s, _, call := requestsServer(t)
	c := openRequest(t, s)
	if w := call("POST", "/api/requests/"+itoa(c.ID)+"/reject", `{"note":"no"}`); w.Code != 200 {
		t.Fatalf("reject: %d %s", w.Code, w.Body)
	}
	if got := strings.Join(kinds(t, s), " "); got != auth.EvChangeDecideStarted+" "+auth.EvChangeDecided {
		t.Errorf("events = %s", got)
	}
}

func TestApprovingWritesIntentAndOutcomeForBoth(t *testing.T) {
	entitlePromotion(t)
	s, _, call := requestsServer(t)
	c := openRequest(t, s)
	old := applyClaimed
	applyClaimed = func(st *auth.Store, c auth.ChangeRequest, _ string) (int, error, error) {
		return 1, nil, st.FinishChangeRequest(c.ID, 1, "")
	}
	t.Cleanup(func() { applyClaimed = old })
	if w := call("POST", "/api/requests/"+itoa(c.ID)+"/approve", `{}`); w.Code != 200 {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	want := []string{auth.EvChangeDecideStarted, auth.EvChangeApplyStarted, auth.EvChangeApplied, auth.EvChangeDecided}
	if got := strings.Join(kinds(t, s), " "); got != strings.Join(want, " ") {
		t.Errorf("events = %s\nwant     %s", got, strings.Join(want, " "))
	}
}

// Fail closed: with the intent unwritable, nothing is decided and nothing is
// applied, and the request is still open for when the log is back.
func TestADecisionIsRefusedWhenTheIntentCannotBeWritten(t *testing.T) {
	s, path, call := requestsServer(t)
	c := openRequest(t, s)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER refuse_intents BEFORE INSERT ON security_events
		WHEN NEW.kind LIKE '%started' BEGIN SELECT RAISE(ABORT, 'disk full'); END`); err != nil {
		t.Fatal(err)
	}
	applied := false
	old := applyClaimed
	applyClaimed = func(*auth.Store, auth.ChangeRequest, string) (int, error, error) { applied = true; return 1, nil, nil }
	t.Cleanup(func() { applyClaimed = old })

	paths := []string{"/reject"}
	if edition.Enterprise {
		edition.SetEntitlement(func(f edition.Feature) bool { return f == edition.Promotion })
		t.Cleanup(func() { edition.SetEntitlement(nil) })
		paths = append(paths, "/approve")
	}
	for _, p := range paths {
		w := call("POST", "/api/requests/"+itoa(c.ID)+p, `{}`)
		if w.Code != 503 {
			t.Errorf("%s with no security log: %d %s", p, w.Code, w.Body)
		}
	}
	if applied {
		t.Error("the request was applied with no intent in the log")
	}
	if got, _ := s.ChangeRequest(c.ID); got.Status != auth.RequestOpen {
		t.Errorf("the request was decided: %+v", got)
	}
}

// Asking twice for the same changes returns the request already open.
func TestASecondAskReturnsTheOpenRequest(t *testing.T) {
	entitlePromotion(t)
	s, _, call := requestsServer(t)
	_ = s
	oldB, oldH := buildChangeRequest, requestHistory
	buildChangeRequest = func(_, _ string, _ []auth.ChangeRequest, opts branch.RequestOptions) (branch.RequestPlan, error) {
		return branch.RequestPlan{Entries: []branch.RequestEntry{{ID: 3, CommandTag: "CREATE TABLE", Statement: "CREATE TABLE t ()"}},
			IncludeData: opts.IncludeData, OmittedCount: 1,
			Omitted: []branch.OmittedEntry{{ID: 4, CommandTag: "DELETE", Object: "public.t", Reason: "a data change"}}}, nil
	}
	requestHistory = func(*auth.Store, string, string) ([]auth.ChangeRequest, error) { return nil, nil }
	t.Cleanup(func() { buildChangeRequest, requestHistory = oldB, oldH })

	first := call("POST", "/api/branches/dev/request", `{"target":"main"}`)
	if first.Code != 201 {
		t.Fatalf("first: %d %s", first.Code, first.Body)
	}
	var a, b requestView
	_ = json.Unmarshal(first.Body.Bytes(), &a)
	if a.IncludeData || a.OmittedCount != 1 || len(a.Omitted) != 1 || a.Omitted[0].ID != 4 {
		t.Errorf("the request does not show what it left out: %+v", a)
	}
	second := call("POST", "/api/branches/dev/request", `{"target":"main"}`)
	_ = json.Unmarshal(second.Body.Bytes(), &b)
	if second.Code != 200 || !b.Existing || b.ID != a.ID {
		t.Fatalf("second: %d, %+v; want #%d back", second.Code, b, a.ID)
	}
	// The same set of entries is the same request, whichever way it was asked
	// for: the statements applied would be the same ones.
	third := call("POST", "/api/branches/dev/request", `{"target":"main","include_data":true}`)
	var c requestView
	_ = json.Unmarshal(third.Body.Bytes(), &c)
	if third.Code != 200 || !c.Existing || c.ID != a.ID {
		t.Fatalf("third: %d %s", third.Code, third.Body)
	}
}
