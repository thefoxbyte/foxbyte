// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/edition"
	"github.com/thefoxbyte/foxbyte/internal/license"
)

// installedStatusForTest gives the package an entitlement to report. A real
// one cannot be made here: a licence has to be signed with the private key,
// which is deliberately not in the repository or in CI.
func installedStatusForTest(t *testing.T) license.Status {
	t.Helper()
	st := license.Status{
		State:   license.Active,
		BoundTo: "machine-a",
		Rebinds: 1,
		License: license.License{
			ID: "FB-0007", Customer: "Acme Ltd", Edition: "enterprise",
			Features:    []string{"anchors", "export"},
			IssuedAt:    time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:    time.Date(2027, 10, 1, 0, 0, 0, 0, time.UTC),
			Fingerprint: "machine-a",
		},
	}
	t.Cleanup(license.SetInstalledForTest(st))
	return st
}

// get asks /api/license as a user and returns the decoded body.
func getLicense(t *testing.T, s *auth.Store, u auth.User) map[string]any {
	t.Helper()
	mux := http.NewServeMux()
	registerLicense(mux)
	key, _, err := s.CreateAPIKey(u.ID, "t")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/api/license", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	rec := httptest.NewRecorder()
	s.Authn(mux).ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%v: %s", err, rec.Body.String())
	}
	return out
}

// An install with no licence has to say so plainly rather than erroring: that
// is what lets the console show a paid feature locked with an explanation.
func TestLicenseEndpointWithNoLicence(t *testing.T) {
	s, _, alice, _ := withACL(t)
	out := getLicense(t, s, alice)
	if out["present"] != false {
		t.Errorf("present = %v, want false", out["present"])
	}
	if out["unlocks"] != false {
		t.Errorf("unlocks = %v, want false", out["unlocks"])
	}
	if out["edition"] != edition.Name() {
		t.Errorf("edition = %v, want %q", out["edition"], edition.Name())
	}
	// Always a list, never null: the console iterates it.
	if _, ok := out["features"].([]any); !ok {
		t.Errorf("features = %#v, want a list", out["features"])
	}
	// Nothing to expire, and no customer to name.
	for _, k := range []string{"expires", "customer", "id", "boundTo"} {
		if _, ok := out[k]; ok {
			t.Errorf("%s is reported when no licence is installed", k)
		}
	}
}

// Who bought the licence and which machine it is tied to are the account's
// details, not the product's. Every signed-in user needs the state and the
// wording — they may be the one looking at a locked page — but not those.
func TestLicenseEndpointHidesTheCustomerFromNonAdmins(t *testing.T) {
	s, admin, alice, _ := withACL(t)
	st := installedStatusForTest(t)

	user := getLicense(t, s, alice)
	for _, k := range []string{"id", "customer", "boundTo", "issuedFor", "rebinds", "licensed"} {
		if _, ok := user[k]; ok {
			t.Errorf("a non-admin was shown %q", k)
		}
	}
	// But they do get what they need to understand a locked page.
	for _, k := range []string{"state", "unlocks", "reason", "action", "features", "edition", "present"} {
		if _, ok := user[k]; !ok {
			t.Errorf("a non-admin was not shown %q", k)
		}
	}
	if user["state"] != st.State.Code() {
		t.Errorf("state = %v, want %q", user["state"], st.State.Code())
	}

	adm := getLicense(t, s, admin)
	if adm["customer"] != st.License.Customer {
		t.Errorf("an admin saw customer = %v, want %q", adm["customer"], st.License.Customer)
	}
	if adm["id"] != st.License.ID {
		t.Errorf("an admin saw id = %v, want %q", adm["id"], st.License.ID)
	}
	if adm["boundTo"] != st.BoundTo {
		t.Errorf("an admin saw boundTo = %v, want %q", adm["boundTo"], st.BoundTo)
	}
	if _, ok := adm["expires"]; !ok {
		t.Error("an admin was not shown the expiry")
	}
}

// The endpoint must answer from what this process is honouring, never from a
// fresh read of the file: a console showing a licence activated five minutes
// ago as active, while the running engine still refused the features, would be
// worse than showing nothing.
func TestLicenseEndpointReportsWhatTheProcessHonours(t *testing.T) {
	s, _, alice, _ := withACL(t)
	st := installedStatusForTest(t)
	out := getLicense(t, s, alice)
	if out["unlocks"] != st.Unlocks() {
		t.Errorf("unlocks = %v, want %v — the endpoint is not reading the installed status",
			out["unlocks"], st.Unlocks())
	}
}

func TestLicenseEndpointNeedsAuth(t *testing.T) {
	s, _, _, _ := withACL(t)
	mux := http.NewServeMux()
	registerLicense(mux)
	rec := httptest.NewRecorder()
	s.Authn(mux).ServeHTTP(rec, httptest.NewRequest("GET", "/api/license", nil))
	if rec.Code != 401 {
		t.Errorf("an unauthenticated request got %d, want 401", rec.Code)
	}
}
