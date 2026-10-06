// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// 403, not 404 and not 500. There is nothing to hide — the edition and the
// licensed features are already on /api/status — and a 404 would leave a
// console unable to tell "not available to you" from "your engine is too old".
// Nothing failed, so it is not a 500 either.
func TestCheckpointRouteRefusesWithoutTheFeature(t *testing.T) {
	edition.SetEntitlement(nil)
	mux := http.NewServeMux()
	registerLedgerV2(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("POST", "/api/branches/main/ledger/checkpoint", nil))
	if rec.Code != 403 {
		t.Fatalf("status %d, want 403: %s", rec.Code, rec.Body.String())
	}
	// The refusal has to name the feature and where to look, or it is just a
	// closed door.
	for _, want := range []string{"Enterprise", "/api/license"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("the refusal does not mention %q: %s", want, rec.Body.String())
		}
	}
}

// Every route a licence closes, in one place, so a new one added without a gate
// shows up as a gap here rather than as a feature given away.
func TestTheGatedRoutesRefuseWithoutALicence(t *testing.T) {
	edition.SetEntitlement(nil)
	mux := http.NewServeMux()
	registerLedgerV2(mux)
	registerImpact(mux)
	registerPolicy(mux, nil)
	for _, c := range []struct{ method, path string }{
		{"POST", "/api/branches/main/ledger/checkpoint"},
		{"GET", "/api/branches/main/ledger/export"},
		{"POST", "/api/branches/main/impact"},
		{"POST", "/api/branches/main/policies"},
		{"PUT", "/api/branches/main/policies/r1"},
		{"DELETE", "/api/branches/main/policies/r1"},
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
		if rec.Code != 403 {
			t.Errorf("%s %s = %d, want 403: %s", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
}

// The free side of the line, asserted so it cannot drift.
//
// These are what a person still needs after an install changes edition: the
// rule that just blocked them, the record of what happened, the anchors they
// already hold. An install that used a feature before upgrading keeps
// everything it produced and can still read it.
func TestReadingTheRecordIsNotGated(t *testing.T) {
	edition.SetEntitlement(nil)
	mux := http.NewServeMux()
	registerLedgerV2(mux)
	registerImpact(mux)
	registerPolicy(mux, nil)
	for _, path := range []string{
		"/api/branches/main/ledger/integrity",
		"/api/branches/main/ledger/entries",
		"/api/branches/main/policies",
		"/api/branches/main/policies/evaluations",
		"/api/ledger/diff?a=main&b=other",
		"/api/blackbox/diff?a=main&b=other",
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		// Without a running branch these answer 404 or 500; what matters is
		// that they are never refused for the licence.
		if rec.Code == 403 {
			t.Errorf("%s was refused as a paid feature: %s", path, rec.Body.String())
		}
	}
}
