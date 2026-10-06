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

// The free side of the line, asserted so it cannot drift: reading an anchor is
// not gated. An install that anchored before upgrading still holds anchors, and
// taking away its ability to check them would punish a customer for the version
// they were on.
func TestReadingTheRecordIsNotGated(t *testing.T) {
	edition.SetEntitlement(nil)
	mux := http.NewServeMux()
	registerLedgerV2(mux)
	for _, path := range []string{
		"/api/branches/main/ledger/integrity",
		"/api/branches/main/ledger/entries",
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
