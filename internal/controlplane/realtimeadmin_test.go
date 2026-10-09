//go:build enterprise

// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

func doReq(mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	return rec
}

// Any non-nil ConnectionState means "this request arrived over TLS", which is
// all sslModeFor reads.
var tlsStateForTest = tls.ConnectionState{}

// What the console's realtime routes require before they do anything.
//
// These sit on the inner /api/ mux, so authentication and authorization are
// already done by the time a handler runs — which is exactly why the two checks
// that are *not* done by the mux need asserting here: the licence, and whether
// the engine has been set up to carry a feed at all. Skipping either turns a
// locked feature into a 500, or a request into a silent no-op.

// Every route that changes something needs Manage, not Use.
//
// A branch's user can read its verdicts — that is the front door, and it needs
// Use. Choosing what streams, running DDL, and minting a credential an
// application subscribes with are the owner's decisions. The rule is a prefix
// so a route added later cannot default to Use by being forgotten.
func TestRealtimeRoutesNeedManage(t *testing.T) {
	for _, c := range []struct{ method, tail string }{
		{"POST", "realtime/enable"},
		{"POST", "realtime/disable"},
		{"POST", "realtime/prepare"},
		{"GET", "realtime/keys"},
		{"POST", "realtime/keys"},
		{"DELETE", "realtime/keys/k1"},
		// And one that does not exist yet, to prove the rule is the prefix
		// rather than a list somebody has to remember to extend.
		{"POST", "realtime/something-added-later"},
	} {
		if got := needFor(c.method, c.tail); got != access.Manage {
			t.Errorf("needFor(%s, %q) = %v, want Manage", c.method, c.tail, got)
		}
	}
}

// The licence is checked before the engine, and both are checked before any
// handler runs. 403 for the licence — there is nothing to hide, the edition is
// already on /api/status — and 409 for the engine, because nothing is wrong
// with the request: the feed has simply not been turned on.
func TestRealtimeAdminRefusesWithoutALicence(t *testing.T) {
	edition.SetEntitlement(nil)
	mux := http.NewServeMux()
	registerRealtimeAdmin(mux, nil)

	for _, c := range []struct{ method, path string }{
		{"POST", "/api/branches/main/realtime/enable"},
		{"POST", "/api/branches/main/realtime/disable"},
		{"POST", "/api/branches/main/realtime/prepare"},
		{"GET", "/api/branches/main/realtime/keys"},
		{"POST", "/api/branches/main/realtime/keys"},
		{"DELETE", "/api/branches/main/realtime/keys/k1"},
	} {
		rec := doReq(mux, c.method, c.path, "")
		if rec.Code != 403 {
			t.Errorf("%s %s: status %d, want 403: %s", c.method, c.path, rec.Code, rec.Body.String())
		}
		// A closed door that does not say where the key is, is just a closed
		// door — the same contract the other gated routes keep.
		for _, want := range []string{"Enterprise", "/api/license"} {
			if !strings.Contains(rec.Body.String(), want) {
				t.Errorf("%s %s: the refusal does not mention %q: %s", c.method, c.path, want, rec.Body.String())
			}
		}
	}
}

// A table name is two fields in a body, not a segment in a path. These are the
// values that must not reach the engine, whatever a caller sends.
func TestTableRefNormalise(t *testing.T) {
	t.Run("an empty schema means public", func(t *testing.T) {
		got, err := tableRef{Table: "orders"}.normalise()
		if err != nil {
			t.Fatal(err)
		}
		if got.Schema != "public" || got.Table != "orders" {
			t.Fatalf("got %+v, want public.orders", got)
		}
	})
	t.Run("whitespace is trimmed", func(t *testing.T) {
		got, err := tableRef{Schema: "  app ", Table: " orders "}.normalise()
		if err != nil {
			t.Fatal(err)
		}
		if got.Schema != "app" || got.Table != "orders" {
			t.Fatalf("got %+v, want app.orders", got)
		}
	})
	t.Run("a missing table is refused, with the shape to send", func(t *testing.T) {
		_, err := tableRef{Schema: "public"}.normalise()
		if err == nil {
			t.Fatal("accepted a request with no table")
		}
		if !strings.Contains(err.Error(), `"table"`) {
			t.Errorf("the error does not show what to send: %v", err)
		}
	})
	// Identifiers are quoted by the enterprise package on the way to SQL. This
	// is the cheap refusal in front of that, which also keeps the message
	// readable when the cause is a typo rather than an attack.
	t.Run("nothing that could end a statement", func(t *testing.T) {
		for _, bad := range []string{
			`orders"; DROP TABLE x --`,
			"orders'",
			"orders;",
			"orders\\",
			"two words",
			"orders\nSELECT 1",
			"orders\ttab",
			"back`tick",
		} {
			if _, err := (tableRef{Schema: "public", Table: bad}).normalise(); err == nil {
				t.Errorf("accepted table name %q", bad)
			}
			if _, err := (tableRef{Schema: bad, Table: "orders"}).normalise(); err == nil {
				t.Errorf("accepted schema name %q", bad)
			}
		}
	})
}

// The DSN handed back names the host the caller actually reached, and tells the
// truth about the certificate.
//
// An install reachable at a name the operator typed should hand back that name:
// a connection string that says 127.0.0.1 to somebody on another machine is
// worse than none at all. And a plain-HTTP loopback fallback has to say
// sslmode=disable, or the client tries https and fails.
func TestMintedDSNDescribesThisInstall(t *testing.T) {
	r, _ := http.NewRequest("GET", "https://db.example.com:8443/x", nil)
	r.Host = "db.example.com:8443"
	if got := requestHost(r); got != "db.example.com:8443" {
		t.Errorf("requestHost = %q, want the host the caller used", got)
	}
	// No TLS on the request: the install fell back to plain HTTP on loopback.
	if got := sslModeFor(r); got != "disable" {
		t.Errorf("sslModeFor(plain) = %q, want disable", got)
	}
	r.TLS = &tlsStateForTest
	if got := sslModeFor(r); got != "require" {
		t.Errorf("sslModeFor(TLS) = %q, want require — a self-signed certificate is encrypted but not verifiable", got)
	}
}
