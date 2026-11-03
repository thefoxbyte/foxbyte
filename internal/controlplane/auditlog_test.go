// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"net/http"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/access"
)

func TestAuditLogRoute(t *testing.T) {
	s, admin, alice, _ := withACL(t)
	old := auditLogState
	auditLogState = func() auditLogReply {
		return auditLogReply{On: true, Mode: "default", Root: "/dbpool/audit", Used: 10, Quota: 100,
			Pending: []string{"old"}, Setup: "fox audit-log setup", Off: "fox audit-log off"}
	}
	t.Cleanup(func() { auditLogState = old })
	mux := http.NewServeMux()
	registerAuditLog(mux)
	h := s.Authn(mux)
	ka, _, _ := s.CreateAPIKey(admin.ID, "t")
	kb, _, _ := s.CreateAPIKey(alice.ID, "t")

	if code, _ := serve(t, h, kb, "GET", "/api/audit-log", ""); code != 403 {
		t.Errorf("a user who is not an admin: %d, want 403", code)
	}
	code, out := serve(t, h, ka, "GET", "/api/audit-log", "")
	if code != 200 || out["on"] != true || out["mode"] != "default" || out["quota"] != float64(100) ||
		out["setup"] != "fox audit-log setup" || len(out["pending"].([]any)) != 1 {
		t.Errorf("an admin: %d %v", code, out)
	}
}

// Changing a mark is the owner's (Manage); reading the marks is Use, as the
// grants are in the catalog for anyone to read.
func TestAuditMarkRoutesNeed(t *testing.T) {
	for _, c := range []struct {
		method, tail string
		want         access.Level
	}{
		{"GET", "audit/tables", access.Use},
		{"PUT", "audit/tables/public/orders", access.Manage},
		{"DELETE", "audit/tables/public/orders", access.Manage},
		{"POST", "audit/anything", access.Manage},
	} {
		if got := needFor(c.method, c.tail); got != c.want {
			t.Errorf("%s %s: %v, want %v", c.method, c.tail, got, c.want)
		}
	}
}
