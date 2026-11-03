// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/branch"
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

func TestAuditRecordsRoute(t *testing.T) {
	s, admin, alice, _ := withACL(t)
	var asked branch.AuditQuery
	old := auditRecords
	auditRecords = func(q branch.AuditQuery) ([]branch.AuditEntry, error) {
		asked = q
		return []branch.AuditEntry{{AuditRecord: branch.AuditRecord{Seq: 7, Kind: "statement", Command: "INSERT"}, TxnOutcome: "COMMIT"}}, nil
	}
	t.Cleanup(func() { auditRecords = old })
	mux := http.NewServeMux()
	registerAuditRecords(mux)
	h := s.Authn(mux)
	ka, _, _ := s.CreateAPIKey(admin.ID, "t")
	kb, _, _ := s.CreateAPIKey(alice.ID, "t")

	if code, _ := serve(t, h, kb, "GET", "/api/audit-log/records", ""); code != 403 {
		t.Errorf("not an admin: %d, want 403", code)
	}
	code, out := serve(t, h, ka, "GET", "/api/audit-log/records?branch=main&table=orders&user=bob&limit=5&errors=1", "")
	recs, _ := out["records"].([]any)
	if code != 200 || len(recs) != 1 || asked.Branch != "main" || asked.Table != "orders" || asked.Login != "bob" ||
		asked.Limit != 5 || len(asked.Kinds) != 1 {
		t.Errorf("admin: %d %v, asked %+v", code, out, asked)
	}
	for _, bad := range []string{"limit=0", "limit=1001", "since=yesterday"} {
		if code, _ := serve(t, h, ka, "GET", "/api/audit-log/records?"+bad, ""); code != 400 {
			t.Errorf("%s: %d, want 400", bad, code)
		}
	}
}

func TestAuditQueryFrom(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	q, err := auditQueryFrom(url.Values{"since": {"2h"}}, now)
	if err != nil || !q.Since.Equal(now.Add(-2*time.Hour)) || q.Limit != 100 {
		t.Errorf("%+v %v", q, err)
	}
	q, err = auditQueryFrom(url.Values{"since": {"2026-11-01T00:00:00Z"}}, now)
	if err != nil || q.Since.Format(time.RFC3339) != "2026-11-01T00:00:00Z" {
		t.Errorf("%+v %v", q, err)
	}
	if d := auditReadDetail(branch.AuditQuery{Table: "orders", Kinds: []string{"outcome"}}, 3); d != "3 record(s): table orders, errors only" {
		t.Errorf("%q", d)
	}
}
