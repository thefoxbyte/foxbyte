// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

func TestAuditLogRoute(t *testing.T) {
	s, admin, alice, _ := withACL(t)
	old := auditLogState
	auditLogState = func(*auth.Store) auditLogReply {
		return auditLogReply{On: true, Mode: "default", Root: "/dbpool/audit", Used: 10, Quota: 100,
			Pending: []string{"old"}, Setup: "fox audit-log setup", Off: "fox audit-log off",
			Findings: []branch.AuditFinding{{Kind: "heartbeat", Branch: "main", Detail: "no heartbeat"}}}
	}
	t.Cleanup(func() { auditLogState = old })
	mux := http.NewServeMux()
	registerAuditLog(mux, s)
	h := s.Authn(mux)
	ka, _, _ := s.CreateAPIKey(admin.ID, "t")
	kb, _, _ := s.CreateAPIKey(alice.ID, "t")

	if code, _ := serve(t, h, kb, "GET", "/api/audit-log", ""); code != 403 {
		t.Errorf("a user who is not an admin: %d, want 403", code)
	}
	code, out := serve(t, h, ka, "GET", "/api/audit-log", "")
	if code != 200 || out["on"] != true || out["mode"] != "default" || out["quota"] != float64(100) ||
		out["setup"] != "fox audit-log setup" || len(out["pending"].([]any)) != 1 || len(out["findings"].([]any)) != 1 {
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
		// Step 6: marking every table with confirmed personal data changes
		// marks, and which tables hold it is the owner's to read.
		{"POST", "audit/tables/personal-data", access.Manage},
		{"GET", "personal-data/unaudited", access.Manage},
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

// Forensic mode, retention and purge: admins only, and what is not valid is
// refused before anything changes.
func TestAuditSettingsRoutes(t *testing.T) {
	s, admin, alice, _ := withACL(t)
	mux := http.NewServeMux()
	registerAuditSettings(mux)
	h := s.Authn(mux)
	ka, _, _ := s.CreateAPIKey(admin.ID, "t")
	kb, _, _ := s.CreateAPIKey(alice.ID, "t")
	for _, c := range []struct{ method, path, body string }{
		{"PUT", "/api/audit-log/mode", `{"forensic":true,"reason":"x"}`},
		{"PUT", "/api/audit-log/retention", `{"days":30}`},
		{"POST", "/api/audit-log/purge", `{"user":"bob"}`},
		{"PUT", "/api/audit-log/forward", `{"url":"https://siem.example.com"}`},
		{"DELETE", "/api/audit-log/forward", ``},
		{"POST", "/api/audit-log/forward/send", ``},
	} {
		if code, _ := serve(t, h, kb, c.method, c.path, c.body); code != 403 {
			t.Errorf("not an admin, %s %s: %d, want 403", c.method, c.path, code)
		}
	}
	for _, c := range []struct{ method, path, body, want string }{
		{"PUT", "/api/audit-log/mode", `{"forensic":true,"reason":"  "}`, "--reason"},
		{"PUT", "/api/audit-log/mode", `{"forensic":true,"branch":"../x","reason":"why"}`, "name"},
		{"PUT", "/api/audit-log/retention", `{"days":0}`, "1 to 3650"},
		{"POST", "/api/audit-log/purge", `{"user":""}`, "login"},
		{"PUT", "/api/audit-log/mode", `not json`, "JSON"},
		{"PUT", "/api/audit-log/forward", `{"url":"http://siem.example.com"}`, "unencrypted"},
		{"PUT", "/api/audit-log/forward", `{"url":"https://u:p@siem.example.com"}`, "password"},
		{"PUT", "/api/audit-log/forward", `{"url":"syslog://logs.example.com","token":"t"}`, "https:// only"},
		{"PUT", "/api/audit-log/forward", `{"url":"https://siem.example.com","ca_pem":"x"}`, "no PEM"},
		{"PUT", "/api/audit-log/forward", `[]`, "JSON"},
	} {
		code, out := serve(t, h, ka, c.method, c.path, c.body)
		if msg, _ := out["error"].(string); code != 400 || !strings.Contains(msg, c.want) {
			t.Errorf("%s %s %s: %d %v", c.method, c.path, c.body, code, out)
		}
	}
}

// Marking every table with confirmed personal data is Enterprise, and says
// so before it touches the branch.
func TestAuditPersonalTablesRouteIsEnterprise(t *testing.T) {
	if edition.Enterprise {
		t.Skip("the Standard edition's refusal")
	}
	s, admin, _, _ := withACL(t)
	mux := http.NewServeMux()
	registerAuditMarks(mux)
	h := s.Authn(mux)
	ka, _, _ := s.CreateAPIKey(admin.ID, "t")
	code, out := serve(t, h, ka, "POST", "/api/branches/main/audit/tables/personal-data", "")
	if msg, _ := out["error"].(string); code != 403 || !strings.Contains(msg, "Enterprise") {
		t.Fatalf("%d %v", code, out)
	}
}
