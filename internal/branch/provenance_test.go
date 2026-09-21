// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestValidProvenanceID(t *testing.T) {
	for _, ok := range []string{"task-42", "JIRA 123", "sess:abc/1", "ünïcode", strings.Repeat("a", 200)} {
		if !ValidProvenanceID(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "a\nb", "a\x01b", "tab\there", strings.Repeat("a", 201)} {
		if ValidProvenanceID(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := (Provenance{TaskID: "bad\x00"}).validate(); !errors.Is(err, ErrInvalidRequest) || !strings.Contains(err.Error(), "task_id") {
		t.Errorf("validate: %v", err)
	}
	if (Provenance{}).Requested() || !(Provenance{ParentSessionID: "p"}).Requested() {
		t.Error("Requested is wrong")
	}
}

func TestNewSessionID(t *testing.T) {
	a, err := NewSessionID("mcp")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewSessionID("mcp")
	if !regexp.MustCompile(`^mcp-[0-9a-f]{16}$`).MatchString(a) || a == b {
		t.Errorf("session ids %q, %q", a, b)
	}
}

func TestCallHash(t *testing.T) {
	h := CallHash("execute_change", "main", "CREATE TABLE t(x int)", "task-1", "")
	if len(h) != 64 || h != CallHash("execute_change", "main", "CREATE TABLE t(x int)", "task-1", "") {
		t.Fatalf("hash not deterministic: %s", h)
	}
	for _, other := range []string{
		CallHash("execute_change", "qa", "CREATE TABLE t(x int)", "task-1", ""),
		CallHash("execute_change", "main", "CREATE TABLE t(y int)", "task-1", ""),
		CallHash("execute_change", "main", "CREATE TABLE t(x int)", "task-2", ""),
		CallHash("execute_change", "main", "CREATE TABLE t(x int)", "task-1", "p"),
		CallHash("run_sql", "main", "CREATE TABLE t(x int)", "task-1", ""),
		// field boundaries must not collide
		CallHash("execute_change", "main", "CREATE TABLE t(x int)task-1", "", ""),
	} {
		if other == h {
			t.Error("different arguments produced the same hash")
		}
	}
}

func TestProvenanceSQL(t *testing.T) {
	task := "it's"
	q := startSessionSQL(AgentSession{SessionID: "s1", AgentID: "agent-a", TaskID: &task})
	for _, want := range []string{"'s1'", "'agent-a'", "NULL", "'it''s'", "ON CONFLICT (session_id) DO NOTHING"} {
		if !strings.Contains(q, want) {
			t.Errorf("session SQL lost %q:\n%s", want, q)
		}
	}
	d := sessionDefaultsSQL(Provenance{SessionID: "s1", TaskID: "t'1"})
	for _, want := range []string{
		"ALTER DATABASE appdb SET bb.session = 's1';",
		"ALTER DATABASE appdb SET bb.task = 't''1';",
		"ALTER DATABASE appdb RESET bb.parent_session;",
	} {
		if !strings.Contains(d, want) {
			t.Errorf("defaults SQL lost %q:\n%s", want, d)
		}
	}
}

func TestClassifyExecError(t *testing.T) {
	var res ExecuteChangeResult
	detail := `{"v":1,"rule_id":"drop-column","action":"block","command":"ALTER TABLE","matched":null,"reason":"r","hint":"h","override":"db_admin","evaluation_id":3,"blackbox_id":9,"impact":null}`
	if err := classifyExecError(&res, &pgconn.PgError{Code: "BBX01", Message: "Blackbox policy: r (rule drop-column)", Detail: detail}); err != nil {
		t.Fatal(err)
	}
	if res.Status != "blocked" || res.Policy == nil || res.Policy.RuleID != "drop-column" || *res.Policy.BlackboxID != 9 || res.Error.Code != "BBX01" {
		t.Fatalf("blocked: %+v", res)
	}
	res = ExecuteChangeResult{}
	if err := classifyExecError(&res, &pgconn.PgError{Code: "42P07", Message: `relation "t" already exists`}); err != nil {
		t.Fatal(err)
	}
	if res.Status != "error" || res.Policy != nil || res.Error.Code != "42P07" {
		t.Fatalf("error: %+v", res)
	}
	other := errors.New("connection refused")
	if classifyExecError(&ExecuteChangeResult{}, other) != other {
		t.Error("a non-database error must be returned")
	}

	n := noticeFrom(&pgconn.Notice{Severity: "NOTICE", Code: "BBX02", Message: "Blackbox policy warning: r (rule drop-index)",
		Detail: `{"v":1,"rule_id":"drop-index","action":"warn","command":"DROP INDEX","reason":"r","hint":"h"}`})
	if n.Policy == nil || n.Policy.RuleID != "drop-index" {
		t.Errorf("warning notice: %+v", n)
	}
	if n := noticeFrom(&pgconn.Notice{Severity: "NOTICE", Code: "00000", Message: "hello"}); n.Policy != nil {
		t.Errorf("plain notice got a policy: %+v", n)
	}
}

func TestFormatAgentSessions(t *testing.T) {
	if FormatAgentSessions(nil) != "No agent sessions." {
		t.Error("empty")
	}
	task := "task-1"
	out := FormatAgentSessions([]AgentSession{{SessionID: "mcp-1", AgentID: "claude", TaskID: &task, Entries: 3}})
	if !strings.Contains(out, "mcp-1") || !strings.Contains(out, "task-1") || !strings.HasSuffix(out, "3") {
		t.Errorf("table:\n%s", out)
	}
}
