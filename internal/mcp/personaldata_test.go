// SPDX-License-Identifier: AGPL-3.0-or-later

package mcp

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// fakeWarnings stands in for the engine's judgement: agent-a and main hold
// unmasked personal data, nothing else does. It records who asked.
func fakeWarnings(t *testing.T) *[]string {
	t.Helper()
	oldW, oldC, oldN, oldMe, oldACL := personalDataWarnings, createAgentBranch, noticed, me, acl
	t.Cleanup(func() { personalDataWarnings, createAgentBranch, noticed, me, acl = oldW, oldC, oldN, oldMe, oldACL })
	noticed = map[string]bool{}
	var asked []string
	personalDataWarnings = func(name, account, who, owner string) []string {
		asked = append(asked, name+" as "+account)
		if name == "agent-a" || name == "main" {
			return []string{"this branch holds unmasked personal data: 2 Aadhaar columns (customers.aadhaar, leads.aadhaar); " + who + " see real values."}
		}
		return nil
	}
	createAgentBranch = func(owner int64, id string) (branch.Info, error) {
		return branch.Info{Agent: id, Branch: "agent-" + id, DSN: "postgresql://x"}, nil
	}
	return &asked
}

// create_branch says it in its result, beside the DSN, and makes the branch
// all the same.
func TestCreateBranchWarnsOfUnmaskedPersonalData(t *testing.T) {
	asked := fakeWarnings(t)
	s, err := auth.Open(auth.Config{DBPath: filepath.Join(t.TempDir(), "a.db"), WebOrigin: "http://x"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	u, _ := s.CreateUser("o@x.io", "password1")
	me = identity{Actor: u.Email, User: u}
	acl = access.NewWith(s, func(string) bool { return true })

	res := callTool([]byte(`{"name":"create_branch","arguments":{"agent_id":"a"}}`))
	text := res["content"].([]map[string]any)[0]["text"].(string)
	if res["isError"] == true || !strings.Contains(text, "DSN: postgresql://x") {
		t.Fatalf("create_branch: %v", res)
	}
	if !strings.Contains(text, "\nWarning: this branch holds unmasked personal data: 2 Aadhaar columns") ||
		!strings.Contains(text, "agents using it see real values") {
		t.Errorf("no warning in %q", text)
	}
	// The branch's own role is what the agent logs in as: no account masking.
	if len(*asked) != 1 || (*asked)[0] != "agent-a as " {
		t.Errorf("asked %v", *asked)
	}
	if res := callTool([]byte(`{"name":"create_branch","arguments":{"agent_id":"b"}}`)); strings.Contains(
		res["content"].([]map[string]any)[0]["text"].(string), "Warning") {
		t.Errorf("a warning for a branch with nothing to warn about: %v", res)
	}
}

// An agent working on such a branch is told once per session: on its first
// call that reaches the branch, and not again.
func TestSessionNoticeOncePerBranch(t *testing.T) {
	asked := fakeWarnings(t)
	me = identity{Actor: "agent:o@x.io", Scope: "agent-a"}
	if n := initializeNotice(); !strings.Contains(n, "this agent and whoever reads its results see real values") {
		t.Errorf("a scoped key's session starts without the notice: %q", n)
	}
	if n := sessionNotice("run_sql", []byte(`{"branch":"agent-a"}`)); n != "" {
		t.Errorf("said again after initialize: %q", n)
	}

	noticed = map[string]bool{}
	me = identity{Actor: "agent:o@x.io"}
	if n := initializeNotice(); n != "" {
		t.Errorf("an account key has no one branch to warn about at the start: %q", n)
	}
	n := sessionNotice("run_sql", []byte(`{"sql":"select 1"}`))
	if !strings.HasPrefix(n, "Notice (main): this branch holds unmasked personal data") {
		t.Errorf("first call on main: %q", n)
	}
	if n := sessionNotice("changes", []byte(`{}`)); n != "" {
		t.Errorf("second call on main: %q", n)
	}
	if n := sessionNotice("run_sql", []byte(`{"branch":"dev"}`)); n != "" {
		t.Errorf("dev holds nothing to warn about: %q", n)
	}
	// Judged as the agent's own role: a masked account's agent key reads masks.
	if (*asked)[len(*asked)-1] != "dev as agent:o@x.io" {
		t.Errorf("asked %v", *asked)
	}
}

// The notice is a content item of its own, after the answer, so a tool's JSON
// answer is still JSON (execute_change's is parsed by clients).
func TestNoticeApartFromTheAnswer(t *testing.T) {
	res := toolResult(`{"status":"applied"}`, "Notice (main): holds unmasked personal data")
	content := res["content"].([]map[string]any)
	if len(content) != 2 {
		t.Fatalf("content %v", content)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(content[0]["text"].(string)), &v); err != nil || v["status"] != "applied" {
		t.Errorf("the answer is not the tool's JSON: %q (%v)", content[0]["text"], err)
	}
	if content[1]["text"] != "Notice (main): holds unmasked personal data" {
		t.Errorf("notice %q", content[1]["text"])
	}
	if c := toolResult("ok", "")["content"].([]map[string]any); len(c) != 1 || c[0]["text"] != "ok" {
		t.Errorf("without a notice: %v", c)
	}
}
