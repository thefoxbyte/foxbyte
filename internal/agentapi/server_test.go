// SPDX-License-Identifier: AGPL-3.0-or-later

package agentapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// An agent's branch is a copy of main, so it holds main's personal data, and
// the agent reads it as it is unless masking applies (PRIV-1). Creating one
// says so in the response, beside the DSN, and still creates it: masking is
// opt-in, and the warning is what makes it a choice.
func TestCreateWarnsOfUnmaskedPersonalData(t *testing.T) {
	oldCreate, oldProv, oldWarn := createAgentBranch, createWithProvenance, agentWarnings
	t.Cleanup(func() { createAgentBranch, createWithProvenance, agentWarnings = oldCreate, oldProv, oldWarn })
	createAgentBranch = func(owner int64, id string) (branch.Info, error) {
		return branch.Info{Agent: id, Branch: "agent-" + id, DSN: "postgresql://x", Status: "ready"}, nil
	}
	createWithProvenance = func(owner int64, id string, p branch.Provenance) (branch.Info, branch.AgentSession, error) {
		info, _ := createAgentBranch(owner, id)
		return info, branch.AgentSession{SessionID: "s1"}, nil
	}
	// The engine's own sentence, for a branch holding three unmasked columns.
	want := branch.UnmaskedSummary{Branch: "agent-a", Scanned: true, Columns: 3,
		ByCategory: map[string]int{"aadhaar": 2, "email": 1},
		Examples:   []string{"customers.aadhaar", "customers.email", "leads.aadhaar"}}.Warning("agents using it", "")
	var asked string
	agentWarnings = func(name, owner string) []string {
		asked = name
		if name == "agent-a" {
			return []string{want}
		}
		return nil
	}
	h := http.NewServeMux()
	h.HandleFunc("POST /agents/{id}/branch", createHandler(nil, access.NewWith(nil, func(string) bool { return false })))

	post := func(id, body string) map[string]any {
		t.Helper()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/agents/"+id+"/branch", strings.NewReader(body)))
		if w.Code != http.StatusCreated {
			t.Fatalf("%s: %d %s", id, w.Code, w.Body)
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	for _, body := range []string{"", `{"task_id":"t1"}`} {
		out := post("a", body)
		ws, _ := out["warnings"].([]any)
		if len(ws) != 1 || ws[0] != want {
			t.Errorf("body %q: warnings %v, want %q", body, out["warnings"], want)
		}
		if !strings.Contains(want, "2 Aadhaar columns, 1 email column (customers.aadhaar") || !strings.Contains(want, "agents using it see real values") {
			t.Errorf("the warning reads %q", want)
		}
		if out["dsn"] != "postgresql://x" || asked != "agent-a" {
			t.Errorf("body %q: %v (asked about %q)", body, out, asked)
		}
	}
	// Nothing to say is said by leaving the field out.
	if out := post("b", ""); out["warnings"] != nil {
		t.Errorf("warnings %v for a branch with nothing to warn about", out["warnings"])
	}
}
