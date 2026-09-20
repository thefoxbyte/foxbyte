// SPDX-License-Identifier: AGPL-3.0-or-later

// Package mcp exposes FoxByte's agent-branch operations over the Model Context
// Protocol (MCP), so an AI agent framework can — through one standard interface —
// get its own disposable database, run SQL, see exactly what it changed (from
// the tamper-evident Blackbox), and throw the database away.
//
// It speaks MCP over stdio: newline-delimited JSON-RPC 2.0 on stdin/stdout.
// stdout carries the protocol, so all logging goes to stderr.
package mcp

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/foxbyte/foxbyte/internal/branch"
	"github.com/foxbyte/foxbyte/internal/version"
)

const protocolVersion = "2024-11-05"

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Serve runs the MCP server on stdio until stdin closes. key is the API key the
// server acts as (see auth.go): without a valid one it serves nothing, since
// every tool here can change databases and each change is recorded against the
// key's account.
func Serve(key string) error {
	log.SetOutput(os.Stderr)
	log.SetPrefix("fox mcp: ")
	who, err := authenticate(key)
	if err != nil {
		if errors.Is(err, ErrNoKey) {
			return fmt.Errorf("%s", KeyHelp)
		}
		return fmt.Errorf("%v\n\n%s", err, KeyHelp)
	}
	me = who
	if me.Scope != "" {
		log.Printf("acting as %s, limited to branch %q", me.Actor, me.Scope)
	} else {
		log.Printf("acting as %s", me.Actor)
	}
	dec := json.NewDecoder(bufio.NewReader(os.Stdin))
	out := bufio.NewWriter(os.Stdout)
	enc := json.NewEncoder(out)

	for {
		var req rpcRequest
		if err := dec.Decode(&req); err != nil {
			if err == io.EOF {
				return nil
			}
			log.Printf("decode: %v", err)
			continue
		}
		resp, respond := dispatch(req)
		if !respond {
			continue // a notification gets no response
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
		if err := out.Flush(); err != nil {
			return err
		}
	}
}

func dispatch(req rpcRequest) (rpcResponse, bool) {
	resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		var p struct {
			ClientInfo struct {
				Name string `json:"name"`
			} `json:"clientInfo"`
		}
		_ = json.Unmarshal(req.Params, &p)
		if branch.ValidProvenanceID(p.ClientInfo.Name) {
			clientName = p.ClientInfo.Name
		}
		resp.Result = map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "foxbyte", "version": version.Version},
		}
	case "ping":
		resp.Result = map[string]any{}
	case "tools/list":
		resp.Result = map[string]any{"tools": toolList()}
	case "tools/call":
		resp.Result = callTool(req.Params)
	default:
		if len(req.ID) != 0 {
			resp.Error = &rpcError{Code: -32601, Message: "method not found: " + req.Method}
		}
	}
	// Requests carry an id and get a response; notifications (no id) do not.
	if len(req.ID) == 0 {
		return resp, false
	}
	return resp, true
}

func tool(name, desc string, props map[string]any, required []string) map[string]any {
	if props == nil {
		props = map[string]any{}
	}
	if required == nil {
		required = []string{}
	}
	return map[string]any{
		"name":        name,
		"description": desc,
		"inputSchema": map[string]any{"type": "object", "properties": props, "required": required},
	}
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

func toolList() []map[string]any {
	tools := []map[string]any{
		tool("create_branch",
			"Create a fresh, isolated Postgres database branch for an agent (a copy-on-write clone of main) and return its connection string (DSN).",
			map[string]any{"agent_id": str("identifier for the agent")}, []string{"agent_id"}),
		tool("list_branches", "List the active agent branches and their DSNs.", nil, nil),
		tool("delete_branch", "Delete an agent's branch and all of its data.",
			map[string]any{"agent_id": str("identifier for the agent")}, []string{"agent_id"}),
		tool("run_sql", "Run SQL on a branch (default 'main') and return the result.",
			map[string]any{
				"branch": str("branch name (default main)"),
				"sql":    str("the SQL to run"),
			}, []string{"sql"}),
		tool("changes",
			"Show recent schema changes (DDL) on a branch — who changed what, when, and with which tool — from Blackbox, the tamper-evident record of schema changes.",
			map[string]any{
				"branch": str("branch name (default main)"),
				"limit":  map[string]any{"type": "integer", "description": "max rows (default 50)"},
			}, nil),
		tool("verify_ledger",
			"Verify a branch's Blackbox has not been tampered with (recomputes the hash chain).",
			map[string]any{"branch": str("branch name (default main)")}, nil),
		tool("ledger_integrity",
			"Check a branch's Blackbox against its checkpoint anchors, which are stored outside the database — catches edited, deleted or wiped history even if the hash chain was rewritten.",
			map[string]any{"branch": str("branch name (default main)")}, nil),
		tool("ledger_entries",
			"List a branch's newest Blackbox entries with their ids, newest first — pass an id to branch_before_change.",
			map[string]any{
				"branch": str("branch name (default main)"),
				"limit":  map[string]any{"type": "integer", "description": "max rows (default 50)"},
			}, nil),
		tool("execute_change",
			"Run a schema change (or any SQL) on a branch as this agent, with provenance: it is recorded in Blackbox with this MCP session, the task_id and parent_session_id you pass, and a hash of the call. Blackbox policy rules are previewed first and enforced by the database. Returns JSON: status applied | blocked (the policy rule, SQLSTATE BBX01) | error | preview (dry_run), the policy preview, any warnings (BBX02) and the Blackbox entry ids it wrote. Runs without superuser rights.",
			map[string]any{
				"branch":            str("branch name (default main)"),
				"sql":               str("the SQL to run"),
				"task_id":           str("the task this change is for"),
				"parent_session_id": str("the agent session that started this one"),
				"dry_run":           map[string]any{"type": "boolean", "description": "only preview the policy rules; don't run anything"},
			}, []string{"sql"}),
		tool("impact",
			"Before changing something, see what it would affect: the objects that depend on the table, view, index or column the statement changes (views — including views on views — foreign keys, indexes, triggers, row-level security policies, functions), which other running branches have it, which Blackbox policy rules it triggers, and a low/medium/high score with the reasons. Nothing is run. Pass sql, or object (and column).",
			map[string]any{
				"branch": str("branch name (default main)"),
				"sql":    str("the DDL statement you plan to run"),
				"object": str("a table, view or index name instead of sql"),
				"column": str("a column of that object"),
			}, nil),
		tool("blackbox_diff",
			"Compare two branches' Blackbox histories: where they split, the schema changes made only on each since, and the objects both changed (possible conflicts). Read-only; nothing is merged.",
			map[string]any{
				"a": str("first branch (e.g. main)"),
				"b": str("second branch"),
			}, []string{"a", "b"}),
		tool("policy_check",
			"Preview which Blackbox policy rules a DDL statement would trigger on a branch — warn or block — without running it. A blocked statement fails with SQLSTATE BBX01 (docs/policy-errors.md).",
			map[string]any{
				"branch": str("branch name (default main)"),
				"sql":    str("the DDL statement to check"),
			}, []string{"sql"}),
		tool("branch_before_change",
			"Create a new branch holding main exactly as it was just before a Blackbox entry (its id from `blackbox_entries` or `ledger_entries`) — to inspect or recover from a bad change. main is not modified. Takes a few minutes (base backup + WAL replay).",
			map[string]any{
				"entry_id": map[string]any{"type": "integer", "description": "Blackbox entry id"},
				"branch":   str("source branch (only main is supported)"),
				"name":     str("new branch name (default main-before-<id>)"),
			}, []string{"entry_id"}),
	}
	// The Blackbox names of the ledger tools, listed alongside the originals.
	for _, a := range blackboxToolNames {
		for _, t := range tools {
			if t["name"] == a.ledger {
				alias := map[string]any{}
				for k, v := range t {
					alias[k] = v
				}
				alias["name"] = a.blackbox
				alias["description"] = t["description"].(string) + " Same as " + a.ledger + "."
				tools = append(tools, alias)
			}
		}
	}
	return tools
}

// blackboxToolNames maps each Blackbox tool name to the ledger tool it runs.
// Blackbox is the product name; the original tool names keep working.
var blackboxToolNames = []struct{ blackbox, ledger string }{
	{"verify_blackbox", "verify_ledger"},
	{"blackbox_integrity", "ledger_integrity"},
	{"blackbox_entries", "ledger_entries"},
}

// clientName is the MCP client's name from initialize (the Blackbox actor for
// execute_change); mcpSession is this server process's agent session id.
var (
	clientName = "mcp"
	mcpSession string
)

func sessionID() (string, error) {
	if mcpSession == "" {
		id, err := branch.NewSessionID("mcp")
		if err != nil {
			return "", err
		}
		mcpSession = id
	}
	return mcpSession, nil
}

// jsonError is a tool failure whose message is a JSON document.
type jsonError []byte

func (e jsonError) Error() string { return string(e) }

// resolveTool returns the ledger tool a Blackbox tool name stands for, or name.
func resolveTool(name string) string {
	for _, a := range blackboxToolNames {
		if name == a.blackbox {
			return a.ledger
		}
	}
	return name
}

func callTool(params json.RawMessage) map[string]any {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	_ = json.Unmarshal(params, &p)
	text, err := runTool(p.Name, p.Arguments)
	if err != nil {
		return map[string]any{
			"content": []map[string]any{{"type": "text", "text": err.Error()}},
			"isError": true,
		}
	}
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}}
}

func runTool(name string, args json.RawMessage) (string, error) {
	tool := resolveTool(name)
	// A branch-scoped key reaches one branch and no further.
	scoped, err := applyScope(tool, args)
	if err != nil {
		return "", err
	}
	args = scoped
	switch tool {
	case "create_branch":
		var a struct {
			AgentID string `json:"agent_id"`
		}
		_ = json.Unmarshal(args, &a)
		if a.AgentID == "" {
			return "", fmt.Errorf("agent_id is required")
		}
		info, err := branch.CreateAgentBranch(a.AgentID)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Branch %q is ready — a disposable Postgres isolated from main.\nDSN: %s", info.Branch, info.DSN), nil

	case "list_branches":
		infos, err := branch.ListAgentBranches()
		if err != nil {
			return "", err
		}
		if len(infos) == 0 {
			return "No agent branches.", nil
		}
		var b strings.Builder
		for _, i := range infos {
			fmt.Fprintf(&b, "%s\t%s\n", i.Branch, i.DSN)
		}
		return strings.TrimRight(b.String(), "\n"), nil

	case "delete_branch":
		var a struct {
			AgentID string `json:"agent_id"`
		}
		_ = json.Unmarshal(args, &a)
		if a.AgentID == "" {
			return "", fmt.Errorf("agent_id is required")
		}
		if err := branch.DeleteAgentBranch(a.AgentID); err != nil {
			return "", err
		}
		return fmt.Sprintf("Deleted the branch for agent %q.", a.AgentID), nil

	case "run_sql":
		var a struct {
			Branch string `json:"branch"`
			SQL    string `json:"sql"`
		}
		_ = json.Unmarshal(args, &a)
		if strings.TrimSpace(a.SQL) == "" {
			return "", fmt.Errorf("sql is required")
		}
		// Run as the non-superuser client role, so an agent's SQL is subject to the
		// guardrail and the ledger's append-only protection like any other client.
		if branch.MCPSuperuser() {
			return branch.QueryText(a.Branch, a.SQL)
		}
		return branch.ClientQueryTextAs(a.Branch, a.SQL, "mcp", me.Actor)

	case "changes":
		var a struct {
			Branch string `json:"branch"`
			Limit  int    `json:"limit"`
		}
		_ = json.Unmarshal(args, &a)
		return branch.LedgerText(a.Branch, a.Limit)

	case "verify_ledger":
		var a struct {
			Branch string `json:"branch"`
		}
		_ = json.Unmarshal(args, &a)
		return branch.LedgerVerify(a.Branch)

	case "ledger_integrity":
		var a struct {
			Branch string `json:"branch"`
		}
		_ = json.Unmarshal(args, &a)
		rep, err := branch.Integrity(a.Branch)
		if err != nil {
			return "", err
		}
		return rep.Summary(), nil

	case "ledger_entries":
		var a struct {
			Branch string `json:"branch"`
			Limit  int    `json:"limit"`
		}
		_ = json.Unmarshal(args, &a)
		entries, err := branch.LedgerEntries(a.Branch, a.Limit)
		if err != nil {
			return "", err
		}
		return branch.FormatLedgerEntries(entries), nil

	case "execute_change":
		var a struct {
			Branch          string `json:"branch"`
			SQL             string `json:"sql"`
			TaskID          string `json:"task_id"`
			ParentSessionID string `json:"parent_session_id"`
			DryRun          bool   `json:"dry_run"`
		}
		_ = json.Unmarshal(args, &a)
		sid, err := sessionID()
		if err != nil {
			return "", err
		}
		stdout := os.Stdout // see branch_before_change
		os.Stdout = os.Stderr
		res, err := branch.ExecuteChange(branch.ExecuteChangeRequest{
			Branch: a.Branch, SQL: a.SQL, TaskID: a.TaskID, ParentSessionID: a.ParentSessionID, DryRun: a.DryRun,
			SessionID: sid, AgentID: clientName, Tool: "mcp",
		})
		os.Stdout = stdout
		if err != nil {
			return "", err
		}
		b, _ := json.MarshalIndent(res, "", "  ")
		if res.Status == "blocked" || res.Status == "error" {
			return "", jsonError(b) // isError, with the same JSON body
		}
		return string(b), nil

	case "impact":
		var a struct {
			Branch string `json:"branch"`
			SQL    string `json:"sql"`
			Object string `json:"object"`
			Column string `json:"column"`
		}
		_ = json.Unmarshal(args, &a)
		stdout := os.Stdout // see branch_before_change
		os.Stdout = os.Stderr
		rep, err := branch.Impact(a.Branch, a.SQL, a.Object, a.Column)
		os.Stdout = stdout
		if err != nil {
			return "", err
		}
		b, _ := json.MarshalIndent(rep, "", "  ")
		return string(b), nil

	case "blackbox_diff":
		var a struct {
			A string `json:"a"`
			B string `json:"b"`
		}
		_ = json.Unmarshal(args, &a)
		if a.A == "" || a.B == "" {
			return "", fmt.Errorf("a and b are required")
		}
		stdout := os.Stdout // see branch_before_change
		os.Stdout = os.Stderr
		d, err := branch.DiffLedgers(a.A, a.B)
		os.Stdout = stdout
		if err != nil {
			return "", err
		}
		b, _ := json.MarshalIndent(d, "", "  ")
		return string(b), nil

	case "policy_check":
		var a struct {
			Branch string `json:"branch"`
			SQL    string `json:"sql"`
		}
		_ = json.Unmarshal(args, &a)
		tag, matches, err := branch.PolicyCheck(a.Branch, a.SQL)
		if err != nil {
			return "", err
		}
		return branch.FormatPolicyCheck(tag, matches), nil

	case "branch_before_change":
		var a struct {
			EntryID int64  `json:"entry_id"`
			Branch  string `json:"branch"`
			Name    string `json:"name"`
		}
		_ = json.Unmarshal(args, &a)
		if a.EntryID <= 0 {
			return "", fmt.Errorf("entry_id is required")
		}
		// The restore starts containers through helpers that echo to stdout, which
		// here carries the protocol. Requests are handled one at a time and the
		// encoder holds the real stdout, so point os.Stdout at stderr meanwhile.
		stdout := os.Stdout
		os.Stdout = os.Stderr
		res, err := branch.BranchBeforeEntry(a.Branch, a.EntryID, a.Name, nil)
		os.Stdout = stdout
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Branch %q is ready: %s as it was just before ledger entry %d (%s %s), recovered to %s %s from base backup %s in %ds.",
			res.Branch, res.Source, res.EntryID, res.CommandTag, res.Object, res.TargetKind, res.Target, res.BaseBackup, res.Seconds), nil

	default:
		return "", fmt.Errorf("unknown tool: %s", name)
	}
}
