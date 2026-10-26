// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

// Blackbox agent provenance: which agent session, task and parent session caused
// a change. A session is recorded in bb.agent_sessions (internal/ledger/
// provenance.sql); the changes it makes carry the session id in the Blackbox
// entry and the task, parent session and tool-call hash in its capture row
// (bb.ledger_ext), which checkpoints anchor.

// Provenance is what a caller may say about an agent run.
type Provenance struct {
	SessionID       string `json:"session_id,omitempty"`
	TaskID          string `json:"task_id,omitempty"`
	ParentSessionID string `json:"parent_session_id,omitempty"`
	// ActFor is an application identity token naming whom the session is
	// started for (F1). Checked by the caller (auth.CheckAppToken), whose
	// verdict is App; the token itself is never stored.
	ActFor string `json:"act_for,omitempty"`
	// App is that verdict. Never read from a request: only the engine sets it.
	App *auth.AppAssertion `json:"-"`
}

// Requested reports whether the caller supplied any provenance.
func (p Provenance) Requested() bool {
	return p.SessionID != "" || p.TaskID != "" || p.ParentSessionID != "" || p.ActFor != ""
}

func (p Provenance) validate() error {
	for field, v := range map[string]string{"session_id": p.SessionID, "task_id": p.TaskID, "parent_session_id": p.ParentSessionID} {
		if v != "" && !ValidProvenanceID(v) {
			return fmt.Errorf("%w: %s must be 1–200 printable characters", ErrInvalidRequest, field)
		}
	}
	return nil
}

// AgentSession is one row of bb.agent_sessions, with how many Blackbox entries
// carry its id.
type AgentSession struct {
	SessionID       string  `json:"session_id"`
	AgentID         string  `json:"agent_id"`
	ParentSessionID *string `json:"parent_session_id"`
	TaskID          *string `json:"task_id"`
	Tool            *string `json:"tool"`
	StartedAt       string  `json:"started_at,omitempty"`
	Entries         int     `json:"entries"`
	// Whom the session was started for, where an application said so:
	// app_state is "asserted by <application>" (with "(key reported
	// compromised)" where that applies) or "none", and absent for a session
	// nobody said anything about.
	AppFor   *string `json:"app_for,omitempty"`
	AppState *string `json:"app_state,omitempty"`
	AppKid   *string `json:"app_kid,omitempty"`
	AppNote  *string `json:"app_note,omitempty"`
	// app is the verdict to record when the session is started.
	app *auth.AppAssertion
}

// ValidProvenanceID reports whether s may be used as a session, task or parent
// session id: 1–200 printable characters.
func ValidProvenanceID(s string) bool {
	if s == "" || len(s) > 200 {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// NewSessionID returns prefix-<16 hex characters>.
func NewSessionID(prefix string) (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + "-" + hex.EncodeToString(b), nil
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// CallHash is the sha256 (hex) of a tool call's arguments, recorded as
// bb.call_hash so a Blackbox entry can be tied to the exact call that caused it.
func CallHash(tool, branchName, sql, taskID, parentSessionID string) string {
	b, _ := json.Marshal(struct {
		Tool            string `json:"tool"`
		Branch          string `json:"branch"`
		SQL             string `json:"sql"`
		TaskID          string `json:"task_id"`
		ParentSessionID string `json:"parent_session_id"`
	}{tool, branchName, sql, taskID, parentSessionID})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func startSessionSQL(s AgentSession) string {
	if s.app == nil {
		return fmt.Sprintf(`INSERT INTO bb.agent_sessions (session_id, agent_id, parent_session_id, task_id, tool)
VALUES (%s, %s, %s, %s, %s) ON CONFLICT (session_id) DO NOTHING`,
			quoteLiteral(s.SessionID), quoteLiteral(s.AgentID), sqlTextOrNull(s.ParentSessionID), sqlTextOrNull(s.TaskID), sqlTextOrNull(s.Tool))
	}
	// Named only when there is something to record, so a branch whose
	// sessions table predates them still records the rest.
	a := s.app
	return fmt.Sprintf(`INSERT INTO bb.agent_sessions (session_id, agent_id, parent_session_id, task_id, tool,
  app_actor, app_state, app_issuer, app_kid, app_tenant, app_note)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (session_id) DO NOTHING`,
		quoteLiteral(s.SessionID), quoteLiteral(s.AgentID), sqlTextOrNull(s.ParentSessionID), sqlTextOrNull(s.TaskID), sqlTextOrNull(s.Tool),
		sqlTextOrNull(strPtr(a.Actor)), quoteLiteral(a.State), sqlTextOrNull(strPtr(a.Issuer)), sqlTextOrNull(strPtr(a.Kid)),
		sqlTextOrNull(strPtr(a.Tenant)), sqlTextOrNull(strPtr(a.Note)))
}

func provenanceErr(name string, err error) error {
	if strings.Contains(err.Error(), "bb.agent_sessions") && strings.Contains(err.Error(), "does not exist") {
		return fmt.Errorf("Blackbox provenance isn't installed on %q — run: fox blackbox upgrade %s", name, name)
	}
	return err
}

// StartAgentSession records a session on a branch (a no-op if it exists).
func StartAgentSession(name string, s AgentSession) error {
	name, err := ledgerBranchName(name)
	if err != nil {
		return err
	}
	if !ValidProvenanceID(s.SessionID) || !ValidProvenanceID(s.AgentID) {
		return fmt.Errorf("%w: session and agent ids must be 1–200 printable characters", ErrInvalidRequest)
	}
	if _, err := ledgerLines(name, startSessionSQL(s)); err != nil {
		return provenanceErr(name, err)
	}
	return nil
}

// AgentSessions lists a branch's newest agent sessions (default 50, at most 1000).
func AgentSessions(name string, limit int) ([]AgentSession, error) {
	name, err := ledgerBranchName(name)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	lines, err := ledgerLines(name, agentSessionsSQL(limit, compromisedNow()))
	if err != nil {
		return nil, provenanceErr(name, err)
	}
	out := make([]AgentSession, 0, len(lines))
	for _, l := range lines {
		if !strings.HasPrefix(l, "{") {
			continue
		}
		var s AgentSession
		if err := json.Unmarshal([]byte(l), &s); err != nil {
			return nil, fmt.Errorf("reading agent sessions: %w", err)
		}
		out = append(out, s)
	}
	return out, nil
}

// agentSessionsSQL reads the newest sessions. Whom each was for is read through
// to_jsonb, so a branch whose table predates those columns lists them as
// absent rather than failing; a key reported compromised from a moment is
// said so, as the Blackbox's own listing does (AppForSQL).
func agentSessionsSQL(limit int, compromised []CompromisedKey) string {
	vals := "SELECT NULL::text, NULL::text, NULL::bigint WHERE false"
	if len(compromised) > 0 {
		rows := make([]string, len(compromised))
		for i, c := range compromised {
			rows[i] = fmt.Sprintf("(%s, %s, %d::bigint)", quoteLiteral(c.Issuer), quoteLiteral(c.Kid), c.Since)
		}
		vals = "VALUES " + strings.Join(rows, ", ")
	}
	return fmt.Sprintf(`SELECT row_to_json(x) FROM (
  SELECT a.session_id, a.agent_id, a.parent_session_id, a.task_id, a.tool,
         to_char(a.started_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS started_at,
         (SELECT count(*) FROM bb.schema_ledger s WHERE s.session = a.session_id) AS entries,
         to_jsonb(a) ->> 'app_actor' AS app_for,
         CASE WHEN to_jsonb(a) ->> 'app_state' = 'asserted' AND EXISTS (
                SELECT 1 FROM (%s) c(issuer, kid, since)
                 WHERE c.issuer = to_jsonb(a) ->> 'app_issuer' AND c.kid = to_jsonb(a) ->> 'app_kid'
                   AND extract(epoch FROM a.started_at) >= c.since)
              THEN 'asserted by ' || (to_jsonb(a) ->> 'app_issuer') || ' (key reported compromised)'
              WHEN to_jsonb(a) ->> 'app_state' = 'asserted' THEN 'asserted by ' || (to_jsonb(a) ->> 'app_issuer')
              ELSE to_jsonb(a) ->> 'app_state' END AS app_state,
         to_jsonb(a) ->> 'app_kid' AS app_kid, to_jsonb(a) ->> 'app_note' AS app_note
  FROM bb.agent_sessions a ORDER BY a.started_at DESC LIMIT %d) x`, vals, limit)
}

// FormatAgentSessions renders sessions as a text table.
func FormatAgentSessions(ss []AgentSession) string {
	if len(ss) == 0 {
		return "No agent sessions."
	}
	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SESSION\tAGENT\tFOR\tTASK\tPARENT SESSION\tTOOL\tSTARTED (UTC)\tENTRIES")
	for _, s := range ss {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\n", s.SessionID, s.AgentID, sessionFor(s), str(s.TaskID), str(s.ParentSessionID), str(s.Tool), s.StartedAt, s.Entries)
	}
	_ = tw.Flush()
	return strings.TrimRight(b.String(), "\n")
}

// sessionFor is whom a session was started for, as fox blackbox's for column
// says it: "alice, asserted by shop", "none: <why>", or "-".
func sessionFor(s AgentSession) string {
	switch {
	case s.AppState == nil:
		return "-"
	case *s.AppState == "none":
		return "none: " + str(s.AppNote)
	case s.AppFor != nil:
		return *s.AppFor + ", " + *s.AppState
	}
	return *s.AppState
}

func sessionDefaultsSQL(p Provenance) string {
	set := func(guc, v string) string {
		if v == "" {
			return fmt.Sprintf("ALTER DATABASE %s RESET %s;\n", pgDatabase, guc)
		}
		return fmt.Sprintf("ALTER DATABASE %s SET %s = %s;\n", pgDatabase, guc, quoteLiteral(v))
	}
	return set("bb.session", p.SessionID) + set("bb.task", p.TaskID) + set("bb.parent_session", p.ParentSessionID)
}

// CreateAgentBranchWithProvenance creates an agent branch like CreateAgentBranch
// and records a session for it: every connection to the branch then carries the
// session, task and parent session, so the agent's changes are attributed without
// the agent doing anything. If the session can't be recorded the branch is removed.
func CreateAgentBranchWithProvenance(agentID string, p Provenance) (Info, AgentSession, error) {
	return CreateAgentBranchWithProvenanceFor(0, agentID, p)
}

// CreateAgentBranchWithProvenanceFor is CreateAgentBranchWithProvenance on
// behalf of an account (see CreateAgentBranchFor).
func CreateAgentBranchWithProvenanceFor(owner int64, agentID string, p Provenance) (Info, AgentSession, error) {
	if err := p.validate(); err != nil {
		return Info{}, AgentSession{}, err
	}
	if p.SessionID == "" {
		id, err := NewSessionID("agent")
		if err != nil {
			return Info{}, AgentSession{}, err
		}
		p.SessionID = id
	}
	info, err := CreateAgentBranchFor(owner, agentID)
	if err != nil {
		return Info{}, AgentSession{}, err
	}
	s := AgentSession{
		SessionID: p.SessionID, AgentID: agentBranch(agentID),
		TaskID: strPtr(p.TaskID), ParentSessionID: strPtr(p.ParentSessionID), Tool: strPtr("agent-api"),
		app: p.App,
	}
	if a := p.App; a != nil {
		state := a.State
		if state == "asserted" {
			state = "asserted by " + a.Issuer
		}
		s.AppFor, s.AppState, s.AppKid, s.AppNote = strPtr(a.Actor), &state, strPtr(a.Kid), strPtr(a.Note)
	}
	err = StartAgentSession(info.Branch, s)
	if err == nil {
		err = psqlStdin(info.Branch, sessionDefaultsSQL(p))
	}
	if err != nil {
		_ = DeleteAgentBranch(agentID)
		return Info{}, AgentSession{}, fmt.Errorf("recording the agent's provenance (the branch was removed): %w", err)
	}
	return info, s, nil
}

// ExecuteChangeRequest is one execute_change call.
type ExecuteChangeRequest struct {
	Branch          string
	SQL             string
	TaskID          string
	ParentSessionID string
	SessionID       string // the caller's session (for MCP: one per server process)
	AgentID         string // recorded as the Blackbox actor
	Tool            string // application_name and agent_sessions.tool, e.g. "mcp"
	DryRun          bool
}

// ChangeNotice is a notice or warning the database sent while running the change.
type ChangeNotice struct {
	Severity string               `json:"severity"`
	Code     string               `json:"code"`
	Message  string               `json:"message"`
	Detail   string               `json:"detail,omitempty"`
	Hint     string               `json:"hint,omitempty"`
	Policy   *ledger.PolicyDetail `json:"policy,omitempty"` // for SQLSTATE BBX02
}

// ChangeError is the database error that stopped the change.
type ChangeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
	Hint    string `json:"hint,omitempty"`
}

// ExecuteChangeResult is what execute_change returns.
type ExecuteChangeResult struct {
	Status          string                `json:"status"` // applied | blocked | error | preview
	Branch          string                `json:"branch"`
	Command         string                `json:"command"`
	SessionID       string                `json:"session_id"`
	TaskID          string                `json:"task_id,omitempty"`
	ParentSessionID string                `json:"parent_session_id,omitempty"`
	CallHash        string                `json:"call_hash"`
	PolicyPreview   []ledger.PolicyDetail `json:"policy_preview"`
	Notices         []ChangeNotice        `json:"notices"`
	Policy          *ledger.PolicyDetail  `json:"policy,omitempty"` // the rule that blocked the change (BBX01)
	Error           *ChangeError          `json:"error,omitempty"`
	Impact          *ImpactReport         `json:"impact,omitempty"` // what the change affects, when its target is recognised
	BlackboxEntries []int64               `json:"blackbox_entries"`
}

func noticeFrom(n *pgconn.Notice) ChangeNotice {
	c := ChangeNotice{Severity: n.Severity, Code: n.Code, Message: n.Message, Detail: n.Detail, Hint: n.Hint}
	if n.Code == ledger.PolicyWarnCode {
		if d, err := ledger.ParsePolicyDetail(n.Detail); err == nil {
			c.Policy = &d
		}
	}
	return c
}

// classifyExecError fills res from a database error and returns nil, or returns
// err unchanged when it isn't one (a connection failure, a timeout).
func classifyExecError(res *ExecuteChangeResult, err error) error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return err
	}
	res.Status = "error"
	if pgErr.Code == ledger.PolicyBlockCode {
		res.Status = "blocked"
		if d, perr := ledger.ParsePolicyDetail(pgErr.Detail); perr == nil {
			res.Policy = &d
		}
	}
	res.Error = &ChangeError{Code: pgErr.Code, Message: pgErr.Message, Detail: pgErr.Detail, Hint: pgErr.Hint}
	return nil
}

// ExecuteChange runs SQL on a branch as an agent, with provenance. It previews
// the policy rules the statement would trigger, then (unless DryRun) runs it as
// the non-superuser client role with the session, task, parent session and call
// hash set, so the policy gate and the Blackbox apply exactly as to any client.
// A refused or failing statement is reported in the result, not as an error.
func ExecuteChange(req ExecuteChangeRequest) (ExecuteChangeResult, error) {
	name, err := ledgerBranchName(req.Branch)
	if err != nil {
		return ExecuteChangeResult{}, err
	}
	if strings.TrimSpace(req.SQL) == "" {
		return ExecuteChangeResult{}, fmt.Errorf("%w: sql is required", ErrInvalidRequest)
	}
	if req.Tool == "" {
		req.Tool = "mcp"
	}
	if req.AgentID == "" {
		req.AgentID = req.Tool
	}
	p := Provenance{SessionID: req.SessionID, TaskID: req.TaskID, ParentSessionID: req.ParentSessionID}
	if err := p.validate(); err != nil {
		return ExecuteChangeResult{}, err
	}
	if !ValidProvenanceID(req.AgentID) || !ValidProvenanceID(req.Tool) {
		return ExecuteChangeResult{}, fmt.Errorf("%w: agent and tool names must be 1–200 printable characters", ErrInvalidRequest)
	}
	if req.SessionID == "" {
		if req.SessionID, err = NewSessionID(req.Tool); err != nil {
			return ExecuteChangeResult{}, err
		}
	}

	res := ExecuteChangeResult{
		Branch: name, SessionID: req.SessionID, TaskID: req.TaskID, ParentSessionID: req.ParentSessionID,
		CallHash: CallHash("execute_change", name, req.SQL, req.TaskID, req.ParentSessionID),
		Notices:  []ChangeNotice{}, BlackboxEntries: []int64{},
	}
	addr, err := EnsureRunning(name)
	if err != nil {
		return ExecuteChangeResult{}, err
	}
	tag, preview, err := PolicyCheck(name, req.SQL)
	if err != nil {
		return ExecuteChangeResult{}, err
	}
	res.Command, res.PolicyPreview = tag, preview
	if rep, err := Impact(name, req.SQL, "", ""); err == nil {
		res.Impact = &rep
	}
	if req.DryRun {
		res.Status = "preview"
		return res, nil
	}

	if err := StartAgentSession(name, AgentSession{SessionID: req.SessionID, AgentID: req.AgentID,
		TaskID: strPtr(req.TaskID), ParentSessionID: strPtr(req.ParentSessionID), Tool: strPtr(req.Tool)}); err != nil {
		return ExecuteChangeResult{}, err
	}
	marker := int64(0)
	if l, err := ledgerLines(name, "SELECT coalesce(max(id), 0) FROM bb.schema_ledger"); err == nil && len(l) > 0 {
		marker, _ = strconv.ParseInt(l[0], 10, 64)
	}

	ctx, cancel := context.WithTimeout(context.Background(), envDurationOr("FOX_EXECUTE_CHANGE_TIMEOUT", 10*time.Minute))
	defer cancel()
	if err := EnsureAppRole(name); err != nil {
		return ExecuteChangeResult{}, err
	}
	// An agent by login where the branch's Blackbox knows db_agent: the
	// bb.actor_kind set below is then only a label, and the agent's SQL cannot
	// change what it is recorded as (agentrole.go).
	role, asAgent := agentLoginRole(name)
	cfg, err := pgx.ParseConfig(fmt.Sprintf("postgres://%s@%s/%s", role, addr, pgDatabase))
	if err != nil {
		return ExecuteChangeResult{}, err
	}
	cfg.Password = ClientRolePassword()
	if asAgent {
		cfg.Password = AgentClientRolePassword()
	}
	// The agent's name at login, not only by set_config below: the Blackbox
	// keys an agent's budget across statements on the login value, which the
	// agent's own SQL cannot change (bb._budget_actor).
	cfg.RuntimeParams["bb.actor"] = req.AgentID
	cfg.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) { res.Notices = append(res.Notices, noticeFrom(n)) }
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return ExecuteChangeResult{}, fmt.Errorf("connecting to %q: %w", name, err)
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(ctx, `SELECT set_config('bb.actor', $1, false), set_config('bb.actor_kind', 'agent', false),
  set_config('application_name', $2, false), set_config('bb.session', $3, false), set_config('bb.task', $4, false),
  set_config('bb.parent_session', $5, false), set_config('bb.call_hash', $6, false)`,
		req.AgentID, req.Tool, req.SessionID, req.TaskID, req.ParentSessionID, res.CallHash); err != nil {
		return ExecuteChangeResult{}, fmt.Errorf("setting provenance: %w", err)
	}

	results, execErr := conn.PgConn().Exec(ctx, req.SQL).ReadAll()
	if execErr != nil {
		if err := classifyExecError(&res, execErr); err != nil {
			return ExecuteChangeResult{}, err
		}
	} else {
		res.Status = "applied"
		if len(results) > 0 {
			res.Command = results[len(results)-1].CommandTag.String()
		}
	}

	if lines, err := ledgerLines(name, fmt.Sprintf(`SELECT s.id FROM bb.schema_ledger s LEFT JOIN bb.ledger_ext e ON e.ledger_id = s.id
WHERE s.id > %d AND s.session = %s AND (e.call_hash = %s OR s.status = 'BLOCKED') ORDER BY s.id`,
		marker, quoteLiteral(req.SessionID), quoteLiteral(res.CallHash))); err == nil {
		for _, l := range lines {
			if id, err := strconv.ParseInt(l, 10, 64); err == nil {
				res.BlackboxEntries = append(res.BlackboxEntries, id)
			}
		}
	}
	return res, nil
}
