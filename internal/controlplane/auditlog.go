// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// The databases' audit log (F6) over HTTP: the console's Audit log page.
//
//	GET /api/audit-log   whether it is on, its mode, where the log is, its space,
//	                     and the databases still running as before the last change
//
// Admins only: where the log is and who is audited is the auditor's business.
// Turning it on or off restarts main, so it is `fox audit-log setup` and
// `off`, which say what they will do first; the page names the command.

type auditLogReply struct {
	On      bool     `json:"on"`
	Mode    string   `json:"mode,omitempty"` // "default"; forensic comes with step 5
	Root    string   `json:"root"`
	Used    int64    `json:"used"`
	Quota   int64    `json:"quota"` // 0: none on this storage
	Pending []string `json:"pending"`
	Setup   string   `json:"setup"`
	Off     string   `json:"off"`
	// What is wrong with it (step 4): lines not arriving, lines lost, a mark
	// taken off outside FoxByte.
	Findings []branch.AuditFinding `json:"findings"`
	// Where forensic mode is on ("" for every branch), and how long records
	// and statement text are kept (step 5a).
	Forensic  map[string]branch.ForensicGrant `json:"forensic"`
	Retention auditRetention                  `json:"retention"`
	// Where records are forwarded and how far delivery has got (step 5b);
	// null when they are not. Never the token.
	Forward *branch.ForwardStatus `json:"forward"`
	// How far the chain is anchored outside the store (step 6).
	Anchors branch.AuditAnchorStatus `json:"anchors"`
}

type auditRetention struct {
	Days         int `json:"days"`
	ForensicDays int `json:"forensic_days"`
}

func registerAuditLog(mux *http.ServeMux, store *auth.Store) {
	mux.HandleFunc("GET /api/audit-log", func(w http.ResponseWriter, r *http.Request) {
		if !isAdmin(r) {
			writeErr(w, 403, errors.New("only an admin may see the audit log's settings"))
			return
		}
		writeJSON(w, 200, auditLogState(store))
	})
}

// The records (F6 Gate 1, step 3):
//
//	GET /api/audit-log/records?branch=&table=&user=&since=&limit=&errors=1
//
// Admins only, and each read is in the security log: the records name logins
// and whom changes were for. since is RFC 3339 or a duration back from now
// (2h); limit is 1 to 1000, 100 by default. What is new in the raw files is
// collected first.
func registerAuditRecords(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/audit-log/records", func(w http.ResponseWriter, r *http.Request) {
		if !isAdmin(r) {
			writeErr(w, 403, errors.New("only an admin may read the audit log"))
			return
		}
		q, err := auditQueryFrom(r.URL.Query(), time.Now())
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		entries, err := auditRecords(q)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		if secLog != nil {
			u, _ := auth.UserFrom(r.Context())
			secLog.Audit(auth.EvAuditLogRead, u.Email, q.Branch, remoteIP(r), auditReadDetail(q, len(entries)))
		}
		writeJSON(w, 200, map[string]any{"records": entries})
	})
}

// auditRecords collects and reads; a variable so a test need not.
var auditRecords = func(q branch.AuditQuery) ([]branch.AuditEntry, error) {
	if _, err := branch.CollectAudit(); err != nil {
		log.Printf("audit log: collecting before a read: %v", err)
	}
	entries, err := branch.ReadAudit(q)
	if entries == nil {
		entries = []branch.AuditEntry{}
	}
	return entries, err
}

// auditQueryFrom reads the query string.
func auditQueryFrom(v url.Values, now time.Time) (branch.AuditQuery, error) {
	q := branch.AuditQuery{Branch: v.Get("branch"), Table: v.Get("table"), Login: v.Get("user"), Limit: 100}
	if s := v.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 1000 {
			return q, fmt.Errorf("limit is 1 to 1000, not %q", s)
		}
		q.Limit = n
	}
	if s := v.Get("since"); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			q.Since = now.Add(-d)
		} else if t, err := time.Parse(time.RFC3339, s); err == nil {
			q.Since = t
		} else {
			return q, fmt.Errorf("since is a time (RFC 3339) or a duration back from now (2h), not %q", s)
		}
	}
	if v.Get("errors") == "1" {
		q.Kinds = []string{"outcome"}
	}
	return q, nil
}

// auditReadDetail is the security log's line for a read: what was asked, and
// how much came back.
func auditReadDetail(q branch.AuditQuery, n int) string {
	var parts []string
	for _, p := range [][2]string{{"table", q.Table}, {"user", q.Login}} {
		if p[1] != "" {
			parts = append(parts, p[0]+" "+p[1])
		}
	}
	if !q.Since.IsZero() {
		parts = append(parts, "since "+q.Since.UTC().Format(time.RFC3339))
	}
	if len(q.Kinds) > 0 {
		parts = append(parts, "errors only")
	}
	asked := "everything"
	if len(parts) > 0 {
		asked = strings.Join(parts, ", ")
	}
	return fmt.Sprintf("%d record(s): %s", n, asked)
}

// auditLogState reads the engine; a variable so a test need not.
var auditLogState = func(store *auth.Store) auditLogReply {
	rep := auditLogReply{
		On:      branch.AuditOn(),
		Root:    branch.AuditRoot(),
		Pending: []string{},
		Setup:   brand.CLI + " audit-log setup",
		Off:     brand.CLI + " audit-log off",
	}
	if rep.On {
		rep.Mode = "default"
		if s, err := branch.AuditUsage(); err == nil {
			rep.Used, rep.Quota = s.Used, s.Quota
		}
	}
	if p, err := branch.AuditPending(); err == nil && p != nil {
		rep.Pending = p
	}
	rep.Forensic = branch.LoadAuditSettings().Forensic
	rep.Retention = auditRetention{Days: branch.AuditRetentionDays(), ForensicDays: branch.ForensicRetentionDays()}
	rep.Forward = branch.AuditForwardStatus()
	rep.Anchors = branch.AuditAnchors()
	rep.Findings = []branch.AuditFinding{}
	if rep.On {
		if f := branch.AuditFindings(branch.MarkEventsFrom(store)); f != nil {
			rep.Findings = f
		}
	}
	return rep
}

// Marking tables (F6 Gate 1, step 2): which tables' writes, and reads, are
// audited, on a branch.
//
//	GET    /api/branches/{name}/audit/tables                   the marked tables (Use)
//	PUT    /api/branches/{name}/audit/tables/{schema}/{table}  mark one: {"reads": bool} (Manage)
//	DELETE /api/branches/{name}/audit/tables/{schema}/{table}  stop auditing it (Manage)
//	POST   /api/branches/{name}/audit/tables/personal-data     mark every table with confirmed
//	                                                          personal data (Manage; Enterprise, step 6)
//
// Each change is in the security log, and in the Blackbox under the person who
// asked, as the grant it is.

type auditMarksReply struct {
	AuditOn bool               `json:"audit_on"`
	Tables  []branch.AuditMark `json:"tables"`
	// Step 6: the SECURITY DEFINER functions naming marked tables, whose
	// statements pgAudit does not see; and, for POST …/personal-data only
	// (Manage, as where personal data sits is), the tables holding confirmed
	// personal data whose writes are still not audited.
	Definers         []branch.DefinerFunc `json:"definers"`
	PersonalUnmarked []string             `json:"personal_unmarked,omitempty"`
	// What the last request marked, for POST …/personal-data.
	Marked []string `json:"marked,omitempty"`
}

// marksReply reads a branch's marks, and what step 6 says beside them.
func marksReply(name string) (auditMarksReply, error) {
	marks, err := branch.AuditMarks(name)
	if err != nil {
		return auditMarksReply{}, err
	}
	rep := auditMarksReply{AuditOn: branch.AuditOn(), Tables: marks, Definers: []branch.DefinerFunc{}}
	if d, err := branch.DefinerFunctions(name); err == nil && d != nil {
		rep.Definers = d
	}
	return rep, nil
}

func registerAuditMarks(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/branches/{name}/audit/tables", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if _, err := branch.EnsureRunning(name); err != nil {
			writeErr(w, 404, err)
			return
		}
		rep, err := marksReply(name)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, rep)
	})
	mux.HandleFunc("POST /api/branches/{name}/audit/tables/personal-data", func(w http.ResponseWriter, r *http.Request) {
		if !requireFeature(w, edition.PersonalData) {
			return
		}
		u, _ := auth.UserFrom(r.Context())
		name := r.PathValue("name")
		if _, err := branch.EnsureRunning(name); err != nil {
			writeErr(w, 404, err)
			return
		}
		marked, err := branch.MarkPersonalDataTables(name, u.Email)
		for _, t := range marked {
			if secLog != nil {
				secLog.Audit(auth.EvAuditMarked, u.Email, name, remoteIP(r), "auditing writes of "+t)
			}
		}
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		rep, err := marksReply(name)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		rep.Marked = marked
		rep.PersonalUnmarked, _ = branch.PersonalTablesUnmarked(name)
		writeJSON(w, 200, rep)
	})
	mux.HandleFunc("PUT /api/branches/{name}/audit/tables/{schema}/{table}", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Reads bool `json:"reads"`
		}
		if r.ContentLength != 0 {
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeErr(w, 400, errors.New(`the body must be JSON: {"reads": true|false}`))
				return
			}
		}
		rel := r.PathValue("schema") + "." + r.PathValue("table")
		what := branch.MarkWhat(branch.AuditMark{Writes: true, Reads: body.Reads})
		markChange(w, r, "auditing "+what+" of "+rel, func(actor string) error {
			return branch.MarkAudited(r.PathValue("name"), r.PathValue("schema"), r.PathValue("table"), body.Reads, actor, "console")
		})
	})
	mux.HandleFunc("DELETE /api/branches/{name}/audit/tables/{schema}/{table}", func(w http.ResponseWriter, r *http.Request) {
		rel := r.PathValue("schema") + "." + r.PathValue("table")
		markChange(w, r, "stopped auditing "+rel, func(actor string) error {
			return branch.UnmarkAudited(r.PathValue("name"), r.PathValue("schema"), r.PathValue("table"), actor, "console")
		})
	})
}

// markChange runs a mark as the signed-in user, records it, and answers with
// the branch's marks as they now are.
func markChange(w http.ResponseWriter, r *http.Request, what string, change func(actor string) error) {
	u, _ := auth.UserFrom(r.Context())
	name := r.PathValue("name")
	if _, err := branch.EnsureRunning(name); err != nil {
		writeErr(w, 404, err)
		return
	}
	if err := change(u.Email); err != nil {
		writeErr(w, 400, err)
		return
	}
	if secLog != nil {
		secLog.Audit(auth.EvAuditMarked, u.Email, name, remoteIP(r), what)
	}
	rep, err := marksReply(name)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, rep)
}

// Forensic mode, retention and purge (F6 Gate 1, step 5a), admins only, each
// in the security log:
//
//	PUT  /api/audit-log/mode       {"forensic": bool, "branch": "", "reason": "…"}
//	PUT  /api/audit-log/retention  {"days": n, "forensic": bool}
//	POST /api/audit-log/purge      {"user": "<login>"}
//
// and forwarding to a SIEM (step 5b):
//
//	PUT    /api/audit-log/forward       {"url": "https://…|syslog://…", "token": "", "ca_pem": "",
//	                                     "text": bool, "from_start": bool}
//	DELETE /api/audit-log/forward       stop forwarding
//	POST   /api/audit-log/forward/send  collect and send what is waiting now
//
// The token and CA bundle come in the body, never as a path: the engine reads
// no file an admin names, so the console cannot send a host file anywhere.
// Neither is ever sent back.
func registerAuditSettings(mux *http.ServeMux) {
	admin := func(w http.ResponseWriter, r *http.Request) (auth.User, bool) {
		u, _ := auth.UserFrom(r.Context())
		if !isAdmin(r) {
			writeErr(w, 403, errors.New("only an admin may change what the audit log keeps"))
			return u, false
		}
		return u, true
	}
	record := func(r *http.Request, kind, actor, subject, detail string) {
		if secLog != nil {
			secLog.Audit(kind, actor, subject, remoteIP(r), detail)
		}
	}
	mux.HandleFunc("PUT /api/audit-log/mode", func(w http.ResponseWriter, r *http.Request) {
		u, ok := admin(w, r)
		if !ok {
			return
		}
		var body struct {
			Forensic bool   `json:"forensic"`
			Branch   string `json:"branch"`
			Reason   string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, errors.New(`the body must be JSON: {"forensic": bool, "branch": "", "reason": "…"}`))
			return
		}
		reached, err := branch.SetForensic(body.Branch, body.Forensic, u.Email, body.Reason)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		where := "every branch"
		if body.Branch != "" {
			where = body.Branch
		}
		detail := "forensic off for " + where
		if body.Forensic {
			detail = "forensic on for " + where + ": " + strings.TrimSpace(body.Reason)
		}
		record(r, auth.EvAuditLogMode, u.Email, body.Branch, detail)
		if reached == nil {
			reached = []string{}
		}
		writeJSON(w, 200, map[string]any{"forensic": branch.LoadAuditSettings().Forensic, "reached": reached})
	})
	mux.HandleFunc("PUT /api/audit-log/retention", func(w http.ResponseWriter, r *http.Request) {
		u, ok := admin(w, r)
		if !ok {
			return
		}
		var body struct {
			Days     int  `json:"days"`
			Forensic bool `json:"forensic"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, errors.New(`the body must be JSON: {"days": n, "forensic": bool}`))
			return
		}
		if err := branch.SetAuditRetention(body.Days, body.Forensic); err != nil {
			writeErr(w, 400, err)
			return
		}
		what := "records"
		if body.Forensic {
			what = "statement text"
		}
		record(r, auth.EvAuditLogRetention, u.Email, "", fmt.Sprintf("%s kept %d days", what, body.Days))
		writeJSON(w, 200, auditRetention{Days: branch.AuditRetentionDays(), ForensicDays: branch.ForensicRetentionDays()})
	})
	mux.HandleFunc("POST /api/audit-log/purge", func(w http.ResponseWriter, r *http.Request) {
		u, ok := admin(w, r)
		if !ok {
			return
		}
		var body struct {
			User string `json:"user"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, errors.New(`the body must be JSON: {"user": "<login>"}`))
			return
		}
		n, err := branch.PurgeForensic(body.User)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		record(r, auth.EvAuditLogPurged, u.Email, body.User, fmt.Sprintf("%d statement text(s) purged", n))
		writeJSON(w, 200, map[string]int{"purged": n})
	})
	mux.HandleFunc("PUT /api/audit-log/forward", func(w http.ResponseWriter, r *http.Request) {
		u, ok := admin(w, r)
		if !ok {
			return
		}
		var body struct {
			URL       string `json:"url"`
			Token     string `json:"token"`
			CAPEM     string `json:"ca_pem"`
			Text      bool   `json:"text"`
			FromStart bool   `json:"from_start"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
			writeErr(w, 400, errors.New(`the body must be JSON: {"url": "https://…", "token": "", "ca_pem": "", "text": bool, "from_start": bool}`))
			return
		}
		pu, err := branch.ParseForwardURL(body.URL)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		if err := branch.SetAuditForward(pu.String(), branch.ForwardOptions{Text: body.Text, CAPEM: []byte(body.CAPEM),
			Token: body.Token, FromStart: body.FromStart, By: u.Email}); err != nil {
			writeErr(w, 400, err)
			return
		}
		detail := "forwarding to " + pu.String()
		if body.Text {
			detail += ", statement text included"
		}
		if body.FromStart {
			detail += ", from the start"
		}
		record(r, auth.EvAuditLogForward, u.Email, "", detail)
		writeJSON(w, 200, map[string]any{"forward": branch.AuditForwardStatus()})
	})
	mux.HandleFunc("DELETE /api/audit-log/forward", func(w http.ResponseWriter, r *http.Request) {
		u, ok := admin(w, r)
		if !ok {
			return
		}
		if branch.LoadAuditSettings().Forward == nil {
			writeJSON(w, 200, map[string]any{"forward": nil})
			return
		}
		if err := branch.StopAuditForward(); err != nil {
			writeErr(w, 500, err)
			return
		}
		record(r, auth.EvAuditLogForward, u.Email, "", "forwarding stopped")
		writeJSON(w, 200, map[string]any{"forward": nil})
	})
	mux.HandleFunc("POST /api/audit-log/forward/send", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := admin(w, r); !ok {
			return
		}
		if branch.LoadAuditSettings().Forward == nil {
			writeErr(w, 400, errors.New("not forwarding: set where to first"))
			return
		}
		if _, err := branch.CollectAudit(); err != nil {
			log.Printf("audit log: collecting before forwarding: %v", err)
		}
		res, err := branch.ForwardAudit()
		reply := map[string]any{"sent": res.Sent, "waiting": res.Waiting, "skipped": res.Skipped, "forward": branch.AuditForwardStatus()}
		if err != nil {
			reply["error"] = err.Error()
		}
		writeJSON(w, 200, reply)
	})
}
