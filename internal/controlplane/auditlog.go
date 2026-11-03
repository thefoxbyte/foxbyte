// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
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
}

func registerAuditLog(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/audit-log", func(w http.ResponseWriter, r *http.Request) {
		if !isAdmin(r) {
			writeErr(w, 403, errors.New("only an admin may see the audit log's settings"))
			return
		}
		writeJSON(w, 200, auditLogState())
	})
}

// auditLogState reads the engine; a variable so a test need not.
var auditLogState = func() auditLogReply {
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
	return rep
}

// Marking tables (F6 Gate 1, step 2): which tables' writes, and reads, are
// audited, on a branch.
//
//	GET    /api/branches/{name}/audit/tables                   the marked tables (Use)
//	PUT    /api/branches/{name}/audit/tables/{schema}/{table}  mark one: {"reads": bool} (Manage)
//	DELETE /api/branches/{name}/audit/tables/{schema}/{table}  stop auditing it (Manage)
//
// Each change is in the security log, and in the Blackbox under the person who
// asked, as the grant it is.

type auditMarksReply struct {
	AuditOn bool               `json:"audit_on"`
	Tables  []branch.AuditMark `json:"tables"`
}

func registerAuditMarks(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/branches/{name}/audit/tables", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if _, err := branch.EnsureRunning(name); err != nil {
			writeErr(w, 404, err)
			return
		}
		marks, err := branch.AuditMarks(name)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, auditMarksReply{AuditOn: branch.AuditOn(), Tables: marks})
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
	marks, err := branch.AuditMarks(name)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, auditMarksReply{AuditOn: branch.AuditOn(), Tables: marks})
}
