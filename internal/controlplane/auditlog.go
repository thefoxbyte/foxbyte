// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"errors"
	"net/http"

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
