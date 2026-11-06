// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// Masking over HTTP (F5, point 4.6). Admins only: the status names the
// accounts masked, and what a person sees of personal data is an admin's to
// decide (design, decision 4).
//
//	GET  /api/masking?branch=main                    where masking stands: free
//	POST /api/masking/setup    {"branch", "apply"}   what setup does, or with apply does it (Enterprise)
//	POST /api/masking/rule     {"branch", "schema", "table", "column", "path", "rule", "off", "apply"}
//	                                                 a rule's cost, or with apply sets it; off takes it off (Enterprise)
//	POST /api/masking/account  {"email", "off"}      masks an account, or unmasks it (Enterprise)
//	GET  /api/masking/keys                           the key domains and the tables using each: free
//	POST /api/masking/key      {"action": "create"|"rotate"|"drop"|"use", "domain", "branch", "schema", "table", "apply"}
//	                                                 what a key change does, or with apply makes it (Enterprise)
//
// Each setup, rule and account change is in the security log.
// maskBody is what the masking calls take.
type maskBody struct {
	Branch string `json:"branch"`
	Schema string `json:"schema"`
	Table  string `json:"table"`
	Column string `json:"column"`
	Path   string `json:"path"`
	Rule   string `json:"rule"`
	Email  string `json:"email"`
	Off    bool   `json:"off"`
	Apply  bool   `json:"apply"`
	Action string `json:"action"` // the keys': create, rotate, drop, use
	Domain string `json:"domain"`
}

func registerMasking(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/masking", func(w http.ResponseWriter, r *http.Request) {
		if !isAdmin(r) {
			writeErr(w, 403, errors.New("only an admin may read where masking stands"))
			return
		}
		st, err := branch.MaskingStatus(r.URL.Query().Get("branch"))
		if err != nil {
			maskFail(w, err)
			return
		}
		writeJSON(w, 200, st)
	})

	read := func(w http.ResponseWriter, r *http.Request) (maskBody, string, bool) {
		var b maskBody
		if !requireFeature(w, edition.Masking) {
			return b, "", false
		}
		if !isAdmin(r) {
			writeErr(w, 403, errors.New("only an admin may change masking"))
			return b, "", false
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&b); err != nil {
			writeErr(w, 400, errors.New("the body must be JSON"))
			return b, "", false
		}
		if b.Branch == "" {
			b.Branch = "main"
		}
		u, _ := auth.UserFrom(r.Context())
		return b, u.Email, true
	}
	record := func(r *http.Request, actor, kind, b, detail string) {
		if secLog != nil {
			secLog.Audit(kind, actor, b, remoteIP(r), detail)
		}
	}

	mux.HandleFunc("POST /api/masking/setup", func(w http.ResponseWriter, r *http.Request) {
		b, actor, ok := read(w, r)
		if !ok {
			return
		}
		if err := branch.MaskHAGuard(); err != nil {
			writeErr(w, 409, err)
			return
		}
		restart := branch.MaskNeedsRestart(b.Branch)
		if !b.Apply {
			writeJSON(w, 200, map[string]any{"branch": b.Branch, "restart": restart, "keyDir": branch.MaskKeyDir()})
			return
		}
		for _, step := range []func() error{branch.EnsureMaskImage, func() error { return branch.EnsureMaskKey("default") }} {
			if err := step(); err != nil {
				maskFail(w, err)
				return
			}
		}
		if restart {
			if err := branch.RestartForMask(b.Branch); err != nil {
				maskFail(w, fmt.Errorf("%s did not come back with the key: %w", b.Branch, err))
				return
			}
			if b.Branch == "main" {
				_ = branch.RestartStandby() // as `fox mask setup`: a standby without the key is reported by status
			}
		}
		if err := branch.SetupMasking(b.Branch, actor); err != nil {
			maskFail(w, err)
			return
		}
		record(r, actor, auth.EvMaskSetup, b.Branch, "masking set up on "+b.Branch)
		writeJSON(w, 200, map[string]any{"branch": b.Branch, "restarted": restart})
	})

	mux.HandleFunc("POST /api/masking/rule", func(w http.ResponseWriter, r *http.Request) {
		b, actor, ok := read(w, r)
		if !ok {
			return
		}
		if b.Schema == "" {
			b.Schema = "public"
		}
		if b.Table == "" || b.Column == "" {
			writeErr(w, 400, errors.New("a rule is on a table's column: table and column are needed"))
			return
		}
		rule := branch.MaskRule{Schema: b.Schema, Table: b.Table, Column: b.Column, Path: b.Path, Rule: b.Rule, By: actor}
		if b.Off {
			if err := branch.DropMaskRule(b.Branch, b.Schema, b.Table, b.Column, b.Path, actor); err != nil {
				maskFail(w, err)
				return
			}
			record(r, actor, auth.EvMaskRule, b.Branch, fmt.Sprintf("rule taken off %s on %s", rule.Where(), b.Branch))
			writeJSON(w, 200, map[string]any{"off": rule.Where()})
			return
		}
		if b.Rule != "" {
			if err := branch.CheckMaskRule(b.Rule, ""); err != nil {
				maskFail(w, err)
				return
			}
		}
		if !b.Apply {
			writeJSON(w, 200, map[string]any{"where": rule.Where(), "cost": branch.MaskCost(b.Rule, b.Path)})
			return
		}
		if err := branch.SetMaskRule(b.Branch, rule); err != nil {
			maskFail(w, err)
			return
		}
		named := b.Rule
		if named == "" {
			named = "(the category's default)"
		}
		record(r, actor, auth.EvMaskRule, b.Branch, fmt.Sprintf("rule %s set on %s on %s", named, rule.Where(), b.Branch))
		writeJSON(w, 200, map[string]any{"set": rule.Where()})
	})

	mux.HandleFunc("POST /api/masking/account", func(w http.ResponseWriter, r *http.Request) {
		b, actor, ok := read(w, r)
		if !ok {
			return
		}
		email := strings.ToLower(strings.TrimSpace(b.Email))
		if err := branch.MaskAccount(email, actor, b.Off); err != nil {
			maskFail(w, err)
			return
		}
		what := "masked"
		if b.Off {
			what = "unmasked"
		}
		record(r, actor, auth.EvMaskAccount, "", what+" "+email)
		writeJSON(w, 200, map[string]any{"email": email, "masked": !b.Off})
	})

	registerMaskKeys(mux, read, record)
}

// registerMaskKeys is step 2's: the keys. Admins only, as the rest.
func registerMaskKeys(mux *http.ServeMux, read func(http.ResponseWriter, *http.Request) (maskBody, string, bool),
	record func(*http.Request, string, string, string, string)) {
	mux.HandleFunc("GET /api/masking/keys", func(w http.ResponseWriter, r *http.Request) {
		if !isAdmin(r) {
			writeErr(w, 403, errors.New("only an admin may read the masking keys"))
			return
		}
		st, err := branch.MaskKeysState()
		if err != nil {
			maskFail(w, err)
			return
		}
		writeJSON(w, 200, st)
	})
	mux.HandleFunc("POST /api/masking/key", func(w http.ResponseWriter, r *http.Request) {
		b, actor, ok := read(w, r)
		if !ok {
			return
		}
		if b.Schema == "" {
			b.Schema = "public"
		}
		switch b.Action {
		case "create":
			if err := branch.CheckMaskDomain(b.Domain); err != nil {
				maskFail(w, err)
				return
			}
			if !b.Apply {
				writeJSON(w, 200, map[string]any{"domain": b.Domain, "keyDir": branch.MaskKeyDir()})
				return
			}
			if err := branch.CreateMaskDomain(b.Domain, actor); err != nil {
				maskFail(w, err)
				return
			}
			record(r, actor, auth.EvMaskKey, "", "key domain "+b.Domain+" made")
			writeJSON(w, 200, map[string]any{"made": b.Domain})
		case "rotate":
			if _, ok := branch.MaskKeyFor(b.Domain); !ok {
				maskFail(w, fmt.Errorf("%w: the install has no key domain %q", branch.ErrInvalidRequest, b.Domain))
				return
			}
			if !b.Apply {
				writeJSON(w, 200, map[string]any{"domain": b.Domain, "cost": branch.MaskRotateCost(b.Domain)})
				return
			}
			var done []string
			if err := branch.RotateMaskKey(b.Domain, actor, func(s string) { done = append(done, s) }); err != nil {
				maskFail(w, err)
				return
			}
			record(r, actor, auth.EvMaskKey, "", "key of domain "+b.Domain+" rotated")
			writeJSON(w, 200, map[string]any{"rotated": b.Domain, "done": done})
		case "drop":
			if !b.Apply {
				writeJSON(w, 200, map[string]any{"domain": b.Domain})
				return
			}
			if err := branch.DropMaskDomain(b.Domain, actor); err != nil {
				if errors.Is(err, branch.ErrMaskDomainInUse) {
					writeErr(w, 409, err)
					return
				}
				maskFail(w, err)
				return
			}
			record(r, actor, auth.EvMaskKey, "", "key domain "+b.Domain+" deleted")
			writeJSON(w, 200, map[string]any{"deleted": b.Domain})
		case "use":
			if b.Table == "" {
				writeErr(w, 400, errors.New("a domain is chosen for a table: table is needed"))
				return
			}
			where := b.Schema + "." + b.Table
			if !b.Apply {
				writeJSON(w, 200, map[string]any{"domain": b.Domain, "branch": b.Branch, "table": where})
				return
			}
			if err := branch.UseMaskDomain(b.Branch, b.Schema, b.Table, b.Domain, actor); err != nil {
				maskFail(w, err)
				return
			}
			record(r, actor, auth.EvMaskKey, b.Branch, fmt.Sprintf("%s on %s put under key domain %s", where, b.Branch, b.Domain))
			writeJSON(w, 200, map[string]any{"table": where, "domain": b.Domain})
		default:
			writeErr(w, 400, errors.New(`action is "create", "rotate", "drop" or "use"`))
		}
	})
}

func maskFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, branch.ErrNotLicensed):
		writeErr(w, 403, err)
	case errors.Is(err, branch.ErrInvalidRequest), errors.Is(err, branch.ErrBadName):
		writeErr(w, 400, err)
	default:
		writeErr(w, 500, err)
	}
}
