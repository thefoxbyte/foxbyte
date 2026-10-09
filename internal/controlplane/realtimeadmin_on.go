//go:build enterprise

// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/thefoxbyte/foxbyte/enterprise/realtime"
	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// Choosing what streams, from the console.
//
// Stage 3. The console page said, in its own comment, that tables are chosen
// with `fox realtime enable` "because that is a decision with refusals
// attached — and a console button would have to reproduce every one of them".
// That was true of a gate. Stage 1 turned the refusals into verdicts carrying
// the exact statements and their cost, so a button no longer has to reproduce
// anything: it runs what the verdict already says.
//
// These are on the inner /api/ mux, so they inherit Authn, checkBranchName,
// authorize and the body limits — unlike the front door, which had to repeat
// them. needFor requires access.Manage for every realtime/ tail: a credential
// minted here subscribes to a branch, and the DDL run here changes a table.
//
//	POST   /api/branches/{name}/realtime/enable     {schema,table,events,full_identity}
//	POST   /api/branches/{name}/realtime/disable    {schema,table}
//	POST   /api/branches/{name}/realtime/prepare    {schema,table,apply}
//	GET    /api/branches/{name}/realtime/keys
//	POST   /api/branches/{name}/realtime/keys       {name}
//	DELETE /api/branches/{name}/realtime/keys/{id}
//
// Reading the verdicts is deliberately not here: GET /realtime/v1/branches/
// {name}/tables already serves them and needs only Use. The console calling
// the same endpoint an application calls is worth more than a second handler.

func registerRealtimeAdmin(api *http.ServeMux, store *auth.Store) {
	api.HandleFunc("POST /api/branches/{name}/realtime/enable", realtimeAdmin(realtimeEnableHandler))
	api.HandleFunc("POST /api/branches/{name}/realtime/disable", realtimeAdmin(realtimeDisableHandler))
	api.HandleFunc("POST /api/branches/{name}/realtime/prepare", realtimeAdmin(realtimePrepareHandler))
	api.HandleFunc("GET /api/branches/{name}/realtime/keys", realtimeAdmin(realtimeKeysList(store)))
	api.HandleFunc("POST /api/branches/{name}/realtime/keys", realtimeAdmin(realtimeKeysCreate(store)))
	api.HandleFunc("DELETE /api/branches/{name}/realtime/keys/{id}", realtimeAdmin(realtimeKeysRevoke(store)))
}

// realtimeAdmin is the licence check and the engine check, which every route
// here shares. Authentication and authorization are already done by the time a
// handler on this mux runs; these two are not, and forgetting either turns a
// locked feature into a 500 or a confusing success.
func realtimeAdmin(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireFeature(w, edition.Realtime) {
			return
		}
		if !branch.RealtimeOn() {
			// 409 rather than 403: nothing is wrong with the request or the
			// licence, the engine has simply not been told to carry a feed. The
			// console turns this into the one command that fixes it.
			writeErr(w, 409, fmt.Errorf("the change feed is not set up on this install — run `fox realtime setup`"))
			return
		}
		next(w, r, r.PathValue("name"))
	}
}

// tableRef is the table a request names, read from the body rather than the
// path. A schema-qualified name in a path segment has to be escaped, unescaped
// and re-checked for separators at every hop; in a body it is two fields.
type tableRef struct {
	Schema string `json:"schema"`
	Table  string `json:"table"`
}

func (t tableRef) normalise() (tableRef, error) {
	t.Schema = strings.TrimSpace(t.Schema)
	t.Table = strings.TrimSpace(t.Table)
	if t.Schema == "" {
		t.Schema = "public"
	}
	if t.Table == "" {
		return t, fmt.Errorf("which table? pass {\"schema\":\"public\",\"table\":\"orders\"}")
	}
	// Identifiers reach SQL through the enterprise package, which quotes them;
	// this is the cheap refusal that keeps an obviously wrong value from
	// getting that far, and keeps the error readable when it is a typo.
	for _, s := range []string{t.Schema, t.Table} {
		if strings.ContainsAny(s, `"'`+"`;\\\n\r\t ") {
			return t, fmt.Errorf("%q is not a table name", s)
		}
	}
	return t, nil
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(w, 400, fmt.Errorf("could not read the request: %w", err))
		return false
	}
	return true
}

func realtimeEnableHandler(w http.ResponseWriter, r *http.Request, name string) {
	var body struct {
		tableRef
		Events []string `json:"events"`
		// FullIdentity is the costly rung of the ladder, and it is never
		// inferred. A caller asks for it by name, having been shown the cost.
		FullIdentity bool `json:"full_identity"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	ref, err := body.normalise()
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	req := realtime.Request{
		Table:        realtime.Table{Schema: ref.Schema, Name: ref.Table},
		Events:       body.Events,
		FullIdentity: body.FullIdentity,
	}
	if err := realtime.Enable(name, req); err != nil {
		// The preflight's refusals arrive here, and they are the useful part of
		// this endpoint: they name the table, the reason and the way forward.
		// Passed through as 409 rather than flattened to 500 — nothing failed,
		// the request was refused.
		writeErr(w, 409, err)
		return
	}
	secLog.Audit(auth.EvRealtimeEnabled, actorOf(r), name, remoteIP(r), ref.Schema+"."+ref.Table)
	verdictOrOK(w, name, ref)
}

func realtimeDisableHandler(w http.ResponseWriter, r *http.Request, name string) {
	var body tableRef
	if !readJSON(w, r, &body) {
		return
	}
	ref, err := body.normalise()
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	if err := realtime.Disable(name, ref.Schema, ref.Table); err != nil {
		writeErr(w, 409, err)
		return
	}
	secLog.Audit(auth.EvRealtimeDisabled, actorOf(r), name, remoteIP(r), ref.Schema+"."+ref.Table)
	verdictOrOK(w, name, ref)
}

// realtimePrepareHandler runs one table's fixes, or shows them.
//
// apply defaults to false, so the dry run is what a caller gets by sending
// nothing. The CLI made the same choice for the same reason: the statements are
// DDL, and a reader should see them before they run.
//
// Unlike `prepare --all`, a costly fix is allowed here — this is one table, named
// by a person who has been shown the cost. The bulk refusal lives in PrepareAll
// and is not weakened; there is no bulk route.
func realtimePrepareHandler(w http.ResponseWriter, r *http.Request, name string) {
	var body struct {
		tableRef
		Apply bool `json:"apply"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	ref, err := body.normalise()
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	v, err := realtime.Look(name, ref.Schema, ref.Table, nil)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	// Withheld tables are refused here as well as hidden from the listing. The
	// listing is what a caller sees; this is what stops one that did not look.
	if v.Table.IsSystem || v.Table.IsExtensionOwned {
		writeErr(w, 403, fmt.Errorf("%s is not an application table", v.Table.Qualified()))
		return
	}
	applied := false
	if body.Apply && len(v.Fixes) > 0 {
		if err := realtime.Prepare(name, v); err != nil {
			writeErr(w, 409, err)
			return
		}
		applied = true
		secLog.Audit(auth.EvRealtimePrepared, actorOf(r), name, remoteIP(r),
			fmt.Sprintf("%s: %d statement(s)", v.Table.Qualified(), len(v.Fixes)))
	}
	// The verdict is re-read after applying, so the answer describes the table
	// as it is now rather than as it was when the decision was made.
	after := v
	if applied {
		if again, err := realtime.Look(name, ref.Schema, ref.Table, nil); err == nil {
			after = again
		}
	}
	writeJSON(w, 200, map[string]any{"applied": applied, "statements": v.Fixes, "table": after})
}

// verdictOrOK answers with the table's verdict after a change, so a console
// does not have to re-fetch the whole branch to redraw one row. A verdict that
// cannot be re-read is not an error — the change already happened.
func verdictOrOK(w http.ResponseWriter, name string, ref tableRef) {
	if v, err := realtime.Look(name, ref.Schema, ref.Table, nil); err == nil {
		writeJSON(w, 200, map[string]any{"table": v})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func realtimeKeysList(store *auth.Store) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, r *http.Request, name string) {
		keys, err := store.RealtimeKeysFor(name)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, map[string]any{"keys": keys})
	}
}

func realtimeKeysCreate(store *auth.Store) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, r *http.Request, name string) {
		var body struct {
			Name string `json:"name"`
		}
		// A missing body is fine here: the only field is a label.
		_ = json.NewDecoder(r.Body).Decode(&body)

		u, _ := auth.UserFrom(r.Context())
		secret, info, err := store.CreateRealtimeKey(u.ID, body.Name, name)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		secLog.Audit(auth.EvRealtimeKeyCreated, u.Email, name, remoteIP(r), "key "+info.ID+" ("+info.Name+")")

		// The DSN is built for the host the caller reached us on, not for a
		// configured one. An install reachable at a name the operator typed
		// should hand back that name — a connection string that says
		// 127.0.0.1 to someone on another machine is worse than none.
		dsn := realtime.DSN{Host: requestHost(r), Branch: name, Key: secret, SSL: sslModeFor(r)}
		// Shown once. The secret is not stored, so this response is the only
		// time it exists anywhere but the caller's screen.
		writeJSON(w, 201, map[string]any{"key": info, "url": dsn.String()})
	}
}

func realtimeKeysRevoke(store *auth.Store) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, r *http.Request, name string) {
		id := r.PathValue("id")
		// Scoped to this branch on purpose: the route is authorized against
		// this branch's owner, so it must not be a way to revoke a key that
		// belongs to another one.
		if err := store.RevokeRealtimeKey(name, id); err != nil {
			writeErr(w, 404, err)
			return
		}
		u, _ := auth.UserFrom(r.Context())
		secLog.Audit(auth.EvRealtimeKeyRevoked, u.Email, name, remoteIP(r), "key "+id)
		writeJSON(w, 200, map[string]any{"revoked": id})
	}
}

func actorOf(r *http.Request) string {
	u, _ := auth.UserFrom(r.Context())
	return u.Email
}

// requestHost is the host:port the caller used, so a minted DSN points back at
// the address they can actually reach.
func requestHost(r *http.Request) string {
	if r.Host != "" {
		return r.Host
	}
	return "127.0.0.1:8080"
}

// sslModeFor reports what a client should expect of this install's certificate.
//
// TLS with a self-signed certificate is `require`: encrypted, identity not
// verifiable, which is what a default install serves. Plain HTTP only happens
// on loopback when no certificate could be made, and the DSN has to say so or
// the client will try https and fail.
func sslModeFor(r *http.Request) realtime.SSLMode {
	if r.TLS == nil {
		return realtime.SSLDisable
	}
	return realtime.SSLRequire
}
