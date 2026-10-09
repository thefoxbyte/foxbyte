//go:build enterprise

// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"fmt"
	"net/http"

	"github.com/thefoxbyte/foxbyte/enterprise/realtime"
	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// The realtime front door: /realtime/v1, on the port the console already uses.
//
// An application that wants the change feed should not have to be told about
// the control plane, and should not be handed a credential that reaches it.
// So realtime gets its own namespace, its own kind of key, and a connection
// string of its own shape — and none of that needs a second port, a second
// certificate or a second firewall rule.
//
//	GET /realtime/v1/branches/{name}/hello    confirm a DSN before relying on it
//	GET /realtime/v1/branches/{name}/tables   what can stream, and what it would take
//	GET /realtime/v1/branches/{name}/stream   the feed
//
// Mounted on the outer mux, because /api/'s gate refuses a scoped key outright
// and that reasoning still stands — it is about the control plane. A more
// specific pattern beats the gate, the trick GET /api/openapi.yaml already
// relies on.
//
// The cost of bypassing that middleware is that this file has to repeat what it
// would have done. The previous route wrote those checks out by hand and said
// so. With three routes that stops being honest, because three copies drift —
// so they share one gate, written once, below.
//
// GET /api/branches/{name}/realtime stays exactly as it was. A subscriber
// running today keeps working; this is a second door, not a replacement.

func mountRealtimeDoor(outer *http.ServeMux, store *auth.Store, acl *access.Checker) {
	gate := realtimeGate(store, acl)
	outer.HandleFunc("GET "+realtime.APIPrefix+"/branches/{name}/hello", gate(realtimeHello))
	outer.HandleFunc("GET "+realtime.APIPrefix+"/branches/{name}/tables", gate(realtimeTables))
	outer.HandleFunc("GET "+realtime.APIPrefix+"/branches/{name}/stream", gate(streamRealtime))
}

// realtimeGate is every check the /api/ middleware would have made, in the
// order it would have made them, for a mux that does not run it.
//
// The order is the part that matters and is not arbitrary:
//
//  1. the branch name, before it reaches anything that resolves it;
//  2. authentication, including realtime keys;
//  3. authorization — answered as 404, because a caller who may not reach a
//     branch must not learn that it exists;
//  4. the licence, after authorization, so an unlicensed install is not itself
//     a way to ask which branches exist;
//  5. and whether the engine is set up for realtime at all.
func realtimeGate(store *auth.Store, acl *access.Checker) func(func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			name := r.PathValue("name")
			// 1. The /api/ gate validates this segment before any handler sees
			//    it; this mux does not, so it is checked here. Answered as 404
			//    rather than 400 for the same reason step 3 is: a name that
			//    cannot exist and a name the caller may not see should look
			//    alike.
			if !branch.ValidName(name) {
				writeErr(w, 404, fmt.Errorf("no branch %q", name))
				return
			}
			// 2. Authentication: a session, an account key, a realtime key for
			//    this branch, or a gateway key for this branch.
			u, ok := store.UserForRealtime(r, name)
			if !ok {
				writeErr(w, 401, fmt.Errorf("pass a realtime key for %q as a Bearer token", name))
				return
			}
			// 3. Authorization.
			if lvl := acl.Level(u, name); lvl == access.None {
				secLog.Audit(auth.EvDenied, u.Email, name, remoteIP(r), "realtime "+r.URL.Path)
				writeErr(w, 404, fmt.Errorf("no branch %q", name))
				return
			}
			// 4. The licence.
			if !requireFeature(w, edition.Realtime) {
				return
			}
			// 5. And the engine.
			if !branch.RealtimeOn() {
				writeErr(w, 409, fmt.Errorf("the change feed is not set up on this install — run `fox realtime setup`"))
				return
			}
			next(w, r, name)
		}
	}
}

// realtimeHello confirms a connection string without subscribing to anything.
//
// It exists because the alternative is worse: a client whose only way to find
// out that its DSN is wrong is to open a stream, which holds a replication slot
// and reports its own failures as stream events. A cheap handshake lets an
// application fail at start-up, with a message, instead of at 3am as silence.
func realtimeHello(w http.ResponseWriter, r *http.Request, name string) {
	writeJSON(w, 200, map[string]any{
		"branch":   name,
		"realtime": "ok",
		"version":  1,
		"tables":   realtime.APIPrefix + "/branches/" + name + "/tables",
		"stream":   realtime.APIPrefix + "/branches/" + name + "/stream",
	})
}

// realtimeTables is stage 1's readiness survey, over HTTP.
//
// The same verdicts the CLI prints, so an application can discover what it may
// subscribe to — and what it would take to subscribe to the rest — rather than
// being told out of band by whoever set the branch up.
func realtimeTables(w http.ResponseWriter, r *http.Request, name string) {
	events := r.URL.Query()["events"]
	verdicts, err := realtime.Survey(name, events)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	// Survey classifies every table, including FoxByte's own and Postgres's;
	// it is the caller that decides what to show. Over HTTP that must be the
	// application's tables only — a realtime key is held by an application, and
	// handing it the names, row counts and column shapes of the bb schema tells
	// it about the hash-chained ledger it has no business knowing.
	//
	// The first version of this handler passed Survey's output straight out,
	// with a comment claiming Survey had already dropped them. It had not, and
	// the integration suite caught 229 system rows on the wire.
	app, withheld := realtime.Application(verdicts)
	writeJSON(w, 200, map[string]any{"branch": name, "tables": app, "withheld": withheld})
}
