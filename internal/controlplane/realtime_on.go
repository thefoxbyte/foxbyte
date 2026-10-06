//go:build enterprise

// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pglogrepl"
	"github.com/thefoxbyte/foxbyte/enterprise/realtime"
	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// GET /api/branches/{name}/realtime — the change feed, as server-sent events.
//
// Mounted on the *outer* mux rather than behind the /api/ gate, because a
// branch-scoped API key has to reach it and Authn refuses those outright. A
// more specific pattern beats the gate, which is the same trick
// GET /api/openapi.yaml already relies on — and the handler then repeats, by
// hand, every check the bypassed middleware would have made. Getting that list
// wrong is the risk of this approach, so it is written out rather than implied.

// MaxStreamDuration bounds one connection.
//
// A forgotten tab holds a replication slot, and a slot holds WAL. The stream
// ends with a resync and the client reconnects with ?since=, which costs it
// nothing and gives the engine a chance to reclaim.
const MaxStreamDuration = time.Hour

// hubs is one fan-out per branch, started on the first subscriber and stopped
// after the last: a branch nobody is listening to should not hold a slot open.
var hubs = struct {
	mu     sync.Mutex
	m      map[string]*realtime.Hub
	cancel map[string]context.CancelFunc
}{m: map[string]*realtime.Hub{}, cancel: map[string]context.CancelFunc{}}

func mountRealtimeStream(outer *http.ServeMux, store *auth.Store, acl *access.Checker) {
	outer.HandleFunc("GET /api/branches/{name}/realtime", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")

		// 1. Authentication, including the narrow branch-scoped-key exception.
		u, ok := store.UserForBranchStream(r, name)
		if !ok {
			writeErr(w, 401, fmt.Errorf("sign in, or use an API key scoped to %q", name))
			return
		}
		// 2. Authorization, answering None with 404 exactly as `allowed` does:
		//    a caller who may not reach a branch is not told it exists.
		if lvl := acl.Level(u, name); lvl == access.None {
			secLog.Audit(auth.EvDenied, u.Email, name, remoteIP(r), "GET realtime")
			writeErr(w, 404, fmt.Errorf("no branch %q", name))
			return
		}
		// 3. The licence. After authorization, so an unlicensed install does
		//    not become a way to ask which branches exist.
		if !requireFeature(w, edition.Realtime) {
			return
		}
		// 4. And the engine has to be set up for it at all.
		if !branch.RealtimeOn() {
			writeErr(w, 409, fmt.Errorf("the change feed is not set up on this install — run `fox realtime setup`"))
			return
		}
		streamRealtime(w, r, name)
	})
}

func streamRealtime(w http.ResponseWriter, r *http.Request, name string) {
	send, _, ok := newSSE(w)
	if !ok {
		writeErr(w, 500, fmt.Errorf("this server cannot stream"))
		return
	}

	since, err := parseSince(r.URL.Query().Get("since"))
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	hub := hubFor(name, since)
	sub := hub.Subscribe()
	defer func() {
		sub.Close()
		releaseHub(name)
	}()

	deadline := time.NewTimer(MaxStreamDuration)
	defer deadline.Stop()

	for {
		select {
		case <-r.Context().Done():
			return // the client went away
		case <-deadline.C:
			send("message", realtime.Notice{Type: "resync", Code: realtime.CodeMaxDuration,
				Detail: "this stream reached its time limit; reconnect with ?since= to carry on"})
			return
		case <-sub.Done():
			// Dropped: overflow, a failed decoder, or the branch going away.
			// Always say why — a stream that just stops looks like a network
			// fault, and the client would retry into the same wall.
			if n := sub.Reason(); n.Type != "" {
				send("message", n)
			}
			return
		case ev := <-sub.Events():
			send("message", ev)
		}
	}
}

// hubFor returns the branch's fan-out, starting a decoder on the first
// subscriber. A branch nobody is listening to should not hold a replication
// slot open, so the decoder's lifetime is the hub's.
func hubFor(name string, since pglogrepl.LSN) *realtime.Hub {
	hubs.mu.Lock()
	defer hubs.mu.Unlock()
	if h, ok := hubs.m[name]; ok {
		return h
	}
	h := realtime.NewHub()
	ctx, cancel := context.WithCancel(context.Background())
	hubs.m[name] = h
	hubs.cancel[name] = cancel
	go realtime.Supervise(ctx, name, branch.SlotName(name, "stream"),
		branch.RealtimeRolePassword(), h, since)
	return h
}

// releaseHub stops the decoder once nobody is listening. The slot stays: it is
// what a reconnecting subscriber resumes from, and `fox up` sweeps the ones
// nothing is coming back for.
func releaseHub(name string) {
	hubs.mu.Lock()
	defer hubs.mu.Unlock()
	h, ok := hubs.m[name]
	if !ok || h.Count() > 0 {
		return
	}
	if cancel, ok := hubs.cancel[name]; ok {
		cancel()
		delete(hubs.cancel, name)
	}
	delete(hubs.m, name)
}

// parseSince reads the ?since= a client passes to resume. An unreadable value
// is refused rather than quietly treated as "from now": silently restarting a
// subscriber at the present moment is how a gap appears in its copy with
// nothing to show for it.
func parseSince(raw string) (pglogrepl.LSN, error) {
	if raw == "" {
		return 0, nil
	}
	lsn, err := pglogrepl.ParseLSN(raw)
	if err != nil {
		return 0, fmt.Errorf("since=%q is not a log position: pass back the commit_lsn of the last change you saw", raw)
	}
	return lsn, nil
}
