//go:build enterprise

// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"context"
	"fmt"
	"log"
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
	// Everything that can refuse runs before the stream is opened.
	//
	// newSSE writes 200 and flushes the headers, and after that the status
	// cannot be changed: a writeErr following it appends a JSON body to a
	// response that has already said 200 and text/event-stream. The subscriber
	// cap did exactly that — the integration suite caught a refusal whose body
	// named the limit while the code was 200 — and an unparseable ?since= had
	// been doing the same since this route was written. A client that checks
	// status codes would have treated both as success and then failed to parse
	// an event stream that was really an error.
	since, err := parseSince(r.URL.Query().Get("since"))
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	// ?transactions=1 adds the begin and commit frames around each
	// transaction's changes. Off by default: see realtime.Begin.
	frames, err := parseFrames(r.URL.Query().Get("transactions"))
	if err != nil {
		writeErr(w, 400, err)
		return
	}

	// What that position can actually be served from, decided before anything
	// is opened. A stream that silently starts somewhere other than where the
	// subscriber asked is the one failure this route must not have.
	hub, verdict, err := resumeFor(name, since)
	switch {
	case err != nil:
		writeErr(w, 409, err)
		return
	case verdict == realtime.ResumeAhead:
		writeErr(w, 400, err400Ahead(name, since))
		return
	case verdict == realtime.ResumeExpired:
		// A stream that opens and says "refetch" rather than an HTTP error:
		// `resync` is a thing every client already handles, it is how a lost
		// slot and a timed-out stream are reported, and the SDKs answer it by
		// refetching the table and subscribing again. A 4xx here would be a
		// new failure for a client that is behaving correctly.
		expired(w, since)
		return
	}
	// Capped. Every subscriber is a reason this branch cannot be suspended and
	// a share of one decoder's fan-out, and a client that reconnects on error
	// with a bug would otherwise add a stream per attempt until the process ran
	// out of something. 429 rather than 503: the request is well-formed and the
	// caller is being asked to hold off, which is what that code means.
	sub, err := hub.TrySubscribe()
	if err != nil {
		// Released here because resumeFor may have just started a decoder for a
		// subscriber that is not going to attach.
		releaseHub(name)
		writeErr(w, 429, err)
		return
	}

	send, _, ok := newSSE(w)
	if !ok {
		sub.Close()
		releaseHub(name)
		writeErr(w, 500, fmt.Errorf("this server cannot stream"))
		return
	}
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
			// One decoder serves every subscriber of a branch, so the frames
			// are always produced and dropped here for subscribers that did
			// not ask. A client written against the unframed feed must not
			// start receiving event types it has no case for.
			if !frames {
				switch ev.(type) {
				case realtime.Begin, realtime.Commit:
					continue
				}
			}
			send("message", ev)
		}
	}
}

// resumeFor returns the branch's fan-out and what may be done with since,
// starting a decoder on the first subscriber. A branch nobody is listening to
// should not hold a replication slot open, so the decoder's lifetime is the
// hub's.
//
// It replaces a hubFor that took since and, if a fan-out was already running,
// returned it and dropped the argument on the floor. That is where the silent
// gap came from: the subscriber was attached to a stream in progress and told
// nothing, and the changes it had asked for had already gone to whoever was
// listening at the time. The argument is now a question with four answers, and
// three of them are not "attach".
func resumeFor(name string, since pglogrepl.LSN) (*realtime.Hub, realtime.ResumeVerdict, error) {
	// No position asked for: from here, which is what it has always meant.
	if since == 0 {
		if h := liveHub(name); h != nil {
			return h, realtime.ResumeLive, nil
		}
		// This subscriber starts the decoder, and where it starts is what every
		// later subscriber's ?since= will be measured against -- so the branch
		// is read even though this one asked for nothing.
		//
		// Best effort, unlike the resuming path below: a subscribe that worked
		// before this check existed must not start failing because a reading
		// failed. The floor stays unknown, and a later subscriber that does
		// want to resume is told to refetch rather than attached blind.
		w, err := resumeWindow(name)
		if err != nil {
			log.Printf("change feed %s: could not read where the stream begins (%v); "+
				"a later ?since= on it will be answered with a refetch", name, err)
		}
		floor := w.Confirmed
		if !w.HaveSlot {
			floor = w.WALEnd
		}
		h, _ := startHub(name, 0, floor)
		return h, realtime.ResumeLive, nil
	}

	// A position was asked for, so the branch is read in every case: a position
	// only means something against the log it claims to have come from, and
	// that is the check the slot-poisoning fault needed.
	w, err := resumeWindow(name)
	if err != nil {
		// Refused rather than guessed. The alternative is handing an unchecked
		// position to the decoder, which is how a slot came to be acknowledged
		// past the end of the log -- and the stream could not have worked
		// anyway, since the decoder needs the branch this query just failed on.
		return nil, 0, err
	}
	// A fan-out already running is the authority on what it can serve: it
	// cannot replay, so the only position it can honour is one nothing has
	// passed, and its floor is newer than any reading of the slot.
	if h := liveHub(name); h != nil {
		w.Live, w.Floor = true, h.Floor()
		v := realtime.JudgeResume(since, w)
		if v == realtime.ResumeAhead || v == realtime.ResumeExpired {
			return nil, v, nil
		}
		return h, realtime.ResumeLive, nil
	}
	switch v := realtime.JudgeResume(since, w); v {
	case realtime.ResumeAhead, realtime.ResumeExpired:
		return nil, v, nil
	}
	h, started := startHub(name, since, since)
	if !started {
		// Somebody started a decoder between the reading and this line, so
		// that hub's floor decides rather than a window from a moment ago.
		w.Live, w.Floor = true, h.Floor()
		if v := realtime.JudgeResume(since, w); v != realtime.ResumeLive {
			return nil, v, nil
		}
	}
	return h, realtime.ResumeLive, nil
}

// readResumeWindow is branch.RealtimeResumeWindow, a variable for the same
// reason ensureRunning is one: the four answers this route gives are worth
// reading in a test, and they are a decision rather than a query.
var readResumeWindow = branch.RealtimeResumeWindow

// resumeWindow reads what a ?since= has to be judged against: the slot's
// acknowledged position and the branch's own log end. What a fan-out already
// running can serve is added to it by the caller.
func resumeWindow(name string) (realtime.Window, error) {
	// Asked while the branch is awake. The reaper suspends a branch nobody is
	// listening to, which is why the slot outlives it; the decoder wakes it,
	// but that is after this.
	if _, err := ensureRunning(name); err != nil {
		return realtime.Window{}, err
	}
	rw, err := readResumeWindow(name, branch.SlotName(name, "stream"))
	if err != nil {
		return realtime.Window{}, fmt.Errorf("could not read %q's log position to resume from: %w", name, err)
	}
	w := realtime.Window{HaveSlot: rw.HaveSlot}
	if rw.HaveSlot {
		if lsn, err := pglogrepl.ParseLSN(rw.Confirmed); err == nil {
			w.Confirmed = lsn
		}
	}
	if lsn, err := pglogrepl.ParseLSN(rw.WALEnd); err == nil {
		w.WALEnd = lsn
	}
	return w, nil
}

// startHub returns the branch's fan-out, and whether this call is what started
// it. A new one is told the position its stream begins at, which is the floor
// every later subscriber's ?since= is measured against.
func startHub(name string, since, floor pglogrepl.LSN) (h *realtime.Hub, started bool) {
	hubs.mu.Lock()
	defer hubs.mu.Unlock()
	if h, ok := hubs.m[name]; ok {
		return h, false
	}
	h = realtime.NewHub()
	// Before the decoder runs, so nothing can be published while the floor is
	// still zero.
	h.StartedAt(floor)
	ctx, cancel := context.WithCancel(context.Background())
	hubs.m[name] = h
	hubs.cancel[name] = cancel
	go realtime.Supervise(ctx, name, branch.SlotName(name, "stream"),
		branch.RealtimeRolePassword(), h, since)
	return h, true
}

// err400Ahead is the refusal for a position this branch has not reached.
//
// Named and worded carefully because the honest causes are not a client bug:
// every branch has a log of its own, so a position from another branch is
// ahead of a young one by construction, and a restore moves a branch's log back
// under a client that is still holding a mark from before it.
func err400Ahead(name string, since pglogrepl.LSN) error {
	return fmt.Errorf("since=%s is ahead of %q's log, so it cannot have come from this feed — "+
		"subscribe without ?since= and refetch the table (each branch has its own log positions, "+
		"and a restore moves them back)", since, name)
}

// expired opens the stream only to say that the position is gone.
func expired(w http.ResponseWriter, since pglogrepl.LSN) {
	send, _, ok := newSSE(w)
	if !ok {
		writeErr(w, 500, fmt.Errorf("this server cannot stream"))
		return
	}
	send("message", realtime.Notice{Type: "resync", Code: realtime.CodeCursorExpired,
		Detail: fmt.Sprintf("the feed cannot replay from since=%s any more: it has been read past, "+
			"either by this branch's own subscribers or because the slot was acknowledged beyond it. "+
			"Refetch the table and subscribe again", since)})
}

// liveHub is the fan-out for a branch if one exists, and nil otherwise.
//
// Deliberately not hubFor: that starts a decoder, which would mean the meter
// taking a reading opened a replication slot on a branch nobody was
// subscribed to. A meter must not change what it measures.
func liveHub(name string) *realtime.Hub {
	hubs.mu.Lock()
	defer hubs.mu.Unlock()
	return hubs.m[name]
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

// parseFrames reads ?transactions=.
//
// A value nobody recognises is refused rather than read as "no": a subscriber
// that asked for frames and silently did not get them would apply a
// transaction in pieces and never know why.
func parseFrames(raw string) (bool, error) {
	switch raw {
	case "", "0", "false":
		return false, nil
	case "1", "true":
		return true, nil
	}
	return false, fmt.Errorf("transactions=%q is not 1 or 0", raw)
}
