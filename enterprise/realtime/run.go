//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jackc/pglogrepl"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// Keeping a decoder alive for as long as somebody is listening.
//
// A decoder is one connection reading one slot, and connections drop: a branch
// restarts, the network blinks, Postgres is reloaded. Reconnecting is ordinary,
// and the slot is what makes it safe — it remembers where the feed had got to,
// so a reconnect resumes rather than skips.
//
// What is not ordinary is failing over and over. After enough consecutive
// failures the stream is ended with a reason, because a client retrying into a
// wall forever is worse than one told to stop.

// MaxConsecutiveFailures is how many times a decoder may fail to start or run
// before its subscribers are told to give up.
const MaxConsecutiveFailures = 10

// backoff grows with consecutive failures, to a ceiling.
func backoff(failures int) time.Duration {
	d := time.Duration(failures) * time.Second
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d
}

// Supervise runs a decoder for a branch until ctx is cancelled, restarting it
// across failures and telling subscribers when it has given up.
//
// since is where the first attempt resumes from. After a reconnect the slot
// decides, which is the point of a durable slot: the decoder asks for 0 and
// Postgres replays from wherever the feed was acknowledged to.
func Supervise(ctx context.Context, branchName, slot, password string, hub *Hub, since pglogrepl.LSN) {
	failures := 0
	for {
		if ctx.Err() != nil {
			return
		}
		err := runOnce(ctx, branchName, slot, password, hub, since)
		since = 0 // only the first attempt resumes from the caller's position
		switch {
		case ctx.Err() != nil:
			return // we were asked to stop; not a failure
		case err == nil:
			failures = 0
		default:
			failures++
			log.Printf("change feed %s: %v (attempt %d)", branchName, err, failures)
			if isSlotLost(err) {
				// The WAL budget did its job: Postgres dropped the slot rather
				// than hold more. The subscriber cannot resume, and must be
				// told so rather than left waiting — a silent gap in its copy
				// is the one outcome this design refuses.
				hub.Close(Notice{Type: "resync", Code: CodeSlotLost,
					Detail: "the feed fell further behind than the WAL budget allows; " +
						"refetch the table and subscribe again"})
				return
			}
			if failures >= MaxConsecutiveFailures {
				hub.Close(Notice{Type: "error", Code: CodeDecoderFailed,
					Detail: "the change feed could not be read after repeated attempts"})
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff(failures)):
		}
	}
}

func runOnce(ctx context.Context, branchName, slot, password string, hub *Hub, since pglogrepl.LSN) error {
	// A branch is a clone of main, so it has whatever roles main had when it was
	// taken -- which for a branch older than `fox realtime setup` is not this
	// one. Idempotent, and cheap next to opening a replication connection.
	if err := branch.EnsureRealtimeRole(branchName, password); err != nil {
		return fmt.Errorf("preparing the %s role on %q: %w", branch.RealtimeRole, branchName, err)
	}
	dsn, err := branch.RealtimeDSN(branchName, password)
	if err != nil {
		return err
	}
	// Every publication the feed owns, because each carries a different set of
	// events and a subscriber wants all of them.
	pubs, err := branch.Publications(branchName)
	if err != nil {
		return err
	}
	if len(pubs) == 0 {
		return fmt.Errorf("nothing is being streamed on %q yet — enable a table first", branchName)
	}
	d, err := NewDecoder(ctx, dsn, slot, strings.Join(pubs, ","), hub)
	if err != nil {
		return err
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = d.Close(closeCtx)
	}()
	if err := d.EnsureSlot(ctx); err != nil {
		return err
	}
	// Everything the subscriber already knew is stale after a reconnect, so the
	// relation cache starts empty and the first row of each table re-announces
	// its shape.
	return d.Run(ctx, since)
}

// isSlotLost reports whether Postgres has invalidated the slot, which is what
// exceeding max_slot_wal_keep_size looks like from here.
//
// Matched on SQLSTATE rather than on the message, which is how the first
// version got it wrong: it looked for "can no longer get changes from
// replication slot" and Postgres actually says "can no longer access
// replication slot". The slot had been invalidated exactly as designed, and the
// decoder treated it as a passing failure -- ten retries over nearly a minute,
// and then "could not be read after repeated attempts" rather than the resync
// that tells a subscriber to refetch. A client left retrying into a wall with
// no idea it has to start again is the one outcome this design promises not to
// produce, and prose is a poor thing to have promised it on.
//
// 55000 is object_not_in_prerequisite_state, which Postgres uses for several
// things, so the message still has to mention a slot -- but the code does the
// work and the wording only narrows it.
func isSlotLost(err error) bool {
	if err == nil {
		return false
	}
	var pge *pgconn.PgError
	if errors.As(err, &pge) && pge.Code == "55000" &&
		strings.Contains(strings.ToLower(pge.Message), "replication slot") {
		return true
	}
	// A segment that has been recycled says so differently, and is the same
	// situation from the subscriber's point of view.
	return strings.Contains(err.Error(), "requested WAL segment")
}
