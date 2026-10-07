//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// An invalidated slot has to be recognised, or a subscriber is told to wait
// when it needs to be told to start again.
//
// The first version matched the message "can no longer get changes from
// replication slot". Postgres says "can no longer access replication slot", so
// the decoder treated an invalidated slot as a passing failure: ten retries
// over nearly a minute, then "could not be read after repeated attempts"
// instead of a resync. Both wordings are here, because the point is that the
// SQLSTATE does the work.
func TestAnInvalidatedSlotIsRecognised(t *testing.T) {
	for _, msg := range []string{
		`can no longer access replication slot "fox_rt_main_stream"`,
		`can no longer get changes from replication slot "fox_rt_main_stream"`,
	} {
		err := error(&pgconn.PgError{Code: "55000", Message: msg})
		if !isSlotLost(err) {
			t.Errorf("not recognised: %s", msg)
		}
		// And still recognised when something has wrapped it on the way up.
		if !isSlotLost(fmt.Errorf("starting replication on x: %w", err)) {
			t.Errorf("not recognised once wrapped: %s", msg)
		}
	}
	if !isSlotLost(errors.New("requested WAL segment 00000001 has already been removed")) {
		t.Error("a recycled WAL segment is the same situation and must be recognised")
	}
}

// And an ordinary failure must not be mistaken for it: a subscriber told to
// refetch when the network merely blinked throws away a position it could have
// resumed from.
func TestAPassingFailureIsNotMistakenForALostSlot(t *testing.T) {
	for _, err := range []error{
		errors.New("connection refused"),
		errors.New("context deadline exceeded"),
		&pgconn.PgError{Code: "53300", Message: "too many connections"},
		// The same SQLSTATE, but about something else entirely.
		&pgconn.PgError{Code: "55000", Message: "database is not accepting commands"},
	} {
		if isSlotLost(err) {
			t.Errorf("mistaken for a lost slot: %v", err)
		}
	}
}
