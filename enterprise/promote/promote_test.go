//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package promote

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

func entry(id int64, actor, kind, tag, obj, sql string) branch.RequestEntry {
	return branch.RequestEntry{ID: id, At: "2026-09-28T10:00:00Z", Actor: actor, ActorKind: kind,
		CommandTag: tag, Object: obj, Statement: sql}
}

// What a branch has already had applied elsewhere must not be offered again, and
// must not make its next round look like a conflict.
func TestAlreadyPromoted(t *testing.T) {
	snapshot, err := branch.MarshalEntries([]branch.RequestEntry{entry(11, "a", "human", "CREATE TABLE", "public.t", "CREATE TABLE t (id int)")})
	if err != nil {
		t.Fatal(err)
	}
	history := []auth.ChangeRequest{
		{ID: 3, Source: "dev", Target: "main", Status: auth.RequestApproved, Applied: 1, Entries: snapshot},
		{ID: 4, Source: "dev", Target: "main", Status: auth.RequestRejected, Applied: 0, Entries: snapshot},
		{ID: 5, Source: "other", Target: "main", Status: auth.RequestApproved, Applied: 1, Entries: snapshot},
		{ID: 6, Source: "dev", Target: "staging", Status: auth.RequestApproved, Applied: 1, Entries: snapshot},
	}
	ids, sessions := alreadyPromoted("dev", "main", history)
	if !ids[11] {
		t.Error("an entry applied by an earlier request is not remembered")
	}
	if !sessions["request-3"] {
		t.Error("the session the statements were applied under is not remembered")
	}
	// A rejected request applied nothing; another source's and another target's
	// requests say nothing about this pair.
	for _, no := range []string{"request-4", "request-5", "request-6"} {
		if sessions[no] {
			t.Errorf("%s should not count for dev → main", no)
		}
	}
	if len(sessions) != 1 {
		t.Errorf("sessions = %v, want only request-3", sessions)
	}
}

// A request with no statements is refused rather than producing an empty
// transaction that reports success.
func TestApplyRequestRefusesNothing(t *testing.T) {
	if _, err := apply(1, "main", "someone@example.com", nil); err != branch.ErrNothingToPromote {
		t.Errorf("applying an empty request gave %v, want branch.ErrNothingToPromote", err)
	}
}

// Names are checked before anything reaches a container.
func TestBuildRequestChecksNames(t *testing.T) {
	if _, _, err := build("dev", "dev", nil); err == nil {
		t.Error("a branch was allowed to be its own source and target")
	}
	if _, _, err := build("../etc", "main", nil); err == nil {
		t.Error("a source that is not a branch name was accepted")
	}
	if _, _, err := build("dev", "../etc", nil); err == nil {
		t.Error("a target that is not a branch name was accepted")
	}
}

// recordingTx stands in for the transaction: what replay asked of it, in order.
type recordingTx struct {
	calls  []execCall
	failOn string
}

type execCall struct {
	sql  string
	args []any
}

func (r *recordingTx) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	r.calls = append(r.calls, execCall{sql, args})
	if r.failOn != "" && strings.Contains(sql, r.failOn) {
		return pgconn.CommandTag{}, errors.New("boom")
	}
	return pgconn.CommandTag{}, nil
}

// The statements replay sent, without the settings between them.
func (r *recordingTx) statements() []string {
	var out []string
	for _, c := range r.calls {
		if !strings.HasPrefix(c.sql, "SELECT set_config(") {
			out = append(out, c.sql)
		}
	}
	return out
}

func alwaysInTx() bool { return true }

// One run of two statements is two entries, each holding the run's whole
// text: replay runs it once, at the first, under its author.
func TestReplayRunsASharedStatementOnce(t *testing.T) {
	run := "CREATE TABLE t (id int); CREATE FUNCTION t_add(i int) RETURNS void LANGUAGE sql AS $$ INSERT INTO t VALUES (i) $$"
	entries := []branch.RequestEntry{
		{ID: 171, Actor: "ada@example.com", CommandTag: "CREATE TABLE", Statement: run},
		{ID: 172, Actor: "ada@example.com", CommandTag: "CREATE FUNCTION", Statement: run},
		{ID: 173, Actor: "bob@example.com", CommandTag: "CREATE INDEX", Statement: "CREATE INDEX ON t (id)"},
	}
	branch.ReplayOnce(entries, map[int64]int64{171: 900, 172: 900, 173: 901})
	tx := &recordingTx{}
	if err := replay(context.Background(), tx, alwaysInTx, 5, "carol@example.com", entries); err != nil {
		t.Fatal(err)
	}
	got := tx.statements()
	if len(got) != 2 || got[0] != run || got[1] != "CREATE INDEX ON t (id)" {
		t.Fatalf("statements = %q", got)
	}
	var actors []any
	for _, c := range tx.calls {
		if strings.Contains(c.sql, "'bb.actor'") {
			actors = append(actors, c.args...)
		}
	}
	if len(actors) != 2 || actors[0] != "ada@example.com" || actors[1] != "bob@example.com" {
		t.Fatalf("actors = %v", actors)
	}
}

// The apply path is not psql: each statement is one Exec, verbatim and with no
// arguments, so nothing but the server reads it. The transaction is the
// caller's, and replay issues none of its own control.
func TestReplayNeverGoesThroughPsql(t *testing.T) {
	stmt := "COMMENT ON TABLE t IS E':var \\\\! rm -rf / \\\\gexec'"
	tx := &recordingTx{}
	if err := replay(context.Background(), tx, alwaysInTx, 7, "carol@example.com",
		[]branch.RequestEntry{{ID: 1, Actor: "ada@example.com", Statement: "  " + stmt + "\n"}}); err != nil {
		t.Fatal(err)
	}
	if got := tx.statements(); len(got) != 1 || got[0] != stmt {
		t.Fatalf("the statement was changed on its way: %q", got)
	}
	for _, c := range tx.calls {
		if c.sql == stmt && len(c.args) != 0 {
			t.Fatalf("the statement was sent with arguments: %v", c.args)
		}
		for _, control := range []string{"BEGIN", "COMMIT", "SET LOCAL", "RESET ROLE", "SET ROLE"} {
			if strings.Contains(c.sql, control) {
				t.Fatalf("replay issued %s itself: %q", control, c.sql)
			}
		}
	}
	src, err := os.ReadFile("promote.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "ExecScript(") {
		t.Fatal("the apply path goes through branch.ExecScript, which is psql over stdin")
	}
}

// The statement after the one that fails is not attempted, and the failure
// names the entry.
func TestReplayStopsAtTheFirstFailure(t *testing.T) {
	tx := &recordingTx{failOn: "CREATE VIEW"}
	err := replay(context.Background(), tx, alwaysInTx, 1, "c", []branch.RequestEntry{
		{ID: 1, Statement: "CREATE TABLE a ()"}, {ID: 2, Statement: "CREATE VIEW b AS SELECT 1"}, {ID: 3, Statement: "CREATE TABLE c ()"},
	})
	if err == nil || !strings.Contains(err.Error(), "entry 2") {
		t.Fatalf("err = %v", err)
	}
	if got := tx.statements(); len(got) != 2 {
		t.Fatalf("carried on after the failure: %q", got)
	}
}

// If a statement ever did end the transaction, the next must not run.
func TestReplayStopsIfTheTransactionEnded(t *testing.T) {
	tx := &recordingTx{}
	err := replay(context.Background(), tx, func() bool { return false }, 1, "c", []branch.RequestEntry{
		{ID: 1, Statement: "CREATE TABLE a ()"}, {ID: 2, Statement: "CREATE TABLE b ()"},
	})
	if !errors.Is(err, errTransactionEnded) {
		t.Fatalf("err = %v", err)
	}
	if got := tx.statements(); len(got) != 1 {
		t.Fatalf("carried on outside the transaction: %q", got)
	}
}

// What a failure says was committed has to be true.
func TestApplyFailureSaysWhatWasCommitted(t *testing.T) {
	refused := &pgconn.PgError{Message: "deferred constraint"}
	lost := errors.New("connection reset")
	cases := []struct {
		name     string
		replayed bool
		err      error
		want     string
	}{
		{"a statement failed", false, lost, "nothing was committed"},
		{"the server refused the commit", true, refused, "nothing was committed"},
		{"the server rolled back at commit", true, pgx.ErrTxCommitRollback, "nothing was committed"},
		{"the commit's answer never came", true, lost, "may or may not be in"},
		{"a statement ended the transaction", false, errTransactionEnded, "part of it may be committed"},
	}
	for _, c := range cases {
		if got := applyFailure("main", c.replayed, c.err).Error(); !strings.Contains(got, c.want) {
			t.Errorf("%s: %q does not say %q", c.name, got, c.want)
		}
	}
}
