//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package promote

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

// ── Schema only by default (TX-6) ────────────────────────────────────────────

func candidate(id int64, tag, obj, status, risk, sql string) ledger.Row {
	return ledger.Row{ID: id, Actor: "agent-a", ActorKind: "agent", CommandTag: tag, ObjectIdentity: obj,
		Status: status, Risk: risk, Statement: sql}
}

func sampleCandidates() []ledger.Row {
	return []ledger.Row{
		candidate(10, "CREATE TABLE", "public.t", "APPLIED", "", "CREATE TABLE t (id int)"),
		candidate(11, "INSERT", "public.t", "APPLIED", "", "INSERT INTO t VALUES (1)"),
		candidate(12, "DELETE", "public.orders", "FLAGGED", "impact", "DELETE FROM orders WHERE id > 0"),
		candidate(13, "UPDATE", "public.orders", "FLAGGED", "budget", "UPDATE orders SET x = 1 WHERE true"),
		candidate(14, "TRUNCATE", "public.orders", "APPLIED", "truncate", "TRUNCATE orders"),
		// A FLAGGED schema change is still a schema change: it stays, with its risk.
		candidate(15, "ALTER TABLE", "public.t", "FLAGGED", "drop-column", "ALTER TABLE t DROP COLUMN c"),
	}
}

func TestDataChangesAreLeftOutByDefault(t *testing.T) {
	p := newForkPlan(nil, nil)
	p.candidates, p.forkAfterID = sampleCandidates(), 9

	plan := p.plan(branch.RequestOptions{})
	var kept []int64
	for _, e := range plan.Entries {
		kept = append(kept, e.ID)
	}
	if fmt.Sprint(kept) != "[10 15]" {
		t.Errorf("a schema-only request carries %v, want the CREATE TABLE and the flagged ALTER", kept)
	}
	if plan.IncludeData || plan.OmittedCount != 4 || len(plan.Omitted) != 4 {
		t.Fatalf("left out %d (listed %d), include_data=%v; want 4 listed and schema only",
			plan.OmittedCount, len(plan.Omitted), plan.IncludeData)
	}
	for _, o := range plan.Omitted {
		if o.ID < 11 || o.ID > 14 || o.Reason == "" || o.CommandTag == "" {
			t.Errorf("left-out entry is not described: %+v", o)
		}
	}
	if plan.ForkAfterID != 9 {
		t.Errorf("fork = %d", plan.ForkAfterID)
	}
}

func TestDataChangesAreCarriedWhenAskedFor(t *testing.T) {
	p := newForkPlan(nil, nil)
	p.candidates = sampleCandidates()
	plan := p.plan(branch.RequestOptions{IncludeData: true})
	if len(plan.Entries) != 6 || plan.OmittedCount != 0 || !plan.IncludeData {
		t.Fatalf("with data included: %d entries, %d left out, include_data=%v", len(plan.Entries), plan.OmittedCount, plan.IncludeData)
	}
}

// The list of what was left out stops; the count does not.
func TestTheOmittedListIsCappedButCounted(t *testing.T) {
	p := newForkPlan(nil, nil)
	for i := 0; i < branch.OmittedListed+50; i++ {
		p.candidates = append(p.candidates, candidate(int64(100+i), "INSERT", "public.t", "APPLIED", "", "INSERT INTO t VALUES (1)"))
	}
	plan := p.plan(branch.RequestOptions{})
	if plan.OmittedCount != branch.OmittedListed+50 || len(plan.Omitted) != branch.OmittedListed {
		t.Fatalf("count %d, listed %d", plan.OmittedCount, len(plan.Omitted))
	}
}

// An object only a left-out data change touched is not a conflict.
func TestConflictsCountOnlyWhatIsCarried(t *testing.T) {
	p := newForkPlan(nil, nil)
	p.candidates = sampleCandidates()
	p.tgtTouched = map[string]bool{"public.orders": true}
	if err := p.conflicts(p.plan(branch.RequestOptions{}).Entries); err != nil {
		t.Errorf("schema only: %v", err)
	}
	if err := p.conflicts(p.plan(branch.RequestOptions{IncludeData: true}).Entries); !errors.Is(err, branch.ErrConflict) {
		t.Errorf("with data: %v, want a conflict on public.orders", err)
	}
}

func TestIsDataChange(t *testing.T) {
	for _, c := range []struct {
		tag, risk string
		want      bool
	}{
		{"INSERT", "", true}, {"update", "", true}, {"DELETE", "unqualified", true}, {"MERGE", "", true},
		{"TRUNCATE", "truncate", true}, {"COPY", "", true}, {"ALTER TABLE", "impact", true},
		{"CREATE TABLE", "", false}, {"ALTER TABLE", "drop-column", false}, {"DROP TABLE", "drop", false},
		{"CREATE TABLE AS", "", false}, {"GRANT", "", false},
	} {
		if got := isDataChange(c.tag, c.risk); got != c.want {
			t.Errorf("isDataChange(%q, %q) = %v", c.tag, c.risk, got)
		}
	}
}

// A mixed message is left out of a schema-only request, not used to refuse
// every later schema change on the branch. The INSERT still does not run.
func TestAMixedMessageIsLeftOutRatherThanBlockingTheRequest(t *testing.T) {
	p := newForkPlan(nil, nil)
	p.candidates = []ledger.Row{
		candidate(27, "CREATE TABLE", "public.e2e_script", "APPLIED", "", "CREATE TABLE e2e_script (id int); INSERT INTO e2e_script VALUES (1)"),
		candidate(40, "CREATE TABLE", "public.e2e_promo", "APPLIED", "", "CREATE TABLE e2e_promo (id int)"),
	}
	plan := p.plan(branch.RequestOptions{})
	if len(plan.Entries) != 1 || plan.Entries[0].ID != 40 {
		t.Fatalf("entries = %+v, want only the later CREATE TABLE", plan.Entries)
	}
	if plan.OmittedCount != 1 || len(plan.Omitted) != 1 || plan.Omitted[0].ID != 27 {
		t.Fatalf("omitted = %+v count %d, want the mixed script", plan.Omitted, plan.OmittedCount)
	}
	if err := checkSchemaOnly(plan.Entries); err != nil {
		t.Errorf("the request that remains is not schema-only: %v", err)
	}
	// Asked for with the data, the mixed message is carried and the safety
	// check still refuses to call it schema-only.
	with := p.plan(branch.RequestOptions{IncludeData: true})
	if len(with.Entries) != 2 {
		t.Fatalf("with data: %d entries, want both", len(with.Entries))
	}
}

// An entry holds its author's whole message, so a schema change sent with a
// data change would carry it in its text.
func TestSchemaOnlyRefusesDataInTheText(t *testing.T) {
	refused := []string{
		"CREATE TABLE t (id int); INSERT INTO t VALUES (1)",
		"ALTER TABLE t ADD c int; UPDATE t SET c = 0",
		"delete from t",
		"WITH gone AS (DELETE FROM t RETURNING *) SELECT count(*) FROM gone",
		"DO $$ BEGIN DELETE FROM t; END $$",
		"TRUNCATE t",
	}
	for _, q := range refused {
		err := checkSchemaOnly([]branch.RequestEntry{{ID: 1, CommandTag: "CREATE TABLE", Statement: q}})
		if !errors.Is(err, branch.ErrNotReplayable) {
			t.Errorf("%q was let through a schema-only request: %v", q, err)
		}
	}
	allowed := []string{
		"CREATE TABLE t (id int)",
		"CREATE FUNCTION f() RETURNS void LANGUAGE sql AS $$ DELETE FROM t $$",
		"CREATE TRIGGER tr AFTER UPDATE ON t FOR EACH ROW EXECUTE FUNCTION f()",
		"COMMENT ON TABLE t IS 'delete me later'",
		"CREATE INDEX ON t (updated_at)",
	}
	for _, q := range allowed {
		if err := checkSchemaOnly([]branch.RequestEntry{{ID: 1, Statement: q}}); err != nil {
			t.Errorf("%q was refused: %v", q, err)
		}
	}
}

// What is applied is a stored snapshot: one made before data changes were left
// out may hold some, and a schema-only request applies none.
func TestApplyRefusesDataInASchemaOnlySnapshot(t *testing.T) {
	entries := []branch.RequestEntry{
		{ID: 1, CommandTag: "CREATE TABLE", Object: "public.t", Statement: "CREATE TABLE t (id int)"},
		{ID: 2, CommandTag: "DELETE", Object: "public.t", Statement: "DELETE FROM t WHERE id = 1"},
	}
	if err := checkSnapshot(auth.ChangeRequest{Source: "dev"}, entries); !errors.Is(err, branch.ErrNotReplayable) {
		t.Errorf("schema-only snapshot with a DELETE: %v", err)
	}
	if err := checkSnapshot(auth.ChangeRequest{Source: "dev", IncludeData: true}, entries); err != nil {
		t.Errorf("a request that asked for data was refused: %v", err)
	}
}

// ── Applied once (TX-7) ──────────────────────────────────────────────────────

// targetTx stands in for the apply's transaction on the target: a record of
// applied requests, and a Blackbox holding the target's own changes.
type targetTx struct {
	recordingTx
	applied map[int64]int
	touched string // what the conflict query answers
	queries []execCall
}

type row struct {
	vals []any
	err  error
}

func (r row) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for i, d := range dest {
		switch p := d.(type) {
		case *int:
			*p = r.vals[i].(int)
		case *string:
			*p = r.vals[i].(string)
		}
	}
	return nil
}

func (f *targetTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if strings.HasPrefix(sql, "INSERT INTO bb.applied_requests") {
		f.calls = append(f.calls, execCall{sql, args})
		id := args[0].(int64)
		if _, ok := f.applied[id]; ok {
			return pgconn.NewCommandTag("INSERT 0 0"), nil
		}
		f.applied[id] = args[3].(int)
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	}
	return f.recordingTx.Exec(ctx, sql, args...)
}

func (f *targetTx) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	f.queries = append(f.queries, execCall{sql, args})
	switch {
	case strings.Contains(sql, "FROM bb.applied_requests"):
		n, ok := f.applied[args[0].(int64)]
		if !ok {
			return row{err: pgx.ErrNoRows}
		}
		return row{vals: []any{n}}
	case strings.Contains(sql, "FROM bb.schema_ledger"):
		return row{vals: []any{f.touched}}
	}
	return row{err: errors.New("unexpected query")}
}

// The statements replay ran, leaving out the record and the settings.
func (f *targetTx) ran() []string {
	var out []string
	for _, s := range f.statements() {
		if !strings.HasPrefix(s, "INSERT INTO bb.applied_requests") {
			out = append(out, s)
		}
	}
	return out
}

func twoEntries() []branch.RequestEntry {
	return []branch.RequestEntry{
		{ID: 21, Actor: "ada@example.com", CommandTag: "CREATE TABLE", Object: "public.a", Statement: "CREATE TABLE a ()"},
		{ID: 22, Actor: "ada@example.com", CommandTag: "CREATE INDEX", Object: "public.a_idx", Statement: "CREATE INDEX a_idx ON a ((1))"},
	}
}

func TestASecondApplyOfTheSameRequestIsRefused(t *testing.T) {
	tx := &targetTx{applied: map[int64]int{}}
	c := auth.ChangeRequest{ID: 7, Source: "dev", Target: "main", ForkAfterID: 20}
	if n, err := applyIn(context.Background(), tx, alwaysInTx, c, "carol@example.com", twoEntries(), nil); err != nil || n != 0 {
		t.Fatalf("first apply: %d, %v", n, err)
	}
	if got := tx.ran(); len(got) != 2 {
		t.Fatalf("first apply ran %q", got)
	}
	// The record is written before anything runs, so a second apply stops at it.
	if !strings.HasPrefix(tx.calls[0].sql, "INSERT INTO bb.applied_requests") {
		t.Errorf("the record was not written first: %q", tx.calls[0].sql)
	}

	again := &targetTx{applied: tx.applied}
	n, err := applyIn(context.Background(), again, alwaysInTx, c, "carol@example.com", twoEntries(), nil)
	if !errors.Is(err, branch.ErrAlreadyApplied) {
		t.Fatalf("second apply: %v, want ErrAlreadyApplied", err)
	}
	if n != 2 {
		t.Errorf("the count recorded the first time is %d, want 2", n)
	}
	if got := again.ran(); len(got) != 0 {
		t.Fatalf("the second apply ran statements: %q", got)
	}
}

func TestAConflictIsFoundAtApplyTime(t *testing.T) {
	tx := &targetTx{applied: map[int64]int{}, touched: "public.a"}
	c := auth.ChangeRequest{ID: 8, Source: "dev", Target: "main", ForkAfterID: 20}
	_, err := applyIn(context.Background(), tx, alwaysInTx, c, "carol@example.com", twoEntries(),
		map[string]bool{"request-3": true})
	if !errors.Is(err, branch.ErrConflict) || !strings.Contains(err.Error(), "public.a") {
		t.Fatalf("err = %v, want a conflict on public.a", err)
	}
	if got := tx.ran(); len(got) != 0 {
		t.Fatalf("statements ran despite the conflict: %q", got)
	}
	// The question asked: after the fork, about the request's objects, and not
	// counting this source's own earlier requests.
	var q *execCall
	for i := range tx.queries {
		if strings.Contains(tx.queries[i].sql, "bb.schema_ledger") {
			q = &tx.queries[i]
		}
	}
	if q == nil {
		t.Fatal("the target's Blackbox was not asked")
	}
	if strings.Contains(q.sql, "statement") {
		t.Error("the conflict check reads statement text, which it does not need")
	}
	if q.args[0] != int64(20) || fmt.Sprint(q.args[1]) != "[public.a public.a_idx]" || fmt.Sprint(q.args[2]) != "[request-3]" {
		t.Errorf("asked with %v", q.args)
	}
	// The record was written in the same transaction, and goes with its rollback.
	if _, ok := tx.applied[8]; !ok {
		t.Error("the record was not written before the check")
	}
}

func TestNoConflictLetsTheApplyThrough(t *testing.T) {
	tx := &targetTx{applied: map[int64]int{}}
	c := auth.ChangeRequest{ID: 9, Source: "dev", Target: "main"}
	if _, err := applyIn(context.Background(), tx, alwaysInTx, c, "carol@example.com", twoEntries(), nil); err != nil {
		t.Fatal(err)
	}
	if got := tx.ran(); len(got) != 2 {
		t.Fatalf("ran %q", got)
	}
}
