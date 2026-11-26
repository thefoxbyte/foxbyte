// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// sealChain builds hash-chained rows from their statements, ids from 1.
func sealChain(stmts ...string) []Row {
	var rows []Row
	prev := ""
	for i, s := range stmts {
		r := Row{ID: int64(i + 1), At: time.Date(2026, 11, 1, 10, 0, i, 0, time.UTC), Actor: "agent-x", ActorKind: "agent",
			CommandTag: "UPDATE", ObjectType: "table", ObjectIdentity: "public.people", Statement: s, Status: "APPLIED", PrevHash: prev}
		r.RowHash = RowHash(r)
		prev = r.RowHash
		rows = append(rows, r)
	}
	return rows
}

// redact does what bb.erasure_redact does to rows: the statements of ids get
// placeholders and seals, and an ERASURE REDACT entry is chained on with the
// seals' digest. It returns the rows as they now stand.
func redact(rows []Row, ids map[int64]string) []Row {
	out := append([]Row(nil), rows...)
	by := int64(len(rows) + 1)
	var idSeals []string
	for i := range out {
		ph, ok := ids[out[i].ID]
		if !ok {
			continue
		}
		out[i].Statement = ph
		out[i].SealOrig = out[i].RowHash
		out[i].Seal = SealOf(out[i].SealOrig, RowHash(out[i]))
		out[i].SealBy = by
		idSeals = append(idSeals, fmt.Sprintf("%d:%s", out[i].ID, out[i].Seal))
	}
	e := Row{ID: by, At: time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC), Actor: "dbadmin", ActorKind: "human", Tool: "fox dpdp erase",
		CommandTag: RedactTag, ObjectType: "erasure", ObjectIdentity: "req", Status: "APPLIED", PrevHash: out[len(out)-1].RowHash,
		Statement: fmt.Sprintf("redacted %d entries; seals sha256:%s", len(idSeals), SealsDigest(idSeals))}
	e.RowHash = RowHash(e)
	return append(out, e)
}

func anchorOver(t *testing.T, rows []Row) Anchor {
	t.Helper()
	a, err := BuildAnchor("main", 1, "", rows)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// A ledger anchored, then redacted by an erasure, still verifies: the chain
// and the anchor by the hashes it was built on, the redacted entries by their
// seals, and the seals by the redaction's digest.
func TestARedactedLedgerVerifies(t *testing.T) {
	rows := sealChain("UPDATE people SET email = 'asha@example.com' WHERE id = 1", "UPDATE people SET note = 'x' WHERE id = 2",
		"DELETE FROM people WHERE email = 'asha@example.com'")
	a := anchorOver(t, rows)
	red := redact(rows, map[int64]string{1: "UPDATE people SET email = $1 WHERE id = $2", 3: "DELETE FROM people WHERE email = $1"})
	rep := Verify(red, []Anchor{a})
	if !rep.Intact || rep.Sealed != 2 {
		t.Fatalf("not intact: %+v", rep)
	}
	if !strings.Contains(strings.Join(rep.Notes, " "), "2 entries were redacted by erasure requests") {
		t.Errorf("the report does not say so: %v", rep.Notes)
	}
	for _, r := range red[:3] {
		if strings.Contains(r.Statement, "asha") {
			t.Errorf("entry %d still holds the value", r.ID)
		}
	}
	// Two branches, one redacted and one not, still share their history.
	if EffectiveHash(red[0]) != EffectiveHash(rows[0]) {
		t.Error("a redacted entry is not the same entry as its unredacted copy")
	}
}

// Every way of tampering after the redaction is caught.
func TestTamperingAfterARedactionIsCaught(t *testing.T) {
	rows := sealChain("UPDATE people SET email = 'asha@example.com' WHERE id = 1", "UPDATE people SET note = 'x' WHERE id = 2")
	a := anchorOver(t, rows)
	ok := redact(rows, map[int64]string{1: "UPDATE people SET email = $1 WHERE id = $2"})
	for name, c := range map[string]struct {
		change func([]Row) []Row
		want   string
	}{
		"a redacted entry's text changed": {func(r []Row) []Row { r[0].Statement = "UPDATE people SET email = $1 WHERE id = 7"; return r },
			"no longer matches its seal"},
		"a seal removed": {func(r []Row) []Row { r[0].Seal, r[0].SealOrig, r[0].SealBy = "", "", 0; return r },
			"no longer match its hash"},
		"text and seal changed together": {func(r []Row) []Row {
			r[0].Statement = "UPDATE people SET email = $1 WHERE id = 7"
			r[0].Seal = SealOf(r[0].SealOrig, RowHash(r[0]))
			return r
		}, "the seals are not the ones"},
		"the digest rewritten too": {func(r []Row) []Row {
			r[0].Statement = "UPDATE people SET email = $1 WHERE id = 7"
			r[0].Seal = SealOf(r[0].SealOrig, RowHash(r[0]))
			r[2].Statement = fmt.Sprintf("redacted 1 entries; seals sha256:%s", SealsDigest([]string{fmt.Sprintf("1:%s", r[0].Seal)}))
			return r
		}, "ledger id 3"},
		"a seal forged for another entry": {func(r []Row) []Row {
			r[1].Statement = "UPDATE people SET note = $1 WHERE id = $2"
			r[1].SealOrig = r[1].RowHash
			r[1].Seal = SealOf(r[1].SealOrig, RowHash(r[1]))
			r[1].SealBy = 3
			return r
		}, "the seals are not the ones"},
		"a seal naming no redaction": {func(r []Row) []Row {
			r[1].Statement = "UPDATE people SET note = $1 WHERE id = $2"
			r[1].SealOrig = r[1].RowHash
			r[1].Seal = SealOf(r[1].SealOrig, RowHash(r[1]))
			r[1].SealBy = 2
			return r
		}, "is not one (a seal was added afterwards)"},
	} {
		rep := Verify(c.change(append([]Row(nil), ok...)), []Anchor{a})
		if rep.Intact || !strings.Contains(strings.Join(rep.Problems, "\n"), c.want) {
			t.Errorf("%s: %v %v", name, rep.Intact, rep.Problems)
		}
	}
}

// A verifier that starts part way through the ledger cannot check a digest
// over seals it never saw, and does not claim one broken.
func TestAStreamFromMidLedgerDoesNotJudgeDigests(t *testing.T) {
	rows := sealChain("UPDATE people SET email = 'asha@example.com' WHERE id = 1", "UPDATE people SET note = 'x' WHERE id = 2")
	red := redact(rows, map[int64]string{1: "UPDATE people SET email = $1 WHERE id = $2"})
	v := NewVerifier(nil)
	v.prev = red[1].PrevHash
	for _, r := range red[1:] {
		if err := v.Add(r); err != nil {
			t.Fatal(err)
		}
	}
	if rep := v.Report(); !rep.Intact {
		t.Errorf("a partial stream reported %v", rep.Problems)
	}
}

func TestSealJSONRoundTrip(t *testing.T) {
	r, err := DecodeRowJSON([]byte(`{"id":4,"at":"2026-11-01T10:00:00Z","statement":"x","row_hash":"aa","seal":{"orig":"aa","seal":"bb","by":9}}`))
	if err != nil || r.SealOrig != "aa" || r.Seal != "bb" || r.SealBy != 9 {
		t.Fatalf("%v %+v", err, r)
	}
	if q := RowsQuerySealed(true, true, ""); !strings.Contains(q, "bb.ledger_seal(s.id) AS seal") {
		t.Errorf("the query does not read seals: %s", q)
	}
	if q := RowsQuery(true, ""); strings.Contains(q, "ledger_seal") {
		t.Errorf("a ledger without seals is asked for them: %s", q)
	}
	if q := ClientRowsQuerySealed(false, true, ""); !strings.Contains(q, "bb.ledger_statement(s.id) AS statement") || !strings.Contains(q, "ledger_seal") {
		t.Errorf("client query: %s", q)
	}
	if q := ExportQuerySealed(true, true); !strings.Contains(q, "override_used, bb.ledger_seal(s.id) AS seal") {
		t.Errorf("export: %s", q)
	}
}
