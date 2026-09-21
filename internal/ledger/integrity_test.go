// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func hexSum(parts ...[]byte) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// The same fixed row the integration test recomputes in SQL (bb._ledger_hash).
func TestRowHashMatchesSQLFormula(t *testing.T) {
	r := Row{
		PrevHash: "abc", ID: 42, At: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Actor: "priya", ActorKind: "human", Tool: "psql", Session: "s1", Branch: "main",
		CommandTag: "CREATE TABLE", ObjectType: "table", ObjectIdentity: "public.t",
		Statement: "CREATE TABLE t()", Status: "APPLIED",
	}
	want := hexSum([]byte("abc|42|2026-01-02 03:04:05|priya|human|psql|s1|main|CREATE TABLE|table|public.t|CREATE TABLE t()|APPLIED|"))
	if got := RowHash(r); got != want {
		t.Errorf("RowHash = %s, want %s", got, want)
	}
}

func TestFormatAt(t *testing.T) {
	ist := time.FixedZone("IST", 5*3600+1800)
	for _, tc := range []struct {
		in   time.Time
		want string
	}{
		{time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), "2026-01-02 03:04:05"},
		{time.Date(2026, 1, 2, 3, 4, 5, 120000000, time.UTC), "2026-01-02 03:04:05.12"},
		{time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC), "2026-01-02 03:04:05.123456"},
		{time.Date(2026, 1, 2, 8, 34, 5, 0, ist), "2026-01-02 03:04:05"}, // rendered in UTC
	} {
		if got := FormatAt(tc.in); got != tc.want {
			t.Errorf("FormatAt(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestMerkleRoot(t *testing.T) {
	a, b, c := LeafHash("a", ""), LeafHash("b", "x"), LeafHash("c", "")
	node := func(l, r [32]byte) [32]byte {
		var out [32]byte
		s := sha256.Sum256(append(append([]byte{0x01}, l[:]...), r[:]...))
		copy(out[:], s[:])
		return out
	}
	if MerkleRoot(nil) != "" {
		t.Error("empty tree should have an empty root")
	}
	if got := MerkleRoot([][32]byte{a}); got != hex.EncodeToString(a[:]) {
		t.Errorf("single leaf: root = %s", got)
	}
	ab := node(a, b)
	if got := MerkleRoot([][32]byte{a, b}); got != hex.EncodeToString(ab[:]) {
		t.Errorf("two leaves: root = %s", got)
	}
	abc := node(ab, node(c, c)) // odd level duplicates the last node
	if got := MerkleRoot([][32]byte{a, b, c}); got != hex.EncodeToString(abc[:]) {
		t.Errorf("three leaves: root = %s", got)
	}
	if hexSum([]byte{0x00}, []byte("b|x")) != hex.EncodeToString(b[:]) {
		t.Error("LeafHash must be sha256(0x00 || row_hash || '|' || ext_hash)")
	}
}

// chain builds n correctly hash-chained rows with ids 1..n.
func chain(n int) []Row {
	rows := make([]Row, n)
	prev := ""
	for i := range rows {
		r := Row{
			ID: int64(i + 1), At: time.Date(2026, 9, 14, 8, 0, i, 123000, time.UTC),
			Actor: "agent-x", ActorKind: "agent", CommandTag: "CREATE TABLE",
			ObjectIdentity: "public.t" + string(rune('a'+i)), Statement: "CREATE TABLE t()",
			Status: "APPLIED", PrevHash: prev, ExtHash: "ext" + string(rune('a'+i)),
		}
		r.RowHash = RowHash(r)
		prev = r.RowHash
		rows[i] = r
	}
	return rows
}

// rechain recomputes prev_hash/row_hash for every row: what an attacker with
// superuser access does to make the SQL chain check pass again.
func rechain(rows []Row) {
	prev := ""
	for i := range rows {
		rows[i].PrevHash = prev
		rows[i].RowHash = RowHash(rows[i])
		prev = rows[i].RowHash
	}
}

func anchors(t *testing.T, rows []Row, cuts ...int) []Anchor {
	t.Helper()
	var out []Anchor
	from, prevRoot := int64(1), ""
	start := 0
	for i, cut := range cuts {
		a, err := BuildAnchor("main", from, prevRoot, rows[start:cut])
		if err != nil {
			t.Fatal(err)
		}
		a.CheckpointID = int64(i + 1)
		out = append(out, a)
		from, prevRoot, start = a.ToID+1, a.MerkleRoot, cut
	}
	return out
}

func TestVerifyIntactAndUnanchoredTail(t *testing.T) {
	rows := chain(6)
	as := anchors(t, rows, 3, 5) // rows 1–3, 4–5; row 6 not yet anchored
	rep := Verify(rows, as)
	if !rep.Intact {
		t.Fatalf("expected intact, got problems: %v", rep.Problems)
	}
	if rep.Rows != 6 || rep.ChainedRows != 6 || rep.Checkpoints != 2 || rep.AnchoredRows != 5 || rep.UnanchoredRows != 1 {
		t.Errorf("unexpected counts: %+v", rep)
	}
	if !strings.HasPrefix(rep.Summary(), "ledger integrity: INTACT") {
		t.Errorf("summary = %q", rep.Summary())
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	cases := map[string]func([]Row) []Row{
		"edit without rechaining": func(r []Row) []Row { r[1].Statement = "DROP TABLE secrets"; return r },
		"edit and rechain (forged)": func(r []Row) []Row {
			r[1].Statement = "DROP TABLE secrets"
			rechain(r)
			return r
		},
		"delete a middle row and rechain": func(r []Row) []Row {
			r = append(r[:2], r[3:]...)
			rechain(r)
			return r
		},
		"delete the newest anchored row": func(r []Row) []Row { return r[:4] },
		"wipe the ledger":                func(r []Row) []Row { return nil },
		"change a capture hash":          func(r []Row) []Row { r[0].ExtHash = "forged"; return r },
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			rows := chain(5)
			as := anchors(t, rows, 3, 5)
			rep := Verify(tamper(append([]Row(nil), rows...)), as)
			if rep.Intact {
				t.Fatalf("tampering was not detected: %s", rep.Summary())
			}
			if !strings.HasPrefix(rep.Summary(), "ledger integrity: TAMPERED") {
				t.Errorf("summary = %q", rep.Summary())
			}
		})
	}
}

func TestVerifyDetectsAnchorGap(t *testing.T) {
	rows := chain(6)
	as := anchors(t, rows, 2, 4, 6)
	rep := Verify(rows, []Anchor{as[0], as[2]}) // middle anchor file removed
	if rep.Intact {
		t.Fatal("a missing anchor in the middle of the sequence should be reported")
	}
}

func TestCheckChain(t *testing.T) {
	rows := chain(4)
	if err := CheckChain(&rows[1], rows[2:]); err != nil {
		t.Errorf("valid continuation reported broken: %v", err)
	}
	if err := CheckChain(&rows[0], rows[2:]); err == nil {
		t.Error("a gap before the rows should be reported")
	}
}

func TestBuildAnchorRejectsBadRanges(t *testing.T) {
	rows := chain(3)
	if _, err := BuildAnchor("main", 1, "", nil); err == nil {
		t.Error("empty range should be rejected")
	}
	if _, err := BuildAnchor("main", 2, "", rows); err == nil {
		t.Error("rows before from_id should be rejected")
	}
	if _, err := BuildAnchor("main", 1, "", []Row{rows[1], rows[0]}); err == nil {
		t.Error("descending ids should be rejected")
	}
}

func TestAnchorFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "anchors", "main")
	rows := chain(3)
	as := anchors(t, rows, 3)
	path, err := WriteAnchor(dir, as[0])
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o444 {
		t.Errorf("anchor should be read-only (0444), got %v %v", fi.Mode().Perm(), err)
	}
	if filepath.Base(path) != "00000000000000000003.json" {
		t.Errorf("anchor file name = %s", filepath.Base(path))
	}
	if _, err := WriteAnchor(dir, as[0]); err == nil {
		t.Error("an existing anchor must never be overwritten")
	}
	got, err := LoadAnchors(dir)
	if err != nil || len(got) != 1 || got[0].MerkleRoot != as[0].MerkleRoot || got[0].Format != AnchorFormat {
		t.Errorf("LoadAnchors = %+v, %v", got, err)
	}
	if none, err := LoadAnchors(filepath.Join(dir, "missing")); err != nil || none != nil {
		t.Errorf("a missing anchor directory should mean no anchors, got %v %v", none, err)
	}
}

func TestDecodeRowJSON(t *testing.T) {
	line := `{"id":7,"at":"2026-09-14T14:10:12.1234+05:30","actor":"agent-x","actor_kind":"agent","tool":null,` +
		`"session":"s","branch":"main","command_tag":"ALTER TABLE","object_type":"table","object_identity":"public.t",` +
		`"statement":"ALTER TABLE t\nADD COLUMN y int","status":"FLAGGED","risk":null,"prev_hash":"p","row_hash":"r",` +
		`"ext_hash":"e","xid":123,"lsn":"0/16B3748","override_used":false}`
	r, err := DecodeRowJSON([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != 7 || r.Tool != "" || r.Risk != "" || r.Statement != "ALTER TABLE t\nADD COLUMN y int" || r.ExtHash != "e" {
		t.Errorf("decoded %+v", r)
	}
	if FormatAt(r.At) != "2026-09-14 08:40:12.1234" {
		t.Errorf("timestamp decoded as %s", FormatAt(r.At))
	}
}

func TestQueries(t *testing.T) {
	if q := RowsQuery(false, ""); strings.Contains(q, "ledger_ext") || !strings.Contains(q, "NULL::text AS ext_hash") {
		t.Errorf("RowsQuery without capture table: %s", q)
	}
	if q := RowsQuery(true, "WHERE s.id > 5"); !strings.Contains(q, "LEFT JOIN bb.ledger_ext") || !strings.Contains(q, "WHERE s.id > 5 ORDER BY s.id") {
		t.Errorf("RowsQuery with capture table: %s", q)
	}
	if q := ExportQuery(true); !strings.Contains(q, "e.override_used") {
		t.Errorf("ExportQuery should include capture columns: %s", q)
	}
}
