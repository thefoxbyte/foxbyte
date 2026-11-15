// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

// TestLedgerPsqlHelper is not a test: it is the stand-in for docker exec psql
// that fakePsql runs. It prints what it was given and exits as told.
func TestLedgerPsqlHelper(t *testing.T) {
	if os.Getenv("FOX_LEDGER_HELPER") != "1" {
		return
	}
	out, _ := os.ReadFile(os.Getenv("FOX_LEDGER_STDOUT"))
	os.Stdout.Write(out)
	os.Stderr.WriteString(os.Getenv("FOX_LEDGER_STDERR"))
	code, _ := strconv.Atoi(os.Getenv("FOX_LEDGER_EXIT"))
	os.Exit(code)
}

// psqlAnswer is what the fake psql prints for one query.
type psqlAnswer struct {
	stdout string
	stderr string
	exit   int
}

// fakePsql replaces the ledger's psql with answer, for the length of the test.
func fakePsql(t *testing.T, answer func(name, sql string) psqlAnswer) {
	t.Helper()
	dir := t.TempDir()
	// A diff reads both ledgers at once, so two calls can arrive together:
	// each must get its own output file.
	var mu sync.Mutex
	n := 0
	old := ledgerPsql
	ledgerPsql = func(name, sql string) (*exec.Cmd, context.Context, context.CancelFunc) {
		a := answer(name, sql)
		mu.Lock()
		n++
		path := filepath.Join(dir, fmt.Sprintf("out-%d", n))
		mu.Unlock()
		if err := os.WriteFile(path, []byte(a.stdout), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestLedgerPsqlHelper$")
		cmd.Env = append(os.Environ(), "FOX_LEDGER_HELPER=1", "FOX_LEDGER_STDOUT="+path,
			"FOX_LEDGER_STDERR="+a.stderr, "FOX_LEDGER_EXIT="+strconv.Itoa(a.exit))
		return cmd, nil, func() {}
	}
	t.Cleanup(func() { ledgerPsql = old })
}

// chainRows builds n hash-chained rows with ids 1..n, touching objects in turn.
func chainRows(n int, objects ...string) []ledger.Row {
	rows := make([]ledger.Row, n)
	prev := ""
	for i := range rows {
		r := ledger.Row{
			ID: int64(i + 1), At: time.Date(2026, 9, 14, 8, 0, i, 123000, time.UTC),
			Actor: "a@x.com", ActorKind: "human", CommandTag: "ALTER TABLE",
			ObjectIdentity: objects[i%len(objects)], Statement: fmt.Sprintf("ALTER TABLE t ADD c%d int", i),
			Status: "APPLIED", PrevHash: prev, ExtHash: fmt.Sprintf("ext%d", i),
		}
		r.RowHash = ledger.RowHash(r)
		prev = r.RowHash
		rows[i] = r
	}
	return rows
}

// rowLines prints rows the way RowsQuery's row_to_json does.
func rowLines(t *testing.T, rows []ledger.Row) string {
	t.Helper()
	opt := func(s string) *string {
		if s == "" {
			return nil
		}
		return &s
	}
	var b strings.Builder
	for _, r := range rows {
		j, err := json.Marshal(map[string]any{
			"id": r.ID, "at": r.At.Format(time.RFC3339Nano), "actor": r.Actor, "actor_kind": r.ActorKind,
			"tool": opt(r.Tool), "session": opt(r.Session), "branch": opt(r.Branch), "command_tag": r.CommandTag,
			"object_type": opt(r.ObjectType), "object_identity": opt(r.ObjectIdentity), "statement": r.Statement,
			"status": r.Status, "risk": opt(r.Risk), "prev_hash": opt(r.PrevHash), "row_hash": opt(r.RowHash),
			"ext_hash": opt(r.ExtHash),
		})
		if err != nil {
			t.Fatal(err)
		}
		b.Write(j)
		b.WriteString("\n")
	}
	return b.String()
}

func buildAnchors(t *testing.T, rows []ledger.Row, cuts ...int) []ledger.Anchor {
	t.Helper()
	var out []ledger.Anchor
	from, prev, start := int64(1), "", 0
	for i, cut := range cuts {
		a, err := ledger.BuildAnchor("main", from, prev, rows[start:cut])
		if err != nil {
			t.Fatal(err)
		}
		a.CheckpointID = int64(i + 1)
		out = append(out, a)
		from, prev, start = a.ToID+1, a.MerkleRoot, cut
	}
	return out
}

// Integrity reads the ledger as a stream, and its report is the one Verify
// gives over the same rows held in memory: intact, with a broken chain, and
// with rows missing from an anchored range.
func TestIntegrityStreamedMatchesVerify(t *testing.T) {
	cases := map[string]func([]ledger.Row) []ledger.Row{
		"intact":       func(r []ledger.Row) []ledger.Row { return r },
		"broken chain": func(r []ledger.Row) []ledger.Row { r[3].Statement = "DROP TABLE x"; return r },
		"row removed":  func(r []ledger.Row) []ledger.Row { return append(r[:5], r[6:]...) },
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			clean := chainRows(40, "public.a", "public.b")
			anchors := buildAnchors(t, clean, 10, 30)
			dir := t.TempDir()
			t.Setenv("FOX_ANCHOR_DIR", dir)
			t.Setenv("FOX_ANCHOR_KEY", filepath.Join(dir, "no-key"))
			for _, a := range anchors {
				if _, err := ledger.WriteAnchor(filepath.Join(dir, "main"), a); err != nil {
					t.Fatal(err)
				}
			}
			rows := tamper(append([]ledger.Row(nil), clean...))
			fakePsql(t, func(_, sql string) psqlAnswer {
				switch {
				case strings.Contains(sql, "to_regclass"):
					return psqlAnswer{stdout: "true|true\n"}
				case strings.Contains(sql, "count(*) FROM bb.ledger_checkpoints"):
					return psqlAnswer{stdout: "2\n"}
				}
				return psqlAnswer{stdout: rowLines(t, rows)}
			})
			got, err := Integrity("main")
			if err != nil {
				t.Fatal(err)
			}
			want := ledger.Verify(rows, anchors)
			if len(got.Notes) < len(want.Notes) {
				t.Fatalf("notes: %v, want at least %v", got.Notes, want.Notes)
			}
			got.Notes = got.Notes[:len(want.Notes)] // the rest are Integrity's own
			if !reflect.DeepEqual(got, want) {
				t.Errorf("streamed report differs\n got: %+v\nwant: %+v", got, want)
			}
		})
	}
}

// A psql that dies part-way is an error with psql's own reason, never a short
// ledger that verifies: the rows before the cut are intact on their own, which
// is exactly the answer that must not come back.
func TestTruncatedLedgerStreamIsAnError(t *testing.T) {
	rows := chainRows(20, "public.a")
	full := rowLines(t, rows)
	cut := full[:len(full)/2]
	cut = cut[:strings.LastIndex(cut, "\n")+1] + `{"id": 11, "at": "2026` // a line cut off mid-row
	fakePsql(t, func(_, sql string) psqlAnswer {
		return psqlAnswer{stdout: cut, stderr: "psql: server closed the connection unexpectedly\n", exit: 2}
	})
	v := ledger.NewVerifier(nil)
	err := streamLedgerRows("main", false, "", v.Add)
	if err == nil {
		t.Fatalf("a truncated stream was accepted: %s", v.Report().Summary())
	}
	if !strings.Contains(err.Error(), "server closed the connection unexpectedly") {
		t.Errorf("error = %v; want psql's own reason, not the half line's decoding error", err)
	}
	if _, err := loadLedgerRows("main", false, ""); err == nil {
		t.Error("loadLedgerRows returned a short ledger without an error")
	}

	// psql succeeded but printed something that is not a row: that is the
	// decoding error, as it always was.
	fakePsql(t, func(_, sql string) psqlAnswer { return psqlAnswer{stdout: `{"id": "x"}` + "\n"} })
	if _, err := loadLedgerRows("main", false, ""); err == nil {
		t.Error("a row that does not decode was accepted")
	}
}

// The diff read as two streams side by side is the diff of the two ledgers in
// memory, and a failure on either side is an error naming that branch.
func TestStreamedDiffMatchesInMemory(t *testing.T) {
	shared := chainRows(30, "public.a", "public.b", "public.c")
	mk := func(extra int, obj string) []ledger.Row {
		rows := append([]ledger.Row(nil), shared...)
		prev := rows[len(rows)-1].RowHash
		for i := 0; i < extra; i++ {
			r := ledger.Row{ID: int64(len(rows) + 1), At: time.Date(2026, 9, 15, 0, 0, i, 0, time.UTC),
				Actor: "b@x.com", CommandTag: "CREATE TABLE", ObjectIdentity: obj,
				Statement: "CREATE TABLE " + obj + fmt.Sprint(i), Status: "APPLIED", PrevHash: prev}
			r.RowHash = ledger.RowHash(r)
			prev = r.RowHash
			rows = append(rows, r)
		}
		return rows
	}
	pairs := map[string][2][]ledger.Row{
		"diverged":    {mk(5, "public.x"), mk(300, "public.x")},
		"one ahead":   {shared, mk(4, "public.y")},
		"same":        {shared, shared},
		"no history":  {nil, mk(2, "public.z")},
		"both empty":  {nil, nil},
		"none shared": {chainRows(5, "public.q"), mk(1, "public.q")[5:]},
	}
	for name, p := range pairs {
		t.Run(name, func(t *testing.T) {
			fakePsql(t, func(branch, _ string) psqlAnswer {
				if branch == "a" {
					return psqlAnswer{stdout: rowLines(t, p[0])}
				}
				return psqlAnswer{stdout: rowLines(t, p[1])}
			})
			db := newDiffBuilder("a", "b")
			if err := WalkLedgerFork("a", "b", db.visitor()); err != nil {
				t.Fatal(err)
			}
			got := db.finish()
			want := buildDiff("a", "b", p[0], p[1])
			if !reflect.DeepEqual(got, want) {
				t.Errorf("streamed diff differs\n got: %+v\nwant: %+v", got, want)
			}
			if n := commonPrefix(p[0], p[1]); got.CommonEntries != n {
				t.Errorf("common entries %d, want %d", got.CommonEntries, n)
			}
		})
	}

	fakePsql(t, func(branch, _ string) psqlAnswer {
		if branch == "b" {
			return psqlAnswer{stdout: rowLines(t, shared[:10]), stderr: "FATAL: terminating connection\n", exit: 2}
		}
		return psqlAnswer{stdout: rowLines(t, shared)}
	})
	err := WalkLedgerFork("a", "b", newDiffBuilder("a", "b").visitor())
	if err == nil || !strings.Contains(err.Error(), `reading "b"'s Blackbox`) {
		t.Errorf("a side cut off part-way: err = %v, want an error naming b", err)
	}
}
