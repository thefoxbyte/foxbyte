// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

// tamperEvent changes one row directly in the store, past the append-only
// trigger: what someone with the file and SQLite can do.
func tamperEvent(t *testing.T, path, set string, id int64) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`DROP TRIGGER security_events_no_update`,
		fmt.Sprintf(`UPDATE security_events SET %s WHERE id = %d`, set, id),
		`CREATE TRIGGER security_events_no_update BEFORE UPDATE ON security_events
		   BEGIN SELECT RAISE(ABORT, 'security_events is append-only'); END`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func logWith(t *testing.T, events int) (*auth.Store, string) {
	t.Helper()
	t.Setenv(brand.EnvName("ANCHOR_DIR"), t.TempDir())
	t.Setenv(brand.EnvName("ANCHOR_KEY"), filepath.Join(t.TempDir(), "signing.key"))
	path := filepath.Join(t.TempDir(), "a.db")
	s, err := auth.Open(auth.Config{DBPath: path, WebOrigin: "http://x"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	addEvents(s, events)
	return s, path
}

func addEvents(s *auth.Store, n int) {
	for i := 0; i < n; i++ {
		s.Audit(auth.EvLoginOK, "a@x.com", "", "127.0.0.1", "")
	}
}

// A log with its first n events already anchored.
func anchoredLog(t *testing.T, n int) (*auth.Store, string) {
	t.Helper()
	s, path := logWith(t, n)
	if a, err := CheckpointSecurityLog(s); err != nil || a == nil || a.ToID != int64(n) {
		t.Fatalf("the first anchor: %+v, %v", a, err)
	}
	return s, path
}

func fullVerify(t *testing.T, s *auth.Store) ledger.Report {
	t.Helper()
	evs, err := s.SecurityEvents(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	anchors, err := ledger.LoadAnchors(SecurityLogAnchorDir())
	if err != nil {
		t.Fatal(err)
	}
	return VerifySecurityLog(evs, anchors, nil)
}

// A checkpoint anchors what is new and leaves a genuine log verifying.
func TestCheckpointAnchorsOnlyWhatIsNew(t *testing.T) {
	s, _ := anchoredLog(t, 4)
	addEvents(s, 2)
	a, err := CheckpointSecurityLog(s)
	if err != nil || a == nil || a.FromID != 5 || a.ToID != 6 || a.EntryCount != 2 {
		t.Fatalf("the second anchor: %+v, %v", a, err)
	}
	if rep := fullVerify(t, s); !rep.Intact || rep.UnanchoredRows != 0 {
		t.Fatalf("a genuine log: %+v", rep)
	}
	if again, err := CheckpointSecurityLog(s); err != nil || again != nil {
		t.Fatalf("with nothing new: %+v, %v", again, err)
	}
}

// What the incremental check catches, and the line it does not cross: an edit
// before the last anchor, left in place, is passed by the checkpoint and caught
// by the full verify. Asserted in both directions so the documented coverage
// cannot quietly stop being true.
func TestCheckpointChecksFromTheLastAnchor(t *testing.T) {
	t.Run("an edit since the anchor is refused", func(t *testing.T) {
		s, path := anchoredLog(t, 4)
		addEvents(s, 2)
		tamperEvent(t, path, "actor = 'nobody'", 5)
		if a, err := CheckpointSecurityLog(s); err == nil || a != nil {
			t.Fatalf("anchored over an edited event: %+v, %v", a, err)
		}
	})
	t.Run("an edit to the anchored event is refused", func(t *testing.T) {
		s, path := anchoredLog(t, 4)
		addEvents(s, 1)
		tamperEvent(t, path, "actor = 'nobody'", 4)
		if a, err := CheckpointSecurityLog(s); err == nil || a != nil {
			t.Fatalf("anchored past an edited anchor event: %+v, %v", a, err)
		}
	})
	t.Run("a rewrite re-hashed up to the new events is refused", func(t *testing.T) {
		s, path := anchoredLog(t, 4)
		addEvents(s, 1)
		// Event 5 chaining from something other than the anchored hash is what
		// recomputing every hash after an old edit leaves behind.
		tamperEvent(t, path, "prev_hash = 'rewritten'", 5)
		if a, err := CheckpointSecurityLog(s); err == nil || a != nil {
			t.Fatalf("anchored a chain not following its anchor: %+v, %v", a, err)
		}
	})
	t.Run("an edit before the anchor is the full verify's to catch", func(t *testing.T) {
		s, path := anchoredLog(t, 4)
		addEvents(s, 1)
		tamperEvent(t, path, "actor = 'nobody'", 2)
		if a, err := CheckpointSecurityLog(s); err != nil || a == nil {
			t.Fatalf("the incremental check looked before its anchor: %+v, %v", a, err)
		}
		if rep := fullVerify(t, s); rep.Intact || rep.FirstBrokenID != 2 {
			t.Fatalf("the full verify missed an edit before the last anchor: %+v", rep)
		}
	})
	t.Run("the first anchor checks everything", func(t *testing.T) {
		s, path := logWith(t, 3)
		tamperEvent(t, path, "actor = 'nobody'", 1)
		if a, err := CheckpointSecurityLog(s); err == nil || a != nil {
			t.Fatalf("a first anchor over an edited log: %+v, %v", a, err)
		}
	})
}

// The tail is read in pages, and every page is counted and checked.
func TestCheckpointPagesThroughTheTail(t *testing.T) {
	old := secLogCheckPageSize
	secLogCheckPageSize = 3
	t.Cleanup(func() { secLogCheckPageSize = old })

	s, path := anchoredLog(t, 1)
	addEvents(s, 7) // a boundary-straddling tail
	a, err := CheckpointSecurityLog(s)
	if err != nil || a == nil || a.EntryCount != 7 || a.ToID != 8 {
		t.Fatalf("a tail longer than a page: %+v, %v", a, err)
	}
	addEvents(s, 6) // exactly two pages
	a, err = CheckpointSecurityLog(s)
	if err != nil || a == nil || a.EntryCount != 6 || a.ToID != 14 {
		t.Fatalf("a tail of exact pages: %+v, %v", a, err)
	}
	if rep := fullVerify(t, s); !rep.Intact {
		t.Fatalf("after paging: %+v", rep)
	}
	addEvents(s, 7)
	tamperEvent(t, path, "actor = 'nobody'", 20) // in the third page
	if a, err := CheckpointSecurityLog(s); err == nil || a != nil {
		t.Fatalf("an edit in a later page: %+v, %v", a, err)
	}
}
