// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"strings"
	"testing"
	"time"
)

// Every history entry on a branch is read, whoever ran it, and none on
// another branch.
func TestEachHistoryEntryReadsEveryones(t *testing.T) {
	s := testStore(t)
	record(t, s, entry("ada@x.com", "main", "SELECT 1"))
	record(t, s, entry("bob@x.com", "main", "SELECT 2"))
	record(t, s, entry("ada@x.com", "dev", "SELECT 3"))
	var who []string
	n, err := s.EachHistoryEntry("main", func(e HistoryEntry) error {
		who = append(who, e.Actor+":"+e.SQL)
		return nil
	})
	if err != nil || n != 2 || strings.Join(who, ",") != "ada@x.com:SELECT 1,bob@x.com:SELECT 2" {
		t.Fatalf("n=%d err=%v %v", n, err, who)
	}
}

func logRun(branch string, branchRun int64) *AadhaarLogRun {
	now := time.Now().UTC()
	return &AadhaarLogRun{Branch: branch, BranchRun: branchRun, Started: now, Finished: now, Actor: "cli:op",
		Read: map[string]int{"history": 3}, Skipped: []AadhaarLogSkip{}, Limits: []string{"l"}}
}

// A run's places are kept, counted, grouped by person, and those a later run
// no longer finds are gone; a source the later run skipped is not.
func TestAadhaarLogRuns(t *testing.T) {
	s := testStore(t)
	at := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	r1 := logRun("main", 1)
	places := []AadhaarLogPlace{
		{Source: AadhaarLogHistory, Entry: 7, Field: "sql", Last4: "0124", Actor: "ada@x.com", At: at, Person: 1},
		{Source: AadhaarLogHistory, Entry: 7, Field: "error", Last4: "0124", Actor: "ada@x.com", At: at, Person: 1},
		{Source: AadhaarLogBlackbox, Entry: 3, Last4: "0124", Actor: "ada", At: at.Add(time.Hour), Person: 1},
		{Source: AadhaarLogAudit, Entry: 40, Last4: "2341", Actor: "bob", At: at, Person: 2},
	}
	if err := s.RecordAadhaarLogs(r1, places); err != nil || r1.ID == 0 {
		t.Fatal(err)
	}
	got, err := s.LatestAadhaarLogRun("main")
	if err != nil || got == nil || got.ID != r1.ID || got.BranchRun != 1 || got.Read["history"] != 3 {
		t.Fatalf("%v %+v", err, got)
	}
	if none, err := s.LatestAadhaarLogRun("dev"); err != nil || none != nil {
		t.Fatalf("dev has a run: %v %+v", err, none)
	}
	people, err := s.AadhaarLogPeople(got)
	if err != nil || len(people) != 2 || people[0].Person != 1 || people[0].Places != 3 ||
		people[0].Sources["history"] != 2 || people[0].Sources["blackbox"] != 1 || !people[0].Since.Equal(at) {
		t.Fatalf("%v %+v", err, people)
	}
	counts, gone, err := s.AadhaarLogCounts(got)
	if err != nil || gone != 0 || len(counts) != 3 || counts[0].Source != "history" || counts[0].Entries != 1 || counts[0].Places != 2 {
		t.Fatalf("%v gone=%d %+v", err, gone, counts)
	}

	// The second run finds the history entry's statement only, and could not
	// read the audit log.
	r2 := logRun("main", 2)
	r2.Skipped = []AadhaarLogSkip{{Source: AadhaarLogAudit, Reason: "unreadable"}}
	if err := s.RecordAadhaarLogs(r2, places[:1]); err != nil {
		t.Fatal(err)
	}
	_, gone, err = s.AadhaarLogCounts(r2)
	if err != nil || gone != 2 {
		t.Fatalf("gone: %v %d (the error and the Blackbox entry, not the skipped audit log's)", err, gone)
	}
	g, err := s.AadhaarLogPlaces(r2, AadhaarLogFilter{Gone: true})
	if err != nil || len(g) != 2 {
		t.Fatalf("%v %+v", err, g)
	}
	for _, p := range g {
		if !p.Gone || p.Person != 0 || p.Source == AadhaarLogAudit {
			t.Errorf("gone place: %+v", p)
		}
	}
	now, err := s.AadhaarLogPlaces(r2, AadhaarLogFilter{Person: 1})
	if err != nil || len(now) != 1 || now[0].Field != "sql" || now[0].FirstSeen.After(now[0].LastSeen) || now[0].Gone {
		t.Fatalf("%v %+v", err, now)
	}
	if src, err := s.AadhaarLogPlaces(r2, AadhaarLogFilter{Source: AadhaarLogBlackbox}); err != nil || len(src) != 0 {
		t.Fatalf("%v %+v", err, src)
	}
}

// A place keeps four digits and nothing else: the store refuses more.
func TestAadhaarLogPlaceKeepsFourDigits(t *testing.T) {
	s := testStore(t)
	for _, bad := range []string{"234567890124", "12a4", "123"} {
		err := s.RecordAadhaarLogs(logRun("main", 1), []AadhaarLogPlace{{Source: AadhaarLogHistory, Entry: 1, Last4: bad, At: time.Now()}})
		if err == nil {
			t.Errorf("kept %q", bad)
		}
	}
	if err := s.RecordAadhaarLogs(&AadhaarLogRun{Branch: "main"}, nil); err == nil {
		t.Error("a run without the run of its tables was kept")
	}
}
