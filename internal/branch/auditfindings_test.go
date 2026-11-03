// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"strings"
	"testing"
	"time"
)

func stmt(session string, n int64, at string) AuditRecord {
	return AuditRecord{Kind: "statement", Branch: "main", Login: "alice", Session: session, Statement: n, Time: at}
}

// A session's numbers that skip some are lines lost; numbers repeated (one
// statement, several tables) and a new session are not.
func TestWithGaps(t *testing.T) {
	sessions := map[string]sessionMark{}
	in := []AuditRecord{
		stmt("s1", 1, "2026-11-04T10:00:01Z"), stmt("s1", 2, "2026-11-04T10:00:02Z"), stmt("s1", 2, "2026-11-04T10:00:02Z"),
		{Kind: "transaction", Session: "s1"},
		stmt("s1", 6, "2026-11-04T10:00:06Z"),
		stmt("s2", 1, "2026-11-04T10:00:07Z"),
	}
	out := withGaps(in, sessions)
	var gaps []AuditRecord
	for _, r := range out {
		if r.Kind == "gap" {
			gaps = append(gaps, r)
		}
	}
	if len(out) != len(in)+1 || len(gaps) != 1 || gaps[0].Statement != 3 || gaps[0].Missing != 3 || gaps[0].Session != "s1" || gaps[0].Login != "alice" {
		t.Fatalf("one gap of 3, statements 3 to 5: %+v", gaps)
	}
	if out[4].Kind != "gap" {
		t.Error("the gap goes where it was found, before the statement that showed it")
	}
	// Across collections: the session's last number is remembered.
	out = withGaps([]AuditRecord{stmt("s1", 8, "2026-11-04T10:01:00Z")}, sessions)
	if len(out) != 2 || out[0].Kind != "gap" || out[0].Statement != 7 || out[0].Missing != 1 {
		t.Errorf("a gap across two collections: %+v", out)
	}
	pruneSessions(sessions, "2026-11-04T10:00:30Z")
	if _, ok := sessions["main/s2"]; ok {
		t.Error("a session silent since before the cutoff is forgotten")
	}
	if _, ok := sessions["main/s1"]; !ok {
		t.Error("a session seen since is kept")
	}
}

func TestHeartbeatLine(t *testing.T) {
	line := `{"timestamp":"2026-11-04 10:05:00.000 UTC","user":"dbadmin","session_id":"x.9","vxid":"3/2","error_severity":"LOG","message":"AUDIT: SESSION,1,1,MISC,SET,,,<not logged>,<not logged>"}`
	r, ok := recordFromLine("main", []byte(line))
	if !ok || r.Kind != "heartbeat" {
		t.Fatalf("the engine's MISC SET is the heartbeat: %+v", r)
	}
	other := strings.Replace(line, `"user":"dbadmin"`, `"user":"alice"`, 1)
	if r, _ := recordFromLine("main", []byte(other)); r.Kind != "statement" {
		t.Errorf("anyone else's SET is a statement: %+v", r)
	}
}

func TestMarkEvents(t *testing.T) {
	for _, c := range []struct {
		detail        string
		table         string
		marked, reads bool
	}{
		{"auditing writes of public.orders", "public.orders", true, false},
		{"auditing writes and reads of public.cards", "public.cards", true, true},
		{"stopped auditing public.orders", "public.orders", false, false},
	} {
		e, ok := ParseMarkEvent("main", c.detail, "bob", "2026-11-04T10:00:00Z")
		if !ok || e.Table != c.table || e.Marked != c.marked || e.Reads != c.reads || e.Branch != "main" || e.By != "bob" {
			t.Errorf("%q: %+v %v", c.detail, e, ok)
		}
	}
	if _, ok := ParseMarkEvent("main", "something else", "", ""); ok {
		t.Error("an unknown detail is not a mark")
	}
	exp := expectedMarks([]MarkEvent{
		{Branch: "main", Table: "public.a", Marked: true},
		{Branch: "main", Table: "public.b", Marked: true, Reads: true},
		{Branch: "main", Table: "public.a", Marked: false},
		{Branch: "main", Table: "public.b", Marked: true},
	})
	if len(exp["main"]) != 1 || exp["main"]["public.b"].Reads {
		t.Errorf("the last word on each table: %+v", exp)
	}
}

func TestFindings(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) string { return now.Add(-d).Format(time.RFC3339) }
	base := findingsInput{
		Now: now, AuditOn: true, Space: AuditSpace{Used: 10, Quota: 100},
		State: auditState{LastRun: ago(time.Minute), Beats: map[string]string{"main": ago(3 * time.Minute)}},
		Running: []runningAudit{
			{Name: "main", Audited: true, Started: now.Add(-24 * time.Hour)},
			{Name: "quiet", Audited: true, Started: now.Add(-time.Hour)},       // never a heartbeat
			{Name: "fresh", Audited: true, Started: now.Add(-2 * time.Minute)}, // too new to have missed one
			{Name: "unaudited", Audited: false, Started: now.Add(-time.Hour)},  // not audited: nothing to beat
		},
	}
	kinds := func(fs []AuditFinding) string {
		var k []string
		for _, f := range fs {
			k = append(k, f.Kind+":"+f.Branch)
		}
		return strings.Join(k, " ")
	}
	if got := kinds(findingsFrom(base)); got != "heartbeat:quiet" {
		t.Errorf("only the branch that has missed its heartbeat: %q", got)
	}

	late := base
	late.State.LastRun = ago(10 * time.Minute)
	late.Space = AuditSpace{Used: 85, Quota: 100}
	if got := kinds(findingsFrom(late)); got != "space: collector: heartbeat:quiet" {
		t.Errorf("space and a stalled collector: %q", got)
	}

	gaps := base
	gaps.Running = nil
	gaps.State.Gaps = []AuditRecord{
		{Kind: "gap", Branch: "main", Login: "alice", Statement: 3, Missing: 2, Time: ago(time.Hour)},
		{Kind: "gap", Branch: "main", Statement: 9, Missing: 1, Time: ago(10 * 24 * time.Hour)}, // over a week ago
	}
	fs := findingsFrom(gaps)
	if len(fs) != 1 || fs[0].Kind != "gap" || !strings.Contains(fs[0].Detail, "2 audit line(s) missing in a session of alice (statements 3 to 4)") {
		t.Errorf("a recent gap, not an old one: %+v", fs)
	}

	marks := base
	marks.Running = nil
	marks.Expected = map[string]map[string]MarkEvent{
		"main":     {"public.a": {Table: "public.a", Marked: true, By: "bob"}, "public.b": {Table: "public.b", Marked: true, Reads: true, By: "bob"}, "public.c": {Table: "public.c", Marked: true}},
		"sleeping": {"public.z": {Table: "public.z", Marked: true}},
	}
	marks.Exists = map[string]map[string]bool{"main": {"public.a": true, "public.b": true, "public.c": true}}
	marks.Marks = map[string][]AuditMark{"main": {
		{Schema: "public", Name: "b", Writes: true, Reads: false},
		{Schema: "public", Name: "c", Writes: true},
	}}
	fs = findingsFrom(marks)
	if got := kinds(fs); got != "mark:main mark:main" {
		t.Fatalf("a mark gone, and reads gone; a branch not running is not checked: %q", got)
	}
	if !strings.Contains(fs[0].Detail, "public.a was marked by bob") || !strings.Contains(fs[1].Detail, "public.b was marked for reads") {
		t.Errorf("%+v", fs)
	}
	// A table dropped since is its own change, not a mark taken off.
	marks.Exists["main"]["public.a"] = false
	if got := kinds(findingsFrom(marks)); got != "mark:main" {
		t.Errorf("a dropped table is not a missing mark: %q", got)
	}

	off := base
	off.AuditOn = false
	off.Running = nil
	off.State.LastRun = ""
	if fs := findingsFrom(off); len(fs) != 0 {
		t.Errorf("audit off: no collector finding: %+v", fs)
	}
}
