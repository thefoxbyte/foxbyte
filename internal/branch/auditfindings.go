// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"log"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

// What can go wrong with the audit log, found rather than assumed (F6 Gate 1,
// step 4; design, sections 13 and 19). A full log drops lines without a word,
// so nothing PostgreSQL says can be waited for: each finding here is checked
// from the outside.
//
//   - space: the log's dataset nearly full (step 1's check, here too)
//   - collector: the store not collected for five minutes
//   - heartbeat: a database's own line, every five minutes, not arriving
//   - gap: a session's statement numbers skipping some, recorded in the chain
//   - mark: a table marked through FoxByte, its mark since taken off
//     outside it (a table's owner can; step 2)
//   - forward: records not reaching the SIEM for five minutes, or removed by
//     retention before they reached it (step 5b)
//   - definer: a SECURITY DEFINER function naming a marked table, whose
//     statements pgAudit does not see (step 6; auditdefiner.go)

// AuditFinding is one thing wrong.
type AuditFinding struct {
	Kind   string `json:"kind"` // space, collector, heartbeat, gap, mark, forward, definer
	Branch string `json:"branch,omitempty"`
	Detail string `json:"detail"`
	Since  string `json:"since,omitempty"` // RFC 3339
}

const (
	heartbeatEvery = 5 * time.Minute
	heartbeatLate  = 15 * time.Minute
	collectorLate  = 5 * time.Minute
	gapsShown      = 7 * 24 * time.Hour
)

// heartbeatSQL is the heartbeat: the engine's superuser setting pgaudit.log
// in a session of its own, which pgAudit logs (MISC SET), with nothing in the
// database touched, so the Blackbox records nothing.
const heartbeatSQL = "SET pgaudit.log = 'misc_set';\n"

// SendHeartbeat makes one audited database write its heartbeat line.
func SendHeartbeat(name string) error {
	if !runsWithAudit(name) {
		return nil
	}
	return psqlQuiet(name, heartbeatSQL)
}

// SendHeartbeats sends one from every running database with audit, and says
// which it reached.
func SendHeartbeats() ([]string, error) {
	names, err := RunningBranches()
	if err != nil {
		return nil, err
	}
	var sent []string
	for _, n := range names {
		if !runsWithAudit(n) {
			continue
		}
		if err := SendHeartbeat(n); err != nil {
			log.Printf("audit log: heartbeat on %s: %v", n, err)
			continue
		}
		sent = append(sent, n)
	}
	return sent, nil
}

// StartAuditHeartbeat sends heartbeats every five minutes in the control
// plane. A heartbeat is no use to the idle reaper: it goes to running
// databases only, through docker, never through the Gateway, so it keeps no
// branch awake.
func StartAuditHeartbeat() {
	go func() {
		time.Sleep(time.Minute)
		for {
			if AuditOn() {
				if _, err := SendHeartbeats(); err != nil {
					log.Printf("audit log: heartbeats: %v", err)
				}
			}
			time.Sleep(heartbeatEvery)
		}
	}()
}

// MarkEvent is a mark set or taken off through FoxByte, read back from the
// security log (EvAuditMarked): what the mark should be.
type MarkEvent struct {
	Branch, Table string
	Marked, Reads bool
	By, At        string
}

// ParseMarkEvent reads one security log event's subject (the branch) and
// detail, as auditlog.go and the API write them: "auditing writes of t",
// "auditing writes and reads of t", "stopped auditing t".
func ParseMarkEvent(subject, detail, by, at string) (MarkEvent, bool) {
	e := MarkEvent{Branch: subject, By: by, At: at}
	switch {
	case strings.HasPrefix(detail, "auditing writes and reads of "):
		e.Table, e.Marked, e.Reads = strings.TrimPrefix(detail, "auditing writes and reads of "), true, true
	case strings.HasPrefix(detail, "auditing writes of "):
		e.Table, e.Marked = strings.TrimPrefix(detail, "auditing writes of "), true
	case strings.HasPrefix(detail, "stopped auditing "):
		e.Table = strings.TrimPrefix(detail, "stopped auditing ")
	default:
		return e, false
	}
	return e, e.Branch != "" && e.Table != ""
}

// expectedMarks is the last word on each table: the marks that should be in
// place, by branch and table.
func expectedMarks(events []MarkEvent) map[string]map[string]MarkEvent {
	out := map[string]map[string]MarkEvent{}
	for _, e := range events {
		if out[e.Branch] == nil {
			out[e.Branch] = map[string]MarkEvent{}
		}
		if e.Marked {
			out[e.Branch][e.Table] = e
		} else {
			delete(out[e.Branch], e.Table)
		}
	}
	return out
}

// runningAudit is one running database, as the findings need it.
type runningAudit struct {
	Name    string
	Audited bool      // started with pgAudit
	Started time.Time // when its container started
}

// findingsInput is everything the findings are made from, so they are a pure
// function of it, and tested.
type findingsInput struct {
	Now      time.Time
	AuditOn  bool
	State    auditState
	Space    AuditSpace
	SpaceErr error
	Running  []runningAudit
	Expected map[string]map[string]MarkEvent
	Marks    map[string][]AuditMark     // running branches' marks as they are
	Exists   map[string]map[string]bool // running branches' expected tables that still exist
	Forward  *AuditForward              // nil when not forwarding
	FState   forwardState
	Definers map[string][]DefinerFunc // running branches' definer functions that name marked tables
}

func findingsFrom(in findingsInput) []AuditFinding {
	var out []AuditFinding
	if in.AuditOn && in.SpaceErr == nil && in.Space.Quota > 0 && in.Space.Used*100 >= in.Space.Quota*80 {
		out = append(out, AuditFinding{Kind: "space", Detail: fmt.Sprintf(
			"the log holds %d%% of its quota: a full log loses audit lines without a word", in.Space.Used*100/in.Space.Quota)})
	}
	if in.AuditOn {
		last, err := time.Parse(time.RFC3339, in.State.LastRun)
		if err != nil || in.Now.Sub(last) > collectorLate {
			f := AuditFinding{Kind: "collector", Detail: "the raw log has not been collected into the store for more than 5 minutes: is the control plane running?"}
			if err == nil {
				f.Since = in.State.LastRun
			}
			out = append(out, f)
		}
	}
	for _, r := range in.Running {
		if !r.Audited {
			continue
		}
		beat, err := time.Parse(time.RFC3339Nano, in.State.Beats[r.Name])
		if err == nil && in.Now.Sub(beat) <= heartbeatLate {
			continue
		}
		since := r.Started
		if err == nil && beat.After(since) {
			since = beat
		}
		if in.Now.Sub(since) <= heartbeatLate {
			continue // started too recently to have missed one
		}
		f := AuditFinding{Kind: "heartbeat", Branch: r.Name,
			Detail: "no heartbeat has reached the store for more than 15 minutes: its audit lines may not be arriving", Since: since.UTC().Format(time.RFC3339)}
		out = append(out, f)
	}
	for _, g := range in.State.Gaps {
		t, err := time.Parse(time.RFC3339Nano, g.Time)
		if err != nil || in.Now.Sub(t) > gapsShown {
			continue
		}
		who := g.Login
		if who == "" {
			who = "a login"
		}
		out = append(out, AuditFinding{Kind: "gap", Branch: g.Branch, Since: g.Time, Detail: fmt.Sprintf(
			"%d audit line(s) missing in a session of %s (statements %d to %d): lost before they reached the log, most often to a full log",
			g.Missing, who, g.Statement, g.Statement+g.Missing-1)})
	}
	out = append(out, forwardFindings(in)...)
	if in.AuditOn {
		names := make([]string, 0, len(in.Definers))
		for b := range in.Definers {
			names = append(names, b)
		}
		sort.Strings(names)
		for _, b := range names {
			for _, f := range in.Definers[b] {
				out = append(out, definerFinding(b, f))
			}
		}
	}
	branches := make([]string, 0, len(in.Expected))
	for b := range in.Expected {
		branches = append(branches, b)
	}
	sort.Strings(branches)
	for _, b := range branches {
		have, running := in.Marks[b]
		if !running {
			continue // a branch not running is not woken to be checked
		}
		now := map[string]AuditMark{}
		for _, m := range have {
			now[m.Schema+"."+m.Name] = m
		}
		tables := make([]string, 0, len(in.Expected[b]))
		for t := range in.Expected[b] {
			tables = append(tables, t)
		}
		sort.Strings(tables)
		for _, t := range tables {
			e := in.Expected[b][t]
			if !in.Exists[b][t] {
				continue // dropped since: that is its own change, in the Blackbox, not a mark taken off
			}
			m, ok := now[t]
			switch {
			case !ok || !m.Writes:
				out = append(out, AuditFinding{Kind: "mark", Branch: b, Since: e.At, Detail: fmt.Sprintf(
					"%s was marked by %s, and its mark has been taken off outside FoxByte: its writes are not audited", t, e.By)})
			case e.Reads && !m.Reads:
				out = append(out, AuditFinding{Kind: "mark", Branch: b, Since: e.At, Detail: fmt.Sprintf(
					"%s was marked for reads by %s, and that has been taken off outside FoxByte: its reads are not audited", t, e.By)})
			}
		}
	}
	return out
}

// forwardFindings: forwarding that keeps failing, and records that never
// reached the SIEM.
func forwardFindings(in findingsInput) []AuditFinding {
	if in.Forward == nil {
		return nil
	}
	var out []AuditFinding
	host := in.Forward.URL
	if u, err := url.Parse(host); err == nil {
		host = u.Host
	}
	if fs := in.FState; fs.LastErr != "" {
		since, err := time.Parse(time.RFC3339, fs.ErrSince)
		if err != nil || in.Now.Sub(since) > forwardLate {
			last := "forwarding was set"
			if fs.LastOK != "" {
				last = fs.LastOK
			}
			out = append(out, AuditFinding{Kind: "forward", Since: fs.ErrSince, Detail: fmt.Sprintf(
				"records have not reached %s since %s (%s): %d wait in the store, kept until their retention",
				host, last, fs.LastErr, max(0, in.State.Seq-fs.Seq))})
		}
	}
	if fs := in.FState; fs.Skipped > 0 {
		if t, err := time.Parse(time.RFC3339, fs.SkipAt); err == nil && in.Now.Sub(t) <= gapsShown {
			out = append(out, AuditFinding{Kind: "forward", Since: fs.SkipAt, Detail: fmt.Sprintf(
				"%d record(s) were removed by retention before they reached %s: the copy there lacks them", fs.Skipped, host)})
		}
	}
	return out
}

// AuditFindings checks everything now. events are the security log's mark
// events, oldest first, which the caller holds (the account store is not
// this package's).
func AuditFindings(events []MarkEvent) []AuditFinding {
	in := findingsInput{Now: time.Now(), AuditOn: AuditOn(), Expected: expectedMarks(events),
		Marks: map[string][]AuditMark{}, Exists: map[string]map[string]bool{}, Definers: map[string][]DefinerFunc{}}
	in.State, _ = loadAuditState()
	in.Space, in.SpaceErr = AuditUsage()
	if in.Forward = LoadAuditSettings().Forward; in.Forward != nil {
		in.FState = loadForwardState()
	}
	if names, err := RunningBranches(); err == nil {
		for _, n := range names {
			r := runningAudit{Name: n, Audited: runsWithAudit(n)}
			if out, err := capture("docker", "inspect", "-f", "{{.State.StartedAt}}", container(n)); err == nil {
				r.Started, _ = time.Parse(time.RFC3339Nano, strings.TrimSpace(out))
			}
			in.Running = append(in.Running, r)
			if in.AuditOn {
				if fs, err := DefinerFunctions(n); err == nil && len(fs) > 0 {
					in.Definers[n] = fs
				}
			}
			if want, wanted := in.Expected[n]; wanted && len(want) > 0 {
				m, err1 := AuditMarks(n)
				ex, err2 := existingTables(n, want)
				if err1 == nil && err2 == nil {
					in.Marks[n], in.Exists[n] = m, ex
				}
			}
		}
	}
	return findingsFrom(in)
}

// MarkEventsFrom reads the marks set and taken off through FoxByte from the
// security log, oldest first.
func MarkEventsFrom(st *auth.Store) []MarkEvent {
	evs, err := st.SecurityEventsOfKind(auth.EvAuditMarked)
	if err != nil {
		return nil
	}
	var out []MarkEvent
	for _, e := range evs {
		if m, ok := ParseMarkEvent(e.Subject, e.Detail, e.Actor, e.At); ok {
			out = append(out, m)
		}
	}
	return out
}

// existingTables reports which of the expected tables a branch still has.
func existingTables(name string, want map[string]MarkEvent) (map[string]bool, error) {
	var lits []string
	for t := range want {
		lits = append(lits, QuoteLiteral(t))
	}
	out, err := QuerySQL(name, "SELECT n.nspname || '.' || c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "+
		"WHERE c.relkind IN ('r', 'p') AND n.nspname || '.' || c.relname = ANY (ARRAY["+strings.Join(lits, ", ")+"]::text[])")
	if err != nil {
		return nil, fmt.Errorf("%w (%s)", err, strings.TrimSpace(out))
	}
	ex := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			ex[l] = true
		}
	}
	return ex, nil
}
