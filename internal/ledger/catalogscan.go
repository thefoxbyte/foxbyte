// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

// The Blackbox's catalog scan: what the event triggers did not record.
//
// The event triggers are the record, and they are only as good as their
// running. A superuser can stop them, for one session or for everyone, and then
// change the schema with nothing written down; and roles, role memberships,
// databases, tablespaces and settings never reach an event trigger at all. So
// the engine reads the catalogue on a schedule (catalogscan.sql), compares it
// with what it read last time, and explains every difference from the ledger
// entries written in between. A change no entry explains is written into the
// ledger itself, as UNRECORDED; a change to a global object, which no entry
// could have explained, as OBSERVED. Both are hash-chained and anchored like
// every other entry.
//
// The previous snapshot is kept by the engine, outside the database
// (internal/branch/catalogscan.go): a superuser who can rewrite the database
// cannot also rewrite what the scan saw before.
//
// This file is the comparison only, with no database, so the rules can be
// tested on their own.

import (
	_ "embed"
	"fmt"
	"sort"
	"strings"
	"time"
)

// CatalogScanQuery returns one row per watched object; see catalogscan.sql.
//
//go:embed catalogscan.sql
var CatalogScanQuery string

// The statuses of the entries the scan writes, beside APPLIED, FLAGGED and
// BLOCKED. Neither is a statement anyone ran, so neither can be replayed, and
// neither marks the moment of the change: it happened some time before the scan
// that found it.
const (
	// StatusUnrecorded: a change to a table, view, index, function, type,
	// trigger, policy or privilege that the event triggers should have recorded
	// and did not. Something stopped them.
	StatusUnrecorded = "UNRECORDED"
	// StatusObserved: a change event triggers cannot see (a role, a role
	// membership, a database, a tablespace, a setting, an event trigger),
	// recorded after the fact.
	StatusObserved = "OBSERVED"
)

// DropsRecorded are the kinds whose drop the event triggers record as it
// happens (log_ddl_drop in ledger.sql; a domain's drop is reported as a type's).
// Dropping a trigger, a policy, a procedure, an aggregate or a foreign table is
// not, so the scan writes it as OBSERVED rather than as a sign that something
// stopped the record. TestDropsRecordedMatchesTheRecorder keeps the two lists
// in step.
var DropsRecorded = map[string]bool{
	"table": true, "view": true, "materialized view": true, "index": true, "function": true,
	"type": true, "domain": true,
}

// ScanTool is the tool column of every entry the scan writes.
const ScanTool = "blackbox-scan"

// IsScanStatus reports whether an entry was written by the catalog scan rather
// than by an event trigger as the change happened.
func IsScanStatus(status string) bool {
	return status == StatusUnrecorded || status == StatusObserved
}

// CatalogObject is one row of catalogscan.sql, as kept between scans.
type CatalogObject struct {
	Kind     string   `json:"k"`
	Identity string   `json:"i"`
	Schema   string   `json:"s,omitempty"`
	Parents  []string `json:"p,omitempty"`
	Def      string   `json:"d,omitempty"`
	ACL      string   `json:"a,omitempty"`
	Global   bool     `json:"g,omitempty"`
}

func (o CatalogObject) same(p CatalogObject) bool {
	return o.Kind == p.Kind && o.Identity == p.Identity && o.Schema == p.Schema &&
		o.Def == p.Def && o.ACL == p.ACL && o.Global == p.Global && sameStrings(o.Parents, p.Parents)
}

// shape is an object without its key: what it is, not which oid it has.
func (o CatalogObject) shape() string {
	return strings.Join([]string{o.Kind, o.Identity, o.Def, o.ACL, strings.Join(o.Parents, ",")}, "\x00")
}

// WindowEntry is a ledger entry written between two scans, as far as the
// comparison needs it.
type WindowEntry struct {
	Tag     string // command_tag
	Object  string // object_identity
	Status  string
	Cascade bool // a DROP that said CASCADE
}

// Finding is one change the scan writes into the ledger.
type Finding struct {
	Status     string // StatusUnrecorded or StatusObserved
	CommandTag string
	ObjectType string
	Object     string
	Risk       string
	Detail     string
}

// Statement is the text the entry carries in place of the SQL nobody saw: a
// comment, so that even a tool that replays entries by their statement does
// nothing with it.
func (f Finding) Statement(from, to time.Time) string {
	when := "since the scan before"
	if !from.IsZero() {
		when = fmt.Sprintf("between %s and %s", from.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339))
	}
	if f.Status == StatusObserved {
		s := fmt.Sprintf("-- Found by the Blackbox's catalog scan %s: %s. Event triggers never see this kind of change, "+
			"so it was not recorded as it happened, and who made it is unknown.", when, f.Detail)
		if f.Risk == "kill-switch" {
			s += " While it stays this way, the Blackbox's event triggers do not run where it applies; the scan reports what they miss."
		}
		return s
	}
	return fmt.Sprintf("-- Not recorded when it was made: %s. The Blackbox's catalog scan found it %s. Its event triggers "+
		"did not run for this change (a superuser can stop them for a session, or for everyone), so who made it is unknown.",
		f.Detail, when)
}

// Comparison is what CompareCatalog decided.
type Comparison struct {
	Findings []Finding
	// Baseline is what the next scan compares with: this snapshot, except for
	// changes held back for a second look.
	Baseline map[string]CatalogObject
	// Pending counts the scans a held-back change has been seen for.
	Pending map[string]int
}

// explainers is what the ledger entries between two scans account for.
type explainers struct {
	objects     map[string]bool
	grant       bool // a GRANT or REVOKE ran: the ledger does not say on what
	defaultPriv bool // ALTER DEFAULT PRIVILEGES ran, likewise
	cascade     bool // a DROP … CASCADE ran: what went with it has no entry of its own
}

func explain(window []WindowEntry) explainers {
	x := explainers{objects: map[string]bool{}}
	for _, e := range window {
		// A blocked change did not happen, and the scan's own entries explain
		// nothing: they are what it found.
		if e.Status != "APPLIED" && e.Status != "FLAGGED" {
			continue
		}
		if e.Object != "" {
			x.objects[e.Object] = true
		}
		switch {
		case e.Tag == "GRANT" || e.Tag == "REVOKE":
			x.grant = true
		case e.Tag == "ALTER DEFAULT PRIVILEGES":
			x.defaultPriv = true
		case strings.HasPrefix(e.Tag, "DROP") && e.Cascade:
			x.cascade = true
		}
	}
	return x
}

func (x explainers) any(names ...[]string) bool {
	for _, list := range names {
		for _, n := range list {
			if n != "" && x.objects[n] {
				return true
			}
		}
	}
	return false
}

// CompareCatalog compares two snapshots of the catalogue, given the ledger
// entries written between them, and returns what the ledger does not account
// for. pending is the previous Comparison's Pending.
//
// A change to a user object is accounted for by an entry on the object, under
// its old or new name, or on a table it belongs to: CREATE INDEX names the
// index, but ALTER TABLE … DISABLE TRIGGER names only the table, and ALTER
// TABLE on a partitioned table changes every partition. A rename is also
// accounted for by an entry on its schema (ALTER SCHEMA … RENAME), and a drop
// by one on its schema (DROP SCHEMA) or by any DROP … CASCADE. A change of
// privileges is accounted for by any GRANT or REVOKE, because the ledger does
// not record which object a GRANT was on.
//
// A change to a global object is never accounted for: no entry could have
// recorded it.
//
// A change to an event trigger is held back for one scan: the Blackbox drops
// and re-creates its own on every start, and a scan that lands in between would
// otherwise report them gone.
func CompareCatalog(prev, cur map[string]CatalogObject, window []WindowEntry, pending map[string]int) Comparison {
	x := explain(window)
	out := Comparison{Baseline: make(map[string]CatalogObject, len(cur)), Pending: map[string]int{}}
	for k, o := range cur {
		out.Baseline[k] = o
	}

	keys := make([]string, 0, len(prev)+len(cur))
	for k := range prev {
		keys = append(keys, k)
	}
	for k := range cur {
		if _, ok := prev[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	// The same object under a new oid (REINDEX CONCURRENTLY builds a new index
	// and gives it the old one's name): not a change.
	rebuilt := map[string]bool{}
	addedByShape := map[string]string{}
	for _, k := range keys {
		if _, had := prev[k]; !had && !cur[k].Global {
			addedByShape[cur[k].shape()] = k
		}
	}
	for _, k := range keys {
		p, had := prev[k]
		if _, has := cur[k]; !had || has || p.Global {
			continue
		}
		if a, ok := addedByShape[p.shape()]; ok && !rebuilt[a] {
			rebuilt[a], rebuilt[k] = true, true
		}
	}

	for _, k := range keys {
		if rebuilt[k] {
			continue
		}
		p, had := prev[k]
		c, has := cur[k]
		if had && has && p.same(c) {
			continue
		}
		if strings.HasPrefix(k, "e:") && pending[k] == 0 {
			out.Pending[k] = 1
			if had {
				out.Baseline[k] = p
			} else {
				delete(out.Baseline, k)
			}
			continue
		}
		var f *Finding
		if (had && p.Global) || (has && c.Global) {
			f = globalFinding(p, had, c, has)
		} else {
			f = objectFinding(x, p, had, c, has)
		}
		if f != nil {
			out.Findings = append(out.Findings, *f)
		}
	}
	return out
}

func objectFinding(x explainers, p CatalogObject, had bool, c CatalogObject, has bool) *Finding {
	unrecorded := func(tag, kind, ident, detail string) *Finding {
		return &Finding{Status: StatusUnrecorded, CommandTag: tag, ObjectType: kind, Object: ident, Risk: "unrecorded", Detail: detail}
	}
	o := c
	if !has {
		o = p
	}
	if o.Kind == "default privileges" {
		if x.defaultPriv {
			return nil
		}
		return unrecorded("ALTER DEFAULT PRIVILEGES", o.Kind, o.Identity, "the default privileges "+o.Identity+" changed")
	}
	switch {
	case !had:
		if x.any([]string{c.Identity}, c.Parents) {
			return nil
		}
		return unrecorded("CREATE "+strings.ToUpper(c.Kind), c.Kind, c.Identity, c.Kind+" "+c.Identity+" was created")
	case !has:
		if x.cascade || x.any([]string{p.Identity, p.Schema}, p.Parents) {
			return nil
		}
		if !DropsRecorded[p.Kind] {
			// Not a sign anything was stopped: the Blackbox never records
			// dropping one of these as it happens. Now it is on the record.
			return &Finding{Status: StatusObserved, CommandTag: "DROP " + strings.ToUpper(p.Kind), ObjectType: p.Kind,
				Object: p.Identity, Risk: "drop",
				Detail: fmt.Sprintf("%s %s was dropped (the Blackbox records dropping a %s only through this scan)", p.Kind, p.Identity, p.Kind)}
		}
		return unrecorded("DROP "+strings.ToUpper(p.Kind), p.Kind, p.Identity, p.Kind+" "+p.Identity+" was dropped")
	}
	names := []string{p.Identity, c.Identity}
	var what []string
	if p.Identity != c.Identity && !x.any(names, p.Parents, c.Parents, []string{p.Schema, c.Schema}) {
		what = append(what, "renamed from "+p.Identity)
	}
	if (p.Def != c.Def || !sameStrings(p.Parents, c.Parents)) && !x.any(names, p.Parents, c.Parents) {
		what = append(what, "its definition changed")
	}
	privileges := p.ACL != c.ACL && !x.grant && !x.any(names, p.Parents, c.Parents)
	if privileges {
		what = append(what, "its privileges changed")
	}
	if len(what) == 0 {
		return nil
	}
	tag := "ALTER " + strings.ToUpper(c.Kind)
	if privileges && len(what) == 1 {
		tag = "GRANT"
	}
	return unrecorded(tag, c.Kind, c.Identity, c.Kind+" "+c.Identity+": "+strings.Join(what, ", "))
}

func globalFinding(p CatalogObject, had bool, c CatalogObject, has bool) *Finding {
	o := c
	if !has {
		o = p
	}
	f := &Finding{Status: StatusObserved, ObjectType: o.Kind, Object: o.Identity}
	noun := map[string]string{
		"role": "ROLE", "database": "DATABASE", "tablespace": "TABLESPACE", "event trigger": "EVENT TRIGGER",
	}[o.Kind]
	switch o.Kind {
	case "role", "database", "tablespace", "event trigger":
		f.Risk = strings.ReplaceAll(o.Kind, " ", "-")
		switch {
		case !had:
			f.CommandTag = "CREATE " + noun
			f.Detail = fmt.Sprintf("%s %s was created%s", o.Kind, c.Identity, paren(c.Def))
		case !has:
			f.CommandTag = "DROP " + noun
			f.Detail = fmt.Sprintf("%s %s was dropped", o.Kind, p.Identity)
		default:
			f.CommandTag = "ALTER " + noun
			var what []string
			if p.Identity != c.Identity {
				what = append(what, "renamed from "+p.Identity)
			}
			if p.Def != c.Def {
				what = append(what, fmt.Sprintf("was %q, now %q", p.Def, c.Def))
			}
			if p.ACL != c.ACL {
				what = append(what, "its privileges changed")
			}
			f.Detail = fmt.Sprintf("%s %s: %s", o.Kind, c.Identity, strings.Join(what, ", "))
		}
		if o.Kind == "event trigger" && strings.HasPrefix(o.Identity, "bb_") &&
			(!has || strings.Contains(c.Def, " DISABLED ") || strings.Contains(c.Def, " REPLICA ")) {
			f.Risk = "kill-switch"
		}
	case "role membership":
		f.Risk = "membership"
		member, group, _ := strings.Cut(o.Identity, " in ")
		switch {
		case !had:
			f.CommandTag = "GRANT"
			f.Detail = fmt.Sprintf("%s became a member of %s%s", member, group, paren(c.Def))
		case !has:
			f.CommandTag = "REVOKE"
			f.Detail = fmt.Sprintf("%s is no longer a member of %s", member, group)
		default:
			f.CommandTag = "GRANT"
			f.Detail = fmt.Sprintf("%s's membership of %s changed: was %q, now %q", member, group, p.Def, c.Def)
		}
	case "setting":
		f.Risk = "setting"
		f.CommandTag = "ALTER ROLE"
		if strings.HasPrefix(o.Identity, "database ") {
			f.CommandTag = "ALTER DATABASE"
		}
		switch {
		case !had:
			f.Detail = fmt.Sprintf("settings for %s: now %q", c.Identity, c.Def)
		case !has:
			f.Detail = fmt.Sprintf("settings for %s removed (were %q)", p.Identity, p.Def)
		default:
			f.Detail = fmt.Sprintf("settings for %s: was %q, now %q", c.Identity, p.Def, c.Def)
		}
		if has && StopsRecording(c.Def) {
			f.Risk = "kill-switch"
		}
	case "server setting":
		f.Risk = "setting"
		f.CommandTag = "ALTER SYSTEM"
		f.Detail = fmt.Sprintf("%s is now %q (was %q)", o.Identity, c.Def, p.Def)
		if !had {
			f.Detail = fmt.Sprintf("%s is %q", o.Identity, c.Def)
		}
		if has && StopsRecording(c.Identity+"="+c.Def) {
			f.Risk = "kill-switch"
		}
	default:
		f.CommandTag = "ALTER"
		f.Detail = o.Kind + " " + o.Identity + " changed"
	}
	return f
}

// StopsRecording reports whether a list of settings ("name=value, …") includes
// one that stops the Blackbox recording: event_triggers off (PostgreSQL 17 and
// later), session_replication_role replica (every event trigger and ordinary
// trigger left at its default stays silent), or the Blackbox 2.0 capture's own
// switch, bb.v2 off.
func StopsRecording(settings string) bool {
	for _, s := range strings.Split(settings, ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(s), "=")
		if !ok {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		value = strings.ToLower(strings.Trim(strings.TrimSpace(value), `"'`))
		switch name {
		case "event_triggers":
			if value == "off" || value == "false" || value == "0" || value == "no" {
				return true
			}
		case "session_replication_role":
			if value == "replica" {
				return true
			}
		case "bb.v2":
			if value == "off" {
				return true
			}
		}
	}
	return false
}

func paren(s string) string {
	if s = strings.TrimSpace(s); s == "" {
		return ""
	}
	return " (" + s + ")"
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
