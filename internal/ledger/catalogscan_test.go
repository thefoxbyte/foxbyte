// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

func table(ident string, def string) CatalogObject {
	schema, _, _ := strings.Cut(ident, ".")
	return CatalogObject{Kind: "table", Identity: ident, Schema: schema, Def: def, ACL: "acl0"}
}

func applied(tag, obj string) WindowEntry {
	return WindowEntry{Tag: tag, Object: obj, Status: "APPLIED"}
}

func compare(prev, cur map[string]CatalogObject, window ...WindowEntry) []Finding {
	return CompareCatalog(prev, cur, window, nil).Findings
}

// A change the event triggers recorded is not reported again: the scan only
// adds what the ledger lacks.
func TestScanReportsNothingTheLedgerRecorded(t *testing.T) {
	prev := map[string]CatalogObject{"c:1": table("public.orders", "v1")}
	cur := map[string]CatalogObject{
		"c:1": table("public.orders", "v2"),
		"c:2": table("public.items", "v1"),
		"c:3": {Kind: "index", Identity: "public.items_idx", Schema: "public", Parents: []string{"public.items"}, Def: "i"},
	}
	got := compare(prev, cur, applied("ALTER TABLE", "public.orders"), applied("CREATE TABLE", "public.items"))
	if len(got) != 0 {
		t.Fatalf("recorded changes were reported again: %+v", got)
	}
	if got := compare(prev, prev); len(got) != 0 {
		t.Fatalf("nothing changed, and the scan reported %+v", got)
	}
}

// What a superuser does with the event triggers stopped is found, named and
// marked UNRECORDED.
func TestScanFindsChangesNoEntryExplains(t *testing.T) {
	prev := map[string]CatalogObject{
		"c:1": table("public.orders", "v1"),
		"c:2": table("public.audit", "v1"),
	}
	cur := map[string]CatalogObject{
		"c:1": table("public.orders", "v2"),
		"c:3": table("public.secret", "v1"),
		"p:9": {Kind: "function", Identity: "public.leak(integer)", Schema: "public", Def: "f"},
	}
	got := compare(prev, cur)
	want := map[string]string{
		"public.orders":        "ALTER TABLE",
		"public.audit":         "DROP TABLE",
		"public.secret":        "CREATE TABLE",
		"public.leak(integer)": "CREATE FUNCTION",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d findings, want %d: %+v", len(got), len(want), got)
	}
	for _, f := range got {
		if f.Status != StatusUnrecorded || f.Risk != "unrecorded" {
			t.Errorf("%s: status %s risk %s", f.Object, f.Status, f.Risk)
		}
		if want[f.Object] != f.CommandTag {
			t.Errorf("%s: tag %q, want %q", f.Object, f.CommandTag, want[f.Object])
		}
	}
}

// Renames keep the object's oid, so they read as renames, accounted for by the
// entry on the new name, or by ALTER SCHEMA … RENAME for everything inside it.
func TestScanFollowsRenames(t *testing.T) {
	prev := map[string]CatalogObject{"c:1": table("public.a", "v1"), "c:2": table("public.b", "v1")}
	cur := map[string]CatalogObject{"c:1": table("public.a2", "v1"), "c:2": table("raw.b", "v1")}
	cur["c:2"] = CatalogObject{Kind: "table", Identity: "raw.b", Schema: "raw", Def: "v1", ACL: "acl0"}
	if got := compare(prev, cur, applied("ALTER TABLE", "public.a2"), applied("ALTER SCHEMA", "raw")); len(got) != 0 {
		t.Fatalf("recorded renames were reported: %+v", got)
	}
	got := compare(prev, cur)
	if len(got) != 2 || !strings.Contains(got[0].Detail, "renamed from public.a") {
		t.Fatalf("unrecorded renames: %+v", got)
	}
	// A schema's entry accounts for a rename, not for a new definition.
	cur["c:2"] = CatalogObject{Kind: "table", Identity: "raw.b", Schema: "raw", Def: "v2", ACL: "acl0"}
	got = compare(prev, cur, applied("ALTER TABLE", "public.a2"), applied("ALTER SCHEMA", "raw"))
	if len(got) != 1 || got[0].Object != "raw.b" || strings.Contains(got[0].Detail, "renamed") {
		t.Fatalf("a definition changed with only the schema's rename recorded: %+v", got)
	}
}

// An index, trigger or policy is accounted for by an entry on its table, and a
// partition by one on any ancestor.
func TestScanCreditsParents(t *testing.T) {
	prev := map[string]CatalogObject{
		"g:1": {Kind: "trigger", Identity: "audit on public.t", Schema: "public", Parents: []string{"public.t"}, Def: "enabled"},
		"c:2": {Kind: "table", Identity: "public.p_2026", Schema: "public", Parents: []string{"public.p_year", "public.p"}, Def: "v1"},
	}
	cur := map[string]CatalogObject{
		"g:1": {Kind: "trigger", Identity: "audit on public.t", Schema: "public", Parents: []string{"public.t"}, Def: "disabled"},
		"c:2": {Kind: "table", Identity: "public.p_2026", Schema: "public", Parents: []string{"public.p_year", "public.p"}, Def: "v2"},
	}
	if got := compare(prev, cur, applied("ALTER TABLE", "public.t"), applied("ALTER TABLE", "public.p")); len(got) != 0 {
		t.Fatalf("changes made through a parent were reported: %+v", got)
	}
}

// DROP … CASCADE records only what it named; what went with it is accounted
// for, and so is everything in a dropped schema.
func TestScanCreditsCascadesAndSchemaDrops(t *testing.T) {
	prev := map[string]CatalogObject{
		"c:1": table("public.t", "v1"),
		"c:2": {Kind: "view", Identity: "public.t_view", Schema: "public", Def: "v"},
		"c:3": table("raw.old", "v1"),
	}
	cur := map[string]CatalogObject{}
	got := compare(prev, cur,
		WindowEntry{Tag: "DROP TABLE", Object: "public.t", Status: "APPLIED", Cascade: true},
		applied("DROP SCHEMA", "raw"))
	if len(got) != 0 {
		t.Fatalf("a cascade's and a schema drop's objects were reported: %+v", got)
	}
	got = compare(prev, cur, applied("DROP TABLE", "public.t"))
	if len(got) != 2 {
		t.Fatalf("without CASCADE or the schema's entry, want the view and raw.old reported: %+v", got)
	}
}

// A GRANT's entry does not say which object it was on, so any GRANT or REVOKE
// accounts for changed privileges, and nothing else does.
func TestScanPrivileges(t *testing.T) {
	prev := map[string]CatalogObject{"c:1": table("public.t", "v1")}
	cur := map[string]CatalogObject{"c:1": {Kind: "table", Identity: "public.t", Schema: "public", Def: "v1", ACL: "acl1"}}
	if got := compare(prev, cur, applied("GRANT", "")); len(got) != 0 {
		t.Fatalf("a recorded GRANT's change was reported: %+v", got)
	}
	got := compare(prev, cur)
	if len(got) != 1 || got[0].CommandTag != "GRANT" || !strings.Contains(got[0].Detail, "privileges changed") {
		t.Fatalf("an unrecorded GRANT: %+v", got)
	}
}

// A blocked change did not happen and the scan's own entries are findings, so
// neither accounts for anything.
func TestScanIgnoresBlockedAndItsOwnEntries(t *testing.T) {
	prev := map[string]CatalogObject{}
	cur := map[string]CatalogObject{"c:1": table("public.t", "v1")}
	for _, st := range []string{"BLOCKED", StatusUnrecorded, StatusObserved} {
		if got := compare(prev, cur, WindowEntry{Tag: "CREATE TABLE", Object: "public.t", Status: st}); len(got) != 1 {
			t.Errorf("an entry with status %s accounted for the change: %+v", st, got)
		}
	}
}

// REINDEX CONCURRENTLY builds a new index under the old name: a new oid, the
// same object.
func TestScanIgnoresARebuiltIndex(t *testing.T) {
	idx := CatalogObject{Kind: "index", Identity: "public.t_v", Schema: "public", Parents: []string{"public.t"}, Def: "i"}
	if got := compare(map[string]CatalogObject{"c:5": idx}, map[string]CatalogObject{"c:9": idx}); len(got) != 0 {
		t.Fatalf("a rebuilt index was reported: %+v", got)
	}
}

// Roles, memberships, databases and settings never reach an event trigger, so
// every change to one is recorded as OBSERVED, and a setting that stops the
// record is marked kill-switch.
func TestScanRecordsGlobalObjects(t *testing.T) {
	prev := map[string]CatalogObject{
		"r:1":              {Kind: "role", Identity: `"alice@x.dev"`, Def: "LOGIN", Global: true},
		"f:event_triggers": {Kind: "server setting", Identity: "event_triggers", Def: "on", Global: true},
	}
	cur := map[string]CatalogObject{
		"r:1":              {Kind: "role", Identity: `"alice@x.dev"`, Def: "SUPERUSER LOGIN", Global: true},
		"r:2":              {Kind: "role", Identity: "mallory", Def: "LOGIN", Global: true},
		"m:7":              {Kind: "role membership", Identity: "mallory in db_admin", Def: "granted by dbadmin", Global: true},
		"s:5:0":            {Kind: "setting", Identity: "database appdb", Def: "bb.v2=off", Global: true},
		"f:event_triggers": {Kind: "server setting", Identity: "event_triggers", Def: "off", Global: true},
	}
	// Even an entry naming the object does not account for it.
	got := compare(prev, cur, applied("CREATE ROLE", "mallory"))
	byObj := map[string]Finding{}
	for _, f := range got {
		if f.Status != StatusObserved {
			t.Errorf("%s: status %s, want OBSERVED", f.Object, f.Status)
		}
		byObj[f.Object] = f
	}
	checks := []struct{ obj, tag, risk, detail string }{
		{`"alice@x.dev"`, "ALTER ROLE", "role", `now "SUPERUSER LOGIN"`},
		{"mallory", "CREATE ROLE", "role", "role mallory was created (LOGIN)"},
		{"mallory in db_admin", "GRANT", "membership", "mallory became a member of db_admin"},
		{"database appdb", "ALTER DATABASE", "kill-switch", `"bb.v2=off"`},
		{"event_triggers", "ALTER SYSTEM", "kill-switch", `now "off"`},
	}
	if len(got) != len(checks) {
		t.Fatalf("got %d findings, want %d: %+v", len(got), len(checks), got)
	}
	for _, c := range checks {
		f, ok := byObj[c.obj]
		if !ok || f.CommandTag != c.tag || f.Risk != c.risk || !strings.Contains(f.Detail, c.detail) {
			t.Errorf("%s: got %+v, want tag %s risk %s detail containing %q", c.obj, f, c.tag, c.risk, c.detail)
		}
	}
}

// The Blackbox re-creates its event triggers on every start; a scan in between
// must not report them gone. A change is reported only when the next scan still
// sees it.
func TestScanHoldsEventTriggerChangesForASecondLook(t *testing.T) {
	on := CatalogObject{Kind: "event trigger", Identity: "bb_log_end", Def: "ddl_command_end ENABLED bb.log_ddl_end", Global: true}
	off := on
	off.Def = "ddl_command_end DISABLED bb.log_ddl_end"
	prev := map[string]CatalogObject{"e:bb_log_end": on}

	first := CompareCatalog(prev, map[string]CatalogObject{}, nil, nil)
	if len(first.Findings) != 0 || first.Pending["e:bb_log_end"] != 1 || !first.Baseline["e:bb_log_end"].same(on) {
		t.Fatalf("first sight of a missing event trigger: %+v", first)
	}
	back := CompareCatalog(first.Baseline, prev, nil, first.Pending)
	if len(back.Findings) != 0 || len(back.Pending) != 0 {
		t.Fatalf("an event trigger that came back was reported: %+v", back)
	}

	held := CompareCatalog(prev, map[string]CatalogObject{"e:bb_log_end": off}, nil, nil)
	second := CompareCatalog(held.Baseline, map[string]CatalogObject{"e:bb_log_end": off}, nil, held.Pending)
	if len(second.Findings) != 1 || second.Findings[0].Risk != "kill-switch" || second.Findings[0].CommandTag != "ALTER EVENT TRIGGER" {
		t.Fatalf("a Blackbox event trigger disabled for two scans: %+v", second.Findings)
	}
	if !second.Baseline["e:bb_log_end"].same(off) || len(second.Pending) != 0 {
		t.Fatalf("after reporting, the baseline should move on: %+v", second)
	}
}

func TestStopsRecording(t *testing.T) {
	for s, want := range map[string]bool{
		"event_triggers=off":                       true,
		"search_path=public, event_triggers=false": true,
		"session_replication_role=replica":         true,
		"bb.v2=off":                                true,
		"event_triggers=on":                        false,
		"session_replication_role=origin":          false,
		"search_path=public":                       false,
	} {
		if got := StopsRecording(s); got != want {
			t.Errorf("StopsRecording(%q) = %v, want %v", s, got, want)
		}
	}
}

// The entry's statement is a comment, so replaying it does nothing, and it says
// when the change was found.
func TestScanFindingStatement(t *testing.T) {
	from := time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC)
	f := Finding{Status: StatusUnrecorded, Detail: "table public.secret was created"}
	s := f.Statement(from, from.Add(5*time.Minute))
	if !strings.HasPrefix(s, "-- ") || strings.Contains(s, "\n") {
		t.Errorf("statement is not a one-line comment: %q", s)
	}
	for _, want := range []string{"table public.secret was created", "2026-10-22T10:00:00Z", "2026-10-22T10:05:00Z", "unknown"} {
		if !strings.Contains(s, want) {
			t.Errorf("statement lacks %q: %s", want, s)
		}
	}
	o := Finding{Status: StatusObserved, Risk: "kill-switch", Detail: "event_triggers is now \"off\""}
	if s := o.Statement(time.Time{}, from); !strings.Contains(s, "since the scan before") || !strings.Contains(s, "do not run") {
		t.Errorf("observed kill-switch statement: %s", s)
	}
}

// The scan leaves out the triggers the Blackbox attaches to user tables; every
// one datachanges.sql and tracking.sql create has to be in its list, or the
// first scan after the Blackbox attaches one reports it as nobody's change.
func TestScanSkipsEveryBlackboxTrigger(t *testing.T) {
	names := regexp.MustCompile(`CREATE TRIGGER (bb_[a-z_]+) `).FindAllStringSubmatch(SchemaData+SchemaTracking, -1)
	if len(names) < 5 {
		t.Fatalf("found %d trigger names in datachanges.sql and tracking.sql", len(names))
	}
	skip := regexp.MustCompile(`g\.tgname !~ '\^bb_\(([a-z_|]+)\)\$'`).FindStringSubmatch(CatalogScanQuery)
	if skip == nil {
		t.Fatal("catalogscan.sql no longer skips the Blackbox's own triggers by name")
	}
	listed := map[string]bool{}
	for _, n := range strings.Split(skip[1], "|") {
		listed["bb_"+n] = true
	}
	for _, n := range names {
		if !listed[n[1]] {
			t.Errorf("the catalog scan would report %s as an unrecorded trigger: add it to catalogscan.sql's list", n[1])
		}
	}
}

// The scan reads no password, ever: not even into a hash it keeps.
func TestScanReadsNoPassword(t *testing.T) {
	for _, s := range []string{"rolpassword", "pg_authid", "pg_shadow", "pg_user_mapping", "umoptions"} {
		if strings.Contains(CatalogScanQuery, s) {
			t.Errorf("catalogscan.sql reads %s", s)
		}
	}
}

// The drops the scan treats as recorded are the ones log_ddl_drop records.
func TestDropsRecordedMatchesTheRecorder(t *testing.T) {
	m := regexp.MustCompile(`r\.object_type NOT IN \(([^)]*)\)`).FindStringSubmatch(Schema)
	if m == nil {
		t.Fatal("ledger.sql's log_ddl_drop no longer lists the object types it records")
	}
	recorded := map[string]bool{}
	for _, q := range strings.Split(m[1], ",") {
		recorded[strings.Trim(strings.TrimSpace(q), "'")] = true
	}
	// The scan's kinds, and what sql_drop reports each as.
	asReported := map[string]string{
		"table": "table", "view": "view", "materialized view": "materialized view", "index": "index",
		"function": "function", "procedure": "procedure", "aggregate": "aggregate", "type": "type",
		"domain": "type", "trigger": "trigger", "policy": "policy", "foreign table": "foreign table",
	}
	for kind, reported := range asReported {
		if DropsRecorded[kind] != recorded[reported] {
			t.Errorf("%s: the scan says its drop is recorded = %v, log_ddl_drop records %q = %v",
				kind, DropsRecorded[kind], reported, recorded[reported])
		}
	}
}

// Dropping a trigger or a policy is not recorded as it happens, so the scan
// records it as OBSERVED, not as a sign the record was stopped.
func TestScanRecordsDropsTheTriggersDoNot(t *testing.T) {
	prev := map[string]CatalogObject{
		"g:1": {Kind: "trigger", Identity: "audit on public.t", Schema: "public", Parents: []string{"public.t"}, Def: "x"},
		"c:2": table("public.gone", "v1"),
	}
	got := compare(prev, map[string]CatalogObject{})
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	for _, f := range got {
		want := map[string]string{"audit on public.t": StatusObserved, "public.gone": StatusUnrecorded}[f.Object]
		if f.Status != want {
			t.Errorf("%s: %s, want %s", f.Object, f.Status, want)
		}
	}
}
