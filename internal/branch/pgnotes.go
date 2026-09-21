// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"sort"
	"strconv"
)

// PGNote is one change between PostgreSQL majors that can break something that
// worked before: what `fox pg upgrade` prints before it moves anything. They are
// taken by hand from each release's "Migration" section, which is the only
// honest source — nothing here is derived.
//
// A note with a Probe is checked against each branch: the probe returns at
// least one row when that branch has something the change affects. A note with
// no probe is about how SQL and clients behave, which a database cannot see, so
// it is shown to everyone.
type PGNote struct {
	Major    string // the release that made the change
	ID       string // stable and greppable, e.g. "pg18-md5-deprecated"
	Headline string
	Detail   string
	DocURL   string
	Probe    string
}

const (
	pg17Notes = "https://www.postgresql.org/docs/17/release-17.html#RELEASE-17-MIGRATION"
	pg18Notes = "https://www.postgresql.org/docs/18/release-18.html#RELEASE-18-MIGRATION"
)

var pgNotes = []PGNote{
	// --- PostgreSQL 17 ---
	{Major: "17", ID: "pg17-maintenance-search-path", DocURL: pg17Notes,
		Headline: "Functions used by indexes and materialized views run with a safe search_path during maintenance",
		Detail: "ANALYZE, CLUSTER, CREATE INDEX, REFRESH MATERIALIZED VIEW, REINDEX and VACUUM now run functions " +
			"with search_path = pg_catalog, pg_temp. An expression index or materialized view whose function uses an " +
			"unqualified name from another schema fails to build during the upgrade's reload. Qualify the names, or " +
			"give the function SET search_path.",
		Probe: `SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indrelid JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE i.indexprs IS NOT NULL AND n.nspname NOT IN ('pg_catalog','information_schema','bb')
			UNION ALL SELECT 1 FROM pg_matviews WHERE schemaname <> 'bb' LIMIT 1`},
	{Major: "17", ID: "pg17-adminpack-removed", DocURL: pg17Notes,
		Headline: "The adminpack extension no longer exists",
		Detail:   "The reload fails on CREATE EXTENSION adminpack. Drop the extension before upgrading.",
		Probe:    `SELECT 1 FROM pg_extension WHERE extname = 'adminpack'`},
	{Major: "17", ID: "pg17-settings-removed", DocURL: pg17Notes,
		Headline: "The settings old_snapshot_threshold, db_user_namespace and trace_recovery_messages are gone",
		Detail:   "A configuration that sets one of them is rejected. Remove it before upgrading.",
		Probe: `SELECT 1 FROM pg_settings WHERE (name = 'old_snapshot_threshold' AND setting <> '-1')
			OR (name = 'db_user_namespace' AND setting = 'on')`},
	{Major: "17", ID: "pg17-interval-ago", DocURL: pg17Notes,
		Headline: "'ago' is only accepted at the end of an interval",
		Detail:   "Interval input such as '1 day ago 2 hours' is now an error. Check application code that builds interval strings."},
	{Major: "17", ID: "pg17-monitoring-columns", DocURL: pg17Notes,
		Headline: "Monitoring views renamed or dropped columns",
		Detail: "pg_stat_bgwriter lost buffers_backend and buffers_backend_fsync; pg_stat_statements renamed " +
			"blk_read_time/blk_write_time to shared_blk_read_time/shared_blk_write_time; pg_stat_progress_vacuum " +
			"and pg_stat_slru renamed columns; pg_collation.colliculocale and pg_database.daticulocale are now " +
			"colllocale and datlocale. Dashboards and scripts that read them need updating."},

	// --- PostgreSQL 18 ---
	{Major: "18", ID: "pg18-data-checksums", DocURL: pg18Notes,
		Headline: "The new cluster has page checksums on",
		Detail: "initdb now enables data checksums by default, so every block is verified as it is read. It costs a " +
			"little CPU and catches silent corruption; nothing to do."},
	{Major: "18", ID: "pg18-md5-deprecated", DocURL: pg18Notes,
		Headline: "MD5 passwords are deprecated",
		Detail: "Setting an MD5 password now warns, and support will be removed in a future major. FoxByte's own " +
			"roles use SCRAM; a role you created with an MD5 password should be moved to SCRAM.",
		Probe: `SELECT 1 FROM pg_authid WHERE rolpassword LIKE 'md5%'`},
	{Major: "18", ID: "pg18-after-trigger-role", DocURL: pg18Notes,
		Headline: "AFTER triggers run as the role that queued the event",
		Detail: "Not the role active when the trigger fires. It matters only for code that changes role between " +
			"the statement and the end of the transaction.",
		Probe: `SELECT 1 FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE NOT t.tgisinternal AND n.nspname <> 'bb' AND (t.tgtype & 66) = 0 LIMIT 1`},
	{Major: "18", ID: "pg18-vacuum-inheritance", DocURL: pg18Notes,
		Headline: "VACUUM and ANALYZE now include inheritance children",
		Detail:   "Use VACUUM ONLY / ANALYZE ONLY for the old behaviour on a parent table.",
		Probe:    `SELECT 1 FROM pg_inherits LIMIT 1`},
	{Major: "18", ID: "pg18-unlogged-partitioned", DocURL: pg18Notes,
		Headline: "A partitioned table can no longer be unlogged",
		Detail:   "The reload fails on an unlogged partitioned table. Make it logged before upgrading.",
		Probe:    `SELECT 1 FROM pg_class WHERE relkind = 'p' AND relpersistence = 'u'`},
	{Major: "18", ID: "pg18-fts-collation", DocURL: pg18Notes,
		Headline: "Full-text search follows the cluster's collation provider",
		Detail: "On a cluster using ICU or the builtin provider, full-text and pg_trgm indexes can order differently; " +
			"they are rebuilt by the reload, so nothing to do for the data, but results may change.",
		Probe: `SELECT 1 FROM pg_database WHERE datname = current_database() AND datlocprovider <> 'c'`},
	{Major: "18", ID: "pg18-csv-end-marker", DocURL: pg18Notes,
		Headline: `COPY FROM ... CSV no longer treats \. as end of data`,
		Detail:   `Only psql reading COPY data from its own input still does. Check scripts that feed CSV through COPY.`},
	{Major: "18", ID: "pg18-sql-removed", DocURL: pg18Notes,
		Headline: "GRANT/REVOKE on RULE is no longer accepted, and time zone abbreviations resolve differently",
		Detail: "RULE privileges had done nothing since 8.2 and are now a syntax error. The session's time zone is " +
			"consulted before timezone_abbreviations when reading an abbreviation."},
}

// majorNum orders majors numerically ("9.6" < "10" < "18"); unparseable is 0.
func majorNum(m string) float64 {
	f, _ := strconv.ParseFloat(m, 64)
	return f
}

// NotesBetween returns the notes a move from one major to another crosses:
// every release after from, up to and including to, oldest first.
func NotesBetween(from, to string) []PGNote {
	var out []PGNote
	for _, n := range pgNotes {
		if majorNum(n.Major) > majorNum(from) && majorNum(n.Major) <= majorNum(to) {
			out = append(out, n)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return majorNum(out[i].Major) < majorNum(out[j].Major) })
	return out
}
