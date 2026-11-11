//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package masking

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// A masked branch (step 5; design, section 12), made on a copy closed to
// everyone but the engine (internal/branch/maskedbranch.go): its marked
// columns overwritten with their masks, the masks' machinery removed, the
// Blackbox started afresh, the files rewritten so no real value is left in
// them, the WAL from before removed, and the result verified. Each step is a
// statement of its own, as VACUUM must be (design, section 17, item 3).

// maskBranch is the Masker's MaskBranch.
func maskBranch(name string, rec branch.MaskedBranch, say func(string)) (branch.MaskedBranchWork, error) {
	var w branch.MaskedBranchWork
	tables := tablesOf(rec.Rules)
	w.Tables = len(tables)

	// 1. Masked in place, from the views the copy came with: what a masked
	// reader reads is what the branch now holds. As the engine, with the
	// tables' triggers quiet (session_replication_role), so the shadows keep
	// the masks the update reads and nothing records it as a change.
	say(fmt.Sprintf("masking %d table(s) in place", len(tables)))
	var checks []string
	for _, t := range tables {
		up, check, err := inPlaceSQL(name, t[0], t[1], rulesFor(rec.Rules, t[0], t[1]))
		if err != nil {
			return w, err
		}
		out, err := branch.MaskedBranchSQL(name, up)
		if err != nil {
			return w, fmt.Errorf("masking %s.%s in place: %w", t[0], t[1], err)
		}
		n, _ := strconv.ParseInt(lastLine(out), 10, 64)
		w.Rows += n
		checks = append(checks, check)
	}
	// Every row now holds exactly its masks.
	say("checking every row holds its masks")
	for i, t := range tables {
		out, err := branch.MaskedBranchSQL(name, checks[i])
		if err != nil {
			return w, fmt.Errorf("checking %s.%s: %w", t[0], t[1], err)
		}
		if n := lastLine(out); n != "0" {
			w.Problems = append(w.Problems, fmt.Sprintf("%s.%s: %s row(s) do not hold their masks", t[0], t[1], n))
		}
	}
	if len(w.Problems) > 0 {
		return w, nil
	}

	// 2. The machinery the masks were read through, which the data no longer
	// needs, then the Blackbox: its statements were the source's, and could
	// hold real values. It starts afresh, numbering on from the source's last
	// entry, so a change request from the branch carries only what is done
	// here (the record keeps that entry). Last, so the drops are not in it.
	say("removing the masks' machinery")
	if _, err := branch.MaskedBranchSQL(name, dropMachinerySQL); err != nil {
		return w, fmt.Errorf("removing the masks' machinery: %w", err)
	}
	say("starting the Blackbox afresh")
	if _, err := branch.MaskedBranchSQL(name, freshBlackboxSQL); err != nil {
		return w, fmt.Errorf("starting the Blackbox afresh: %w", err)
	}

	// 3. The files: a masked table's old row versions, and the statistics
	// ANALYZE replaced, stay in their files until rewritten.
	say("rewriting the masked tables' and the statistics' files")
	if _, err := branch.MaskedBranchSQL(name, rewriteSQL(tables)); err != nil {
		return w, fmt.Errorf("rewriting the files: %w", err)
	}

	// 4. The WAL from before: the source's segments the copy came with, and
	// the full-page images of the pages as they were before masking. The
	// source's replication slots would keep them; with recycling off, each
	// checkpoint after a switch deletes what it no longer needs.
	say("removing the WAL from before the masking")
	last, err := branch.MaskedBranchSQL(name, beforeWALSQL)
	if err != nil {
		return w, fmt.Errorf("reading the WAL position: %w", err)
	}
	before := lastLine(last)
	if _, err := branch.MaskedBranchSQL(name, dropWALSQL); err != nil {
		return w, fmt.Errorf("removing the WAL from before: %w", err)
	}

	// 5. Verified.
	say("verifying")
	p, err := verify(name, rec, before)
	if err != nil {
		return w, err
	}
	w.Problems = append(w.Problems, p...)
	return w, nil
}

// inPlaceSQL is one table's update, and the count of rows that do not hold
// their masks afterwards (0 when masked). Compared as text: json has no
// equality.
func inPlaceSQL(name, schema, table string, rules []branch.MaskRule) (string, string, error) {
	cols, err := branch.MaskColumns(name, schema, table)
	if err != nil {
		return "", "", err
	}
	key := ""
	for _, c := range cols {
		if c.Key {
			if key != "" {
				return "", "", fmt.Errorf("%s.%s has a primary key of more than one column", schema, table)
			}
			key = c.Name
		}
	}
	if key == "" {
		return "", "", fmt.Errorf("%s.%s has no primary key", schema, table)
	}
	seen := map[string]bool{}
	var masked []string
	for _, r := range rules {
		if !seen[r.Column] {
			seen[r.Column] = true
			masked = append(masked, r.Column)
		}
	}
	sort.Strings(masked)
	nm := namesFor(schema, table)
	var set, differ []string
	for _, c := range masked {
		set = append(set, fmt.Sprintf("%s = v.%s", ident(c), ident(c)))
		differ = append(differ, fmt.Sprintf("b.%s::text IS DISTINCT FROM v.%s::text", ident(c), ident(c)))
	}
	k := ident(key)
	up := fmt.Sprintf(`SET session_replication_role = replica;
WITH u AS (UPDATE %s b SET %s FROM %s v WHERE b.%s = v.%s AND (%s) RETURNING 1) SELECT count(*) FROM u;`,
		nm.base, strings.Join(set, ", "), nm.view, k, k, strings.Join(differ, " OR "))
	check := fmt.Sprintf(`SELECT count(*) FROM %s b LEFT JOIN %s v ON v.%s = b.%s WHERE v.%s IS NULL OR %s;`,
		nm.base, nm.view, k, k, k, strings.Join(differ, " OR "))
	return up, check, nil
}

// dropMachinerySQL removes the masks' views, shadows, triggers, lookup, guard
// and rules: on a masked branch nobody is masked, the data is.
const dropMachinerySQL = `SET bb.allow_destructive = on;
DROP EVENT TRIGGER IF EXISTS bb_mask_close;
DROP SCHEMA IF EXISTS ` + branch.MaskSchema + ` CASCADE;
DROP FUNCTION IF EXISTS bb.mask_close_paths_et();
DROP FUNCTION IF EXISTS bb.mask_close_paths(boolean);
DROP TABLE IF EXISTS bb.mask_closed, bb.mask_rules, bb.mask_tables;
`

// freshBlackboxSQL empties the Blackbox's tables in one statement, as the
// engine, past their append-only triggers. Its sequence is kept, so the
// branch's first entry follows the source's last.
//
// The Aadhaar exposure report's places too (point 4.5): each names a row of
// the source by its key and a number's last four digits, which are the
// source's, not the masks'.
const freshBlackboxSQL = `SET session_replication_role = replica;
DO $bbfresh$
DECLARE t text; ts text[] := '{}';
BEGIN
  FOREACH t IN ARRAY ARRAY['bb.ledger_ext', 'bb.ledger_checkpoints', 'bb.agent_sessions', 'bb.schema_ledger',
                           'bb.aadhaar_places', 'bb.aadhaar_columns', 'bb.aadhaar_runs'] LOOP
    IF to_regclass(t) IS NOT NULL THEN ts := ts || t; END IF;
  END LOOP;
  IF array_length(ts, 1) > 0 THEN
    EXECUTE 'TRUNCATE ' || array_to_string(ts, ', ');
  END IF;
END $bbfresh$;
`

// rewriteSQL rewrites each masked table, with its indexes and TOAST, then the
// statistics, old and new.
func rewriteSQL(tables [][2]string) string {
	var b strings.Builder
	for _, t := range tables {
		fmt.Fprintf(&b, "VACUUM FULL %s;\n", namesFor(t[0], t[1]).base)
	}
	b.WriteString("ANALYZE;\nVACUUM FULL pg_statistic;\nVACUUM FULL pg_statistic_ext_data;\nCHECKPOINT;\n")
	return b.String()
}

// beforeWALSQL drops the source's replication slots, which would keep the WAL
// from before, and names the segment being written: it and every one before
// it go.
const beforeWALSQL = `SELECT count(pg_drop_replication_slot(slot_name)) FROM pg_replication_slots WHERE NOT active;
SELECT pg_walfile_name(pg_current_wal_lsn());
`

// dropWALSQL: recycling off, three switches and checkpoints, then back.
const dropWALSQL = `ALTER SYSTEM SET wal_recycle = off;
ALTER SYSTEM SET wal_keep_size = 0;
SELECT pg_reload_conf();
SELECT pg_sleep(0.5);
SELECT pg_switch_wal();
CHECKPOINT;
SELECT pg_switch_wal();
CHECKPOINT;
SELECT pg_switch_wal();
CHECKPOINT;
ALTER SYSTEM RESET wal_recycle;
ALTER SYSTEM RESET wal_keep_size;
SELECT pg_reload_conf();
`

// verifySample is how many rows of each table the verifying scan reads.
const verifySample = 10000

// verify checks what the steps promised, and returns what does not hold.
func verify(name string, rec branch.MaskedBranch, before string) ([]string, error) {
	var problems []string
	out, err := branch.MaskedBranchSQL(name, fmt.Sprintf(`SELECT
  (SELECT count(*) FROM pg_ls_waldir() WHERE name ~ '^[0-9A-F]{24}$' AND name <= %s)
  || '|' || (CASE WHEN to_regclass('bb.schema_ledger') IS NULL THEN 0 ELSE (SELECT count(*) FROM bb.schema_ledger WHERE id <= %d) END)
  || '|' || (to_regnamespace('%s') IS NULL)
  || '|' || (SELECT count(*) FROM pg_replication_slots);`, lit(before), rec.Fork, branch.MaskSchema))
	if err != nil {
		return nil, fmt.Errorf("verifying: %w", err)
	}
	f := strings.Split(lastLine(out), "|")
	if len(f) != 4 {
		return nil, fmt.Errorf("verifying: unexpected %q", lastLine(out))
	}
	if f[0] != "0" {
		problems = append(problems, fmt.Sprintf("pg_wal still holds %s segment(s) from before the masking", f[0]))
	}
	if f[1] != "0" {
		problems = append(problems, fmt.Sprintf("the Blackbox still holds %s of %s's entries", f[1], rec.From))
	}
	if f[2] != "true" {
		problems = append(problems, "the masks' machinery is still there")
	}
	if f[3] != "0" {
		problems = append(problems, fmt.Sprintf("%s replication slot(s) are left, keeping old WAL", f[3]))
	}

	// The scan, as point 4 reads any branch: a masked category found where
	// no rule masked it means real values left. A ruled column holds its
	// masks (checked row by row above; a fake looks like what it fakes), and
	// a finding rejected on the source is not personal data.
	rep, err := branch.ScanPersonalData(name, branch.PIIScanOptions{Sample: verifySample, Actor: "masked branch " + name})
	if err != nil {
		return nil, fmt.Errorf("the verifying scan: %w", err)
	}
	if rep.Scan == nil {
		return nil, fmt.Errorf("the verifying scan recorded no scan")
	}
	cats := map[string]bool{}
	ruled := map[string]bool{}
	for _, r := range rec.Rules {
		cats[r.Category] = true
		ruled[r.Schema+"\x00"+r.Table+"\x00"+r.Column+"\x00"+r.Path] = true
	}
	for _, fd := range rep.Findings {
		// A masked category anywhere, and anything a reviewer confirmed as
		// personal data: either is real values left where no rule masked them.
		if fd.LastScan != rep.Scan.ID || fd.State == branch.PIIRejected || !(cats[fd.Category] || fd.State == branch.PIIConfirmed) {
			continue
		}
		// A rule on the column masks every path in it; one on a path, that path.
		if ruled[fd.Schema+"\x00"+fd.Table+"\x00"+fd.Column+"\x00"+fd.Path] || ruled[fd.Schema+"\x00"+fd.Table+"\x00"+fd.Column+"\x00"] {
			continue
		}
		at := fd.Schema + "." + fd.Table + "." + fd.Column + fd.Path
		why := fmt.Sprintf("%d of %d sampled", fd.Matched, fd.Sampled)
		if fd.State == branch.PIIConfirmed {
			why = "a reviewer confirmed it as personal data"
		}
		problems = append(problems, fmt.Sprintf("%s holds %s with no rule masking it (%s): set a rule on %s, or reject the finding there as not personal data",
			at, fd.Category, why, rec.From))
	}
	return problems, nil
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}
