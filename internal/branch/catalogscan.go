// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

// The engine's half of the Blackbox's catalog scan (internal/ledger/
// catalogscan.go says what it is for): read a branch's catalogue and the
// ledger in one snapshot, compare with what this engine read last time, write
// what the ledger lacks into the ledger, and remember what it saw.
//
// What it saw is kept here, in the engine's state directory, not in the
// database. A superuser who stopped the event triggers could otherwise also
// rewrite the scan's memory to match, and the change would never show.
//
// Free in every edition, like the record it completes.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
	"github.com/thefoxbyte/foxbyte/internal/version"
)

const catalogScanFormat = 1

// catalogScanState is what one scan leaves for the next.
type catalogScanState struct {
	Format int `json:"format"`
	// The fox and the PostgreSQL major that took it. A new fox re-creates the
	// Blackbox's own event triggers as it sees fit, and a new major stores
	// expressions differently, so either starts the comparison afresh for what
	// it changes.
	Fox     string `json:"fox"`
	PGMajor int    `json:"pg_major"`
	// The newest ledger entry in the scan's snapshot. The next scan explains
	// changes from the entries after it, and checks it is still there with the
	// same hash: if it is not, this is not the history the scan last read.
	LedgerID   int64                           `json:"ledger_id"`
	LedgerHash string                          `json:"ledger_hash"`
	At         time.Time                       `json:"at"`
	Objects    map[string]ledger.CatalogObject `json:"objects"`
	Pending    map[string]int                  `json:"pending,omitempty"`
}

// catalogScanPath is where a branch's scan state is kept.
func catalogScanPath(name string) string {
	return brand.StatePath("blackbox-scan", name+".json")
}

// forgetCatalogScan drops a branch's scan state. A branch deleted and made
// again under the same name is a fresh clone of its parent, not the database
// the scan last read; comparing the two would report the difference between
// them as changes nobody recorded.
func forgetCatalogScan(name string) {
	if err := os.Remove(catalogScanPath(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("blackbox scan: forgetting %s: %v", name, err)
	}
}

func loadCatalogScan(name string) (*catalogScanState, error) {
	b, err := os.ReadFile(catalogScanPath(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s catalogScanState
	if err := json.Unmarshal(b, &s); err != nil || s.Format != catalogScanFormat {
		// Unreadable or from another format: start again rather than fail every
		// scan from now on.
		return nil, nil
	}
	return &s, nil
}

func saveCatalogScan(name string, s catalogScanState) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(catalogScanPath(name)), 0o700); err != nil {
		return err
	}
	return writeSecretFile(catalogScanPath(name), b)
}

// CatalogScanResult is what one scan did.
type CatalogScanResult struct {
	Branch string
	// Baseline is set when nothing was compared: the first scan of a branch,
	// or a fresh start (Reason says why). Changes made before it cannot be
	// found.
	Baseline bool
	Reason   string
	Objects  int
	Findings []ledger.Finding
}

// catalogSnapshot is one consistent reading of a branch.
type catalogSnapshot struct {
	pgMajor     int
	ledgerID    int64
	ledgerHash  string
	continuous  bool // the entry the last scan ended at is still there, unchanged
	objects     map[string]ledger.CatalogObject
	window      []ledger.WindowEntry
	hasLedger   bool
	scannedAtDB time.Time
}

// ScanCatalog runs the catalog scan on a running branch now, and writes what it
// finds into the branch's ledger.
func ScanCatalog(name string) (CatalogScanResult, error) {
	name, err := ledgerBranchName(name)
	if err != nil {
		return CatalogScanResult{}, err
	}
	res := CatalogScanResult{Branch: name}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	conn, err := OpenSuper(ctx, name)
	if err != nil {
		return res, err
	}
	defer conn.Close(context.Background())
	// One scan of a branch at a time, across processes: the scheduler's and
	// `fox blackbox scan`'s would otherwise both record the same finding. A
	// session lock, released when the connection closes.
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock(hashtext('bb.catalog_scan'))"); err != nil {
		return res, err
	}

	prev, err := loadCatalogScan(name)
	if err != nil {
		return res, err
	}
	var fromID int64
	var fromHash string
	if prev != nil {
		fromID, fromHash = prev.LedgerID, prev.LedgerHash
	}
	snap, err := readCatalog(ctx, conn, fromID, fromHash)
	if err != nil {
		return res, err
	}
	if !snap.hasLedger {
		return res, fmt.Errorf("branch %q has no Blackbox to write to", name)
	}
	res.Objects = len(snap.objects)
	now := snap.scannedAtDB

	next := catalogScanState{
		Format: catalogScanFormat, Fox: version.Version, PGMajor: snap.pgMajor,
		LedgerID: snap.ledgerID, LedgerHash: snap.ledgerHash, At: now, Objects: snap.objects,
	}
	var note *ledger.Finding
	switch {
	case prev == nil:
		res.Baseline, res.Reason = true, "first scan of this branch"
	case prev.PGMajor != snap.pgMajor:
		res.Baseline, res.Reason = true, fmt.Sprintf("PostgreSQL %d is now %d", prev.PGMajor, snap.pgMajor)
		note = &ledger.Finding{Status: ledger.StatusObserved, CommandTag: "SCAN", ObjectType: "catalog", Risk: "rescan",
			Detail: fmt.Sprintf("PostgreSQL %d was upgraded to %d, which stores definitions differently, so the scan "+
				"started again from what is there now; changes made between the last scan and the upgrade were not compared",
				prev.PGMajor, snap.pgMajor)}
	case !snap.continuous:
		res.Baseline, res.Reason = true, fmt.Sprintf("Blackbox entry %d is not the one the last scan read", prev.LedgerID)
		note = &ledger.Finding{Status: ledger.StatusObserved, CommandTag: "SCAN", ObjectType: "catalog", Risk: "rescan",
			Detail: fmt.Sprintf("Blackbox entry %d, where the last scan ended, is missing or different: this database "+
				"was restored or replaced, or its history rewritten (fox blackbox integrity checks which). The scan "+
				"started again from what is there now", prev.LedgerID)}
	default:
		before := prev.Objects
		if prev.Fox != version.Version {
			// A new fox may add, drop or change the Blackbox's own event
			// triggers; that is the upgrade, not a change to report.
			before = make(map[string]ledger.CatalogObject, len(prev.Objects))
			for k, o := range prev.Objects {
				if !strings.HasPrefix(k, "e:bb_") {
					before[k] = o
				}
			}
			for k, o := range snap.objects {
				if strings.HasPrefix(k, "e:bb_") {
					before[k] = o
				}
			}
		}
		cmp := ledger.CompareCatalog(before, snap.objects, snap.window, prev.Pending)
		res.Findings = cmp.Findings
		next.Objects, next.Pending = cmp.Baseline, cmp.Pending
	}

	write := res.Findings
	if note != nil {
		write = append([]ledger.Finding{*note}, write...)
	}
	if len(write) > 0 {
		var from time.Time
		if prev != nil {
			from = prev.At
		}
		if err := recordFindings(ctx, conn, name, write, from, now); err != nil {
			// The state is not saved, so the next scan finds the same again.
			return res, fmt.Errorf("recording what the scan found: %w", err)
		}
	}
	if err := saveCatalogScan(name, next); err != nil {
		return res, fmt.Errorf("saving the scan: %w", err)
	}
	return res, nil
}

// readCatalog reads the catalogue, the newest ledger entry and the entries
// since fromID in one REPEATABLE READ snapshot, so a change and the entry that
// records it are either both seen or both not.
func readCatalog(ctx context.Context, conn *pgx.Conn, fromID int64, fromHash string) (catalogSnapshot, error) {
	snap := catalogSnapshot{objects: map[string]ledger.CatalogObject{}}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return snap, err
	}
	defer tx.Rollback(context.Background())
	// Names in the output (regproc, regclass) come out schema-qualified and the
	// same every time.
	if _, err := tx.Exec(ctx, "SET LOCAL search_path = pg_catalog"); err != nil {
		return snap, err
	}
	if err := tx.QueryRow(ctx, "SELECT current_setting('server_version_num')::int / 10000, "+
		"to_regclass('bb.schema_ledger') IS NOT NULL, clock_timestamp()").Scan(&snap.pgMajor, &snap.hasLedger, &snap.scannedAtDB); err != nil {
		return snap, err
	}
	if !snap.hasLedger {
		return snap, nil
	}
	var hash *string
	err = tx.QueryRow(ctx, "SELECT id, row_hash FROM bb.schema_ledger ORDER BY id DESC LIMIT 1").Scan(&snap.ledgerID, &hash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return snap, err
	}
	if hash != nil {
		snap.ledgerHash = *hash
	}
	snap.continuous = true
	if fromID > 0 {
		var h *string
		err := tx.QueryRow(ctx, "SELECT row_hash FROM bb.schema_ledger WHERE id = $1", fromID).Scan(&h)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			snap.continuous = false
		case err != nil:
			return snap, err
		default:
			snap.continuous = h != nil && *h == fromHash
		}
	}

	rows, err := tx.Query(ctx, ledger.CatalogScanQuery)
	if err != nil {
		return snap, fmt.Errorf("reading the catalogue: %w", err)
	}
	for rows.Next() {
		var key string
		var kind, ident, schema, def, acl *string
		var parents []string
		var global bool
		if err := rows.Scan(&key, &kind, &ident, &schema, &parents, &def, &acl, &global); err != nil {
			rows.Close()
			return snap, err
		}
		snap.objects[key] = ledger.CatalogObject{
			Kind: deref(kind), Identity: deref(ident), Schema: deref(schema), Parents: nonEmpty(parents),
			Def: deref(def), ACL: deref(acl), Global: global,
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return snap, fmt.Errorf("reading the catalogue: %w", err)
	}

	rows, err = tx.Query(ctx, `SELECT coalesce(command_tag, ''), coalesce(object_identity, ''), status,
	         coalesce(command_tag LIKE 'DROP%' AND statement ~* '\mcascade\M', false)
	    FROM bb.schema_ledger WHERE id > $1 AND id <= $2`, fromID, snap.ledgerID)
	if err != nil {
		return snap, err
	}
	for rows.Next() {
		var e ledger.WindowEntry
		if err := rows.Scan(&e.Tag, &e.Object, &e.Status, &e.Cascade); err != nil {
			rows.Close()
			return snap, err
		}
		snap.window = append(snap.window, e)
	}
	rows.Close()
	return snap, rows.Err()
}

// recordFindings appends the scan's findings to the ledger, in one
// transaction. The ledger's own trigger chains them like any other entry.
func recordFindings(ctx context.Context, conn *pgx.Conn, name string, fs []ledger.Finding, from, to time.Time) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	for _, f := range fs {
		if _, err := tx.Exec(ctx, `INSERT INTO bb.schema_ledger
		    (actor, actor_kind, tool, session, branch, command_tag, object_type, object_identity, statement, status, risk)
		    VALUES (NULL, NULL, $1, NULL, $2, $3, $4, nullif($5, ''), $6, $7, $8)`,
			ledger.ScanTool, name, f.CommandTag, f.ObjectType, f.Object, f.Statement(from, to), f.Status, f.Risk); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func nonEmpty(s []string) []string {
	var out []string
	for _, v := range s {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// StartCatalogScanner scans every running branch in the background, every
// FOX_BLACKBOX_SCAN_INTERVAL (default 5m), the first time a minute after
// start. Like the checkpointer it only looks at branches already running, so it
// never wakes a suspended one: a suspended branch cannot change, and the scan
// after it next starts compares with what this one saw. FOX_BLACKBOX_SCAN=off
// disables it; `fox blackbox scan` still works.
func StartCatalogScanner() {
	switch strings.ToLower(strings.TrimSpace(brand.Getenv("BLACKBOX_SCAN"))) {
	case "off", "0", "false", "no":
		log.Printf("blackbox scan: scheduler disabled (FOX_BLACKBOX_SCAN)")
		return
	}
	interval := envDurationOr("FOX_BLACKBOX_SCAN_INTERVAL", 5*time.Minute)
	first := interval
	if first > time.Minute {
		first = time.Minute
	}
	log.Printf("blackbox scan: every %s", interval)
	go func() {
		time.Sleep(first)
		said := map[string]string{}
		for {
			scanRunningBranches(said)
			time.Sleep(interval)
		}
	}()
}

// scanRunningBranches scans each running branch once. said holds the last
// error logged for each branch: a branch caught starting or stopping fails the
// same way scan after scan, and saying so every few minutes buries the log.
func scanRunningBranches(said map[string]string) {
	names, err := RunningBranches()
	if err != nil {
		return
	}
	for _, n := range names {
		res, err := ScanCatalog(n)
		if err != nil {
			if said[n] != err.Error() {
				said[n] = err.Error()
				log.Printf("blackbox scan %s: %v", n, err)
			}
			continue
		}
		delete(said, n)
		if len(res.Findings) > 0 {
			log.Printf("blackbox scan %s: recorded %d change(s) the event triggers did not", n, len(res.Findings))
		}
		// Each one too, so an operator reading the log sees what without
		// opening the Blackbox.
		for _, f := range res.Findings {
			log.Printf("blackbox scan %s: %s %s %s (%s)", n, f.Status, f.CommandTag, f.Object, f.Risk)
		}
	}
}

// FormatCatalogScan is the CLI's report of one scan.
func FormatCatalogScan(r CatalogScanResult) string {
	var b strings.Builder
	switch {
	case r.Baseline:
		fmt.Fprintf(&b, "%s: %d objects read, nothing compared (%s).\n", r.Branch, r.Objects, r.Reason)
		b.WriteString("The next scan reports any change no Blackbox entry accounts for.")
	case len(r.Findings) == 0:
		fmt.Fprintf(&b, "%s: %d objects read. Every change since the last scan is in the Blackbox.", r.Branch, r.Objects)
	default:
		fmt.Fprintf(&b, "%s: %d objects read. Recorded %s the event triggers did not:\n", r.Branch, r.Objects,
			plural(len(r.Findings), "change"))
		for _, f := range r.Findings {
			fmt.Fprintf(&b, "  %-10s %-24s %s\n", f.Status, f.CommandTag, f.Detail)
		}
		b.WriteString("They are in the Blackbox now, with who made them unknown.")
	}
	return b.String()
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.Itoa(n) + " " + word + "s"
}
