//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package pii

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// The Aadhaar exposure report's logs part (point 4.5b): the branch's query
// history entries, the audit log's forensic statement text for it and its
// Blackbox's statements, read in the same run as its tables. The numbers stay
// in memory, as the tables' do; each place is kept in the install's store as
// its source, its entry and the number's last four digits.

// maxLogListed bounds the log places one run keeps.
const maxLogListed = 100000

type logPlaceKey struct {
	source string
	entry  int64
	field  string
	last4  string
}

// logExposure is what a run has found in the logs so far.
type logExposure struct {
	places  []auth.AadhaarLogPlace
	kept    map[logPlaceKey]bool
	persons map[int32]bool
	numbers int64
	capped  bool
}

// add records the numbers found in one entry of one source, grouping them
// with the tables' by e's numbers.
func (l *logExposure) add(e *exposure, source string, entry int64, field, actor string, at time.Time, numbers []string) {
	for _, n := range numbers {
		l.numbers++
		v, _ := strconv.ParseUint(n, 10, 64)
		p, ok := e.people[v]
		if !ok {
			if len(e.people) < maxGrouped {
				p = int32(len(e.people) + 1)
				e.people[v] = p
			} else {
				e.grouped = false
			}
		}
		if p > 0 {
			l.persons[p] = true
		}
		k := logPlaceKey{source, entry, field, n[8:]}
		if l.kept[k] {
			continue
		}
		if len(l.places) >= maxLogListed {
			l.capped = true
			continue
		}
		l.kept[k] = true
		l.places = append(l.places, auth.AadhaarLogPlace{
			Source: source, Entry: entry, Field: field, Last4: n[8:], Actor: actor, At: at.UTC(), Person: int(p),
		})
	}
}

// readExposureLogs reads a branch's logs. A source that cannot be read is
// listed as skipped, and the others are still read. tablePeople is how many
// people the tables' read numbered: a person numbered past it is in the logs
// only.
func readExposureLogs(ctx context.Context, conn *pgx.Conn, name string, o branch.AadhaarRunOptions, e *exposure, tablePeople int32) (auth.AadhaarLogRun, []auth.AadhaarLogPlace) {
	lr := auth.AadhaarLogRun{Branch: name, Started: time.Now().UTC(), Actor: o.Actor, Read: map[string]int{}, Skipped: []auth.AadhaarLogSkip{}}
	l := &logExposure{kept: map[logPlaceKey]bool{}, persons: map[int32]bool{}}
	skip := func(source string, err error) {
		lr.Skipped = append(lr.Skipped, auth.AadhaarLogSkip{Source: source, Reason: exposureFailure(err, o.TableTimeout)})
	}

	// Query history: the statement, and its error, which can quote a value
	// (a duplicate key's, for one).
	n, err := o.Store.EachHistoryEntry(name, func(h auth.HistoryEntry) error {
		at := time.UnixMilli(h.At)
		if shapeRE.MatchString(h.SQL) {
			l.add(e, auth.AadhaarLogHistory, h.ID, "sql", h.Actor, at, findAadhaar(h.SQL))
		}
		if shapeRE.MatchString(h.Error) {
			l.add(e, auth.AadhaarLogHistory, h.ID, "error", h.Actor, at, findAadhaar(h.Error))
		}
		return ctx.Err()
	})
	if err != nil {
		skip(auth.AadhaarLogHistory, err)
	} else {
		lr.Read[auth.AadhaarLogHistory] = n
	}

	// The audit log's statement text, kept only in forensic mode.
	n, err = branch.ScanForensicTexts(name, shapeRE.MatchString, func(t branch.ForensicText) {
		l.add(e, auth.AadhaarLogAudit, t.Seq, "", t.Login, t.At, findAadhaar(t.Text))
	})
	if err != nil {
		skip(auth.AadhaarLogAudit, err)
	} else {
		lr.Read[auth.AadhaarLogAudit] = n
	}

	// The Blackbox's statements.
	if n, err := readBlackboxExposure(ctx, conn, o.TableTimeout, e, l); err != nil {
		skip(auth.AadhaarLogBlackbox, err)
	} else {
		lr.Read[auth.AadhaarLogBlackbox] = n
	}

	lr.Numbers = l.numbers
	lr.People = len(l.persons)
	for p := range l.persons {
		if p <= tablePeople {
			lr.Linked++
		}
	}
	lr.Listed = len(l.places)
	lr.Limits = logExposureLimits(o.Store, l, e.grouped)
	lr.Finished = time.Now().UTC()
	return lr, l.places
}

// readBlackboxExposure reads the branch's Blackbox statements that may hold a
// number, as a table is read: read-only, with the table's time limit, its
// places added once the read has finished. It returns how many entries the
// Blackbox has.
func readBlackboxExposure(ctx context.Context, conn *pgx.Conn, timeout time.Duration, e *exposure, l *logExposure) (int, error) {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL statement_timeout = %d", timeout.Milliseconds())); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout = '10s'"); err != nil {
		return 0, err
	}
	var have bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('bb.schema_ledger') IS NOT NULL`).Scan(&have); err != nil || !have {
		return 0, err
	}
	var total int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM bb.schema_ledger`).Scan(&total); err != nil {
		return 0, err
	}
	rows, err := tx.Query(ctx, `SELECT id, at, coalesce(actor, ''), statement FROM bb.schema_ledger
		WHERE statement ~ `+branch.QuoteLiteral(shapePG)+` ORDER BY id`)
	if err != nil {
		return 0, err
	}
	type hit struct {
		id      int64
		at      time.Time
		actor   string
		numbers []string
	}
	var hits []hit
	for rows.Next() {
		var h hit
		var stmt string
		if err := rows.Scan(&h.id, &h.at, &h.actor, &stmt); err != nil {
			rows.Close()
			return 0, err
		}
		if h.numbers = findAadhaar(stmt); len(h.numbers) > 0 {
			hits = append(hits, h)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	for _, h := range hits {
		l.add(e, auth.AadhaarLogBlackbox, h.id, "", h.actor, h.at, h.numbers)
	}
	return total, nil
}

// logExposureLimits are what the logs part cannot claim.
func logExposureLimits(st *auth.Store, l *logExposure, grouped bool) []string {
	history := "Query history holds what the console, the API and the CLI ran"
	if set, err := st.HistorySettings(); err == nil {
		if set.Enabled {
			history += fmt.Sprintf(", for %d days, for those who have not turned theirs off", set.RetentionDays)
		} else {
			history += "; it is turned off for this install, so nothing new is recorded"
		}
	}
	out := []string{
		history + ". What psql and applications run through the gateway is never in it. A statement and its error were both read.",
		fmt.Sprintf("The audit log keeps a statement's text only in forensic mode, for %d days; its other records hold no values.", branch.ForensicRetentionDays()),
		"The Blackbox keeps the statements of the branch's schema changes, and of agents' updates and deletes. It is hash-chained, so a number there cannot be taken out; the report says where it is.",
		"Each place is kept as its source, its entry's number there and the number's last four digits, with who made the entry and when. Since when is when the entry was made.",
		"Not read: PostgreSQL's own log files, backups, WAL archives and anything copied out of FoxByte.",
	}
	if l.capped {
		out = append(out, fmt.Sprintf("At most %d places in the logs are kept for a run.", maxLogListed))
	}
	if !grouped {
		out = append(out, fmt.Sprintf("More than %d distinct numbers were found; places of numbers past those are kept without a person.", maxGrouped))
	}
	return out
}
