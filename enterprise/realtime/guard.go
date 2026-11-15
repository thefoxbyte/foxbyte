//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// Whether a table that is streaming may still stream.
//
// Enable refuses a table with row-level security, or one db_client cannot
// fully read, because decoded WAL carries every row and every column whoever
// is listening. But that check is made once, and a table can change after it:
// someone turns on RLS, revokes a column, or adds a column only some roles may
// read. Logical decoding takes no notice of any of that. So a running decoder
// asks the same questions again:
//
//   - when it starts, for every table its publications carry;
//   - whenever pgoutput describes a table (a Relation message). Postgres sends
//     one before a table's first change on each connection, and again after
//     anything that changes the table's definition, its grants or its RLS
//     setting, so the answer is fresh before the first row after the change;
//   - every RecheckInterval, in case a change reached the catalog without a
//     Relation message following it.
//
// A table that now fails is not streamed: its changes are dropped here, before
// any subscriber sees them, and the reason is logged. It streams again once the
// catalog says it may, from that point on; what was dropped is not replayed.

// RecheckInterval is how often a running decoder asks the catalog again.
const RecheckInterval = 30 * time.Second

// checkTimeout bounds one catalog question, so a branch that stops answering
// fails the decoder (which then reconnects) instead of stalling it.
const checkTimeout = 10 * time.Second

// Catalog is what the decoder asks about the tables it streams.
type Catalog interface {
	// Published is the facts for every table the feed's publications carry.
	Published(ctx context.Context) ([]Table, error)
	// Relation is the facts for one table by OID, and false when the feed's
	// publications no longer carry it.
	Relation(ctx context.Context, oid uint32) (Table, bool, error)
}

// streamBlock is why a published table may not stream any more, or "" when it
// may. These are the checks Enable refuses on that are about who may read
// what; a missing replica identity is not one of them, since it breaks
// updates rather than exposing anything.
func streamBlock(t Table) string {
	v := Assess(t, []string{"insert"}, true)
	switch {
	case v.State == Impossible:
		return v.Reason
	case !t.ClientCanUseSchema:
		return fmt.Sprintf("db_client can no longer use the %s schema, so it may not read %s", t.Schema, t.Qualified())
	case !t.ClientCanSelect:
		return fmt.Sprintf("db_client can no longer read %s", t.Qualified())
	case len(t.hiddenStreamed()) > 0:
		return fmt.Sprintf("db_client cannot read %s on %s, and the change feed carries those columns",
			strings.Join(t.hiddenStreamed(), ", "), t.Qualified())
	}
	return ""
}

// setVerdict records whether a table may stream, and says so in the log when
// that changes. It reports whether the table was blocked before.
func (d *Decoder) setVerdict(table, reason string) (wasBlocked bool) {
	if d.verdicts == nil {
		d.verdicts = map[string]string{}
	}
	old, known := d.verdicts[table]
	d.verdicts[table] = reason
	wasBlocked = known && old != ""
	switch {
	case reason != "" && old != reason:
		log.Printf("change feed %s: no longer streaming %s: %s", d.slot, table, reason)
	case reason == "" && wasBlocked:
		log.Printf("change feed %s: streaming %s again; changes made while it was blocked were not sent", d.slot, table)
	}
	return wasBlocked
}

// recheckAll asks about every published table, and announces the shape of any
// that may stream again.
func (d *Decoder) recheckAll() error {
	if d.catalog == nil {
		return fmt.Errorf("the change feed has no catalog to check its tables against")
	}
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()
	tables, err := d.catalog.Published(ctx)
	if err != nil {
		return fmt.Errorf("checking which tables may still stream: %w", err)
	}
	seen := map[string]bool{}
	for _, t := range tables {
		name := t.Qualified()
		seen[name] = true
		reason := streamBlock(t)
		narrowed := d.setAllowed(name, t.StreamColumns)
		if wasBlocked := d.setVerdict(name, reason); reason == "" && (wasBlocked || narrowed) {
			// Announced again when the columns change too, so a subscriber's
			// idea of the table's shape matches what it is about to be sent.
			d.reannounce(name)
		}
	}
	// A table that left the publications is forgotten rather than blocked: if
	// it is added back, its next change is checked afresh (allowed) instead of
	// waiting for the next round here.
	for name := range d.verdicts {
		if !seen[name] {
			delete(d.verdicts, name)
			delete(d.allowed, name)
		}
	}
	return nil
}

// setAllowed records the columns a table may stream (nil: all of them), and
// reports whether that changed for a table already known.
func (d *Decoder) setAllowed(table string, cols []string) (changed bool) {
	if d.allowed == nil {
		d.allowed = map[string][]string{}
	}
	old, known := d.allowed[table]
	d.allowed[table] = append([]string(nil), cols...)
	if cols == nil {
		d.allowed[table] = nil
	}
	if !known {
		return false
	}
	if (old == nil) != (cols == nil) || len(old) != len(cols) {
		return true
	}
	for i := range old {
		if old[i] != cols[i] {
			return true
		}
	}
	return false
}

// narrow is a relation and its tuples with every column the table may not
// stream taken out, before anything is built from them.
//
// This is the decoder's half of the column choice, and it runs whether or not
// the publication already filtered: where Postgres could apply a column list,
// pgoutput sends only those columns and this changes nothing; where it could
// not (an older major, or REPLICA IDENTITY FULL with updates published), this
// is the only thing between the whole row and a subscriber. Old and new tuples
// go through the same cut, so a previous value of a column left out is never
// sent either.
//
// Done on the relation and the tuples together because a tuple is positional:
// column i of the tuple is column i of the relation, and dropping one without
// the other would put values under the wrong names.
func (d *Decoder) narrow(rel Relation, tuples ...[]ColumnValue) (Relation, [][]ColumnValue) {
	allowed, known := d.allowed[rel.Qualified()]
	if !known || allowed == nil {
		return rel, tuples
	}
	keep := make([]bool, len(rel.Columns))
	out := Relation{Schema: rel.Schema, Name: rel.Name, ReplicaIdentity: rel.ReplicaIdentity}
	for i, c := range rel.Columns {
		for _, a := range allowed {
			if c.Name == a {
				keep[i] = true
				out.Columns = append(out.Columns, c)
				break
			}
		}
	}
	cut := make([][]ColumnValue, len(tuples))
	for j, t := range tuples {
		if t == nil {
			continue
		}
		cut[j] = make([]ColumnValue, 0, len(out.Columns))
		for i, v := range t {
			if i < len(keep) && keep[i] {
				cut[j] = append(cut[j], v)
			}
		}
	}
	return out, cut
}

// recheckRelation asks about one table, as pgoutput has just described it.
func (d *Decoder) recheckRelation(oid uint32, rel Relation) (reason string, wasBlocked bool, err error) {
	if d.catalog == nil {
		reason = "the change feed has no catalog to check it against"
		return reason, d.setVerdict(rel.Qualified(), reason), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()
	t, ok, err := d.catalog.Relation(ctx, oid)
	if err != nil {
		return "", false, fmt.Errorf("checking whether %s may still stream: %w", rel.Qualified(), err)
	}
	if !ok {
		reason = "it is no longer in the feed's publications"
	} else {
		reason = streamBlock(t)
		d.setAllowed(rel.Qualified(), t.StreamColumns)
	}
	return reason, d.setVerdict(rel.Qualified(), reason), nil
}

// sendable is the relation a change belongs to, and whether that change may be
// sent: false for a table pgoutput never described, and for one the catalog
// says may not stream. A table with no verdict yet is asked about now, so the
// answer is never assumed. ok is false whenever err is set.
func (d *Decoder) sendable(oid uint32) (rel Relation, ok bool, err error) {
	rel, known := d.relations[oid]
	if !known {
		return rel, false, nil
	}
	reason, checked := d.verdicts[rel.Qualified()]
	if !checked {
		if reason, _, err = d.recheckRelation(oid, rel); err != nil {
			return rel, false, err
		}
	}
	return rel, reason == "", nil
}

// reannounce sends a table's shape again, for one that may stream once more:
// its schema events were held back while it was blocked.
func (d *Decoder) reannounce(table string) {
	for _, rel := range d.relations {
		if rel.Qualified() == table {
			shown, _ := d.narrow(rel)
			d.hub.Publish(Schema{Type: "schema", Table: rel.Qualified(), Columns: shown.Columns})
			return
		}
	}
}

// pgCatalog answers the decoder's questions over an ordinary connection of
// its own, as the decode role. The replication connection cannot run queries
// while it streams, and a separate connection keeps each answer to one round
// trip rather than a docker exec.
type pgCatalog struct {
	conn *pgconn.PgConn
	// haveColumns is whether bb.realtime_columns has been seen to exist, so
	// the check is not repeated on every question.
	haveColumns bool
}

// publishedSQL narrows factsSQL to the tables the feed's publications carry.
const publishedSQL = ` AND EXISTS (
      SELECT 1 FROM pg_publication_tables pt
      WHERE pt.pubname LIKE '` + branch.PublicationPrefix + `%'
        AND pt.schemaname = n.nspname AND pt.tablename = c.relname)`

// openCatalog connects with the decoder's own connection string, minus the
// replication option.
func openCatalog(ctx context.Context, dsn string) (*pgCatalog, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, fmt.Errorf("reading the feed's connection string: %w", err)
	}
	q := u.Query()
	q.Del("replication")
	u.RawQuery = q.Encode()
	conn, err := pgconn.Connect(ctx, u.String())
	if err != nil {
		return nil, fmt.Errorf("opening the connection the feed checks its tables with: %w", err)
	}
	return &pgCatalog{conn: conn}, nil
}

func (c *pgCatalog) Close(ctx context.Context) error { return c.conn.Close(ctx) }

func (c *pgCatalog) Published(ctx context.Context) ([]Table, error) {
	return c.query(ctx, publishedSQL)
}

func (c *pgCatalog) Relation(ctx context.Context, oid uint32) (Table, bool, error) {
	ts, err := c.query(ctx, publishedSQL+fmt.Sprintf(" AND c.oid = %d", oid))
	if err != nil || len(ts) == 0 {
		return Table{}, false, err
	}
	return ts[0], true, nil
}

// query runs factsSQL, the one catalog query Survey and Enable use, so the
// decoder judges a table on exactly the facts Enable judged it on.
func (c *pgCatalog) query(ctx context.Context, where string) ([]Table, error) {
	res, err := c.conn.Exec(ctx, factsSQL+where).ReadAll()
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, r := range res {
		for _, row := range r.Rows {
			if len(row) > 0 {
				lines = append(lines, string(row[0]))
			}
		}
	}
	rows, err := decodeFacts(lines)
	if err != nil {
		return nil, err
	}
	stream, err := c.streamColumns(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Table, 0, len(rows))
	for _, r := range rows {
		r.Table.StreamColumns = stream[r.Table.Qualified()]
		out = append(out, r.Table)
	}
	return out, nil
}

// streamColumns reads the column choices the decoder enforces. A branch where
// no table was ever narrowed has no record, and every table streams every
// column, as it did before the choice existed.
//
// A record that exists but cannot be read is an error, not an empty answer:
// streaming whole rows because a grant was missing is exactly the failure this
// is here to prevent, so the decoder stops and reconnects instead.
func (c *pgCatalog) streamColumns(ctx context.Context) (map[string][]string, error) {
	if !c.haveColumns {
		// Asked of pg_class rather than with to_regclass: naming a schema the
		// role has no USAGE on is an error even when the question is only
		// whether something exists, and on a branch nobody has narrowed the
		// decode role may never have been granted it.
		res, err := c.conn.Exec(ctx, columnsExistSQL).ReadAll()
		if err != nil {
			return nil, err
		}
		if len(res) == 0 || len(res[0].Rows) == 0 || string(res[0].Rows[0][0]) != "t" {
			return map[string][]string{}, nil
		}
		// Once there it stays: Enable never drops it.
		c.haveColumns = true
	}
	res, err := c.conn.Exec(ctx, streamColumnsSQL).ReadAll()
	if err != nil {
		return nil, fmt.Errorf("reading which columns may stream: %w", err)
	}
	var lines []string
	for _, r := range res {
		for _, row := range r.Rows {
			if len(row) > 0 {
				lines = append(lines, string(row[0]))
			}
		}
	}
	return decodeStreamColumns(lines)
}
