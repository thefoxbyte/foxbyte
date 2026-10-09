//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pglogrepl"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

// One decoder per branch, reading the write-ahead log and handing rows to a Hub.
//
// Started on the first subscriber and stopped after the last, because a branch
// nobody is listening to should not be holding a replication slot open — a slot
// with no reader is WAL that cannot be reclaimed.
//
// The position is acknowledged only once subscribers have actually received the
// events, never on receipt. That is the whole of what makes replay mean
// anything: acknowledge early and a subscriber that drops at the wrong moment
// comes back to find the feed has moved on without it, with no error anywhere.

// StandbyInterval is how often the decoder tells Postgres where it has got to.
// Ten seconds is well inside the default wal_sender_timeout of sixty.
const StandbyInterval = 10 * time.Second

// Decoder streams one branch's changes.
type Decoder struct {
	conn        *pgconn.PgConn
	slot        string
	publication string
	hub         *Hub

	relations map[uint32]Relation
	// tx is the transaction being decoded. pgoutput with proto_version 1 and no
	// streaming sends only complete transactions, in commit order, so there is
	// exactly one of these at a time and no interleaving to untangle.
	tx txState
	// acked is the last position every subscriber has been given. Only this is
	// reported to Postgres, so WAL behind it stays reclaimable and WAL ahead of
	// it stays available for a subscriber that reconnects.
	acked pglogrepl.LSN
}

// NewDecoder opens a replication connection. dsn must carry
// `replication=database`; the caller builds it, because the credentials are the
// engine's business rather than this package's.
func NewDecoder(ctx context.Context, dsn, slot, publication string, hub *Hub) (*Decoder, error) {
	conn, err := pgconn.Connect(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("opening a replication connection: %w", err)
	}
	return &Decoder{conn: conn, slot: slot, publication: publication, hub: hub,
		relations: map[uint32]Relation{}}, nil
}

// EnsureSlot creates the slot if it is not there. Idempotent, because a
// subscriber reconnecting must land on the slot it left behind — that is what
// it resumes from.
func (d *Decoder) EnsureSlot(ctx context.Context) error {
	_, err := pglogrepl.CreateReplicationSlot(ctx, d.conn, d.slot, "pgoutput",
		pglogrepl.CreateReplicationSlotOptions{Temporary: false})
	if err != nil && !isDuplicateSlot(err) {
		return fmt.Errorf("creating the replication slot %s: %w", d.slot, err)
	}
	return nil
}

// A slot that already exists is the ordinary case, not a failure: it is what a
// reconnecting subscriber resumes from.
func isDuplicateSlot(err error) bool {
	var pge *pgconn.PgError
	return errors.As(err, &pge) && pge.Code == "42710" // duplicate_object
}

// Run streams until the context is cancelled or the connection fails.
//
// since is where to resume from: the LSN a subscriber last saw. Zero starts
// from wherever the slot is, which for a new slot is "now".
func (d *Decoder) Run(ctx context.Context, since pglogrepl.LSN) error {
	d.acked = since
	if err := pglogrepl.StartReplication(ctx, d.conn, d.slot, since,
		pglogrepl.StartReplicationOptions{PluginArgs: []string{
			"proto_version '1'", "publication_names '" + d.publication + "'",
		}}); err != nil {
		return fmt.Errorf("starting replication on %s: %w", d.slot, err)
	}

	next := time.Now().Add(StandbyInterval)
	for {
		if time.Now().After(next) {
			// Only what subscribers have been given. See the note on acked.
			if err := pglogrepl.SendStandbyStatusUpdate(ctx, d.conn,
				pglogrepl.StandbyStatusUpdate{WALWritePosition: d.acked}); err != nil {
				return fmt.Errorf("reporting the replication position: %w", err)
			}
			next = time.Now().Add(StandbyInterval)
		}

		recvCtx, cancel := context.WithDeadline(ctx, next)
		msg, err := d.conn.ReceiveMessage(recvCtx)
		cancel()
		if err != nil {
			if pgconn.Timeout(err) {
				continue // nothing happened; send a standby update and wait again
			}
			return fmt.Errorf("receiving from the replication stream: %w", err)
		}

		cd, ok := msg.(*pgproto3.CopyData)
		if !ok {
			continue // a notice or similar; nothing to decode
		}
		switch cd.Data[0] {
		case pglogrepl.PrimaryKeepaliveMessageByteID:
			ka, err := pglogrepl.ParsePrimaryKeepaliveMessage(cd.Data[1:])
			if err != nil {
				return err
			}
			if ka.ReplyRequested {
				next = time.Now() // answer on the next turn of the loop
			}
		case pglogrepl.XLogDataByteID:
			xld, err := pglogrepl.ParseXLogData(cd.Data[1:])
			if err != nil {
				return err
			}
			if err := d.handle(xld); err != nil {
				return err
			}
		}
	}
}

// Close ends the replication connection. The slot stays: it is what a
// reconnecting subscriber resumes from, and sweeping it is a decision made
// elsewhere, where "is anyone still interested" can be answered.
func (d *Decoder) Close(ctx context.Context) error { return d.conn.Close(ctx) }

// handle turns one WAL record into what subscribers receive.
func (d *Decoder) handle(xld pglogrepl.XLogData) error {
	m, err := pglogrepl.Parse(xld.WALData)
	if err != nil {
		return fmt.Errorf("parsing a logical replication message: %w", err)
	}
	return d.handleMessage(m, xld.WALStart.String())
}

// txState is what is known about the transaction being decoded.
//
// begun is whether a Begin frame has actually been published. It is held back
// until the first visible change, so a transaction that touched only
// unsubscribed tables produces no frame at all — Postgres reports those, and a
// frame around nothing is noise every subscriber would have to learn to ignore.
type txState struct {
	xid       uint32
	commitLSN string
	at        string
	changes   int
	begun     bool
}

// handleMessage is the half worth testing: a parsed message in, events out.
func (d *Decoder) handleMessage(m pglogrepl.Message, lsn string) error {
	switch msg := m.(type) {
	case *pglogrepl.BeginMessage:
		// Remembered, not published. FinalLSN is where this transaction will
		// commit, which pgoutput announces up front — so every change in it can
		// carry the boundary a subscriber resumes from, rather than that only
		// becoming known at the end.
		d.tx = txState{
			xid:       msg.Xid,
			commitLSN: msg.FinalLSN.String(),
			at:        msg.CommitTime.UTC().Format(time.RFC3339Nano),
		}

	case *pglogrepl.RelationMessage:
		rel := relationFrom(msg)
		// Re-announce only when the shape actually changed, or every
		// transaction would repeat the schema for no reason.
		if old, seen := d.relations[msg.RelationID]; !seen || !sameShape(old, rel) {
			d.hub.Publish(Schema{Type: "schema", Table: rel.Qualified(), Columns: rel.Columns})
		}
		d.relations[msg.RelationID] = rel

	case *pglogrepl.InsertMessage:
		if rel, ok := d.relations[msg.RelationID]; ok {
			d.publishChange(BuildChange(rel, "insert", d.commitLSN(lsn), nil, tupleFrom(msg.Tuple)), lsn)
		}
	case *pglogrepl.UpdateMessage:
		if rel, ok := d.relations[msg.RelationID]; ok {
			d.publishChange(BuildChange(rel, "update", d.commitLSN(lsn),
				tupleFrom(msg.OldTuple), tupleFrom(msg.NewTuple)), lsn)
		}
	case *pglogrepl.DeleteMessage:
		if rel, ok := d.relations[msg.RelationID]; ok {
			d.publishChange(BuildChange(rel, "delete", d.commitLSN(lsn), tupleFrom(msg.OldTuple), nil), lsn)
		}
	case *pglogrepl.TruncateMessage:
		// One event per relation, with no row data — there is none to send. It
		// almost never fires: datachanges.sql blocks TRUNCATE by default.
		for _, id := range msg.RelationIDs {
			if rel, ok := d.relations[id]; ok {
				d.publishChange(Change{Type: "change", Table: rel.Qualified(),
					Action: "truncate", CommitLSN: d.commitLSN(lsn), Identity: map[string]Value{}}, lsn)
			}
		}
	case *pglogrepl.CommitMessage:
		// Close the frame, but only if one was opened: a transaction whose
		// changes were all on tables nobody subscribed to published no Begin,
		// and a lone Commit would be a frame around nothing.
		if d.tx.begun {
			d.hub.Publish(Commit{Type: "commit", Xid: d.tx.xid,
				CommitLSN: msg.CommitLSN.String(),
				At:        msg.CommitTime.UTC().Format(time.RFC3339Nano),
				Changes:   d.tx.changes})
		}
		d.tx = txState{}
		// Everything in this transaction has been handed to the hub, so the
		// position is now safe to acknowledge.
		d.acked = msg.CommitLSN
	}
	return nil
}

// publishChange sends one change, opening the transaction's frame if this is
// the first visible change in it.
func (d *Decoder) publishChange(c Change, recordLSN string) {
	if d.tx.commitLSN != "" && !d.tx.begun {
		d.hub.Publish(Begin{Type: "begin", Xid: d.tx.xid, CommitLSN: d.tx.commitLSN, At: d.tx.at})
		d.tx.begun = true
	}
	c.Xid = d.tx.xid
	c.LSN = recordLSN
	d.tx.changes++
	d.hub.Publish(c)
}

// commitLSN is the boundary to stamp on a change: the transaction's commit
// position when one is known, and otherwise the record's own.
//
// The fallback should never be reached — pgoutput wraps every DML message in
// BEGIN and COMMIT — but a change with no resume position at all would be worse
// than one with an imprecise one, and silently writing an empty string would
// turn a decoder bug into a subscriber that cannot resume.
func (d *Decoder) commitLSN(recordLSN string) string {
	if d.tx.commitLSN != "" {
		return d.tx.commitLSN
	}
	return recordLSN
}

// relationFrom converts pglogrepl's description of a table into ours.
func relationFrom(msg *pglogrepl.RelationMessage) Relation {
	rel := Relation{Schema: msg.Namespace, Name: msg.RelationName,
		ReplicaIdentity: msg.ReplicaIdentity}
	for _, c := range msg.Columns {
		rel.Columns = append(rel.Columns, Column{
			Name: c.Name, TypeOID: c.DataType,
			// pgoutput sets flag 1 on the columns that make up the replica
			// identity, which is exactly what a subscriber needs to locate a
			// row.
			Key: c.Flags&1 == 1,
		})
	}
	return rel
}

// tupleFrom converts a pgoutput tuple into ours, keeping the distinction
// between null, unchanged-TOAST and a value — which is the distinction the
// whole wire format is built around.
func tupleFrom(t *pglogrepl.TupleData) []ColumnValue {
	if t == nil {
		return nil
	}
	out := make([]ColumnValue, 0, len(t.Columns))
	for _, c := range t.Columns {
		out = append(out, ColumnValue{Kind: c.DataType, Text: string(c.Data)})
	}
	return out
}

// sameShape reports whether two descriptions of a table agree, so a schema
// event is sent when it means something and not otherwise.
func sameShape(a, b Relation) bool {
	if a.Schema != b.Schema || a.Name != b.Name || len(a.Columns) != len(b.Columns) {
		return false
	}
	for i := range a.Columns {
		if a.Columns[i] != b.Columns[i] {
			return false
		}
	}
	return true
}
