// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/safego"
)

// Shared state — phase 2 of docs/FOX_HA_Plan.md: accounts, API keys and the
// records authored around them reach every node, so a failover does not leave
// nobody able to sign in.
//
// The decision, recorded in §3.2 and taken again before this was written: the
// store does **not** move into `main`. internal/auth imports exactly one
// package of ours and never the engine, so signing in, verifying a key and
// appending to the security log all work while the database is down — and that
// is the window this phase exists to protect. Accounts kept inside the thing
// that fails over are accounts nobody can read during a failover.
//
// So every node keeps its own store, and the rows are carried between them over
// the channel that already exists: the WAL the standby is already streaming,
// already over TLS, already authenticated, already watched. A document of the
// carried tables (internal/auth/shared.go) is written into a database of its
// own on the primary; physical replication puts it on the other machine; that
// machine reads it from its own copy and applies it into its own SQLite. Auth
// reads never leave the local file, so the property above is kept.
//
// One writer, always. The node that is nobody's follower ships; a node that
// followsageprimary elsewhere applies. There is no merge, and there cannot be
// one: two nodes writing accounts would need consensus, which §2 of the review
// priced for a two-server shop and which this deliberately does not buy.
//
// What this is not:
//
//   - Not synchronous. The document travels in the WAL, so a failover can lose
//     the last few seconds of account changes, exactly as it can lose the last
//     few seconds of writes. An account created during the incident may not be
//     on the surviving machine.
//   - Not a merge. A node that follows has its carried tables *replaced* by
//     the document. Accounts created on a follower are overwritten, which is
//     why `user create` refuses there.
//   - Not row-level. The whole document is rewritten whenever it changes,
//     which is the right shape for the thousands of rows these tables hold and
//     the wrong one for millions. The limit is stated rather than discovered:
//     if accounts ever reach that scale this becomes a row-level log, and the
//     digest is already the seam that would need.

const (
	// StateDatabase holds the carried document, in a database of its own
	// rather than in appdb.
	//
	// Two reasons, both load-bearing. `fox export` dumps a branch's appdb, so
	// accounts in there would travel inside somebody's portable export —
	// password hashes and API key hashes in a tarball nobody thought of as a
	// credential store. And PUBLIC's default CONNECT privilege is revoked here,
	// which cannot be done to the database every client uses.
	//
	// Brand-free and frozen like the other stored names (docs/branding.md).
	StateDatabase = "statedb"

	stateTable = "shared"

	// envStateSync turns the carrying off, or changes how often it happens.
	envStateSync = "STATE_SYNC_INTERVAL"
)

// stateSyncDefault is how often a node looks. Ten seconds because the thing
// being carried changes when a person creates an account or mints a key, which
// is rare, and the cost of looking is one small query.
const stateSyncDefault = 10 * time.Second

// SharedStore is the half of the work that belongs to the account store. An
// interface rather than *auth.Store so the loop can be tested without one.
type SharedStore interface {
	SharedState() ([]byte, string, error)
	SharedStateDigest() (string, error)
	ApplySharedState([]byte) (auth.SharedApply, error)
}

// stateDuty is what a node does with the shared state.
type stateDuty int

const (
	stateIdle   stateDuty = iota // nothing to do: no engine to carry it through
	stateLead                    // write the document: this node owns the accounts
	stateFollow                  // read the document: this node's accounts are a copy
)

func (d stateDuty) String() string {
	switch d {
	case stateLead:
		return "ships"
	case stateFollow:
		return "applies"
	}
	return "idle"
}

// stateSyncDuty decides which it is, and from which container.
//
// Pure, and tested, because the one thing this must never do is let two nodes
// write: that is how an account revoked on one machine comes back from the
// other. A node follows if and only if it follows a primary elsewhere —
// `node join` records that, and `ha failover` clears it, so a promoted node
// becomes the writer by the same act that makes it the primary.
func stateSyncDuty(joined bool, joinedStandby, localPrimary string) (stateDuty, string) {
	if joined {
		// The copy streaming from the remote primary is where the document
		// arrives; this node's own main is idle while it follows.
		if joinedStandby != "running" {
			return stateIdle, ""
		}
		return stateFollow, container("standby")
	}
	if localPrimary != "running" {
		return stateIdle, ""
	}
	return stateLead, PrimaryContainer()
}

// StartStateSync carries the accounts between nodes for as long as this process
// runs. Started by the control plane, which is the one process per node that
// holds the store and already runs the other schedulers.
func StartStateSync(s SharedStore) {
	iv := stateSyncInterval()
	if iv == 0 {
		log.Printf("shared state: carrying off (%s)", brand.EnvName(envStateSync))
		return
	}
	go func() {
		time.Sleep(10 * time.Second) // let the stack settle after a start
		for {
			safego.Run("shared state", func() {
				if err := SyncSharedState(s); err != nil {
					log.Printf("shared state: %v", err)
				}
			})
			time.Sleep(iv)
		}
	}()
}

func stateSyncInterval() time.Duration {
	v := strings.TrimSpace(os.Getenv(brand.EnvName(envStateSync)))
	switch v {
	case "":
		return stateSyncDefault
	case "off", "0":
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		log.Printf("shared state: %s=%q is not a duration; using %s", brand.EnvName(envStateSync), v, stateSyncDefault)
		return stateSyncDefault
	}
	return d
}

// SyncSharedState does one round: ship the document, or apply it, or neither.
func SyncSharedState(s SharedStore) error {
	duty, cont := stateSyncDuty(IsStandbyNode(), ContainerState("standby"), ContainerState(primaryBranch()))
	switch duty {
	case stateLead:
		return shipSharedState(s, cont)
	case stateFollow:
		return applySharedState(s, cont)
	}
	return nil
}

// shipSharedState writes this node's accounts into the replicated database, if
// what is there is not already them.
//
// The stored digest is read first rather than a local memo kept, so the ship is
// self-healing: a node that has just been promoted, or restarted, or whose row
// was lost with a restore, notices and writes it again without being told.
func shipSharedState(s SharedStore, cont string) error {
	doc, digest, err := s.SharedState()
	if err != nil {
		return fmt.Errorf("reading this node's accounts: %w", err)
	}
	stored, _, err := storedStateDigest(cont)
	if err != nil {
		return err
	}
	if stored == digest {
		return nil
	}
	if err := putSharedState(cont, doc, digest); err != nil {
		return fmt.Errorf("carrying this node's accounts to the replicated database: %w", err)
	}
	log.Printf("shared state: carried %d bytes to %s (digest %s)", len(doc), StateDatabase, short(digest))
	return nil
}

// applySharedState reads the document from this node's copy and writes it into
// the local store, if it says anything new.
func applySharedState(s SharedStore, cont string) error {
	stored, at, err := storedStateDigest(cont)
	if err != nil {
		return err
	}
	if stored == "" {
		// The primary has not shipped yet — an install that predates this, or
		// one whose control plane has not come round yet. Nothing to apply, and
		// nothing wrong.
		return nil
	}
	mine, err := s.SharedStateDigest()
	if err != nil {
		return fmt.Errorf("reading this node's accounts: %w", err)
	}
	if mine == stored {
		return nil
	}
	doc, err := getSharedState(cont)
	if err != nil {
		return err
	}
	res, err := s.ApplySharedState(doc)
	if err != nil {
		return fmt.Errorf("applying the primary's accounts: %w", err)
	}
	// Removals are logged separately because they are the surprising half: a
	// row this node had and the primary does not is a row that goes, and on a
	// follower that includes anything created here by mistake.
	log.Printf("shared state: applied the primary's accounts as of %s — %d row(s) written, %d removed",
		at, res.Written, res.Removed)
	return nil
}

func short(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}

// --- the replicated database -------------------------------------------------

// stateConn opens a connection to a container, on database db.
//
// pgx with a parameter rather than psql with a quoted literal: the document
// carries emails, pipeline specifications and change-request snapshots, all of
// which are somebody else's text. A dollar-quoted SQL literal would need a tag
// that text cannot contain, and there is no such tag — a parameter needs none.
func stateConn(ctx context.Context, cont, db string) (*pgx.Conn, error) {
	ip, err := containerIP(cont)
	if err != nil {
		return nil, fmt.Errorf("finding %s: %w", cont, err)
	}
	cfg, err := pgx.ParseConfig(fmt.Sprintf("postgres://%s@%s:5432/%s", pgUser, ip, db))
	if err != nil {
		return nil, err
	}
	cfg.Password = pgPass()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s on %s: %w", db, cont, err)
	}
	return conn, nil
}

const stateOpTimeout = 30 * time.Second

// ensureStateDatabase creates the database and its table if they are not there.
// Only a leader calls it: a follower's copy is read-only and already has both.
func ensureStateDatabase(ctx context.Context, cont string) error {
	admin, err := stateConn(ctx, cont, pgDatabase)
	if err != nil {
		return err
	}
	defer admin.Close(context.Background())
	var exists bool
	if err := admin.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)",
		StateDatabase).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		// CREATE DATABASE cannot be parameterised or run in a transaction, and
		// the name is a constant in this file rather than anything a caller
		// supplies.
		if _, err := admin.Exec(ctx, "CREATE DATABASE "+StateDatabase); err != nil {
			return fmt.Errorf("creating %s: %w", StateDatabase, err)
		}
		// Every role can connect to a new database by default, and this one
		// holds password and key hashes. db_client, the per-user roles and
		// every agent role inherit that default, so it is taken away
		// explicitly — the one privilege change that makes this database
		// different from appdb.
		if _, err := admin.Exec(ctx, "REVOKE CONNECT ON DATABASE "+StateDatabase+" FROM PUBLIC"); err != nil {
			return fmt.Errorf("closing %s to everyone else: %w", StateDatabase, err)
		}
		log.Printf("shared state: created %s, closed to every role but %s", StateDatabase, pgUser)
	}
	st, err := stateConn(ctx, cont, StateDatabase)
	if err != nil {
		return err
	}
	defer st.Close(context.Background())
	// One row, id 1. The document is small and is rewritten whole; a log of
	// changes would need pruning, a snapshot for a node joining later, and a
	// position per follower, all to carry a few thousand rows.
	_, err = st.Exec(ctx, `CREATE TABLE IF NOT EXISTS `+stateTable+` (
  id int PRIMARY KEY,
  at timestamptz NOT NULL,
  node text NOT NULL,
  digest text NOT NULL,
  payload jsonb NOT NULL)`)
	return err
}

func putSharedState(cont string, doc []byte, digest string) error {
	ctx, cancel := context.WithTimeout(context.Background(), stateOpTimeout)
	defer cancel()
	if err := ensureStateDatabase(ctx, cont); err != nil {
		return err
	}
	conn, err := stateConn(ctx, cont, StateDatabase)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	host, _ := os.Hostname()
	_, err = conn.Exec(ctx, `INSERT INTO `+stateTable+` (id, at, node, digest, payload)
VALUES (1, now(), $1, $2, $3::jsonb)
ON CONFLICT (id) DO UPDATE SET at = excluded.at, node = excluded.node,
  digest = excluded.digest, payload = excluded.payload`, host, digest, string(doc))
	return err
}

// storedStateDigest is the cheap question — has anything changed? — asked
// without moving the document. An absent database or table is not a failure: it
// is an install where nothing has shipped yet.
func storedStateDigest(cont string) (digest, at string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), stateOpTimeout)
	defer cancel()
	conn, err := stateConn(ctx, cont, StateDatabase)
	if err != nil {
		if missingState(err) {
			return "", "", nil
		}
		return "", "", err
	}
	defer conn.Close(context.Background())
	row := conn.QueryRow(ctx, `SELECT digest, to_char(at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
FROM `+stateTable+` WHERE id = 1`)
	if err := row.Scan(&digest, &at); err != nil {
		if missingState(err) {
			return "", "", nil
		}
		return "", "", err
	}
	return digest, at, nil
}

func getSharedState(cont string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), stateOpTimeout)
	defer cancel()
	conn, err := stateConn(ctx, cont, StateDatabase)
	if err != nil {
		return nil, err
	}
	defer conn.Close(context.Background())
	var doc string
	if err := conn.QueryRow(ctx, `SELECT payload::text FROM `+stateTable+` WHERE id = 1`).Scan(&doc); err != nil {
		return nil, err
	}
	return []byte(doc), nil
}

// missingState reports whether an error means "nothing has shipped here yet"
// rather than "this is broken": no such database, no such table, no row.
//
// Matched on the text because that is what reaches a caller through either a
// connection failure or a query, and the three cases are all ordinary on a
// fresh install or a node that joined a moment ago.
func missingState(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, ok := range []string{
		"does not exist",    // the database or the table
		"no rows in result", // nothing shipped yet
		"3D000",             // invalid_catalog_name
		"42P01",             // undefined_table
	} {
		if strings.Contains(s, ok) {
			return true
		}
	}
	return false
}

// DescribeSharedState is the "=== accounts ===" part of `ha status`: whether
// this node owns the accounts or copies them, and how current the copy is.
func DescribeSharedState(s SharedStore) string {
	duty, cont := stateSyncDuty(IsStandbyNode(), ContainerState("standby"), ContainerState(primaryBranch()))
	if duty == stateIdle {
		return "accounts and keys are not being carried: no running database to carry them through."
	}
	stored, at, err := storedStateDigest(cont)
	if err != nil {
		return "accounts and keys: " + err.Error()
	}
	if stored == "" {
		if duty == stateFollow {
			return "this node's accounts are a copy, and the primary has not sent one yet —\n" +
				"it may be running a version that does not carry them."
		}
		return "accounts and keys have not been carried yet; the next round will do it."
	}
	mine, err := s.SharedStateDigest()
	if err != nil {
		return "accounts and keys: " + err.Error()
	}
	switch {
	case duty == stateLead && mine == stored:
		return fmt.Sprintf("this node owns the accounts and keys, and a copy of them went into the\n"+
			"replicated database at %s. A node that joins gets them from there.", at)
	case duty == stateLead:
		return fmt.Sprintf("this node owns the accounts and keys; the copy in the replicated database is\n"+
			"from %s and is behind. The next round will replace it.", at)
	case mine == stored:
		return fmt.Sprintf("this node's accounts and keys are a copy of the primary's, current as of %s.\n"+
			"Sign-ins here work while the primary is unreachable. `%s user create` is refused:\n"+
			"an account made here would be overwritten by the next copy.", at, brand.CLI)
	default:
		return fmt.Sprintf("this node's accounts and keys are a copy and are out of step with the\n"+
			"primary's (sent at %s). The next round will apply them.", at)
	}
}

// SharedStateIsACopy reports whether this node's accounts are somebody else's
// to change — which is what `user create` needs to know, and the one question
// about this that a command asks.
func SharedStateIsACopy() bool { return IsStandbyNode() }
