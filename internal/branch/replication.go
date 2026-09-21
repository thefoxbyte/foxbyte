// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ErrNotReplicating: the branch has no continuous import to report on or cut over.
var ErrNotReplicating = errors.New("not a continuous import")

// Replication is where a continuous import (ImportContinuous) stands: the
// subscription's tables and how many have finished their initial copy, and when
// the source last sent anything.
type Replication struct {
	Branch        string `json:"branch"`
	Replicating   bool   `json:"replicating"`
	Tables        int    `json:"tables"`       // tables the subscription covers
	TablesReady   int    `json:"tables_ready"` // initial copy done, now streaming
	LastMessageAt string `json:"last_message_at,omitempty"`
	ReceivedLSN   string `json:"received_lsn,omitempty"`
}

// Ready reports whether every table has finished its initial copy, i.e. whether
// cutting over now keeps a complete copy.
func (r Replication) Ready() bool { return r.Replicating && r.Tables > 0 && r.TablesReady == r.Tables }

const replicationSQL = `SELECT json_build_object(
  'replicating', EXISTS (SELECT 1 FROM pg_subscription WHERE subname = 'bb_sub'),
  'tables', (SELECT count(*) FROM pg_subscription_rel sr JOIN pg_subscription s ON s.oid = sr.srsubid
             WHERE s.subname = 'bb_sub'),
  'tables_ready', (SELECT count(*) FROM pg_subscription_rel sr JOIN pg_subscription s ON s.oid = sr.srsubid
                   WHERE s.subname = 'bb_sub' AND sr.srsubstate = 'r'),
  'last_message_at', (SELECT to_char(max(last_msg_receipt_time) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
                      FROM pg_stat_subscription WHERE subname = 'bb_sub'),
  'received_lsn', (SELECT max(received_lsn)::text FROM pg_stat_subscription WHERE subname = 'bb_sub'))`

// ReplicationStatus reports a branch's continuous import, if it has one.
func ReplicationStatus(name string) (Replication, error) {
	r, err := parseReplication(name, func() ([]string, error) { return ledgerLines(name, replicationSQL) })
	return r, err
}

func parseReplication(name string, lines func() ([]string, error)) (Replication, error) {
	out, err := lines()
	if err != nil {
		return Replication{}, fmt.Errorf("reading replication state of %q: %w", name, err)
	}
	if len(out) == 0 {
		return Replication{}, fmt.Errorf("reading replication state of %q: no result", name)
	}
	r := Replication{Branch: name}
	if err := json.Unmarshal([]byte(out[len(out)-1]), &r); err != nil {
		return Replication{}, fmt.Errorf("reading replication state of %q: %w", name, err)
	}
	r.Branch = name
	return r, nil
}

// Replicating lists the running branches that have a continuous import.
func Replicating() ([]Replication, error) {
	names, err := RunningBranches()
	if err != nil {
		return nil, err
	}
	out := []Replication{}
	for _, n := range names {
		if n == "main" {
			continue // an import always lands in its own branch
		}
		r, err := ReplicationStatus(n)
		if err != nil || !r.Replicating {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// CutoverReplication finishes a continuous import from the API: unlike the CLI's
// ImportCutover, it refuses a branch that isn't replicating, so a cutover
// request can't silently succeed against the wrong branch.
func CutoverReplication(name string) (int, error) {
	r, err := ReplicationStatus(name)
	if err != nil {
		return 0, err
	}
	if !r.Replicating {
		return 0, fmt.Errorf("%w: branch %q has no replication to cut over", ErrNotReplicating, name)
	}
	if err := ImportCutoverTo(&Progress{}, name); err != nil {
		return 0, err
	}
	return TableCount(name), nil
}
