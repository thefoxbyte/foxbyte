// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"
)

// LedgerEntry is one ledger entry with its id — what `fox ledger branch-before`
// and its REST/MCP/web counterparts take. The existing ledger views don't show
// ids and are left unchanged; this is a separate listing.
type LedgerEntry struct {
	ID         int64  `json:"id"`
	At         string `json:"at"` // UTC, RFC 3339 to the second
	Actor      string `json:"actor"`
	CommandTag string `json:"command_tag"`
	Object     string `json:"object_identity"`
	Status     string `json:"status"`
	Risk       string `json:"risk"`
}

func entriesQuery(limit int) string {
	return fmt.Sprintf(`SELECT json_build_object('id', id,
  'at', to_char(at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
  'actor', coalesce(actor, ''), 'command_tag', coalesce(command_tag, ''),
  'object_identity', coalesce(object_identity, ''), 'status', coalesce(status, ''), 'risk', coalesce(risk, ''))
FROM bb.schema_ledger ORDER BY id DESC LIMIT %d`, limit)
}

// LedgerEntries returns a branch's newest ledger entries (newest first, at most
// 1000; default 50) with their ids.
func LedgerEntries(name string, limit int) ([]LedgerEntry, error) {
	name, err := ledgerBranchName(name)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	lines, err := ledgerLines(name, entriesQuery(limit))
	if err != nil {
		return nil, err
	}
	entries := make([]LedgerEntry, 0, len(lines))
	for _, l := range lines {
		if !strings.HasPrefix(l, "{") {
			continue
		}
		var e LedgerEntry
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			return nil, fmt.Errorf("reading ledger entries: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// FormatLedgerEntries renders entries as an aligned text table, id first.
func FormatLedgerEntries(entries []LedgerEntry) string {
	if len(entries) == 0 {
		return "No ledger entries."
	}
	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tTIME (UTC)\tACTOR\tCOMMAND\tOBJECT\tSTATUS\tRISK")
	for _, e := range entries {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", e.ID, e.At, e.Actor, e.CommandTag, e.Object, e.Status, e.Risk)
	}
	_ = tw.Flush()
	return strings.TrimRight(b.String(), "\n")
}
