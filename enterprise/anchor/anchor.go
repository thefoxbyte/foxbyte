//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

// Package anchor writes the Blackbox's tamper-evidence: a Merkle checkpoint of
// a branch's new ledger entries, signed and written outside the database, and
// the export an auditor checks offline against it.
//
// Writing is the paid half. Reading is not, and stays in internal/branch:
// Integrity checks anchors, fox-verify checks them offline, and the security
// log's own anchors are written there in every edition. An install that
// anchored before changing edition keeps every anchor it has and can still
// prove it.
package anchor

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

// init registers both halves with internal/branch.
func init() { branch.SetAnchorWriter(write, export) }

// lastCheckpoint returns the last checkpoint's to_id and merkle_root (0, "" if none).
func lastCheckpoint(name string) (int64, string, error) {
	lines, err := branch.LedgerQuery(name, "SELECT coalesce((SELECT to_id::text || '|' || merkle_root "+
		"FROM bb.ledger_checkpoints ORDER BY to_id DESC LIMIT 1), '0|')")
	if err != nil {
		return 0, "", err
	}
	if len(lines) == 0 {
		return 0, "", nil
	}
	f := strings.SplitN(lines[0], "|", 2)
	to, err := strconv.ParseInt(f[0], 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf("reading the last checkpoint: %q", lines[0])
	}
	root := ""
	if len(f) > 1 {
		root = f[1]
	}
	return to, root, nil
}

func write(name string) (*ledger.Anchor, string, error) {
	name, err := branch.ResolveBranch(name)
	if err != nil {
		return nil, "", err
	}
	withExt, hasCheckpoints, err := branch.LedgerV2Tables(name)
	if err != nil {
		return nil, "", err
	}
	if !hasCheckpoints {
		return nil, "", fmt.Errorf("ledger checkpoints are not installed on %q — run: fox ledger upgrade %s", name, name)
	}
	lastTo, prevRoot, err := lastCheckpoint(name)
	if err != nil {
		return nil, "", err
	}
	// The new rows, plus the last chained row before them so the chain link into
	// the new range is checked too.
	rows, err := branch.LedgerRows(name, withExt, fmt.Sprintf(
		"WHERE s.id > %d OR s.id = (SELECT max(id) FROM bb.schema_ledger WHERE id <= %d AND row_hash IS NOT NULL)",
		lastTo, lastTo))
	if err != nil {
		return nil, "", err
	}
	var pred *ledger.Row
	var fresh []ledger.Row
	for i := range rows {
		if rows[i].ID <= lastTo {
			p := rows[i]
			pred = &p
		} else {
			fresh = append(fresh, rows[i])
		}
	}
	if len(fresh) == 0 {
		return nil, "", nil
	}
	if err := ledger.CheckChain(pred, fresh); err != nil {
		return nil, "", fmt.Errorf("not anchoring %q: %v — inspect with: fox ledger integrity %s", name, err, name)
	}
	a, err := ledger.BuildAnchor(name, lastTo+1, prevRoot, fresh)
	if err != nil {
		return nil, "", err
	}
	dir := branch.AnchorDir(name)
	path := filepath.Join(dir, ledger.AnchorFileName(a.ToID))
	lines, err := branch.LedgerQuery(name, fmt.Sprintf(`INSERT INTO bb.ledger_checkpoints
  (from_id, to_id, entry_count, last_row_hash, merkle_root, prev_root, algorithm, anchor_uri)
  VALUES (%d, %d, %d, %s, %s, %s, %s, %s) RETURNING id`,
		a.FromID, a.ToID, a.EntryCount, branch.QuoteLiteral(a.LastRowHash), branch.QuoteLiteral(a.MerkleRoot),
		branch.QuoteLiteral(a.PrevRoot), branch.QuoteLiteral(a.Algorithm), branch.QuoteLiteral(path)))
	if err != nil {
		return nil, "", fmt.Errorf("recording the checkpoint: %w", err)
	}
	if len(lines) == 0 {
		return nil, "", errors.New("recording the checkpoint: no id returned")
	}
	if a.CheckpointID, err = strconv.ParseInt(lines[0], 10, 64); err != nil {
		return nil, "", fmt.Errorf("recording the checkpoint: unexpected id %q", lines[0])
	}
	// Signed, so a copy of the anchor proves itself wherever it goes. A key
	// that cannot be read is an error: an unsigned anchor after signed ones
	// is exactly what a verifier refuses.
	key, err := ledger.LoadOrCreateSigningKey(branch.AnchorKeyPath())
	if err != nil {
		return &a, "", fmt.Errorf("checkpoint %d was recorded but its anchor could not be signed: %w", a.CheckpointID, err)
	}
	ledger.SignAnchor(&a, key)
	if _, err := ledger.WriteAnchor(dir, a); err != nil {
		return &a, "", fmt.Errorf("checkpoint %d was recorded but its anchor could not be written: %w", a.CheckpointID, err)
	}
	if branch.TruthyEnv("FOX_ANCHOR_IMMUTABLE") {
		if err := exec.Command("sudo", "chattr", "+i", path).Run(); err != nil {
			log.Printf("anchor %s: chattr +i failed (%v) — the file is read-only but not immutable", path, err)
		}
	}
	// Off the machine too, when backups go to a remote target. A failure is
	// retried with the next checkpoint: MirrorAnchors copies whatever is not
	// marked copied yet.
	if _, err := branch.MirrorAnchors(); err != nil {
		log.Printf("anchor %s: copying it to the backup target: %v", path, err)
	}
	return &a, path, nil
}

// ExportLedger writes every ledger row of a branch, with its capture columns, as
// JSON lines — a file fox-verify can check offline against the anchors.
func export(name string, w io.Writer) error {
	name, err := branch.ResolveBranch(name)
	if err != nil {
		return err
	}
	withExt, _, err := branch.LedgerV2Tables(name)
	if err != nil {
		return err
	}
	lines, err := branch.LedgerQuery(name, ledger.ExportQuery(withExt))
	if err != nil {
		return err
	}
	for _, l := range lines {
		if strings.HasPrefix(l, "{") {
			if _, err := io.WriteString(w, l+"\n"); err != nil {
				return err
			}
		}
	}
	return nil
}
