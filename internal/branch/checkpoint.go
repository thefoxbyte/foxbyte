// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"fmt"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"io"
	"log"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

// Blackbox 2.0 checkpoints: a Merkle root over a contiguous range of ledger
// entries, recorded in bb.ledger_checkpoints and written as a read-only anchor
// file outside the database. Integrity trusts the anchor files, so history that
// was rewritten inside the database — even with a recomputed hash chain — is
// detected. The same checks are available to anyone via cmd/fox-verify.

// AnchorDir is where a branch's anchor files are written: FOX_ANCHOR_DIR
// (e.g. a write-once mount) or ~/.fox/anchors, plus the branch name.
func AnchorDir(name string) string {
	base := strings.TrimSpace(brand.Getenv("ANCHOR_DIR"))
	if base == "" {
		base = brand.StatePath("anchors")
	}
	return filepath.Join(base, name)
}

func ledgerBranchName(name string) (string, error) {
	if name == "" {
		name = "main"
	}
	if name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("invalid branch name %q", name)
	}
	return name, nil
}

// ledgerLines runs a query as the superuser and returns its non-empty output
// lines (one JSON document per row for the ledger queries).
func ledgerLines(name, sql string) ([]string, error) {
	out, err := exec.Command("sudo", "docker", "exec", "--env-file", pgEnvFile(), container(name),
		"psql", "-U", pgUser, "-d", pgDatabase, "-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1", "-c", sql).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return nil, fmt.Errorf("%s", strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, err
	}
	var lines []string
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return lines, nil
}

// ledgerV2Tables reports whether the 2.0 capture and checkpoint tables exist.
func ledgerV2Tables(name string) (ext, checkpoints bool, err error) {
	lines, err := ledgerLines(name, "SELECT (to_regclass('bb.ledger_ext') IS NOT NULL)::text || '|' || "+
		"(to_regclass('bb.ledger_checkpoints') IS NOT NULL)::text")
	if err != nil {
		return false, false, err
	}
	if len(lines) == 0 {
		return false, false, fmt.Errorf("no answer from branch %q", name)
	}
	f := strings.Split(lines[0], "|")
	return f[0] == "true", len(f) > 1 && f[1] == "true", nil
}

func loadLedgerRows(name string, withExt bool, where string) ([]ledger.Row, error) {
	lines, err := ledgerLines(name, ledger.RowsQuery(withExt, where))
	if err != nil {
		return nil, err
	}
	rows := make([]ledger.Row, 0, len(lines))
	for _, l := range lines {
		if !strings.HasPrefix(l, "{") {
			continue
		}
		r, err := ledger.DecodeRowJSON([]byte(l))
		if err != nil {
			return nil, err
		}
		rows = append(rows, r)
	}
	return rows, nil
}

// lastCheckpoint returns the last checkpoint's to_id and merkle_root (0, "" if none).
func lastCheckpoint(name string) (int64, string, error) {
	lines, err := ledgerLines(name, "SELECT coalesce((SELECT to_id::text || '|' || merkle_root "+
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

// Checkpoint anchors a branch's ledger entries added since its last checkpoint.
// It returns (nil, "", nil) when there is nothing new. It refuses to anchor rows
// whose hash chain is already broken.
func Checkpoint(name string) (*ledger.Anchor, string, error) {
	name, err := ledgerBranchName(name)
	if err != nil {
		return nil, "", err
	}
	withExt, hasCheckpoints, err := ledgerV2Tables(name)
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
	rows, err := loadLedgerRows(name, withExt, fmt.Sprintf(
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
	dir := AnchorDir(name)
	path := filepath.Join(dir, ledger.AnchorFileName(a.ToID))
	lines, err := ledgerLines(name, fmt.Sprintf(`INSERT INTO bb.ledger_checkpoints
  (from_id, to_id, entry_count, last_row_hash, merkle_root, prev_root, algorithm, anchor_uri)
  VALUES (%d, %d, %d, %s, %s, %s, %s, %s) RETURNING id`,
		a.FromID, a.ToID, a.EntryCount, quoteLiteral(a.LastRowHash), quoteLiteral(a.MerkleRoot),
		quoteLiteral(a.PrevRoot), quoteLiteral(a.Algorithm), quoteLiteral(path)))
	if err != nil {
		return nil, "", fmt.Errorf("recording the checkpoint: %w", err)
	}
	if len(lines) == 0 {
		return nil, "", errors.New("recording the checkpoint: no id returned")
	}
	if a.CheckpointID, err = strconv.ParseInt(lines[0], 10, 64); err != nil {
		return nil, "", fmt.Errorf("recording the checkpoint: unexpected id %q", lines[0])
	}
	if _, err := ledger.WriteAnchor(dir, a); err != nil {
		return &a, "", fmt.Errorf("checkpoint %d was recorded but its anchor could not be written: %w", a.CheckpointID, err)
	}
	if truthyEnv("FOX_ANCHOR_IMMUTABLE") {
		if err := exec.Command("sudo", "chattr", "+i", path).Run(); err != nil {
			log.Printf("anchor %s: chattr +i failed (%v) — the file is read-only but not immutable", path, err)
		}
	}
	return &a, path, nil
}

// Integrity checks a branch's whole ledger against the anchor files in its
// anchor directory.
func Integrity(name string) (ledger.Report, error) {
	name, err := ledgerBranchName(name)
	if err != nil {
		return ledger.Report{}, err
	}
	withExt, hasCheckpoints, err := ledgerV2Tables(name)
	if err != nil {
		return ledger.Report{}, err
	}
	rows, err := loadLedgerRows(name, withExt, "")
	if err != nil {
		return ledger.Report{}, err
	}
	dir := AnchorDir(name)
	anchors, err := ledger.LoadAnchors(dir)
	if err != nil {
		return ledger.Report{}, err
	}
	rep := ledger.Verify(rows, anchors)
	if hasCheckpoints {
		if lines, err := ledgerLines(name, "SELECT count(*) FROM bb.ledger_checkpoints"); err == nil && len(lines) > 0 {
			if n, _ := strconv.Atoi(lines[0]); n != len(anchors) {
				rep.Notes = append(rep.Notes, fmt.Sprintf(
					"the database lists %d checkpoint(s); %d anchor file(s) are in %s — the anchor files are the source of truth",
					n, len(anchors), dir))
			}
		}
	} else {
		rep.Notes = append(rep.Notes, "ledger checkpoints are not installed on this branch — run: fox ledger upgrade "+name)
	}
	return rep, nil
}

// ExportLedger writes every ledger row of a branch, with its capture columns, as
// JSON lines — a file fox-verify can check offline against the anchors.
func ExportLedger(name string, w io.Writer) error {
	name, err := ledgerBranchName(name)
	if err != nil {
		return err
	}
	withExt, _, err := ledgerV2Tables(name)
	if err != nil {
		return err
	}
	lines, err := ledgerLines(name, ledger.ExportQuery(withExt))
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

func envDurationOr(key string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(strings.TrimSpace(brand.GetenvFull(key))); err == nil && d > 0 {
		return d
	}
	return def
}

func envIntOr(key string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(brand.GetenvFull(key))); err == nil && n > 0 {
		return n
	}
	return def
}

// pendingCheckpointRows counts ledger rows not yet checkpointed on a branch, or
// -1 when checkpoints aren't installed there.
func pendingCheckpointRows(name string) (int, error) {
	_, hasCheckpoints, err := ledgerV2Tables(name)
	if err != nil || !hasCheckpoints {
		return -1, err
	}
	lines, err := ledgerLines(name, "SELECT count(*) FROM bb.schema_ledger WHERE id > "+
		"(SELECT coalesce(max(to_id), 0) FROM bb.ledger_checkpoints)")
	if err != nil || len(lines) == 0 {
		return -1, err
	}
	return strconv.Atoi(lines[0])
}

// StartCheckpointer anchors new ledger entries on every running branch in the
// background: once FOX_CHECKPOINT_INTERVAL (default 10m) has passed since
// the branch's last checkpoint, or sooner when FOX_CHECKPOINT_ENTRIES
// (default 500) entries are waiting. It only looks at branches that are already
// running, so it never wakes a suspended one. FOX_CHECKPOINTS=off disables it.
func StartCheckpointer() {
	switch strings.ToLower(strings.TrimSpace(brand.Getenv("CHECKPOINTS"))) {
	case "off", "0", "false", "no":
		log.Printf("ledger checkpoints: scheduler disabled (FOX_CHECKPOINTS)")
		return
	}
	interval := envDurationOr("FOX_CHECKPOINT_INTERVAL", 10*time.Minute)
	threshold := envIntOr("FOX_CHECKPOINT_ENTRIES", 500)
	tick := interval
	if tick > 2*time.Minute {
		tick = 2 * time.Minute
	}
	log.Printf("ledger checkpoints: every %s or %d entries, checked every %s", interval, threshold, tick)
	go func() {
		last := map[string]time.Time{}
		t := time.NewTicker(tick)
		defer t.Stop()
		for range t.C {
			names, err := RunningBranches()
			if err != nil {
				continue
			}
			for _, n := range names {
				pending, err := pendingCheckpointRows(n)
				if err != nil || pending <= 0 {
					continue
				}
				if pending < threshold && time.Since(last[n]) < interval {
					continue
				}
				last[n] = time.Now()
				a, _, err := Checkpoint(n)
				if err != nil {
					log.Printf("ledger checkpoint %s: %v", n, err)
					continue
				}
				if a != nil {
					log.Printf("ledger checkpoint %s #%d: ids %d–%d (%d entries), root %s",
						n, a.CheckpointID, a.FromID, a.ToID, a.EntryCount, a.MerkleRoot)
				}
			}
		}
	}()
}
