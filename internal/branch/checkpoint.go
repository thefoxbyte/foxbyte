// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"io"
	"log"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/edition"
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

// AnchorKeyPath is the Ed25519 key that signs anchors: FOX_ANCHOR_KEY, or
// ~/.fox/anchor-signing.key. Its public key is beside it, with ".pub" added.
// The databases cannot read either; point FOX_ANCHOR_KEY at a mounted secret
// to keep the key off the machine's own disk.
func AnchorKeyPath() string {
	if p := strings.TrimSpace(brand.Getenv("ANCHOR_KEY")); p != "" {
		return p
	}
	return brand.StatePath("anchor-signing.key")
}

// AnchorPublicKey returns the public key anchors are signed with, creating the
// key pair if there is none yet.
func AnchorPublicKey() (ed25519.PublicKey, string, error) {
	key, err := ledger.LoadOrCreateSigningKey(AnchorKeyPath())
	if err != nil {
		return nil, "", err
	}
	return key.Public().(ed25519.PublicKey), AnchorKeyPath() + ".pub", nil
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

// Checkpoint anchors a branch's ledger entries added since its last checkpoint.
// It returns (nil, "", nil) when there is nothing new. It refuses to anchor rows
// whose hash chain is already broken.

// Checkpoint anchors a branch's new ledger entries outside the database.
//
// The gate lives here rather than only at the CLI and the REST route, because
// this is the one function that writes an anchor: the scheduler calls it too,
// and a future caller would otherwise have to remember.
func Checkpoint(name string) (*ledger.Anchor, string, error) {
	if err := requireFeature(edition.Anchors); err != nil {
		return nil, "", err
	}
	if writeAnchor == nil {
		return nil, "", ErrAnchorsNotLicensed
	}
	return writeAnchor(name)
}

// The paid half, supplied by enterprise/anchor in an Enterprise build and nil
// in a Standard one. Reading stays here — Integrity below, AnchorDir,
// AnchorPublicKey and the security log's own anchors in seclog.go — so an
// install that anchored before changing edition can still prove it.
var (
	writeAnchor  func(name string) (*ledger.Anchor, string, error)
	exportLedger func(name string, w io.Writer) error
)

// SetAnchorWriter installs them. Called from enterprise/anchor's init, and from
// nowhere else.
func SetAnchorWriter(write func(string) (*ledger.Anchor, string, error), export func(string, io.Writer) error) {
	writeAnchor, exportLedger = write, export
}

// ExportLedger writes every ledger row of a branch, with its capture columns,
// as JSON lines — a file fox-verify can check offline against the anchors.
func ExportLedger(name string, w io.Writer) error {
	// fox-verify keeps working without this. It reads the live database with
	// --dsn, so the free verification path does not depend on a paid export —
	// which it would, if this were the only way to produce the file it checks.
	if err := requireFeature(edition.Export); err != nil {
		return err
	}
	if exportLedger == nil {
		return ErrExportNotLicensed
	}
	return exportLedger(name, w)
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
	if pub, err := ledger.ReadPublicKey(AnchorKeyPath() + ".pub"); err == nil {
		ledger.VerifySignatures(&rep, anchors, pub)
	}
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
	// Say why nothing new is being anchored, or this reads as a fault.
	//
	// An install that upgrades into the gating keeps the anchors it already
	// has, and they keep verifying — the summary would just show a number of
	// unanchored rows climbing with no explanation, which looks exactly like a
	// checkpointer that has stopped working. The difference between a broken
	// install and an unlicensed feature is the whole of this sentence.
	if !edition.Has(edition.Anchors) && rep.UnanchoredRows > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf(
			"%d row(s) will stay unanchored: %v. The chain above is still checked in full, "+
				"and anchors already written still verify.", rep.UnanchoredRows, ErrAnchorsNotLicensed))
	}
	return rep, nil
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
// saidWhyNotAnchoring keeps the scheduler from repeating itself every tick.
// The reason is worth saying once and worth saying clearly; saying it every two
// minutes would bury the log it is written into.
var saidWhyNotAnchoring sync.Once

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
		store, serr := auth.OpenFromEnv()
		if serr != nil {
			log.Printf("security log checkpoints: %v", serr)
		}
		for range t.C {
			// The security log, on the same schedule as the branches.
			if store != nil && time.Since(last[secLogAnchorDir]) >= interval {
				last[secLogAnchorDir] = time.Now()
				if a, err := CheckpointSecurityLog(store); err != nil {
					log.Printf("security log checkpoint: %v", err)
				} else if a != nil {
					log.Printf("security log checkpoint: events %d–%d", a.FromID, a.ToID)
				}
			}
			// The branch ledgers' half, and only this half. The security
			// log above keeps anchoring in every edition.
			if !edition.Has(edition.Anchors) {
				saidWhyNotAnchoring.Do(func() {
					log.Printf("ledger checkpoints: not anchoring branch ledgers — %v "+
						"(the security log is still anchored, and existing anchors still verify)",
						ErrAnchorsNotLicensed)
				})
				continue
			}
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
