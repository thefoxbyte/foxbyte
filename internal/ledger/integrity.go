// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

// Integrity checking for the Blackbox, shared by the engine
// (`fox ledger checkpoint|integrity`) and the standalone fox-verify tool.
//
// This file uses only the Go standard library on purpose: it is everything an
// auditor needs to trust to check the ledger, so it stays small, readable, and
// independent of the engine, the database and the network.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// AnchorFormat identifies version 1 of the checkpoint anchor format described in
// docs/ledger-anchor-format.md. Verifiers reject any other value.
const AnchorFormat = "ledger-anchor/1"

// MerkleAlgorithm names how merkle_root is computed (see LeafHash and MerkleRoot).
const MerkleAlgorithm = "sha256-merkle-v1"

// maxProblems caps how many individual problems a report lists.
const maxProblems = 25

// Row is one Blackbox entry and its 2.0 capture hash. NULL columns are "".
type Row struct {
	ID             int64
	At             time.Time
	Actor          string
	ActorKind      string
	Tool           string
	Session        string
	Branch         string
	CommandTag     string
	ObjectType     string
	ObjectIdentity string
	Statement      string
	Status         string
	Risk           string
	PrevHash       string
	RowHash        string // "" for legacy rows written before hash chaining
	ExtHash        string // "" when the row has no 2.0 capture
}

// RowHash recomputes a row's hash exactly as bb._ledger_hash does in SQL: sha256
// over the fields joined with '|', NULLs as empty strings, `at` as UTC text.
func RowHash(r Row) string {
	s := strings.Join([]string{
		r.PrevHash, strconv.FormatInt(r.ID, 10), FormatAt(r.At),
		r.Actor, r.ActorKind, r.Tool, r.Session, r.Branch, r.CommandTag,
		r.ObjectType, r.ObjectIdentity, r.Statement, r.Status, r.Risk,
	}, "|")
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// FormatAt renders a timestamp the way PostgreSQL prints
// (at AT TIME ZONE 'UTC')::text: "2006-01-02 15:04:05", plus a fractional part
// with trailing zeros removed when there is one.
func FormatAt(t time.Time) string {
	u := t.UTC()
	s := u.Format("2006-01-02 15:04:05")
	if us := u.Nanosecond() / 1000; us != 0 {
		s += "." + strings.TrimRight(fmt.Sprintf("%06d", us), "0")
	}
	return s
}

// LeafHash is a checkpoint leaf: sha256(0x00 || row_hash || "|" || ext_hash),
// where row_hash is the row's recomputed hash (hex) and ext_hash its capture
// hash (hex, or empty). The 0x00 prefix separates leaves from inner nodes.
func LeafHash(rowHash, extHash string) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write([]byte(rowHash))
	h.Write([]byte("|"))
	h.Write([]byte(extHash))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// MerkleRoot combines leaves pairwise as sha256(0x01 || left || right) until one
// node remains, duplicating the last node of any odd-sized level. It returns the
// root as hex, or "" for no leaves.
func MerkleRoot(leaves [][32]byte) string {
	if len(leaves) == 0 {
		return ""
	}
	level := append([][32]byte(nil), leaves...)
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		next := make([][32]byte, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			h := sha256.New()
			h.Write([]byte{0x01})
			h.Write(level[i][:])
			h.Write(level[i+1][:])
			var n [32]byte
			copy(n[:], h.Sum(nil))
			next = append(next, n)
		}
		level = next
	}
	return hex.EncodeToString(level[0][:])
}

// rootOf is the Merkle root over rows, each leaf built from the row's
// recomputed hash, so it commits to the row contents themselves.
func rootOf(rows []Row) string {
	leaves := make([][32]byte, len(rows))
	for i, r := range rows {
		leaves[i] = LeafHash(RowHash(r), r.ExtHash)
	}
	return MerkleRoot(leaves)
}

// Anchor is one checkpoint as written outside the database. Its JSON form is the
// published anchor format.
type Anchor struct {
	Format       string    `json:"format"`
	Algorithm    string    `json:"algorithm"`
	Branch       string    `json:"branch"`
	CheckpointID int64     `json:"checkpoint_id"`
	FromID       int64     `json:"from_id"`
	ToID         int64     `json:"to_id"`
	EntryCount   int       `json:"entry_count"`
	LastRowHash  string    `json:"last_row_hash"`
	MerkleRoot   string    `json:"merkle_root"`
	PrevRoot     string    `json:"prev_root"`
	CreatedAt    time.Time `json:"created_at"`
	// KeyID and Signature are present on anchors written since 22 Sep 2026:
	// an Ed25519 signature over SigningPayload, by the key KeyID names (see
	// sign.go). Older anchors have neither.
	KeyID     string `json:"key_id,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// BuildAnchor checkpoints rows — every ledger row with an id from fromID up to
// the last row's id, in ascending order. prevRoot is the previous checkpoint's
// merkle_root ("" for the first).
func BuildAnchor(branch string, fromID int64, prevRoot string, rows []Row) (Anchor, error) {
	if len(rows) == 0 {
		return Anchor{}, errors.New("no ledger rows to checkpoint")
	}
	for i, r := range rows {
		if r.ID < fromID || (i > 0 && r.ID <= rows[i-1].ID) {
			return Anchor{}, fmt.Errorf("rows must have ascending ids starting at or after %d (row %d)", fromID, r.ID)
		}
	}
	last := rows[len(rows)-1]
	return Anchor{
		Format:      AnchorFormat,
		Algorithm:   MerkleAlgorithm,
		Branch:      branch,
		FromID:      fromID,
		ToID:        last.ID,
		EntryCount:  len(rows),
		LastRowHash: RowHash(last),
		MerkleRoot:  rootOf(rows),
		PrevRoot:    prevRoot,
		CreatedAt:   time.Now().UTC(),
	}, nil
}

// AnchorFileName is the file an anchor is stored in: its to_id, zero-padded so
// files sort in checkpoint order.
func AnchorFileName(toID int64) string { return fmt.Sprintf("%020d.json", toID) }

// WriteAnchor writes a to dir as a read-only file and returns its path. It never
// overwrites an existing anchor.
func WriteAnchor(dir string, a Anchor) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, AnchorFileName(a.ToID))
	if _, err := os.Lstat(path); err == nil {
		return "", fmt.Errorf("anchor %s already exists", path)
	}
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return "", err
	}
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return "", err
	}
	if err := os.Chmod(tmp, 0o444); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return path, nil
}

// LoadAnchors reads every *.json anchor in dir. A missing directory means no
// anchors, not an error.
func LoadAnchors(dir string) ([]Anchor, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Anchor
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var a Anchor
		if err := json.Unmarshal(b, &a); err != nil {
			return nil, fmt.Errorf("anchor %s: %w", e.Name(), err)
		}
		out = append(out, a)
	}
	return out, nil
}

// Report is the outcome of checking a ledger against its anchors.
type Report struct {
	Intact         bool     `json:"intact"`
	Rows           int      `json:"rows"`
	ChainedRows    int      `json:"chained_rows"`
	LegacyRows     int      `json:"legacy_rows"`
	Checkpoints    int      `json:"checkpoints"`
	AnchoredRows   int      `json:"anchored_rows"`
	UnanchoredRows int      `json:"unanchored_rows"`
	FirstBrokenID  int64    `json:"first_broken_id,omitempty"`
	Problems       []string `json:"problems"`
	Notes          []string `json:"notes"`
}

func (r *Report) problem(format string, args ...any) {
	if len(r.Problems) < maxProblems {
		r.Problems = append(r.Problems, fmt.Sprintf(format, args...))
	} else if len(r.Problems) == maxProblems {
		r.Problems = append(r.Problems, "…further problems omitted")
	}
}

type chainResult struct {
	chained, legacy int
	firstBroken     int64
	problems        []string
}

// chainCheck walks rows in id order, recomputing each chained row's hash and its
// link to the previous chained row — the same check `fox ledger verify` runs in
// SQL. prev is the row_hash the first chained row must link to.
func chainCheck(rows []Row, prev string) chainResult {
	var c chainResult
	for _, r := range rows {
		if r.RowHash == "" {
			c.legacy++
			continue
		}
		c.chained++
		broken := false
		if RowHash(r) != r.RowHash {
			c.problems = append(c.problems, fmt.Sprintf("ledger id %d: its contents no longer match its hash (edited)", r.ID))
			broken = true
		}
		if r.PrevHash != prev {
			c.problems = append(c.problems, fmt.Sprintf("ledger id %d: chain link broken (an earlier row was removed or rewritten)", r.ID))
			broken = true
		}
		if broken && c.firstBroken == 0 {
			c.firstBroken = r.ID
		}
		prev = r.RowHash
	}
	return c
}

// CheckChain returns the first hash-chain problem in rows (ascending ids), given
// the last chained row before them (nil if there is none).
func CheckChain(pred *Row, rows []Row) error {
	prev := ""
	if pred != nil {
		prev = pred.RowHash
	}
	if c := chainCheck(rows, prev); len(c.problems) > 0 {
		return errors.New(c.problems[0])
	}
	return nil
}

// Verify checks a whole ledger (all rows) against its anchors. The anchors are
// the source of truth: a ledger whose hash chain was rewritten consistently still
// fails here, because its rows no longer produce the anchored Merkle roots.
func Verify(rows []Row, anchors []Anchor) Report {
	rep := Report{Problems: []string{}, Notes: []string{}}
	rows = append([]Row(nil), rows...)
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	rep.Rows = len(rows)

	c := chainCheck(rows, "")
	rep.ChainedRows, rep.LegacyRows, rep.FirstBrokenID = c.chained, c.legacy, c.firstBroken
	for _, p := range c.problems {
		rep.problem("%s", p)
	}

	anchors = append([]Anchor(nil), anchors...)
	sort.Slice(anchors, func(i, j int) bool { return anchors[i].ToID < anchors[j].ToID })
	rep.Checkpoints = len(anchors)
	for i, a := range anchors {
		label := fmt.Sprintf("checkpoint %d (ledger ids %d–%d)", a.CheckpointID, a.FromID, a.ToID)
		if a.Format != AnchorFormat {
			rep.problem("%s: unknown anchor format %q", label, a.Format)
			continue
		}
		if i > 0 {
			p := anchors[i-1]
			if a.FromID != p.ToID+1 {
				rep.problem("%s does not continue checkpoint %d (ids %d–%d): anchors are missing or overlap", label, p.CheckpointID, p.FromID, p.ToID)
			}
			if a.PrevRoot != p.MerkleRoot {
				rep.problem("%s: anchor chain broken (prev_root does not match checkpoint %d)", label, p.CheckpointID)
			}
		} else if a.PrevRoot != "" {
			rep.Notes = append(rep.Notes, fmt.Sprintf("the earliest anchor here (%s) continues an older checkpoint whose anchor file is not present; rows before id %d are only hash-chain checked", label, a.FromID))
		}
		lo := sort.Search(len(rows), func(k int) bool { return rows[k].ID >= a.FromID })
		hi := sort.Search(len(rows), func(k int) bool { return rows[k].ID > a.ToID })
		in := rows[lo:hi]
		rep.AnchoredRows += len(in)
		if len(in) != a.EntryCount {
			rep.problem("%s: %d rows were anchored but the ledger now has %d in that range (rows deleted or inserted)", label, a.EntryCount, len(in))
			continue
		}
		if rootOf(in) != a.MerkleRoot {
			rep.problem("%s: the rows no longer match what was anchored (Merkle root mismatch)", label)
			continue
		}
		if RowHash(in[len(in)-1]) != a.LastRowHash {
			rep.problem("%s: the last anchored row differs from its anchor", label)
		}
	}

	if len(anchors) == 0 {
		rep.UnanchoredRows = len(rows)
	} else {
		first, last := anchors[0].FromID, anchors[len(anchors)-1].ToID
		for _, r := range rows {
			if r.ID < first || r.ID > last {
				rep.UnanchoredRows++
			}
		}
	}
	rep.Intact = len(rep.Problems) == 0
	return rep
}

// Summary renders the report for a terminal. The first line starts with
// "ledger integrity: INTACT" or "ledger integrity: TAMPERED".
func (r Report) Summary() string {
	var b strings.Builder
	state := "INTACT"
	if !r.Intact {
		state = "TAMPERED"
	}
	fmt.Fprintf(&b, "ledger integrity: %s — %d rows (%d hash-chained", state, r.Rows, r.ChainedRows)
	if r.LegacyRows > 0 {
		fmt.Fprintf(&b, ", %d unchained legacy", r.LegacyRows)
	}
	b.WriteString(")")
	if r.Checkpoints == 0 {
		b.WriteString("; no checkpoint anchors found")
	} else {
		fmt.Fprintf(&b, "; %d checkpoint anchor(s) cover %d rows", r.Checkpoints, r.AnchoredRows)
	}
	if r.UnanchoredRows > 0 {
		fmt.Fprintf(&b, "; %d row(s) not yet anchored", r.UnanchoredRows)
	}
	for _, p := range r.Problems {
		b.WriteString("\n  ✗ " + p)
	}
	for _, n := range r.Notes {
		b.WriteString("\n  · " + n)
	}
	return b.String()
}

// rowJSON is a ledger row as produced by RowsQuery or ExportQuery (row_to_json).
type rowJSON struct {
	ID             int64   `json:"id"`
	At             string  `json:"at"`
	Actor          *string `json:"actor"`
	ActorKind      *string `json:"actor_kind"`
	Tool           *string `json:"tool"`
	Session        *string `json:"session"`
	Branch         *string `json:"branch"`
	CommandTag     *string `json:"command_tag"`
	ObjectType     *string `json:"object_type"`
	ObjectIdentity *string `json:"object_identity"`
	Statement      *string `json:"statement"`
	Status         *string `json:"status"`
	Risk           *string `json:"risk"`
	PrevHash       *string `json:"prev_hash"`
	RowHash        *string `json:"row_hash"`
	ExtHash        *string `json:"ext_hash"`
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// DecodeRowJSON parses one ledger row from its JSON form. Unknown fields (such as
// the extra capture columns in an export) are ignored.
func DecodeRowJSON(b []byte) (Row, error) {
	var j rowJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return Row{}, err
	}
	at, err := time.Parse(time.RFC3339Nano, j.At)
	if err != nil {
		return Row{}, fmt.Errorf("ledger id %d: bad timestamp %q: %w", j.ID, j.At, err)
	}
	return Row{
		ID: j.ID, At: at,
		Actor: deref(j.Actor), ActorKind: deref(j.ActorKind), Tool: deref(j.Tool),
		Session: deref(j.Session), Branch: deref(j.Branch), CommandTag: deref(j.CommandTag),
		ObjectType: deref(j.ObjectType), ObjectIdentity: deref(j.ObjectIdentity),
		Statement: deref(j.Statement), Status: deref(j.Status), Risk: deref(j.Risk),
		PrevHash: deref(j.PrevHash), RowHash: deref(j.RowHash), ExtHash: deref(j.ExtHash),
	}, nil
}

const rowColumns = "s.id, s.at, s.actor, s.actor_kind, s.tool, s.session, s.branch, s.command_tag, " +
	"s.object_type, s.object_identity, s.statement, s.status, s.risk, s.prev_hash, s.row_hash"

// RowsQuery selects ledger rows as one JSON document per row, in id order, with
// each row's capture hash when the 2.0 capture table exists. where may be empty.
func RowsQuery(withExt bool, where string) string {
	ext, join := "NULL::text AS ext_hash", ""
	if withExt {
		ext, join = "e.ext_hash", " LEFT JOIN bb.ledger_ext e ON e.ledger_id = s.id"
	}
	return "SELECT row_to_json(x)::text FROM (SELECT " + rowColumns + ", " + ext +
		" FROM bb.schema_ledger s" + join + " " + where + " ORDER BY s.id) x"
}

// ExportQuery selects every ledger row with all of its capture columns, one JSON
// document per row in id order — the `fox ledger export` format.
func ExportQuery(withExt bool) string {
	if !withExt {
		return RowsQuery(false, "")
	}
	return "SELECT row_to_json(x)::text FROM (SELECT " + rowColumns +
		", e.ext_hash, e.xid, e.lsn, e.task_id, e.parent_session, e.call_hash, e.override_used" +
		" FROM bb.schema_ledger s LEFT JOIN bb.ledger_ext e ON e.ledger_id = s.id ORDER BY s.id) x"
}
