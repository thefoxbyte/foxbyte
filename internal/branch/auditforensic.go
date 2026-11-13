// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// Forensic mode and retention (F6 Gate 1, step 5a; design, sections 10 and
// 11).
//
// Forensic mode turns on pgAudit's statement text, literals and all, for the
// whole install or one branch, switched on deliberately by an admin with a
// reason. Parameters stay off in both modes: F1's tokens are parameters.
//
// The text is personal data in a way the rest of a record is not, so it is
// kept apart from the chain. A record holds the text's SHA-256; the text goes
// to a forensic file of its own, kept 30 days by default, and purged for a
// person on request (F4). Removing it breaks nothing: the chain never held it.
// verify checks every text still kept against the hash its record holds.

// AuditSettings are the admin's choices, in the state directory, as the audit
// marker is.
type AuditSettings struct {
	RetentionDays int `json:"retention_days,omitempty"`
	ForensicDays  int `json:"forensic_days,omitempty"`
	// Forensic is where forensic mode is on: "" for the whole install, or a
	// branch's name, with who turned it on, why and when.
	Forensic map[string]ForensicGrant `json:"forensic,omitempty"`
	// Forward is where records are forwarded (step 5b), nil when nowhere.
	Forward *AuditForward `json:"forward,omitempty"`
}

// ForensicGrant is forensic mode turned on somewhere.
type ForensicGrant struct {
	By     string `json:"by"`
	Reason string `json:"reason"`
	Since  string `json:"since"` // RFC 3339
}

// auditSettingsPath is a variable so a test can keep it somewhere harmless.
var auditSettingsPath = func() string { return brand.StatePath("audit-settings.json") }

// LoadAuditSettings reads the settings; none is defaults.
func LoadAuditSettings() AuditSettings {
	var s AuditSettings
	if b, err := os.ReadFile(auditSettingsPath()); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	if s.Forensic == nil {
		s.Forensic = map[string]ForensicGrant{}
	}
	return s
}

func saveAuditSettings(s AuditSettings) error {
	b, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(auditSettingsPath()), 0o700); err != nil {
		return err
	}
	tmp := auditSettingsPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, auditSettingsPath())
}

const defaultForensicDays = 30

// AuditRetentionDays is how long records are kept: the setting, else
// FOX_AUDIT_RETENTION_DAYS, else a year.
func AuditRetentionDays() int {
	if d := LoadAuditSettings().RetentionDays; d > 0 {
		return d
	}
	if n, err := strconv.Atoi(strings.TrimSpace(brand.Getenv(envAuditRetention))); err == nil && n > 0 {
		return n
	}
	return 365
}

// ForensicRetentionDays is how long statement text is kept: the setting, else
// 30 days, and never longer than the records it belongs to.
func ForensicRetentionDays() int {
	d := LoadAuditSettings().ForensicDays
	if d <= 0 {
		d = defaultForensicDays
	}
	return min(d, AuditRetentionDays())
}

// SetAuditRetention sets how long records are kept, or statement text when
// forensic is set. 1 to 3650 days; text never longer than records.
func SetAuditRetention(days int, forensic bool) error {
	if days < 1 || days > 3650 {
		return fmt.Errorf("retention is 1 to 3650 days, not %d", days)
	}
	s := LoadAuditSettings()
	if forensic {
		if days > AuditRetentionDays() {
			return fmt.Errorf("statement text cannot be kept longer than the records it belongs to (%d days)", AuditRetentionDays())
		}
		s.ForensicDays = days
	} else {
		if s.ForensicDays > days {
			s.ForensicDays = days
		}
		s.RetentionDays = days
	}
	return saveAuditSettings(s)
}

// ForensicFor reports whether a database runs in forensic mode.
func ForensicFor(name string) bool {
	s := LoadAuditSettings()
	_, all := s.Forensic[""]
	_, one := s.Forensic[name]
	return all || one
}

// SetForensic turns forensic mode on or off for the whole install (branch
// "") or one branch, and applies it at once to every running database it
// covers: the mode is a reload, never a restart. Returns the databases it
// reached.
func SetForensic(branchName string, on bool, by, reason string) ([]string, error) {
	if branchName != "" {
		if err := checkName(branchName); err != nil {
			return nil, err
		}
	}
	if on && strings.TrimSpace(reason) == "" {
		return nil, errors.New("forensic mode records what statements held: say why it is needed (--reason)")
	}
	s := LoadAuditSettings()
	if on {
		s.Forensic[branchName] = ForensicGrant{By: by, Reason: strings.TrimSpace(reason), Since: time.Now().UTC().Format(time.RFC3339)}
	} else {
		delete(s.Forensic, branchName)
	}
	if err := saveAuditSettings(s); err != nil {
		return nil, err
	}
	names, err := RunningBranches()
	if err != nil {
		return nil, err
	}
	var reached []string
	for _, n := range names {
		if branchName != "" && n != branchName {
			continue
		}
		if !runsWithAudit(n) {
			continue
		}
		if err := EnsureAuditPolicy(n); err != nil {
			return reached, fmt.Errorf("applying the mode to %s: %w", n, err)
		}
		reached = append(reached, n)
	}
	return reached, nil
}

// --- the forensic text, beside the chain ---------------------------------

// forensicText is one statement's text, kept beside its record.
type forensicText struct {
	Seq    int64  `json:"seq"`
	Branch string `json:"branch"`
	Login  string `json:"login,omitempty"`
	Text   string `json:"text"`
}

func forensicDir() string            { return filepath.Join(AuditStoreDir(), "forensic") }
func forensicPath(day string) string { return filepath.Join(forensicDir(), day+".jsonl.gz") }

// appendForensic keeps the text of the records that have one.
func appendForensic(day string, recs []AuditRecord) error {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	enc := json.NewEncoder(zw)
	n := 0
	for _, r := range recs {
		if r.Text == "" {
			continue
		}
		if err := enc.Encode(forensicText{Seq: r.Seq, Branch: r.Branch, Login: r.Login, Text: r.Text}); err != nil {
			return err
		}
		n++
	}
	if n == 0 {
		return nil
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := os.MkdirAll(forensicDir(), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(forensicPath(day), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(buf.Bytes()); err != nil {
		return err
	}
	return f.Sync()
}

func readForensic(day string) ([]forensicText, error) {
	f, err := os.Open(forensicPath(day))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, err
	}
	defer zr.Close()
	var out []forensicText
	dec := json.NewDecoder(zr)
	for {
		var t forensicText
		if err := dec.Decode(&t); err == io.EOF {
			return out, nil
		} else if err != nil {
			return out, fmt.Errorf("forensic text of %s: %w", day, err)
		}
		out = append(out, t)
	}
}

func forensicDays() []string {
	files, _ := filepath.Glob(filepath.Join(forensicDir(), "*.jsonl.gz"))
	var days []string
	for _, f := range files {
		days = append(days, strings.TrimSuffix(filepath.Base(f), ".jsonl.gz"))
	}
	sort.Strings(days)
	return days
}

// forensicTexts reads every text kept, by record number.
func forensicTexts() (map[int64]forensicText, error) {
	out := map[int64]forensicText{}
	for _, day := range forensicDays() {
		ts, err := readForensic(day)
		if err != nil {
			return out, err
		}
		for _, t := range ts {
			out[t.Seq] = t
		}
	}
	return out, nil
}

// pruneForensic removes statement text older than its retention, whole days.
func pruneForensic(cutoff string) (int, error) {
	n := 0
	for _, day := range forensicDays() {
		if day >= cutoff {
			break
		}
		if err := os.Remove(forensicPath(day)); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// PurgeForensic removes every statement text a login's statements left, for a
// request about that person's data (F4). Their records stay, with the hash
// of a text no longer kept: what was done stays, what it held goes. Returns
// how many texts went.
func PurgeForensic(login string) (int, error) {
	if strings.TrimSpace(login) == "" {
		return 0, errors.New("whose statement text: a login")
	}
	unlock, err := lockAuditStore()
	if err != nil {
		return 0, err
	}
	defer unlock()
	removed := 0
	for _, day := range forensicDays() {
		ts, err := readForensic(day)
		if err != nil {
			return removed, err
		}
		var keep []forensicText
		for _, t := range ts {
			if t.Login == login {
				removed++
				continue
			}
			keep = append(keep, t)
		}
		if len(keep) == len(ts) {
			continue
		}
		if err := rewriteForensic(day, keep); err != nil {
			return removed, err
		}
	}
	return removed, nil
}

// rewriteForensic writes a day's texts anew: they are not chained, so they
// may be.
func rewriteForensic(day string, ts []forensicText) error {
	if len(ts) == 0 {
		return os.Remove(forensicPath(day))
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	enc := json.NewEncoder(zw)
	for _, t := range ts {
		if err := enc.Encode(t); err != nil {
			return err
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	tmp := forensicPath(day) + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, forensicPath(day))
}

// verifyForensic checks each text kept against the hash its record holds, and
// that a text belongs to a record at all.
func verifyForensic(recs []AuditRecord, texts map[int64]forensicText) []string {
	bySeq := map[int64]AuditRecord{}
	for _, r := range recs {
		bySeq[r.Seq] = r
	}
	var problems []string
	seqs := make([]int64, 0, len(texts))
	for s := range texts {
		seqs = append(seqs, s)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	for _, s := range seqs {
		r, ok := bySeq[s]
		sum := sha256.Sum256([]byte(texts[s].Text))
		switch {
		case !ok:
			// A record removed by retention before its text: a text whose
			// record is gone proves nothing either way, unless its record is
			// still meant to be there.
			continue
		case r.TextSHA == "":
			problems = append(problems, fmt.Sprintf("record %d had no statement text, and text is kept for it", s))
		case hex.EncodeToString(sum[:]) != r.TextSHA:
			problems = append(problems, fmt.Sprintf("the statement text kept for record %d is not the text it recorded", s))
		}
	}
	return problems
}

// ForensicText is one statement's text from forensic mode, as the Aadhaar
// exposure report's logs part reads it (point 4.5b), with when it ran.
type ForensicText struct {
	Seq   int64
	Login string
	Text  string
	At    time.Time
}

// ScanForensicTexts reads every statement text kept for a branch, day by day,
// and hands fn those keep accepts, each with its record's time (the day it was
// collected, when its record cannot be found). It returns how many texts the
// branch has. Texts are read one day at a time, and records only for a day
// that had a text kept.
func ScanForensicTexts(branchName string, keep func(text string) bool, fn func(ForensicText)) (int, error) {
	n := 0
	for _, day := range forensicDays() {
		ts, err := readForensic(day)
		if err != nil {
			return n, err
		}
		var kept []ForensicText
		want := map[int64]int{}
		for _, t := range ts {
			if t.Branch != branchName {
				continue
			}
			n++
			if keep(t.Text) {
				want[t.Seq] = len(kept)
				kept = append(kept, ForensicText{Seq: t.Seq, Login: t.Login, Text: t.Text})
			}
		}
		if len(kept) == 0 {
			continue
		}
		dayStart, _ := time.Parse("2006-01-02", day)
		for i := range kept {
			kept[i].At = dayStart.UTC()
		}
		if _, err := os.Stat(dayPath(day)); err == nil {
			if err := scanDay(day, func(r AuditRecord) {
				if i, ok := want[r.Seq]; ok {
					if at, err := time.Parse(time.RFC3339Nano, r.Time); err == nil {
						kept[i].At = at.UTC()
					}
				}
			}); err != nil {
				return n, err
			}
		}
		for _, t := range kept {
			fn(t)
		}
	}
	return n, nil
}
