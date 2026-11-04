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
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The audit log's store and the collector that fills it (F6 Gate 1, step 3;
// design, section 9).
//
// PostgreSQL writes each database's log as JSON lines into its directory
// under AuditRoot, as the container's postgres user, readable by nobody else.
// The collector reads what is new there through sudo, as the engine reaches
// everything else it does not own, keeps the fields a record has, and appends
// them to the store: one gzip file per day under AuditRoot/.store, owned by
// this install's user, so the CLI and the console read it without sudo. A
// branch's name never starts with a dot, so the store is never taken for one.
//
// The raw files are deleted once collected and two days old: until then they
// hold the server's own lines (startups, checkpoints), which an operator
// reads, and which the store does not keep.
//
// Crash safety: a batch is appended to its day's file, then the state that
// says how far each raw file was read and how long each day's file is. A
// crash between the two leaves a day file longer than the state says, and the
// next collection cuts it back, so the batch is read again, once.

const (
	auditStoreName    = ".store"
	auditRawKeep      = 48 * time.Hour
	auditMaxRead      = 64 << 20 // per raw file per collection
	auditFirstBytes   = 4096     // enough to hold a raw file's first line, which is how it is recognised
	envAuditRetention = "AUDIT_RETENTION_DAYS"
)

// AuditStoreDir is where the records are kept. A variable so a test can keep
// them somewhere harmless.
var AuditStoreDir = func() string { return AuditRoot() + "/" + auditStoreName }

// auditState is how far the collector has got.
type auditState struct {
	Seq  int64    `json:"seq"`
	Head string   `json:"head"`
	Base struct { // the last record retention removed: the chain continues from it
		Seq  int64  `json:"seq"`
		Hash string `json:"hash"`
	} `json:"base"`
	Raw  map[string]rawPos `json:"raw"`  // branch/file -> how far it was read
	Days map[string]int64  `json:"days"` // day -> the size its file had when last written

	// What step 4's findings read (design, section 13).
	LastRun  string                 `json:"last_run,omitempty"` // the last collection that finished
	Sessions map[string]sessionMark `json:"sessions,omitempty"` // branch/session -> its last statement number
	Beats    map[string]string      `json:"beats,omitempty"`    // branch -> its last heartbeat's time
	Gaps     []AuditRecord          `json:"gaps,omitempty"`     // the newest gap records, at most auditGapsKept
}

const auditGapsKept = 200

type rawPos struct {
	Off   int64  `json:"off"`
	First string `json:"first"` // SHA-256 of the file's first line, which never changes once written
}

func statePath() string { return filepath.Join(AuditStoreDir(), "state.json") }

func loadAuditState() (auditState, error) {
	s := auditState{Raw: map[string]rawPos{}, Days: map[string]int64{}, Sessions: map[string]sessionMark{}, Beats: map[string]string{}}
	b, err := os.ReadFile(statePath())
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("reading the audit log's state: %w", err)
	}
	if s.Raw == nil {
		s.Raw = map[string]rawPos{}
	}
	if s.Days == nil {
		s.Days = map[string]int64{}
	}
	if s.Sessions == nil {
		s.Sessions = map[string]sessionMark{}
	}
	if s.Beats == nil {
		s.Beats = map[string]string{}
	}
	return s, nil
}

func saveAuditState(s auditState) error {
	b, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		return err
	}
	tmp := statePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, statePath())
}

func dayPath(day string) string { return filepath.Join(AuditStoreDir(), day+".jsonl.gz") }

// repairDays cuts each day file back to the size the state recorded, and
// removes one the state does not know: what a crash between appending and
// recording left behind, which is read again from the raw files.
//
// Only what is recognisably that. A batch is one gzip member, so a crash
// leaves bytes that begin, at exactly the recorded size, with gzip's magic
// number. A file that was edited and compressed again is longer or shorter
// in some other way, and is left as it is: cutting it would turn the
// evidence of an edit into a file that cannot be read, and verify reports it.
func repairDays(s auditState) error {
	files, _ := filepath.Glob(filepath.Join(AuditStoreDir(), "*.jsonl.gz"))
	for _, f := range files {
		day := strings.TrimSuffix(filepath.Base(f), ".jsonl.gz")
		want, known := s.Days[day]
		st, err := os.Stat(f)
		if err != nil {
			continue
		}
		switch {
		case !known:
			if err := os.Remove(f); err != nil {
				return err
			}
		case st.Size() > want && memberAt(f, want):
			if err := os.Truncate(f, want); err != nil {
				return err
			}
		case st.Size() != want:
			log.Printf("audit log: %s is %d bytes, and the collector wrote %d: it was changed, and is left for verify to report",
				filepath.Base(f), st.Size(), want)
		}
	}
	return nil
}

// collectDay is the day file a collection writes to.
func collectDay(now time.Time) string { return now.UTC().Format("2006-01-02") }

// memberAt reports whether a gzip member begins at off in a file.
func memberAt(path string, off int64) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	b := make([]byte, 2)
	if _, err := f.ReadAt(b, off); err != nil {
		return false
	}
	return b[0] == 0x1f && b[1] == 0x8b
}

// appendDay writes records to a day's file as one more gzip member: a file of
// several members reads as one stream.
func appendDay(day string, recs []AuditRecord) (int64, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	enc := json.NewEncoder(zw)
	for _, r := range recs {
		if err := enc.Encode(r); err != nil {
			return 0, err
		}
	}
	if err := zw.Close(); err != nil {
		return 0, err
	}
	f, err := os.OpenFile(dayPath(day), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if _, err := f.Write(buf.Bytes()); err != nil {
		return 0, err
	}
	if err := f.Sync(); err != nil {
		return 0, err
	}
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

// readDay reads a day's records.
func readDay(day string) ([]AuditRecord, error) {
	f, err := os.Open(dayPath(day))
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
	var out []AuditRecord
	dec := json.NewDecoder(zr)
	for {
		var r AuditRecord
		if err := dec.Decode(&r); err == io.EOF {
			return out, nil
		} else if err != nil {
			return out, fmt.Errorf("%s: %w", day, err)
		}
		out = append(out, r)
	}
}

// storedDays lists the days the store holds, oldest first.
func storedDays() []string {
	files, _ := filepath.Glob(filepath.Join(AuditStoreDir(), "*.jsonl.gz"))
	var days []string
	for _, f := range files {
		days = append(days, strings.TrimSuffix(filepath.Base(f), ".jsonl.gz"))
	}
	sort.Strings(days)
	return days
}

// rawFile is one raw log file, as `find` lists it.
type rawFile struct {
	Key   string // branch/file
	Size  int64
	MTime time.Time
}

// listRawFiles lists every database's raw files, oldest first.
func listRawFiles() ([]rawFile, error) {
	out, err := capture("find", AuditRoot(), "-mindepth", "2", "-maxdepth", "2", "-name", "audit-*.json", "-printf", `%P\t%s\t%T@\n`)
	if err != nil {
		return nil, err
	}
	return parseRawListing(out), nil
}

// parseRawListing reads find's "branch/file<TAB>size<TAB>mtime" lines.
func parseRawListing(out string) []rawFile {
	var files []rawFile
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Split(l, "\t")
		if len(f) != 3 || !strings.Contains(f[0], "/") || strings.HasPrefix(f[0], ".") {
			continue
		}
		size, err1 := strconv.ParseInt(f[1], 10, 64)
		mt, err2 := strconv.ParseFloat(f[2], 64)
		if err1 != nil || err2 != nil {
			continue
		}
		files = append(files, rawFile{Key: f[0], Size: size, MTime: time.Unix(0, int64(mt*1e9))})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].MTime.Before(files[j].MTime) })
	return files
}

// readRaw reads n bytes of a raw file from an offset.
func readRaw(key string, off, n int64) ([]byte, error) {
	cmd, ctx, cancel := sudoCmd(2*time.Minute, "dd", "if="+filepath.Join(AuditRoot(), key),
		"iflag=skip_bytes,count_bytes", "skip="+strconv.FormatInt(off, 10), "count="+strconv.FormatInt(n, 10), "status=none")
	defer cancel()
	out, err := cmd.Output()
	return out, execErr(ctx, 2*time.Minute, "dd", withStderr(err))
}

// firstLineKey is the SHA-256 of a file's first complete line, or "" when it
// has none yet.
func firstLineKey(head []byte) string {
	i := bytes.IndexByte(head, '\n')
	if i < 0 {
		return ""
	}
	sum := sha256.Sum256(head[:i+1])
	return hex.EncodeToString(sum[:])
}

// completeLines splits off the complete lines: a line still being written is
// left for the next collection.
func completeLines(b []byte) (lines [][]byte, used int64) {
	end := bytes.LastIndexByte(b, '\n')
	if end < 0 {
		return nil, 0
	}
	for _, l := range bytes.Split(b[:end], []byte("\n")) {
		if len(bytes.TrimSpace(l)) > 0 {
			lines = append(lines, l)
		}
	}
	return lines, int64(end + 1)
}

// ensureAuditStoreDir makes the store's directory, this user's.
func ensureAuditStoreDir() error {
	if st, err := os.Stat(AuditStoreDir()); err == nil && st.IsDir() {
		return nil
	}
	me := strconv.Itoa(os.Getuid())
	return run("install", "-d", "-o", me, "-g", strconv.Itoa(os.Getgid()), "-m", "0700", AuditStoreDir())
}

// CollectResult is what one collection did.
type CollectResult struct {
	Records int // added to the store
	Removed int // raw files deleted
	Pruned  int // days of records past retention
}

// CollectAudit moves what is new in the raw logs into the store. Safe to run
// from several processes: one collects at a time.
func CollectAudit() (CollectResult, error) {
	var res CollectResult
	if _, err := os.Stat(AuditRoot()); err != nil {
		return res, nil // never turned on: nothing to collect
	}
	if err := ensureAuditStoreDir(); err != nil {
		return res, err
	}
	unlock, err := lockAuditStore()
	if err != nil {
		return res, err
	}
	defer unlock()

	s, err := loadAuditState()
	if err != nil {
		return res, err
	}
	if err := repairDays(s); err != nil {
		return res, err
	}
	files, err := listRawFiles()
	if err != nil {
		return res, err
	}
	var recs []AuditRecord
	seen := map[string]bool{}
	for _, f := range files {
		seen[f.Key] = true
		pos := s.Raw[f.Key]
		if f.Size == 0 {
			s.Raw[f.Key] = rawPos{}
			continue
		}
		head, err := readRaw(f.Key, 0, min(f.Size, auditFirstBytes))
		if err != nil {
			log.Printf("audit log: reading %s: %v", f.Key, err)
			continue
		}
		// A file replaced under its name (PostgreSQL reuses a name a week
		// later) starts again from its beginning. It is known by its first
		// line, which a growing file keeps.
		first := firstLineKey(head)
		if (pos.First != "" && first != "" && pos.First != first) || f.Size < pos.Off {
			pos = rawPos{}
		}
		if first != "" {
			pos.First = first
		}
		if f.Size > pos.Off {
			b, err := readRaw(f.Key, pos.Off, min(f.Size-pos.Off, auditMaxRead))
			if err != nil {
				log.Printf("audit log: reading %s: %v", f.Key, err)
				continue
			}
			lines, used := completeLines(b)
			branch := strings.SplitN(f.Key, "/", 2)[0]
			for _, l := range lines {
				if r, ok := recordFromLine(branch, l); ok {
					recs = append(recs, r)
				}
			}
			pos.Off += used
		}
		s.Raw[f.Key] = pos
	}
	for k := range s.Raw {
		if !seen[k] {
			delete(s.Raw, k)
		}
	}

	// Seal and append to the day they are collected on, so the files read in
	// date order are the chain in order. A record's own time can be days
	// earlier (a raw file collected late); filed by that, it would sit before
	// records it follows, and break the chain as verify reads it. Collected
	// on or after the day it happened, it is still found by a read from that
	// day on.
	// A session whose statement numbers skip some lost lines: a record of the
	// gap goes into the chain where it was found.
	recs = withGaps(recs, s.Sessions)
	for i := range recs {
		sealRecord(&recs[i], s.Seq+1, s.Head)
		s.Seq, s.Head = recs[i].Seq, recs[i].Hash
		switch recs[i].Kind {
		case "heartbeat":
			s.Beats[recs[i].Branch] = recs[i].Time
		case "gap":
			s.Gaps = append(s.Gaps, recs[i])
			if n := len(s.Gaps); n > auditGapsKept {
				s.Gaps = s.Gaps[n-auditGapsKept:]
			}
		}
	}
	pruneSessions(s.Sessions, time.Now().Add(-auditRawKeep).UTC().Format(time.RFC3339Nano))
	s.LastRun = time.Now().UTC().Format(time.RFC3339)
	if len(recs) > 0 {
		day := collectDay(time.Now())
		// The text first: a crash after it and before the records leaves
		// text for records not yet written, which the read again replaces
		// (it is keyed by record number); the other way, records whose text
		// was never kept.
		if err := appendForensic(day, recs); err != nil {
			return res, err
		}
		size, err := appendDay(day, recs)
		if err != nil {
			return res, err
		}
		s.Days[day] = size
	}
	res.Records = len(recs)
	if err := saveAuditState(s); err != nil {
		return res, err
	}

	// Raw files read to their end and two days old.
	now := time.Now()
	for _, f := range files {
		if pos, ok := s.Raw[f.Key]; ok && pos.Off == f.Size && now.Sub(f.MTime) > auditRawKeep {
			if err := run("rm", "-f", filepath.Join(AuditRoot(), f.Key)); err == nil {
				delete(s.Raw, f.Key)
				res.Removed++
			}
		}
	}
	pruned, err := pruneDays(&s, now.UTC().AddDate(0, 0, -AuditRetentionDays()).Format("2006-01-02"))
	if err != nil {
		return res, err
	}
	res.Pruned = pruned
	if _, err := pruneForensic(now.UTC().AddDate(0, 0, -ForensicRetentionDays()).Format("2006-01-02")); err != nil {
		return res, err
	}
	if res.Removed > 0 || res.Pruned > 0 {
		if err := saveAuditState(s); err != nil {
			return res, err
		}
	}
	return res, nil
}

// pruneDays removes the days before cutoff, oldest first. The chain then
// continues from the last record removed, which the state keeps as its base.
func pruneDays(s *auditState, cutoff string) (int, error) {
	n := 0
	for _, day := range storedDays() {
		if day >= cutoff {
			break
		}
		old, err := readDay(day)
		if err != nil {
			return n, err
		}
		if k := len(old); k > 0 {
			s.Base.Seq, s.Base.Hash = old[k-1].Seq, old[k-1].Hash
		}
		if err := os.Remove(dayPath(day)); err != nil {
			return n, err
		}
		delete(s.Days, day)
		n++
	}
	return n, nil
}

// AuditQuery chooses records.
type AuditQuery struct {
	Branch, Table, Login string
	Since                time.Time
	Limit                int
	Kinds                []string // statement, transaction, outcome; all when empty
}

// AuditEntry is a statement as people read it: the record, and how its
// transaction ended and whom it was for, from the transaction's own records.
type AuditEntry struct {
	AuditRecord
	TxnOutcome string `json:"txn_outcome,omitempty"`
	// Text is forensic mode's statement text, while it is kept; TextGone says
	// a record had text that has expired or been purged.
	Text     string    `json:"text,omitempty"`
	TextGone bool      `json:"text_gone,omitempty"`
	TxnFor   *AuditFor `json:"txn_for,omitempty"`
	Error    string    `json:"error,omitempty"` // its transaction's error, as a SQLSTATE
}

// ReadAudit reads the newest records that match, newest first: statements
// joined to their transaction's outcome and whom it was for, and the
// outcome records of errors outside any audited statement.
func ReadAudit(q AuditQuery) ([]AuditEntry, error) {
	if q.Limit <= 0 {
		q.Limit = 100
	}
	days := storedDays()
	var all []AuditRecord
	var out []AuditEntry
	for i := len(days) - 1; i >= 0 && len(out) < q.Limit; i-- {
		if !q.Since.IsZero() && days[i] < q.Since.UTC().Format("2006-01-02") {
			break
		}
		recs, err := readDay(days[i])
		if err != nil {
			return nil, err
		}
		all = append(recs, all...)
		out = joinAudit(all, q)
	}
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	attachTexts(out)
	return out, nil
}

// joinAudit is ReadAudit's work on records in hand, pure so it is tested.
func joinAudit(recs []AuditRecord, q AuditQuery) []AuditEntry {
	type key struct{ session, vxid string }
	txn := map[key]AuditRecord{}
	errs := map[key]string{}
	for _, r := range recs {
		k := key{r.Session, r.VXID}
		switch {
		case r.Kind == "transaction" && r.Outcome != "SUBROLLBACK":
			txn[k] = r
		case r.Kind == "outcome" && r.SQLState != "":
			errs[k] = r.SQLState
		}
	}
	want := map[string]bool{}
	for _, k := range q.Kinds {
		want[k] = true
	}
	var out []AuditEntry
	for i := len(recs) - 1; i >= 0; i-- {
		r := recs[i]
		if len(want) > 0 && !want[r.Kind] {
			continue
		}
		if len(want) == 0 && (r.Kind == "transaction" || r.Kind == "heartbeat") {
			continue // transactions are shown on the statements they close; heartbeats are the engine's
		}
		if q.Branch != "" && r.Branch != q.Branch {
			continue
		}
		if q.Login != "" && r.Login != q.Login {
			continue
		}
		if q.Table != "" && !tableMatches(r.Object, q.Table) {
			continue
		}
		if !q.Since.IsZero() && r.Time < q.Since.UTC().Format(time.RFC3339Nano) {
			continue
		}
		e := AuditEntry{AuditRecord: r}
		if t, ok := txn[key{r.Session, r.VXID}]; ok && r.Kind == "statement" {
			e.TxnOutcome, e.TxnFor = t.Outcome, t.For
		}
		if r.Kind == "statement" {
			e.Error = errs[key{r.Session, r.VXID}]
		}
		out = append(out, e)
	}
	return out
}

// attachTexts gives each forensic record its statement text, while it is
// kept and still matches the hash its record holds.
func attachTexts(entries []AuditEntry) {
	need := false
	for _, e := range entries {
		if e.TextSHA != "" {
			need = true
			break
		}
	}
	if !need {
		return
	}
	texts, _ := forensicTexts()
	for i := range entries {
		if entries[i].TextSHA == "" {
			continue
		}
		t, ok := texts[entries[i].Seq]
		sum := sha256.Sum256([]byte(t.Text))
		if ok && hex.EncodeToString(sum[:]) == entries[i].TextSHA {
			entries[i].Text = t.Text
		} else {
			entries[i].TextGone = true
		}
	}
}

// tableMatches compares a record's object with a table asked for by name or
// schema.name.
func tableMatches(object, table string) bool {
	if object == "" {
		return false
	}
	if strings.Contains(table, ".") {
		return object == table
	}
	return object == table || strings.HasSuffix(object, "."+table)
}

// VerifyAudit checks the whole store's chain, and that it ends where the
// collector says it does.
func VerifyAudit() (ChainReport, error) {
	s, err := loadAuditState()
	if err != nil {
		return ChainReport{}, err
	}
	var all []AuditRecord
	var unreadable []string
	for _, day := range storedDays() {
		recs, err := readDay(day)
		if err != nil {
			unreadable = append(unreadable, fmt.Sprintf("the records of %s cannot all be read (%v): the file was changed", day, err))
		}
		all = append(all, recs...)
	}
	rep := verifyChain(all, s.Base.Seq, s.Base.Hash)
	texts, err := forensicTexts()
	if err != nil {
		unreadable = append(unreadable, fmt.Sprintf("the statement text cannot all be read (%v): a file was changed", err))
	}
	if p := verifyForensic(all, texts); len(p) > 0 {
		rep.Problems = append(rep.Problems, p...)
		rep.Intact = false
	}
	if len(unreadable) > 0 {
		rep.Problems = append(unreadable, rep.Problems...)
		rep.Intact = false
	}
	last := s.Base.Seq
	lastHash := s.Base.Hash
	if n := len(all); n > 0 {
		last, lastHash = all[n-1].Seq, all[n-1].Hash
	}
	if last != s.Seq || lastHash != s.Head {
		rep.Problems = append(rep.Problems, fmt.Sprintf("the store ends at record %d, and the collector wrote up to %d: records at the end were removed", last, s.Seq))
		rep.Intact = false
	}
	return rep, nil
}

// StartAuditCollector collects every minute in the control plane, and then
// forwards what is new when forwarding is set. A store that was never begun
// costs one stat a minute.
func StartAuditCollector() {
	go func() {
		time.Sleep(30 * time.Second)
		lastErr := ""
		for {
			if res, err := CollectAudit(); err != nil {
				log.Printf("audit log: collecting: %v", err)
			} else if res.Removed > 0 || res.Pruned > 0 {
				log.Printf("audit log: %d record(s) collected, %d raw file(s) removed, %d day(s) past retention removed",
					res.Records, res.Removed, res.Pruned)
			}
			// A failure is said once, not every minute: the findings keep it.
			if _, err := ForwardAudit(); err != nil {
				if err.Error() != lastErr {
					log.Printf("audit log: forwarding: %v (the records wait in the store and go when it works)", err)
				}
				lastErr = err.Error()
			} else if lastErr != "" {
				log.Printf("audit log: forwarding works again")
				lastErr = ""
			}
			time.Sleep(time.Minute)
		}
	}()
}
