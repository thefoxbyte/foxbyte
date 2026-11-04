// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The audit log's records (F6 Gate 1, step 3; design, sections 5 and 9).
//
// PostgreSQL writes JSON lines; most of what a line carries is not kept. A
// record has the fields section 5 names and nothing else: when, which branch,
// the login, what kind of statement on which object, the session and virtual
// transaction that join a statement to its outcome, the outcome, and whom it
// was for. Never a message, a detail, a client address or an application
// name. In forensic mode (step 5) the statement's text, which pgAudit puts in
// its own line, is the one addition.
//
// Records are hash-chained in the order they are collected, as the security
// log's events are: each carries the previous one's hash and its own, over
// everything else it holds. An edit, a removal or a reordering breaks the
// chain from that record on.

// AuditRecord is one record.
type AuditRecord struct {
	Seq    int64  `json:"seq"`
	Time   string `json:"time"` // RFC 3339, UTC
	Branch string `json:"branch"`
	Login  string `json:"login,omitempty"`
	// Kind is statement (a line of pgAudit's), transaction (how a transaction
	// with audited statements ended, and whom it was for), outcome (an error,
	// as its SQLSTATE), heartbeat (the engine's own line, every five minutes,
	// that shows lines are arriving), or gap (lines found missing: a session's
	// statement numbers skipped some).
	Kind         string    `json:"kind"`
	Audit        string    `json:"audit,omitempty"` // SESSION or OBJECT
	Class        string    `json:"class,omitempty"` // READ, WRITE, DDL, ROLE, …
	Command      string    `json:"command,omitempty"`
	ObjectType   string    `json:"object_type,omitempty"`
	Object       string    `json:"object,omitempty"`
	Statement    int64     `json:"statement,omitempty"`
	Substatement int64     `json:"substatement,omitempty"`
	Session      string    `json:"session,omitempty"`
	VXID         string    `json:"vxid,omitempty"`
	Outcome      string    `json:"outcome,omitempty"` // COMMIT, ROLLBACK, PREPARE, SUBROLLBACK; ERROR, FATAL, PANIC
	Undone       int       `json:"undone,omitempty"`  // SUBROLLBACK: how many audit lines it undid
	Missing      int64     `json:"missing,omitempty"` // gap: how many statements' lines are missing, from Statement on
	SQLState     string    `json:"sqlstate,omitempty"`
	For          *AuditFor `json:"for,omitempty"`
	// TextSHA is the SHA-256 of the statement's text, in forensic mode. The
	// chain holds the hash, never the text: the text is kept beside the
	// chain (auditforensic.go), so it can expire after 30 days and be purged
	// for a person (F4) without breaking the chain. verify checks each text
	// still kept against its hash.
	TextSHA string `json:"text_sha,omitempty"`
	// Text is the statement's text while it is being collected, and when a
	// read finds it kept. Never written into a day file, never hashed.
	Text string `json:"-"`
	Prev string `json:"prev"`
	Hash string `json:"hash"`
}

// AuditFor is whom a transaction was for (F1): asserted by an application,
// claimed, or none.
type AuditFor struct {
	State  string `json:"state"`
	Issuer string `json:"issuer,omitempty"`
	Actor  string `json:"actor,omitempty"`
}

// rawLine is the part of a PostgreSQL JSON log line a record is made from.
type rawLine struct {
	Timestamp string `json:"timestamp"`
	User      string `json:"user"`
	Session   string `json:"session_id"`
	VXID      string `json:"vxid"`
	Severity  string `json:"error_severity"`
	State     string `json:"state_code"`
	Message   string `json:"message"`
}

const pgLogTime = "2006-01-02 15:04:05.000 MST"

// recordFromLine makes a record of one log line, or reports false for a line
// that is not one: the server's own lines, and what the hook redacted below
// an error, which hold nothing an audit asks about. Only bb_identity and
// pgAudit write lines beginning "AUDIT: ": a client's RAISE that tries is
// redacted before it reaches the file (design, section 19).
func recordFromLine(branch string, line []byte) (AuditRecord, bool) {
	var l rawLine
	if err := json.Unmarshal(line, &l); err != nil || !strings.HasPrefix(l.Message, "AUDIT: ") {
		return AuditRecord{}, false
	}
	t, err := time.Parse(pgLogTime, l.Timestamp)
	if err != nil {
		return AuditRecord{}, false
	}
	f, err := csvFields(strings.TrimPrefix(l.Message, "AUDIT: "))
	if err != nil || len(f) == 0 {
		return AuditRecord{}, false
	}
	r := AuditRecord{
		Time:    t.UTC().Format(time.RFC3339Nano),
		Branch:  branch,
		Login:   l.User,
		Session: l.Session,
		VXID:    l.VXID,
	}
	switch f[0] {
	case "SESSION", "OBJECT":
		if len(f) < 7 {
			return AuditRecord{}, false
		}
		r.Kind, r.Audit, r.Class, r.Command, r.ObjectType, r.Object = "statement", f[0], f[3], f[4], f[5], f[6]
		// The heartbeat: the engine's own superuser setting pgaudit.log in a
		// session of its own, which pgAudit logs as MISC SET. No client logs
		// in as that superuser, and the policy logs no MISC otherwise.
		if r.Login == pgUser && r.Class == "MISC" && r.Command == "SET" {
			r.Kind = "heartbeat"
		}
		r.Statement, _ = strconv.ParseInt(f[1], 10, 64)
		r.Substatement, _ = strconv.ParseInt(f[2], 10, 64)
		if len(f) > 7 && f[7] != "<not logged>" {
			r.Text = f[7]
			sum := sha256.Sum256([]byte(r.Text))
			r.TextSHA = hex.EncodeToString(sum[:])
		}
	case "TXN":
		// TXN,<vxid>,COMMIT|ROLLBACK|PREPARE,<state>,<issuer>,<actor>
		// TXN,<vxid>,SUBROLLBACK,<n>
		// Its own vxid: the line's is cleared by the time a commit is logged.
		if len(f) < 3 {
			return AuditRecord{}, false
		}
		r.Kind, r.VXID, r.Outcome = "transaction", f[1], f[2]
		if r.Outcome == "SUBROLLBACK" {
			if len(f) > 3 {
				r.Undone, _ = strconv.Atoi(f[3])
			}
		} else if len(f) >= 6 && f[3] != "" {
			r.For = &AuditFor{State: f[3], Issuer: f[4], Actor: f[5]}
		}
	case "OUTCOME":
		// OUTCOME,<severity>,<sqlstate>
		if len(f) < 3 {
			return AuditRecord{}, false
		}
		r.Kind, r.Outcome, r.SQLState = "outcome", f[1], f[2]
	default:
		return AuditRecord{}, false
	}
	return r, true
}

// csvFields splits pgAudit's comma-separated fields, quoted as CSV.
func csvFields(s string) ([]string, error) {
	cr := csv.NewReader(strings.NewReader(s))
	cr.LazyQuotes = true
	cr.FieldsPerRecord = -1
	return cr.Read()
}

// sealRecord gives a record its place in the chain: its number, the previous
// record's hash, and its own hash over everything else it holds.
func sealRecord(r *AuditRecord, seq int64, prev string) {
	r.Seq, r.Prev, r.Hash = seq, prev, ""
	r.Hash = recordHash(*r)
}

// recordHash is SHA-256 over the record as JSON with its hash empty. Go writes
// a struct's fields in their declared order, so the same record always gives
// the same bytes.
func recordHash(r AuditRecord) string {
	r.Hash = ""
	b, _ := json.Marshal(r)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ChainReport is what verifying the chain found.
type ChainReport struct {
	Records  int64    `json:"records"`
	First    int64    `json:"first"` // the first record's number (later than 1 once retention removed the oldest)
	Intact   bool     `json:"intact"`
	Problems []string `json:"problems,omitempty"`
	// The last record, which an anchor would anchor (step 6).
	Last     int64  `json:"last"`
	LastHash string `json:"last_hash,omitempty"`
	// The anchors checked, and the last record they cover.
	Anchors  int      `json:"anchors,omitempty"`
	Anchored int64    `json:"anchored,omitempty"`
	Notes    []string `json:"notes,omitempty"`
}

// verifyChain checks records in order: each numbered one after the last,
// naming the last one's hash, and hashing to what it says. base is the record
// before the first one kept (its number and hash), or zero for the start.
func verifyChain(records []AuditRecord, baseSeq int64, baseHash string) ChainReport {
	rep := ChainReport{Intact: true, Records: int64(len(records)), First: baseSeq + 1}
	seq, prev := baseSeq, baseHash
	for _, r := range records {
		switch {
		case r.Seq != seq+1:
			rep.Problems = append(rep.Problems, fmt.Sprintf("record %d follows %d: %d record(s) missing or out of order", r.Seq, seq, r.Seq-seq-1))
		case r.Prev != prev:
			rep.Problems = append(rep.Problems, fmt.Sprintf("record %d does not name the record before it", r.Seq))
		case recordHash(r) != r.Hash:
			rep.Problems = append(rep.Problems, fmt.Sprintf("record %d was changed after it was written", r.Seq))
		}
		seq, prev = r.Seq, r.Hash
	}
	rep.Intact = len(rep.Problems) == 0
	return rep
}

// sessionMark is how far one session's statement numbers have got.
type sessionMark struct {
	Branch string `json:"branch"`
	Last   int64  `json:"last"`
	Seen   string `json:"seen"` // the last record's time, for pruning
}

// withGaps returns records with a gap record before each statement whose
// number skips some: pgAudit numbers only the statements it logs, one after
// another in a session, so a number that jumps is lines lost (a full log,
// most often). sessions is updated: the last number seen in each.
func withGaps(recs []AuditRecord, sessions map[string]sessionMark) []AuditRecord {
	out := make([]AuditRecord, 0, len(recs))
	for _, r := range recs {
		if r.Kind == "statement" || r.Kind == "heartbeat" {
			if r.Statement > 0 && r.Session != "" {
				k := r.Branch + "/" + r.Session
				m := sessions[k]
				if m.Last > 0 && r.Statement > m.Last+1 {
					out = append(out, AuditRecord{
						Time: r.Time, Branch: r.Branch, Login: r.Login, Kind: "gap", Session: r.Session,
						Statement: m.Last + 1, Missing: r.Statement - m.Last - 1,
					})
				}
				if r.Statement > m.Last {
					m.Last = r.Statement
				}
				m.Branch, m.Seen = r.Branch, r.Time
				sessions[k] = m
			}
		}
		out = append(out, r)
	}
	return out
}

// pruneSessions forgets sessions not seen since cutoff: a gap is found only
// within a session, and one silent for two days has ended.
func pruneSessions(sessions map[string]sessionMark, cutoff string) {
	for k, m := range sessions {
		if m.Seen < cutoff {
			delete(sessions, k)
		}
	}
}
