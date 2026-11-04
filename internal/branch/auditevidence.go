// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/edition"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

// The audit log's evidence export (F6 Gate 1, step 6b; design, sections 12
// and 16): one document an auditor is handed for a period, saying what the
// audit log covered, what it did not, whether the records are intact and
// anchored, whether they reached the SIEM, what went wrong, and who changed
// any of it. It states coverage and limits as section 12 does, never more.
//
// Enterprise: enterprise/auditevidence assembles it from the reads below,
// which are free, as every read of the audit log is.

// AuditEvidenceFormat names the document.
const AuditEvidenceFormat = "audit-evidence/1"

// EvidenceOptions is what an export is asked for.
type EvidenceOptions struct {
	Since, Until time.Time // the period; Until zero for now
	Records      bool      // include the records themselves, with their place in the chain
	By           string    // who asked
	// Events are the security log's audit-log events, oldest first, which the
	// caller holds (the account store is not this package's).
	Events []auth.SecurityEvent
}

// AuditEvidence is the document.
type AuditEvidence struct {
	Format    string            `json:"format"`
	Generated string            `json:"generated"` // RFC 3339
	By        string            `json:"by"`
	Product   string            `json:"product"`
	Version   string            `json:"version"`
	Edition   string            `json:"edition"`
	Period    EvidencePeriod    `json:"period"`
	Coverage  EvidenceCoverage  `json:"coverage"`
	Integrity EvidenceIntegrity `json:"integrity"`
	Delivery  EvidenceDelivery  `json:"delivery"`
	Activity  EvidenceActivity  `json:"activity"`
	// Changes are the security log's events about the audit log in the
	// period: turned on and off, marks, modes, retention, purges, forwarding,
	// reads of the records.
	Changes []auth.SecurityEvent `json:"changes"`
	// Records are the period's records with seq, prev and hash, and never
	// statement text: with Anchors and PublicKey, a reviewer can check the
	// chain and the anchors over them without FoxByte.
	Records   []AuditRecord   `json:"records,omitempty"`
	Anchors   []ledger.Anchor `json:"anchors,omitempty"`
	PublicKey string          `json:"public_key,omitempty"` // hex Ed25519, the anchors' key
	// Limits are what this document cannot show, stated so nobody reads
	// more into it.
	Limits []string `json:"limits"`
}

// EvidencePeriod is the period, RFC 3339.
type EvidencePeriod struct {
	Since string `json:"since"`
	Until string `json:"until"`
}

// EvidenceCoverage is what was audited, and what by design was not.
type EvidenceCoverage struct {
	On            bool                     `json:"on"`
	Forensic      map[string]ForensicGrant `json:"forensic"` // where statement text is kept ("" for every branch)
	RetentionDays int                      `json:"retention_days"`
	ForensicDays  int                      `json:"forensic_retention_days"`
	Logged        []string                 `json:"logged"`
	NotLogged     []string                 `json:"not_logged"`
	Checked       []string                 `json:"checked"`
	Branches      []EvidenceBranch         `json:"branches"`
}

// EvidenceBranch is one branch as it stands: its marks, the definer functions
// that escape them, and the tables with confirmed personal data not marked.
type EvidenceBranch struct {
	Name             string        `json:"name"`
	Read             bool          `json:"read"` // false: not running, so not woken to be read
	Audited          bool          `json:"audited"`
	Marks            []AuditMark   `json:"marks"`
	Definers         []DefinerFunc `json:"definers"`
	PersonalUnmarked []string      `json:"personal_unmarked"`
	Note             string        `json:"note,omitempty"`
}

// EvidenceIntegrity is the chain and its anchors, verified when produced.
type EvidenceIntegrity struct {
	ChainReport
	AnchorsKept AuditAnchorStatus `json:"anchor_status"`
	KeyID       string            `json:"key_id,omitempty"`
}

// EvidenceDelivery is where the records go, and what is wrong now.
type EvidenceDelivery struct {
	Forward  *ForwardStatus `json:"forward"` // null: not forwarded
	Findings []AuditFinding `json:"findings"`
}

// EvidenceActivity counts the period's records.
type EvidenceActivity struct {
	Records    int            `json:"records"`
	ByKind     map[string]int `json:"by_kind"`
	ByBranch   map[string]int `json:"by_branch"`
	Errors     int            `json:"errors"`     // outcomes that were errors
	Heartbeats int            `json:"heartbeats"` // the engine's own lines, every five minutes
	Gaps       []AuditRecord  `json:"gaps"`       // lines found missing, with how many
}

// The coverage statements (design, section 12), the same in every document.
var (
	EvidenceLogged = []string{
		"role and schema changes, by every login",
		"writes to marked tables, by every login",
		"reads of tables marked for reads, by every login",
		"each audited transaction's outcome: commit, rollback, or the error's SQLSTATE",
		"who: the login, and whom the change was for when an application asserted it (F1)",
	}
	EvidenceNotLogged = []string{
		"statements on tables that are not marked",
		"statement text and values, unless forensic mode was on (coverage.forensic says where)",
		"TRUNCATE, which the Blackbox refuses by default and records when allowed",
		"changes applied by continuous import's replication, which run no statements",
		"statements inside SECURITY DEFINER functions (coverage.branches[].definers names those that name marked tables)",
		"anything a database superuser does after turning auditing off for their own session; FoxByte's own superuser is the engine's",
	}
	EvidenceChecked = []string{
		"the hash chain over every record kept, and every anchor against it",
		"free space in the log's dataset, the collector running, a heartbeat from each audited database every five minutes, and statement numbers that skip (gap records in the chain)",
		"marks taken off outside FoxByte",
		"delivery to the SIEM, when forwarding is set",
	}
	EvidenceLimits = []string{
		"Branches that were not running when this was produced were not woken to be read: their marks are as the changes below last set them.",
		"Records retention removed before the period ends are not here; the chain was verified over every record still kept.",
		"SECURITY DEFINER functions are found by a word match on their source: it can name too many, and misses a table name built at run time.",
		"A record says who and what, and never what a statement held; in forensic mode its text is kept apart from the chain and expires.",
		"The anchors prove the records against an edit made after they were anchored; records collected since the last anchor rest on the chain alone.",
	}
)

// buildAuditEvidence is the paid half, supplied by enterprise/auditevidence in
// an Enterprise build and nil in a Standard one.
var buildAuditEvidence func(o EvidenceOptions) (AuditEvidence, error)

// SetAuditEvidence installs it. Called from enterprise/auditevidence's init,
// and from nowhere else.
func SetAuditEvidence(fn func(o EvidenceOptions) (AuditEvidence, error)) { buildAuditEvidence = fn }

// ProduceAuditEvidence produces the evidence for a period.
func ProduceAuditEvidence(o EvidenceOptions) (AuditEvidence, error) {
	if err := requireFeature(edition.Export); err != nil {
		return AuditEvidence{}, err
	}
	if buildAuditEvidence == nil {
		return AuditEvidence{}, ErrExportNotLicensed
	}
	if o.Until.IsZero() {
		o.Until = time.Now()
	}
	if !o.Since.Before(o.Until) {
		return AuditEvidence{}, fmt.Errorf("%w: the period ends before it starts", ErrInvalidRequest)
	}
	return buildAuditEvidence(o)
}

// EvidenceSummary is the security log's line for an export: the period, and
// what it held.
func EvidenceSummary(ev AuditEvidence) string {
	s := fmt.Sprintf("evidence for %s to %s: %d record(s) in the period, chain %s", ev.Period.Since, ev.Period.Until,
		ev.Activity.Records, map[bool]string{true: "intact", false: "NOT intact"}[ev.Integrity.Intact])
	if ev.Records != nil {
		s += ", the records included"
	}
	return s
}

// AuditRecordsBetween reads the records collected in [since, until), in
// order, without statement text.
func AuditRecordsBetween(since, until time.Time) ([]AuditRecord, error) {
	var out []AuditRecord
	for _, day := range storedDays() {
		// A day file holds what was collected that day, so one before the
		// period's first day holds nothing in it.
		if day < since.UTC().AddDate(0, 0, -1).Format("2006-01-02") {
			continue
		}
		recs, err := readDay(day)
		if err != nil {
			return nil, fmt.Errorf("the records of %s cannot all be read (%v)", day, err)
		}
		for _, r := range recs {
			// Parsed, not compared as text: RFC 3339 drops trailing zeros,
			// so "…01.5Z" sorts after "…01.55Z".
			at, err := time.Parse(time.RFC3339Nano, r.Time)
			if err != nil || at.Before(since) || !at.Before(until) {
				continue
			}
			r.Text = ""
			out = append(out, r)
		}
	}
	return out, nil
}

// AuditBranchCoverage reads a running branch's marks, the definer functions
// naming them, and its tables with confirmed personal data not marked.
func AuditBranchCoverage(name string) EvidenceBranch {
	b := EvidenceBranch{Name: name, Read: true, Audited: runsWithAudit(name),
		Marks: []AuditMark{}, Definers: []DefinerFunc{}, PersonalUnmarked: []string{}}
	var notes []string
	if m, err := AuditMarks(name); err != nil {
		notes = append(notes, "marks not read: "+err.Error())
	} else {
		b.Marks = m
	}
	if d, err := DefinerFunctions(name); err != nil {
		notes = append(notes, "definer functions not read: "+err.Error())
	} else if d != nil {
		b.Definers = d
	}
	if p, err := PersonalTablesUnmarked(name); err != nil {
		notes = append(notes, "personal data not read: "+err.Error())
	} else if p != nil {
		b.PersonalUnmarked = p
	}
	if len(notes) > 0 {
		b.Note = fmt.Sprint(notes)
	}
	return b
}
