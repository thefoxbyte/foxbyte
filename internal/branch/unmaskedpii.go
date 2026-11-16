// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// Unmasked personal data (audit finding PRIV-1).
//
// A branch is a copy of main, and an agent's branch is a byte-for-byte one, so
// whoever is handed a branch is handed whatever personal data main holds. That
// is the product working as designed: masking is opt-in and stays so. What was
// missing is anybody saying it. Every place a branch is handed to an agent or a
// person now asks this file, and warns when the answer is "real values".
//
// The answer comes from the records, never the data: bb.pii_findings (what
// review confirmed) and bb.mask_rules (what is masked). Both are read in every
// edition, as reading what a scan found always is. A branch no scan has touched
// is "never scanned", which is not the same as "no personal data", and is said
// so.

// PersonalColumn is a column personal-data review has confirmed, or one a
// masking rule covers (which is only ever set on a confirmed finding).
type PersonalColumn struct {
	Schema   string `json:"schema"`
	Table    string `json:"table"`
	Column   string `json:"column"`
	Category string `json:"category,omitempty"`
	Mask     string `json:"mask,omitempty"` // the masking rule, if one is set
}

// Where is the column as a person writes it: table.column in public, and
// schema.table.column anywhere else.
func (c PersonalColumn) Where() string {
	if c.Schema == "" || c.Schema == "public" {
		return c.Table + "." + c.Column
	}
	return c.Schema + "." + c.Table + "." + c.Column
}

// Both records, for one table or all of them. Only confirmed findings count: a
// suggested one is a question for a reviewer, and warning (or, in the change
// feed, refusing) on it would make every scan a source of noise.
const (
	confirmedPIISQL = `SELECT json_build_object('schema', schema_name, 'table', table_name, 'column', column_name,
  'category', min(category)) FROM bb.pii_findings WHERE state = 'confirmed'%s
  GROUP BY schema_name, table_name, column_name`
	maskRuleColumnsSQL = `SELECT json_build_object('schema', schema_name, 'table', table_name, 'column', column_name,
  'category', min(category), 'mask', min(rule)) FROM bb.mask_rules WHERE true%s
  GROUP BY schema_name, table_name, column_name`
	// One question for all three tables: a query naming a missing table fails
	// when it is planned, so each is asked about before it is read.
	personalTablesSQL = `SELECT (to_regclass('bb.pii_findings') IS NOT NULL)::text || '|' ||
  (to_regclass('bb.mask_rules') IS NOT NULL)::text || '|' || (to_regclass('bb.pii_scans') IS NOT NULL)::text`
	anyScanSQL = `SELECT EXISTS (SELECT 1 FROM bb.pii_scans)::text`
)

// personalRecord is what the two records say about a branch.
type personalRecord struct {
	Scanned bool             // a scan has run on it, or on what it was copied from
	Columns []PersonalColumn // confirmed or masked, by place
}

// ConfirmedPersonalColumns is every confirmed personal-data column on a branch,
// and every column a masking rule covers, with the rule. schema and table
// narrow it to one table; "" reads them all. A branch never scanned and never
// masked has neither record, and so nothing here.
//
// Shared by the change feed's refusal (enterprise/realtime) and the warnings
// below, so the two never disagree about which columns hold personal data.
func ConfirmedPersonalColumns(branchName, schema, table string) ([]PersonalColumn, error) {
	r, err := readPersonalRecordOnce(branchName, schema, table)
	return r.Columns, err
}

func readPersonalRecordOnce(branchName, schema, table string) (personalRecord, error) {
	var rec personalRecord
	lines, err := LedgerQuery(branchName, personalTablesSQL)
	if err != nil {
		return rec, fmt.Errorf("asking %s for its personal-data records: %w", branchName, err)
	}
	if len(lines) == 0 {
		return rec, fmt.Errorf("no answer from branch %q", branchName)
	}
	have := strings.Split(lines[0], "|")
	if len(have) != 3 {
		return rec, fmt.Errorf("unreadable answer from branch %q: %q", branchName, lines[0])
	}
	where := ""
	if schema != "" {
		where = fmt.Sprintf(" AND schema_name = %s AND table_name = %s", quoteLiteral(schema), quoteLiteral(table))
	}
	byPlace := map[string]PersonalColumn{}
	for i, src := range []struct{ rel, sql string }{
		{"bb.pii_findings", confirmedPIISQL},
		{"bb.mask_rules", maskRuleColumnsSQL},
	} {
		if have[i] != "true" {
			continue
		}
		rows, err := LedgerQuery(branchName, fmt.Sprintf(src.sql, where))
		if err != nil {
			return rec, fmt.Errorf("reading %s: %w", src.rel, err)
		}
		for _, l := range rows {
			var c PersonalColumn
			if err := json.Unmarshal([]byte(l), &c); err != nil {
				return rec, fmt.Errorf("reading %s: %w", src.rel, err)
			}
			k := c.Schema + "." + c.Table + "." + c.Column
			p := byPlace[k]
			p.Schema, p.Table, p.Column = c.Schema, c.Table, c.Column
			if p.Category == "" {
				p.Category = c.Category
			}
			if c.Mask != "" {
				p.Mask = c.Mask
			}
			byPlace[k] = p
		}
	}
	for _, c := range byPlace {
		rec.Columns = append(rec.Columns, c)
	}
	sort.Slice(rec.Columns, func(i, j int) bool { return rec.Columns[i].Where() < rec.Columns[j].Where() })
	if have[2] == "true" {
		scans, err := LedgerQuery(branchName, anyScanSQL)
		if err != nil {
			return rec, fmt.Errorf("reading bb.pii_scans: %w", err)
		}
		rec.Scanned = len(scans) > 0 && scans[0] == "true"
	}
	// A finding is only ever made by a scan, so findings with no scan row are
	// a branch whose scans were pruned, not one never looked at.
	if !rec.Scanned && len(rec.Columns) > 0 {
		rec.Scanned = true
	}
	return rec, nil
}

// The records are read again at most this often per branch. The console's
// branch list asks for every branch every ten seconds, and the answer changes
// only when somebody scans, reviews or masks, which is not a ten-second thing.
const personalRecordTTL = 30 * time.Second

var personalRecords struct {
	sync.Mutex
	byName map[string]cachedPersonalRecord
}

type cachedPersonalRecord struct {
	rec personalRecord
	at  time.Time
}

// readPersonalRecord is the record of a whole branch, briefly cached. A
// variable so the tests need no database.
var readPersonalRecord = func(name string) (personalRecord, error) {
	personalRecords.Lock()
	c, ok := personalRecords.byName[name]
	personalRecords.Unlock()
	if ok && time.Since(c.at) < personalRecordTTL {
		return c.rec, nil
	}
	rec, err := readPersonalRecordOnce(name, "", "")
	if err != nil {
		return rec, err
	}
	personalRecords.Lock()
	if personalRecords.byName == nil {
		personalRecords.byName = map[string]cachedPersonalRecord{}
	}
	personalRecords.byName[name] = cachedPersonalRecord{rec: rec, at: time.Now()}
	personalRecords.Unlock()
	return rec, nil
}

// forgetPersonalData drops what this process remembers of a branch's records,
// for a caller that has just changed them.
func forgetPersonalData(name string) {
	if name == "" {
		name = "main"
	}
	personalRecords.Lock()
	delete(personalRecords.byName, name)
	personalRecords.Unlock()
}

// Which edition can do what about it. Variables so the tests can be either.
var (
	maskingAvailable  = func() bool { return requireMasker() == nil }
	scanningAvailable = func() bool { return edition.Has(edition.PersonalData) && scanPII != nil }
	isMaskedBranch    = IsMaskedBranch
)

// UnmaskedSummary is what a reader of a branch would see of its confirmed
// personal data: how many columns reach them as real values, of what kind, and
// a few of them by name.
type UnmaskedSummary struct {
	Branch  string `json:"branch"`
	Account string `json:"account,omitempty"`
	// Scanned is false for a branch no scan has ever run on (nor on what it
	// was copied from). Nothing is known about it then, which is not the
	// same as nothing being there.
	Scanned bool `json:"scanned"`
	// Columns is how many confirmed personal-data columns are not masked for
	// this reader; ByCategory splits them by kind.
	Columns    int            `json:"columns"`
	ByCategory map[string]int `json:"byCategory,omitempty"`
	// Examples are up to three of them, as table.column.
	Examples []string `json:"examples,omitempty"`
	// NoRule is how many of them have no masking rule at all; the rest have
	// one that this reader is not held to.
	NoRule int `json:"noRule"`
	// unruled is the first of those, for the command that would set one.
	unruled string
	// MaskingAvailable is whether this install can mask (Enterprise, with a
	// licence for it), which decides what the warning says to do.
	MaskingAvailable  bool `json:"maskingAvailable"`
	ScanningAvailable bool `json:"scanningAvailable"`
}

// Exposed reports whether the reader sees real values of confirmed personal
// data on the branch.
func (s UnmaskedSummary) Exposed() bool { return s.Columns > 0 }

// maxExamples is how many columns a warning names. Enough to recognise the
// data; the full list is `fox pii findings`.
const maxExamples = 3

// UnmaskedPersonalData reports what of a branch's confirmed personal data
// reaches account unmasked. account is an email, an agent key's role
// ("agent:<email>"), or "" for a reader no account masking applies to: an
// agent branch's own login role, or the superuser.
//
// A column is masked for a reader when it has a masking rule and either the
// branch is a masked branch (its data holds the masks, for everybody) or the
// reader is a masked account there (AccountMaskedOn: masked, not an admin, and
// not given unmask on this branch). Everything else confirmed is real values.
//
// It reads two small tables, briefly cached, and never table data.
func UnmaskedPersonalData(branchName, account string) (UnmaskedSummary, error) {
	if branchName == "" {
		branchName = "main"
	}
	s := UnmaskedSummary{Branch: branchName, Account: account,
		MaskingAvailable: maskingAvailable(), ScanningAvailable: scanningAvailable()}
	rec, err := readPersonalRecord(branchName)
	if err != nil {
		return s, err
	}
	s.Scanned = rec.Scanned
	maskedHere := isMaskedBranch(branchName)
	readerMasked := false
	if !maskedHere && account != "" {
		readerMasked = AccountMaskedOn(branchName, account)
	}
	for _, c := range rec.Columns {
		// A rule-only column (no confirmed finding) is still a column review
		// confirmed when the rule was set, so it counts like one.
		if c.Mask != "" && (maskedHere || readerMasked) {
			continue
		}
		s.Columns++
		if c.Mask == "" {
			if s.NoRule == 0 {
				s.unruled = c.Where()
			}
			s.NoRule++
		}
		cat := c.Category
		if cat == "" {
			cat = "personal data"
		}
		if s.ByCategory == nil {
			s.ByCategory = map[string]int{}
		}
		s.ByCategory[cat]++
		if len(s.Examples) < maxExamples {
			s.Examples = append(s.Examples, c.Where())
		}
	}
	return s, nil
}

// categoryNames are the categories whose names are not written in lower case.
var categoryNames = map[string]string{
	"aadhaar": "Aadhaar", "pan": "PAN", "gstin": "GSTIN", "upi": "UPI", "ifsc": "IFSC",
	"voter_id": "voter ID", "date_of_birth": "date of birth", "ip_address": "IP address",
	"vehicle_registration": "vehicle registration", "card": "card number",
}

func categoryName(c string) string {
	if n, ok := categoryNames[strings.ToLower(c)]; ok {
		return n
	}
	return strings.ReplaceAll(c, "_", " ")
}

// Counts is "3 Aadhaar columns, 2 email columns": the most common first.
func (s UnmaskedSummary) Counts() string {
	type kv struct {
		k string
		n int
	}
	var list []kv
	for k, n := range s.ByCategory {
		list = append(list, kv{k, n})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		return list[i].k < list[j].k
	})
	parts := make([]string, 0, len(list))
	for _, e := range list {
		word := "columns"
		if e.n == 1 {
			word = "column"
		}
		parts = append(parts, fmt.Sprintf("%d %s %s", e.n, categoryName(e.k), word))
	}
	return strings.Join(parts, ", ")
}

// Warning is the sentence to show whoever is handing this branch on, or ""
// when there is nothing to warn about. who is the reader as the sentence names
// them ("agents using it"). owner, when known, is the account whose masking
// would hide the values, for the command it suggests.
func (s UnmaskedSummary) Warning(who, owner string) string {
	if who == "" {
		who = "anyone using it"
	}
	if !s.Scanned {
		w := fmt.Sprintf("branch %q has never been scanned for personal data, so nothing says whether %s see "+
			"real personal data; branches are unmasked by default. ", s.Branch, who)
		if s.ScanningAvailable {
			return w + fmt.Sprintf("Scan it: %s pii scan --branch %s", brand.CLI, scanTarget(s.Branch))
		}
		return w + fmt.Sprintf("Scanning and masking need %s Enterprise.", brand.Product)
	}
	if !s.Exposed() {
		return ""
	}
	ex := strings.Join(s.Examples, ", ")
	if s.Columns > len(s.Examples) {
		ex += ", ..."
	}
	w := fmt.Sprintf("this branch holds unmasked personal data: %s (%s); %s see real values. ", s.Counts(), ex, who)
	if !s.MaskingAvailable {
		return w + fmt.Sprintf("Masking can hide them, and masking needs %s Enterprise.", brand.Product)
	}
	return w + "Masking (Enterprise) can hide them: " + s.maskHint(owner)
}

// maskHint is the command, or the two, that would mask what was found: a rule
// on each column without one, and the account masked so it reads the masks
// (its agents are then given masked branches).
func (s UnmaskedSummary) maskHint(owner string) string {
	var cmds []string
	if s.unruled != "" {
		cmds = append(cmds, fmt.Sprintf("%s mask rule %s --branch %s (one per column)", brand.CLI, s.unruled, scanTarget(s.Branch)))
	}
	acct := strings.TrimPrefix(owner, agentKeyRolePrefix)
	if acct == "" {
		acct = "<email>"
	}
	if acct == "<email>" || !IsMaskedAccount(acct) {
		cmds = append(cmds, fmt.Sprintf("%s mask account %s", brand.CLI, acct))
	}
	if len(cmds) == 0 {
		cmds = append(cmds, fmt.Sprintf("%s mask status", brand.CLI))
	}
	return strings.Join(cmds, ", then ")
}

// scanTarget is where a scan or a rule for a branch belongs. An agent's branch
// is made fresh from main each time, so main is where its rules and scans have
// to be.
func scanTarget(name string) string {
	if strings.HasPrefix(name, "agent-") {
		return "main"
	}
	return name
}

// PersonalDataWarnings is UnmaskedPersonalData turned into the warnings a
// response carries: none when there is nothing to say, and none when the
// records could not be read, since a warning must never stop a branch being
// made or used.
func PersonalDataWarnings(branchName, account, who, owner string) []string {
	s, err := UnmaskedPersonalData(branchName, account)
	if err != nil {
		return nil
	}
	if w := s.Warning(who, owner); w != "" {
		return []string{w}
	}
	return nil
}
