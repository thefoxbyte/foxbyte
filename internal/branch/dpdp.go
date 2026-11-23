// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// The DPDP personal-data inventory (point 11.1): for each table holding
// personal data a reviewer confirmed (point 4.6), the basis it is processed on
// under the Digital Personal Data Protection Act, 2023, its purpose, whose data
// it is, and how long it is kept.
//
// One entry per table; a column may carry its own, which replaces the table's
// for that column. A confirmed column with neither is a gap. The entries live
// in the branch (bb.dpdp_entries, bb.dpdp_history), beside the findings they
// describe, so a branch made from main carries main's inventory.
//
// Setting and removing entries is Enterprise; enterprise/dpdp supplies them.
// Reading the inventory is free, by the rule in edition.go: what a customer
// recorded is theirs to read whatever the licence says later.
//
// The words below are FoxByte's reading of the Act (Gazette of India, 11
// August 2023) and the Rules (G.S.R. 846(E), 13 November 2025). They are not
// legal advice; docs/dpdp-inventory.md gives each one's source.

// DPDPChoice is one word an entry may use: its value, and how it reads.
type DPDPChoice struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// DPDPVocabulary is every word an entry may use, so the console and the CLI
// show the same labels and neither keeps its own list.
type DPDPVocabulary struct {
	Bases      []DPDPChoice `json:"bases"`
	Principals []DPDPChoice `json:"principals"`
	Units      []DPDPChoice `json:"units"`
	From       []DPDPChoice `json:"from"`
	Reasons    []DPDPChoice `json:"reasons"`
}

// DPDPWords is the vocabulary. The bases are s.4(1): consent (s.6) or one of
// the legitimate uses of s.7, clause by clause.
var DPDPWords = DPDPVocabulary{
	Bases: []DPDPChoice{
		{"consent", "Consent (s.6)"},
		{"7a", "Given voluntarily for a specified purpose, not objected to (s.7(a))"},
		{"7b", "A State subsidy, benefit, service, certificate, licence or permit (s.7(b))"},
		{"7c", "A State function under law, or sovereignty, integrity and security (s.7(c))"},
		{"7d", "A legal duty to disclose information to the State (s.7(d))"},
		{"7e", "Complying with a judgment, decree or order (s.7(e))"},
		{"7f", "A medical emergency (s.7(f))"},
		{"7g", "Health services during an epidemic or other threat to public health (s.7(g))"},
		{"7h", "Safety or assistance during a disaster or a breakdown of public order (s.7(h))"},
		{"7i", "Employment, or safeguarding the employer from loss or liability (s.7(i))"},
	},
	Principals: []DPDPChoice{
		{"customer", "Customers and users"},
		{"employee", "Employees"},
		{"applicant", "Job applicants"},
		{"vendor", "Vendors and their contacts"},
		{"child", "Children, under 18 (s.2(f))"},
		{"disability", "Persons with a disability who have a lawful guardian (s.9(1))"},
		{"other", "Other people"},
	},
	Units: []DPDPChoice{
		{"days", "days"},
		{"months", "months"},
		{"years", "years"},
	},
	From: []DPDPChoice{
		{"collection", "collection"},
		{"last_contact", "the person's last contact (s.8(8))"},
		{"account_closed", "the account is closed"},
		{"contract_end", "the contract ends"},
		{"purpose_served", "the purpose is served (s.8(7)(a))"},
	},
	Reasons: []DPDPChoice{
		{"law", "A law requires it (s.8(7))"},
		{"contract", "A contract"},
		{"purpose", "The purpose needs it"},
	},
}

// The most of each unit a retention may be: a hundred years, in any unit.
var dpdpMaxKeep = map[string]int{"days": 36500, "months": 1200, "years": 100}

// DPDPKeep is how long an entry's data is kept: Count Unit after From, for
// Reason, which Citation names when it is a law or a contract.
type DPDPKeep struct {
	Count    int    `json:"count"`
	Unit     string `json:"unit"`
	From     string `json:"from"`
	Reason   string `json:"reason"`
	Citation string `json:"citation"`
}

// DPDPEntry is one table's entry, or one column's (Column set).
type DPDPEntry struct {
	Schema     string    `json:"schema"`
	Table      string    `json:"table"`
	Column     string    `json:"column"` // "" for the table's entry
	Basis      string    `json:"basis"`
	Purpose    string    `json:"purpose"`
	Principals []string  `json:"principals"`
	Keep       DPDPKeep  `json:"keep"`
	Note       string    `json:"note"`
	SetBy      string    `json:"setBy"`
	SetAt      time.Time `json:"setAt"`
}

// DPDPColumn is one confirmed column of a table, and what covers it.
type DPDPColumn struct {
	Column     string   `json:"column"`
	Categories []string `json:"categories"` // confirmed findings' categories, sorted
	Paths      []string `json:"paths"`      // JSON paths inside it that hold them; [] for the column itself
	// By is what covers it: "column" (its own entry, in Override), "table"
	// (the table's), or "" (nothing: a gap).
	By       string     `json:"by"`
	Override *DPDPEntry `json:"override"`
}

// DPDPTable is one table holding confirmed personal data.
type DPDPTable struct {
	Schema  string       `json:"schema"`
	Table   string       `json:"table"`
	Entry   *DPDPEntry   `json:"entry"` // nil when the table has none
	Columns []DPDPColumn `json:"columns"`
	Gaps    int          `json:"gaps"` // columns with no entry
	// Notices are what the entries say against the findings, in sentences:
	// a table holding children's data whose entry does not list children.
	Notices []string `json:"notices"`
}

// DPDPInventory is a branch's inventory now.
type DPDPInventory struct {
	Branch string      `json:"branch"`
	Tables []DPDPTable `json:"tables"`
	// GapColumns and GapTables count what has no entry: the number fox check
	// and the dashboard warn about.
	GapColumns int `json:"gapColumns"`
	GapTables  int `json:"gapTables"`
	// Stale are entries for places that no longer hold confirmed personal
	// data: a finding rejected, a column dropped. Kept, not deleted, and
	// listed so someone decides.
	Stale []DPDPEntry `json:"stale"`
	// Undecided counts findings no reviewer has confirmed or rejected; they
	// are not in the inventory until someone does.
	Undecided int `json:"undecided"`
	// Scanned is when the branch was last scanned; nil before its first.
	Scanned *time.Time `json:"scanned"`
	// Limits are what the inventory cannot claim, in sentences.
	Limits     []string       `json:"limits"`
	Vocabulary DPDPVocabulary `json:"vocabulary"`
}

// DPDPChange is one change to an entry: what was set, or what was removed.
type DPDPChange struct {
	ID     int64     `json:"id"`
	Action string    `json:"action"` // set, removed
	Entry  DPDPEntry `json:"entry"`
	Actor  string    `json:"actor"`
	At     time.Time `json:"at"`
}

// ErrNoDPDPEntry is a remove, or a history, for a place with no entry.
var ErrNoDPDPEntry = errors.New("no DPDP inventory entry there")

// ErrDPDPNotLicensed refuses setting and removing entries.
var ErrDPDPNotLicensed = notLicensed{edition.DPDP}

var (
	setDPDP    func(name string, e DPDPEntry, actor string) error
	removeDPDP func(name, schema, table, column, actor string) error
)

// SetDPDPInventory installs setting and removing entries. Called from
// enterprise/dpdp's init, and from nowhere else.
func SetDPDPInventory(set func(name string, e DPDPEntry, actor string) error,
	remove func(name, schema, table, column, actor string) error) {
	setDPDP, removeDPDP = set, remove
}

func dpdpFind(cs []DPDPChoice, v string) (int, bool) {
	for i, c := range cs {
		if c.Value == v {
			return i, true
		}
	}
	return 0, false
}

func dpdpValues(cs []DPDPChoice) string {
	vs := make([]string, len(cs))
	for i, c := range cs {
		vs[i] = c.Value
	}
	return strings.Join(vs, ", ")
}

// DPDPLabel is how a word of the vocabulary reads; the word itself if it is
// not one.
func DPDPLabel(cs []DPDPChoice, v string) string {
	if i, ok := dpdpFind(cs, v); ok {
		return cs[i].Label
	}
	return v
}

// CheckDPDPEntry tidies an entry and refuses what cannot be right. It does
// not look at the branch; SetDPDPEntry does that.
func CheckDPDPEntry(e DPDPEntry) (DPDPEntry, error) {
	bad := func(f string, a ...any) (DPDPEntry, error) {
		return e, fmt.Errorf("%w: %s", ErrInvalidRequest, fmt.Sprintf(f, a...))
	}
	e.Schema, e.Table, e.Column = strings.TrimSpace(e.Schema), strings.TrimSpace(e.Table), strings.TrimSpace(e.Column)
	e.Purpose, e.Note = strings.TrimSpace(e.Purpose), strings.TrimSpace(e.Note)
	e.Keep.Citation = strings.TrimSpace(e.Keep.Citation)
	if e.Schema == "" || e.Table == "" {
		return bad("an entry is for a table: schema.table, or schema.table.column for one column")
	}
	if _, ok := dpdpFind(DPDPWords.Bases, e.Basis); !ok {
		return bad("the basis is one of %s, not %q", dpdpValues(DPDPWords.Bases), e.Basis)
	}
	if e.Purpose == "" {
		return bad("say what the data is processed for: the purpose, as the notice to the person states it")
	}
	if n := len([]rune(e.Purpose)); n > 1000 {
		return bad("the purpose is at most 1,000 characters, not %d", n)
	}
	if n := len([]rune(e.Note)); n > 1000 {
		return bad("the note is at most 1,000 characters, not %d", n)
	}
	// Whose data, once each, in the vocabulary's order.
	seen := map[int]bool{}
	for _, p := range e.Principals {
		i, ok := dpdpFind(DPDPWords.Principals, strings.TrimSpace(p))
		if !ok {
			return bad("whose data is one or more of %s, not %q", dpdpValues(DPDPWords.Principals), p)
		}
		seen[i] = true
	}
	if len(seen) == 0 {
		return bad("say whose data it is: one or more of %s", dpdpValues(DPDPWords.Principals))
	}
	e.Principals = e.Principals[:0:0]
	for i, c := range DPDPWords.Principals {
		if seen[i] {
			e.Principals = append(e.Principals, c.Value)
		}
	}
	k := e.Keep
	max, ok := dpdpMaxKeep[k.Unit]
	if !ok {
		return bad("the retention's unit is days, months or years, not %q", k.Unit)
	}
	if k.Count < 0 || k.Count > max {
		return bad("keep it 0 to %d %s, not %d", max, k.Unit, k.Count)
	}
	if _, ok := dpdpFind(DPDPWords.From, k.From); !ok {
		return bad("the retention runs from one of %s, not %q", dpdpValues(DPDPWords.From), k.From)
	}
	if k.Count == 0 && k.From == "collection" {
		return bad("0 %s after collection keeps nothing; give a period, or a later start", k.Unit)
	}
	if _, ok := dpdpFind(DPDPWords.Reasons, k.Reason); !ok {
		return bad("the retention's reason is one of %s, not %q", dpdpValues(DPDPWords.Reasons), k.Reason)
	}
	if k.Reason != "purpose" && k.Citation == "" {
		return bad("name the %s that sets the period (the citation)", k.Reason)
	}
	if n := len([]rune(k.Citation)); n > 500 {
		return bad("the citation is at most 500 characters, not %d", n)
	}
	return e, nil
}

// Where is schema.table, or schema.table.column.
func (e DPDPEntry) Where() string {
	if e.Column == "" {
		return e.Schema + "." + e.Table
	}
	return e.Schema + "." + e.Table + "." + e.Column
}

// String reads a retention: "3 years after the person's last contact (s.8(8)),
// because a law requires it: PMLA s.12".
func (k DPDPKeep) String() string {
	from := DPDPLabel(DPDPWords.From, k.From)
	var s string
	switch {
	case k.Count == 0:
		s = "until " + from
	case k.Count == 1:
		s = "1 " + strings.TrimSuffix(k.Unit, "s") + " after " + from
	default:
		s = strconv.Itoa(k.Count) + " " + k.Unit + " after " + from
	}
	switch k.Reason {
	case "law":
		s += "; a law requires it: " + k.Citation
	case "contract":
		s += "; a contract: " + k.Citation
	}
	return s
}

// Summary is the security log's line for a set: where, and the basis. Never
// the purpose: it is the customer's free text.
func (e DPDPEntry) Summary() string {
	return fmt.Sprintf("%s: basis %s, %s, kept %s", e.Where(), e.Basis, strings.Join(e.Principals, "+"), e.Keep.Brief())
}

// Brief is the retention's period and start, briefly: "3 years after
// last_contact".
func (k DPDPKeep) Brief() string {
	if k.Count == 0 {
		return "until " + k.From
	}
	return fmt.Sprintf("%d %s after %s", k.Count, k.Unit, k.From)
}

// SplitDPDPPlace reads schema.table or schema.table.column; a bare table is
// in public.
func SplitDPDPPlace(s string) (schema, table, column string, err error) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	for _, p := range parts {
		if p == "" {
			return "", "", "", fmt.Errorf("%w: %q is not schema.table or schema.table.column", ErrInvalidRequest, s)
		}
	}
	switch len(parts) {
	case 1:
		return "public", parts[0], "", nil
	case 2:
		return parts[0], parts[1], "", nil
	case 3:
		return parts[0], parts[1], parts[2], nil
	}
	return "", "", "", fmt.Errorf("%w: %q is not schema.table or schema.table.column", ErrInvalidRequest, s)
}

// --- reading -----------------------------------------------------------------

// DPDPInventoryOf reads a branch's inventory. Free in every edition.
func DPDPInventoryOf(name string) (DPDPInventory, error) {
	if name == "" {
		name = "main"
	}
	inv := DPDPInventory{Branch: name}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := OpenSuper(ctx, name)
	if err != nil {
		return inv, err
	}
	defer conn.Close(context.Background())
	return readDPDPInventory(ctx, conn, name)
}

func readDPDPInventory(ctx context.Context, conn *pgx.Conn, name string) (DPDPInventory, error) {
	var findings []PIIFinding
	var scanned *time.Time
	var haveFindings bool
	if err := conn.QueryRow(ctx, "SELECT to_regclass('bb.pii_findings') IS NOT NULL AND to_regclass('bb.pii_scans') IS NOT NULL").Scan(&haveFindings); err != nil {
		return DPDPInventory{Branch: name}, err
	}
	if haveFindings {
		var err error
		if findings, err = readFindings(ctx, conn, ""); err != nil {
			return DPDPInventory{Branch: name}, err
		}
		if err := conn.QueryRow(ctx, "SELECT max(finished_at) FROM bb.pii_scans").Scan(&scanned); err != nil {
			return DPDPInventory{Branch: name}, err
		}
	}
	entries, err := readDPDPEntries(ctx, conn)
	if err != nil {
		return DPDPInventory{Branch: name}, err
	}
	inv := BuildDPDPInventory(name, findings, entries)
	inv.Scanned = scanned
	return inv, nil
}

func haveDPDP(ctx context.Context, conn *pgx.Conn) (bool, error) {
	var have bool
	err := conn.QueryRow(ctx, "SELECT to_regclass('bb.dpdp_entries') IS NOT NULL AND to_regclass('bb.dpdp_history') IS NOT NULL").Scan(&have)
	return have, err
}

const dpdpEntryCols = `schema_name, table_name, column_name, basis, purpose, principals,
	keep_count, keep_unit, keep_from, keep_reason, keep_citation, note, set_by, set_at`

func scanDPDPEntry(row pgx.Row) (DPDPEntry, error) {
	var e DPDPEntry
	err := row.Scan(&e.Schema, &e.Table, &e.Column, &e.Basis, &e.Purpose, &e.Principals,
		&e.Keep.Count, &e.Keep.Unit, &e.Keep.From, &e.Keep.Reason, &e.Keep.Citation, &e.Note, &e.SetBy, &e.SetAt)
	return e, err
}

func readDPDPEntries(ctx context.Context, conn *pgx.Conn) ([]DPDPEntry, error) {
	have, err := haveDPDP(ctx, conn)
	if err != nil || !have {
		return nil, err
	}
	rows, err := conn.Query(ctx, `SELECT `+dpdpEntryCols+` FROM bb.dpdp_entries ORDER BY schema_name, table_name, column_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DPDPEntry
	for rows.Next() {
		e, err := scanDPDPEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// BuildDPDPInventory puts findings and entries together: every table with a
// confirmed finding, what covers each of its columns, the gaps, the notices,
// and the entries whose place no longer holds confirmed personal data.
func BuildDPDPInventory(name string, findings []PIIFinding, entries []DPDPEntry) DPDPInventory {
	inv := DPDPInventory{Branch: name, Tables: []DPDPTable{}, Stale: []DPDPEntry{}, Vocabulary: DPDPWords}
	type tkey struct{ schema, table string }
	type col struct {
		cats, paths map[string]bool
	}
	tables := map[tkey]map[string]*col{}
	for _, f := range findings {
		switch f.State {
		case PIISuggested:
			inv.Undecided++
			continue
		case PIIConfirmed:
		default:
			continue
		}
		k := tkey{f.Schema, f.Table}
		if tables[k] == nil {
			tables[k] = map[string]*col{}
		}
		c := tables[k][f.Column]
		if c == nil {
			c = &col{map[string]bool{}, map[string]bool{}}
			tables[k][f.Column] = c
		}
		c.cats[f.Category] = true
		if f.Path != "" {
			c.paths[f.Path] = true
		}
	}
	tableEntry := map[tkey]*DPDPEntry{}
	colEntry := map[tkey]map[string]*DPDPEntry{}
	for i := range entries {
		e := &entries[i]
		k := tkey{e.Schema, e.Table}
		cols, held := tables[k]
		switch {
		case e.Column == "" && held:
			tableEntry[k] = e
		case e.Column != "" && held && cols[e.Column] != nil:
			if colEntry[k] == nil {
				colEntry[k] = map[string]*DPDPEntry{}
			}
			colEntry[k][e.Column] = e
		default:
			inv.Stale = append(inv.Stale, *e)
		}
	}
	keys := make([]tkey, 0, len(tables))
	for k := range tables {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].schema != keys[j].schema {
			return keys[i].schema < keys[j].schema
		}
		return keys[i].table < keys[j].table
	})
	for _, k := range keys {
		t := DPDPTable{Schema: k.schema, Table: k.table, Entry: tableEntry[k], Columns: []DPDPColumn{}, Notices: []string{}}
		names := make([]string, 0, len(tables[k]))
		for n := range tables[k] {
			names = append(names, n)
		}
		sort.Strings(names)
		childUnlisted := []string{}
		for _, n := range names {
			c := tables[k][n]
			dc := DPDPColumn{Column: n, Categories: dpdpSorted(c.cats), Paths: dpdpSorted(c.paths), Override: colEntry[k][n]}
			var covering *DPDPEntry
			switch {
			case dc.Override != nil:
				dc.By, covering = "column", dc.Override
			case t.Entry != nil:
				dc.By, covering = "table", t.Entry
			default:
				t.Gaps++
			}
			// s.9(1): a child's data needs a parent's verifiable consent. The
			// scanner calls a date of birth under 18 a child's (category
			// child); an entry that does not say so is worth a second look.
			if c.cats["child"] && covering != nil && !dpdpHas(covering.Principals, "child") {
				childUnlisted = append(childUnlisted, n)
			}
			t.Columns = append(t.Columns, dc)
		}
		if len(childUnlisted) > 0 {
			t.Notices = append(t.Notices, fmt.Sprintf(
				"%s holds a child's data (a confirmed finding), but its entry does not list children: s.9(1) asks for a parent's verifiable consent before a child's data is processed",
				strings.Join(childUnlisted, ", ")))
		}
		if t.Gaps > 0 {
			inv.GapColumns += t.Gaps
			inv.GapTables++
		}
		inv.Tables = append(inv.Tables, t)
	}
	inv.Limits = []string{
		"Only places a reviewer confirmed as personal data are listed (fox pii mark). Personal data no scan found, and findings not yet decided, are not here.",
		"The bases, categories and retention are what was recorded here; FoxByte does not check them against the notices given to people or the consents they gave.",
		"The words are FoxByte's reading of the DPDP Act, 2023 and the DPDP Rules, 2025, not legal advice. Have them reviewed before relying on them.",
	}
	if inv.Undecided > 0 {
		inv.Limits = append(inv.Limits, fmt.Sprintf("%d finding(s) are undecided; decide them with fox pii mark, or on the Personal data page.", inv.Undecided))
	}
	return inv
}

func dpdpSorted(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func dpdpHas(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// DPDPHistory reads every change to a table's entries, its own and its
// columns', or one column's when column is set. Free in every edition.
func DPDPHistory(name, schema, table, column string) ([]DPDPChange, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := OpenSuper(ctx, name)
	if err != nil {
		return nil, err
	}
	defer conn.Close(context.Background())
	out := []DPDPChange{}
	have, err := haveDPDP(ctx, conn)
	if err != nil || !have {
		return out, err
	}
	q := `SELECT id, action, entry, actor, at FROM bb.dpdp_history WHERE schema_name = $1 AND table_name = $2`
	args := []any{schema, table}
	if column != "" {
		q += ` AND column_name = $3`
		args = append(args, column)
	}
	rows, err := conn.Query(ctx, q+` ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var c DPDPChange
		var raw []byte
		if err := rows.Scan(&c.ID, &c.Action, &raw, &c.Actor, &c.At); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &c.Entry); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// --- changing ----------------------------------------------------------------

// SetDPDPEntry records an entry, replacing the one at its place, and returns
// it as stored. The place must hold personal data a reviewer confirmed: an
// entry for a table nobody has shown holds any is a typo or a guess.
func SetDPDPEntry(name string, e DPDPEntry, actor string) (DPDPEntry, error) {
	if err := requireFeature(edition.DPDP); err != nil {
		return e, err
	}
	if setDPDP == nil {
		return e, ErrDPDPNotLicensed
	}
	e, err := CheckDPDPEntry(e)
	if err != nil {
		return e, err
	}
	inv, err := DPDPInventoryOf(name)
	if err != nil {
		return e, err
	}
	if !holdsConfirmed(inv, e.Schema, e.Table, e.Column) {
		return e, fmt.Errorf("%w: %s holds no personal data a reviewer confirmed; confirm its findings first (fox pii mark)", ErrInvalidRequest, e.Where())
	}
	if err := setDPDP(name, e, actor); err != nil {
		return e, err
	}
	return readDPDPEntry(name, e.Schema, e.Table, e.Column)
}

// RemoveDPDPEntry removes the entry at a place; its history keeps it.
func RemoveDPDPEntry(name, schema, table, column, actor string) error {
	if err := requireFeature(edition.DPDP); err != nil {
		return err
	}
	if removeDPDP == nil {
		return ErrDPDPNotLicensed
	}
	return removeDPDP(name, schema, table, column, actor)
}

func holdsConfirmed(inv DPDPInventory, schema, table, column string) bool {
	for _, t := range inv.Tables {
		if t.Schema != schema || t.Table != table {
			continue
		}
		if column == "" {
			return true
		}
		for _, c := range t.Columns {
			if c.Column == column {
				return true
			}
		}
	}
	return false
}

func readDPDPEntry(name, schema, table, column string) (DPDPEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := OpenSuper(ctx, name)
	if err != nil {
		return DPDPEntry{}, err
	}
	defer conn.Close(context.Background())
	e, err := scanDPDPEntry(conn.QueryRow(ctx, `SELECT `+dpdpEntryCols+` FROM bb.dpdp_entries
		WHERE schema_name = $1 AND table_name = $2 AND column_name = $3`, schema, table, column))
	if errors.Is(err, pgx.ErrNoRows) {
		return e, ErrNoDPDPEntry
	}
	return e, err
}

// --- exporting ---------------------------------------------------------------

// DPDPCSVHeader is the export's first line.
var DPDPCSVHeader = []string{"schema", "table", "column", "categories", "covered_by", "basis", "basis_label",
	"purpose", "principals", "retention", "keep_reason", "keep_citation", "note", "set_by", "set_at"}

// WriteDPDPCSV writes the inventory one confirmed column a row, for a DPO's
// register: each with the entry that covers it, or none.
func WriteDPDPCSV(w io.Writer, inv DPDPInventory) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(DPDPCSVHeader); err != nil {
		return err
	}
	for _, t := range inv.Tables {
		for _, c := range t.Columns {
			e := c.Override
			if c.By == "table" {
				e = t.Entry
			}
			row := []string{t.Schema, t.Table, c.Column, strings.Join(c.Categories, " "), c.By}
			if e == nil {
				row[4] = "none"
				row = append(row, "", "", "", "", "", "", "", "", "", "")
			} else {
				row = append(row, e.Basis, DPDPLabel(DPDPWords.Bases, e.Basis), e.Purpose, strings.Join(e.Principals, " "),
					e.Keep.String(), e.Keep.Reason, e.Keep.Citation, e.Note, e.SetBy, e.SetAt.UTC().Format(time.RFC3339))
			}
			for i := range row {
				row[i] = dpdpCell(row[i])
			}
			if err := cw.Write(row); err != nil {
				return err
			}
		}
	}
	cw.Flush()
	return cw.Error()
}

// dpdpCell neutralises a value a spreadsheet would run as a formula: a
// purpose or a note is whatever someone typed.
func dpdpCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
