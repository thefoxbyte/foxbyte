// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
	"github.com/thefoxbyte/foxbyte/internal/safego"
)

// Retention acted on (point 11.3; DPDP Act s.8(7), the Rules' Rule 8;
// docs/dpdp-inventory.md). A table's period is its inventory entry's on
// main. The rows past it are found by a date column an admin names, never
// by a value, and erased as an erasure request erases rows, by key and
// limited to that table: on main, then every branch, recorded as a request
// so restores, outcomes and evidence (11.2) see it like any other.
//
// Decided 28 Nov 2026: it runs on a scheduler of its own in the control
// plane (point 10's general one is parked), once a day; only a table an
// admin armed, after seeing what would go, is erased from; a row is erased
// no sooner than a year from its date, whatever the entry says (Rule 8(3)
// keeps personal data and its logs a year from the processing); and every
// erasure is told of at least 48 hours before (Rule 8(2)), through a
// webhook the customer sets, and waits until the notice was delivered.
//
// The query and the erasure are the engine's (Enterprise, the dpdp
// feature); reading the settings, the tables and the notices is free.

// RetentionQuery asks the engine for a table's rows dated before a cutoff.
type RetentionQuery struct {
	Schema, Table, Column string
	Cutoff                time.Time
	Limit                 int
	// Exclude are rows retention erased already, by key: a cleared row keeps
	// its date, and is not erased again.
	Exclude []string
}

// RetentionRow is one row past its period: its key and its date.
type RetentionRow struct {
	Key   string    `json:"key"` // a JSON array of the key's columns, as text
	Since time.Time `json:"since"`
}

// RetentionDue is what the engine found.
type RetentionDue struct {
	Schema     string         `json:"schema"`
	Table      string         `json:"table"`
	Column     string         `json:"column"`
	KeyColumns []string       `json:"keyColumns"`
	Cutoff     time.Time      `json:"cutoff"`
	Total      int            `json:"total"`   // rows dated before the cutoff
	Undated    int            `json:"undated"` // rows with no date: never acted on
	Rows       []RetentionRow `json:"rows"`    // the oldest, up to the limit
}

// ---- settings -------------------------------------------------------------------

// RetentionSettings are the install's: on or off, and where the notice goes.
type RetentionSettings struct {
	On     bool      `json:"on"`
	Notify string    `json:"notify"`
	Secret string    `json:"secret,omitempty"` // signs each notice; never shown again
	By     string    `json:"by"`
	Since  time.Time `json:"since"`
	// LastRun and LastSummary are the last run's, for status and fox check.
	LastRun     *time.Time `json:"lastRun,omitempty"`
	LastSummary string     `json:"lastSummary,omitempty"`
}

var retentionSettingsPath = func() string { return brand.StatePath("retention.json") }

// retentionInventory is main's inventory, where each table's period is.
var retentionInventory = func() (DPDPInventory, error) { return DPDPInventoryOf("main") }

// LoadRetentionSettings reads the settings; off when none were saved.
func LoadRetentionSettings() RetentionSettings {
	var r RetentionSettings
	if b, err := os.ReadFile(retentionSettingsPath()); err == nil {
		_ = json.Unmarshal(b, &r)
	}
	return r
}

func saveRetentionSettings(r RetentionSettings) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(retentionSettingsPath()), 0o700); err != nil {
		return err
	}
	return writeSecretFile(retentionSettingsPath(), b)
}

// Public is the settings without the secret.
func (r RetentionSettings) Public() RetentionSettings {
	r.Secret = ""
	return r
}

// ErrRetentionOff is a run asked for while retention is off.
var ErrRetentionOff = errors.New("retention is off")

// checkNotifyURL accepts HTTPS anywhere, and plain HTTP only to this machine:
// a notice names a person's row.
func checkNotifyURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: --notify needs an address, https://…", ErrInvalidRequest)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); (ip != nil && ip.IsLoopback()) || host == "localhost" {
			return nil
		}
		return fmt.Errorf("%w: a notice names a person's row, so it goes over HTTPS; plain HTTP only to this machine", ErrInvalidRequest)
	}
	return fmt.Errorf("%w: --notify is https://… (or http:// to this machine), not %s", ErrInvalidRequest, u.Scheme)
}

// SetRetentionOn turns retention on, with the address each notice is posted
// to. It returns the secret notices are signed with, shown this once.
// Enterprise.
func SetRetentionOn(s *auth.Store, notify, by string) (string, error) {
	if err := requireFeature(edition.DPDP); err != nil {
		return "", err
	}
	if err := checkNotifyURL(notify); err != nil {
		return "", err
	}
	r := LoadRetentionSettings()
	sec := make([]byte, 32)
	if _, err := rand.Read(sec); err != nil {
		return "", err
	}
	r.On, r.Notify, r.Secret, r.By, r.Since = true, strings.TrimSpace(notify), hex.EncodeToString(sec), by, time.Now().UTC()
	if err := saveRetentionSettings(r); err != nil {
		return "", err
	}
	if s != nil {
		s.Audit(auth.EvRetentionSettings, by, "main", "", "retention on, notices to "+r.Notify)
	}
	return r.Secret, nil
}

// SetRetentionOff turns retention off: nothing is noticed or erased until it
// is on again. Notices already sent stay open, and act on the next run on.
func SetRetentionOff(s *auth.Store, by string) error {
	r := LoadRetentionSettings()
	r.On, r.By, r.Since = false, by, time.Now().UTC()
	if err := saveRetentionSettings(r); err != nil {
		return err
	}
	if s != nil {
		s.Audit(auth.EvRetentionSettings, by, "main", "", "retention off")
	}
	return nil
}

// RetentionNoticePeriod is how long before an erasure its notice goes: 48
// hours (Rule 8(2)). FOX_RETENTION_NOTICE shortens it for a test; the plan
// says when it is under the Rule's.
func RetentionNoticePeriod() time.Duration {
	if v := strings.TrimSpace(brand.Getenv("RETENTION_NOTICE")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= 0 {
			return d
		}
	}
	return 48 * time.Hour
}

// retentionBatch is how many rows of a table one run notices or erases.
func retentionBatch() int {
	if v := strings.TrimSpace(brand.Getenv("RETENTION_BATCH")); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 && n <= 5000 {
			return n
		}
	}
	return 500
}

// ---- the period ---------------------------------------------------------------------

// RetentionFloor is the least a row is kept from its date: a year (Rule 8(3)).
const RetentionFloor = "1 year"

// retentionCutoff is the date before which a row's period has ended: the
// entry's period back from now, or a year, whichever is earlier (decided 28
// Nov 2026). raised says the year won.
func retentionCutoff(k DPDPKeep, now time.Time) (cutoff time.Time, raised bool, ok bool) {
	if k.Count <= 0 {
		return time.Time{}, false, false // until the purpose is served: FoxByte cannot tell when
	}
	switch k.Unit {
	case "days":
		cutoff = now.AddDate(0, 0, -k.Count)
	case "months":
		cutoff = now.AddDate(0, -k.Count, 0)
	case "years":
		cutoff = now.AddDate(-k.Count, 0, 0)
	default:
		return time.Time{}, false, false
	}
	floor := now.AddDate(-1, 0, 0)
	if cutoff.After(floor) {
		return floor, true, true
	}
	return cutoff, false, true
}

// ---- tables ---------------------------------------------------------------------------

// RetentionView is one table with a period on main, as retention sees it.
type RetentionView struct {
	Schema  string     `json:"schema"`
	Table   string     `json:"table"`
	Keep    DPDPKeep   `json:"keep"`
	Column  string     `json:"column"`
	Armed   bool       `json:"armed"`
	ArmedBy string     `json:"armedBy,omitempty"`
	Cutoff  *time.Time `json:"cutoff,omitempty"`
	// Raised says the year of Rule 8(3) holds the rows longer than the entry.
	Raised  bool `json:"raised"`
	Due     int  `json:"due"`
	Undated int  `json:"undated"`
	Noticed int  `json:"noticed"` // notices open
	// Why says why it is not acted on, in a sentence; "" when it is.
	Why string `json:"why,omitempty"`
}

// Where names the table.
func (v RetentionView) Where() string { return v.Schema + "." + v.Table }

// RetentionStatus is the install's retention now.
type RetentionStatus struct {
	Settings RetentionSettings `json:"settings"`
	Notice   string            `json:"notice"` // the notice period, said
	Tables   []RetentionView   `json:"tables"`
	Limits   []string          `json:"limits"`
}

// GetRetentionStatus reads every table with a period in main's inventory and
// what retention would do with it now. Free; the counts need the engine.
func GetRetentionStatus(s *auth.Store) (RetentionStatus, error) {
	st := RetentionStatus{Settings: LoadRetentionSettings().Public(), Tables: []RetentionView{}, Notice: RetentionNoticePeriod().String()}
	if RetentionNoticePeriod() < 48*time.Hour {
		st.Notice += " (shorter than Rule 8(2)'s 48 hours: " + brand.EnvName("RETENTION_NOTICE") + " is set)"
	}
	st.Limits = retentionLimits()
	inv, err := retentionInventory()
	if err != nil {
		return st, err
	}
	set := map[string]auth.RetentionTable{}
	if s != nil {
		ts, err := s.RetentionTables()
		if err != nil {
			return st, err
		}
		for _, t := range ts {
			set[t.Schema+"."+t.Table] = t
		}
	}
	open := map[string]int{}
	if s != nil {
		ns, _ := s.RetentionNotices("", "", true, 100000)
		for _, n := range ns {
			open[n.Schema+"."+n.Table]++
		}
	}
	now := time.Now().UTC()
	for _, t := range inv.Tables {
		if t.Entry == nil {
			continue
		}
		v := RetentionView{Schema: t.Schema, Table: t.Table, Keep: t.Entry.Keep}
		if rt, ok := set[v.Where()]; ok {
			v.Column, v.Armed = rt.Column, rt.Armed
			if rt.Armed {
				v.ArmedBy = rt.By
			}
		}
		v.Noticed = open[v.Where()]
		cut, raised, ok := retentionCutoff(t.Entry.Keep, now)
		switch {
		case !ok:
			v.Why = "kept " + t.Entry.Keep.String() + ": FoxByte cannot tell when that is, so its rows go by an erasure request"
		case v.Column == "":
			v.Why = "no date column: name the one its period runs from (" + brand.CLI + " dpdp retention column " + v.Where() + " <column>)"
		}
		if ok {
			v.Cutoff, v.Raised = &cut, raised
		}
		if ok && v.Column != "" && erasure != nil && erasure.Due != nil {
			d, err := erasure.Due("main", RetentionQuery{Schema: t.Schema, Table: t.Table, Column: v.Column, Cutoff: cut, Limit: 1, Exclude: erasedKeys(s, t.Schema, t.Table)})
			if err != nil {
				v.Why = err.Error()
			} else {
				v.Due, v.Undated = d.Total, d.Undated
			}
		}
		if v.Why == "" && !v.Armed {
			v.Why = "not armed: its rows past the period are listed, never erased, until an admin arms it (" + brand.CLI + " dpdp retention arm " + v.Where() + ")"
		}
		st.Tables = append(st.Tables, v)
	}
	sort.Slice(st.Tables, func(i, j int) bool { return st.Tables[i].Where() < st.Tables[j].Where() })
	return st, nil
}

func retentionLimits() []string {
	return []string{
		"A row's period runs from the date in the column named for its table; a row with no date there is never acted on, and is counted.",
		"A row is kept at least a year from that date, whatever the entry says: Rule 8(3) keeps personal data and the logs of its processing a year from the processing.",
		"Only the table's own rows go, by key, on main and every branch; a row of another table goes only where a foreign key takes it with a delete. Logs (the Blackbox, query history, the audit log) follow their own retention.",
		"The notice is posted to the customer's address, signed; telling the person is the customer's. A row whose notice was not delivered is not erased.",
		"The periods are the customer's entries; FoxByte does not check them against the Third Schedule or the notices given.",
		ErasureReview,
	}
}

func dueEngine() (*ErasureEngine, error) {
	eng, err := erasureEngine()
	if err != nil {
		return nil, err
	}
	if eng.Due == nil || eng.PlanRetention == nil {
		return nil, fmt.Errorf("this build's erasure engine cannot act on retention")
	}
	return eng, nil
}

func entryOf(table string) (*DPDPEntry, error) {
	schema, tbl, col, err := SplitDPDPPlace(table)
	if err != nil {
		return nil, err
	}
	if col != "" {
		return nil, fmt.Errorf("%w: retention is a table's, not a column's (%s)", ErrInvalidRequest, table)
	}
	inv, err := retentionInventory()
	if err != nil {
		return nil, err
	}
	for _, t := range inv.Tables {
		if t.Schema == schema && t.Table == tbl && t.Entry != nil {
			return t.Entry, nil
		}
	}
	return nil, fmt.Errorf("%w: %s.%s has no inventory entry on main, so no period (%s dpdp set)", ErrInvalidRequest, schema, tbl, brand.CLI)
}

// SetRetentionColumn names the date a table's period runs from, checking it
// is a date the engine can read. Enterprise.
func SetRetentionColumn(s *auth.Store, table, column, by string) (RetentionDue, error) {
	eng, err := dueEngine()
	if err != nil {
		return RetentionDue{}, err
	}
	e, err := entryOf(table)
	if err != nil {
		return RetentionDue{}, err
	}
	cut, _, ok := retentionCutoff(e.Keep, time.Now().UTC())
	if !ok {
		return RetentionDue{}, fmt.Errorf("%w: %s is kept %s, which has no date to act on", ErrInvalidRequest, table, e.Keep.String())
	}
	column = strings.TrimSpace(column)
	d, err := eng.Due("main", RetentionQuery{Schema: e.Schema, Table: e.Table, Column: column, Cutoff: cut, Limit: 1, Exclude: erasedKeys(s, e.Schema, e.Table)})
	if err != nil {
		return d, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	cur := currentRetentionTable(s, e.Schema, e.Table)
	if err := s.SetRetentionTable(auth.RetentionTable{Schema: e.Schema, Table: e.Table, Column: column, Armed: cur.Armed, By: by, Reason: cur.Reason}); err != nil {
		return d, err
	}
	s.Audit(auth.EvRetentionTable, by, "main", "", fmt.Sprintf("%s.%s's period runs from %s", e.Schema, e.Table, column))
	return d, nil
}

func currentRetentionTable(s *auth.Store, schema, table string) auth.RetentionTable {
	ts, _ := s.RetentionTables()
	for _, t := range ts {
		if t.Schema == schema && t.Table == table {
			return t
		}
	}
	return auth.RetentionTable{}
}

// RetentionPreview is what arming a table would erase now: its due rows.
func RetentionPreview(s *auth.Store, table string) (RetentionDue, error) {
	eng, err := dueEngine()
	if err != nil {
		return RetentionDue{}, err
	}
	e, err := entryOf(table)
	if err != nil {
		return RetentionDue{}, err
	}
	rt := currentRetentionTable(s, e.Schema, e.Table)
	if rt.Column == "" {
		return RetentionDue{}, fmt.Errorf("%w: %s.%s has no date column yet (%s dpdp retention column %s.%s <column>)", ErrInvalidRequest, e.Schema, e.Table, brand.CLI, e.Schema, e.Table)
	}
	cut, _, ok := retentionCutoff(e.Keep, time.Now().UTC())
	if !ok {
		return RetentionDue{}, fmt.Errorf("%w: %s.%s is kept %s, which has no date to act on", ErrInvalidRequest, e.Schema, e.Table, e.Keep.String())
	}
	return eng.Due("main", RetentionQuery{Schema: e.Schema, Table: e.Table, Column: rt.Column, Cutoff: cut, Limit: 20, Exclude: erasedKeys(s, e.Schema, e.Table)})
}

// ArmRetention arms a table: from now on its rows past the period are
// noticed and erased. The caller has shown the preview. Enterprise.
func ArmRetention(s *auth.Store, table, by, reason string) (RetentionDue, error) {
	d, err := RetentionPreview(s, table)
	if err != nil {
		return d, err
	}
	if strings.TrimSpace(reason) == "" {
		return d, fmt.Errorf("%w: say why with --reason (who decided, or the policy)", ErrInvalidRequest)
	}
	if err := s.SetRetentionTable(auth.RetentionTable{Schema: d.Schema, Table: d.Table, Armed: true, By: by, Reason: strings.TrimSpace(reason)}); err != nil {
		return d, err
	}
	s.Audit(auth.EvRetentionTable, by, "main", "", fmt.Sprintf("%s.%s armed, %d row(s) past the period now: %s", d.Schema, d.Table, d.Total, strings.TrimSpace(reason)))
	return d, nil
}

// DisarmRetention stops a table being erased from; its open notices stay,
// and are not acted on until it is armed again. Free: stopping is never paid.
func DisarmRetention(s *auth.Store, table, by string) error {
	schema, tbl, col, err := SplitDPDPPlace(table)
	if err != nil {
		return err
	}
	if col != "" {
		return fmt.Errorf("%w: retention is a table's (%s)", ErrInvalidRequest, table)
	}
	if err := s.SetRetentionTable(auth.RetentionTable{Schema: schema, Table: tbl, Armed: false, By: by}); err != nil {
		return err
	}
	s.Audit(auth.EvRetentionTable, by, "main", "", fmt.Sprintf("%s.%s disarmed", schema, tbl))
	return nil
}

// ---- the notice ------------------------------------------------------------------------

// RetentionNoticeBody is what is posted to the customer's address: the rows,
// by key, that will be erased after a time unless the person comes back.
type RetentionNoticeBody struct {
	Type       string               `json:"type"` // retention.notice
	Product    string               `json:"product"`
	Branch     string               `json:"branch"`
	Table      string               `json:"table"`
	KeyColumns []string             `json:"keyColumns"`
	Kept       string               `json:"kept"` // the entry's period, said
	EraseAfter time.Time            `json:"eraseAfter"`
	Rule       string               `json:"rule"`
	Rows       []RetentionNoticeRow `json:"rows"`
}

// RetentionNoticeRow is one row in a notice.
type RetentionNoticeRow struct {
	Key   json.RawMessage `json:"key"`
	Since time.Time       `json:"since"`
}

// NoticeSignature is the header a notice's signature is in: sha256=<hex of
// HMAC-SHA256 over the body, keyed with the secret retention on gave>.
const NoticeSignature = "X-FoxByte-Signature"

// postNotice delivers one notice; a 2xx is delivery.
var postNotice = func(r RetentionSettings, body []byte) error {
	mac := hmac.New(sha256.New, []byte(r.Secret))
	mac.Write(body)
	req, err := http.NewRequest(http.MethodPost, r.Notify, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(NoticeSignature, "sha256="+hex.EncodeToString(mac.Sum(nil)))
	c := &http.Client{Timeout: 15 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("the address answered %s", resp.Status)
	}
	return nil
}

// ---- a run ---------------------------------------------------------------------------------

// RetentionRunTable is what a run did with one armed table.
type RetentionRunTable struct {
	Table   string `json:"table"`
	Due     int    `json:"due"`
	Noticed int    `json:"noticed"` // notices sent this run
	Waiting int    `json:"waiting"` // noticed, their time not yet up
	Renewed int    `json:"renewed"` // no longer due when their time came
	Erased  int    `json:"erased"`  // rows erased this run
	Request int64  `json:"request,omitempty"`
	Error   string `json:"error,omitempty"`
}

// RetentionRun is one run.
type RetentionRun struct {
	At     time.Time           `json:"at"`
	By     string              `json:"by"`
	Tables []RetentionRunTable `json:"tables"`
	Notes  []string            `json:"notes"`
}

// Summary is the run in a line.
func (r RetentionRun) Summary() string {
	var n, e, w int
	var errs []string
	for _, t := range r.Tables {
		n, e, w = n+t.Noticed, e+t.Erased, w+t.Waiting
		if t.Error != "" {
			errs = append(errs, t.Table)
		}
	}
	s := fmt.Sprintf("%d table(s): %d row(s) noticed, %d waiting, %d erased", len(r.Tables), n, w, e)
	if len(errs) > 0 {
		s += "; failed on " + strings.Join(errs, ", ")
	}
	return s
}

var retentionMu sync.Mutex

// RunRetention notices and erases, once, for every armed table: a row past
// its period is noticed, and erased once its notice's time is up if it is
// still past (the person did not come back). Enterprise; one run at a time.
func RunRetention(s *auth.Store, by string) (RetentionRun, error) {
	run := RetentionRun{At: time.Now().UTC(), By: by, Tables: []RetentionRunTable{}, Notes: []string{}}
	set := LoadRetentionSettings()
	if !set.On {
		return run, fmt.Errorf("%w: turn it on with %s dpdp retention on --notify https://…", ErrRetentionOff, brand.CLI)
	}
	eng, err := dueEngine()
	if err != nil {
		return run, err
	}
	retentionMu.Lock()
	defer retentionMu.Unlock()
	unlock, err := lockBranch("retention@install", "run retention")
	if err != nil {
		return run, err
	}
	defer unlock()
	ts, err := s.RetentionTables()
	if err != nil {
		return run, err
	}
	if RetentionNoticePeriod() < 48*time.Hour {
		run.Notes = append(run.Notes, "The notice period is "+RetentionNoticePeriod().String()+", shorter than Rule 8(2)'s 48 hours: "+brand.EnvName("RETENTION_NOTICE")+" is set.")
	}
	for _, t := range ts {
		if !t.Armed {
			continue
		}
		run.Tables = append(run.Tables, runTable(s, eng, set, t, by))
	}
	now := time.Now().UTC()
	set = LoadRetentionSettings()
	set.LastRun, set.LastSummary = &now, run.Summary()
	_ = saveRetentionSettings(set)
	s.Audit(auth.EvRetentionRun, by, "main", "", "retention run: "+run.Summary())
	return run, nil
}

func runTable(s *auth.Store, eng *ErasureEngine, set RetentionSettings, t auth.RetentionTable, by string) RetentionRunTable {
	where := t.Schema + "." + t.Table
	out := RetentionRunTable{Table: where}
	fail := func(err error) RetentionRunTable {
		out.Error = err.Error()
		return out
	}
	e, err := entryOf(where)
	if err != nil {
		return fail(err)
	}
	if t.Column == "" {
		return fail(fmt.Errorf("no date column"))
	}
	now := time.Now().UTC()
	cut, _, ok := retentionCutoff(e.Keep, now)
	if !ok {
		return fail(fmt.Errorf("kept %s, which has no date to act on", e.Keep.String()))
	}
	erased := erasedKeys(s, t.Schema, t.Table)
	due, err := eng.Due("main", RetentionQuery{Schema: t.Schema, Table: t.Table, Column: t.Column, Cutoff: cut, Limit: retentionBatch(), Exclude: erased})
	if err != nil {
		return fail(err)
	}
	out.Due = due.Total
	stillDue := map[string]RetentionRow{}
	for _, r := range due.Rows {
		stillDue[normKey(r.Key)] = r
	}
	open, err := s.RetentionNotices(t.Schema, t.Table, true, 100000)
	if err != nil {
		return fail(err)
	}
	noticed := map[string]bool{}
	var ripe []auth.RetentionNotice
	for _, n := range open {
		noticed[normKey(n.Key)] = true
		if now.Before(n.EraseAfter) {
			out.Waiting++
			continue
		}
		ripe = append(ripe, n)
	}
	// Due and not yet told: told now, one notice for the table.
	var fresh []RetentionRow
	for _, r := range due.Rows {
		if !noticed[normKey(r.Key)] {
			fresh = append(fresh, r)
		}
	}
	if len(fresh) > 0 {
		after := now.Add(RetentionNoticePeriod())
		body := RetentionNoticeBody{Type: "retention.notice", Product: brand.Product, Branch: "main", Table: where, KeyColumns: due.KeyColumns,
			Kept: e.Keep.String(), EraseAfter: after, Rule: "DPDP Rules, 2025, Rule 8(2)", Rows: make([]RetentionNoticeRow, len(fresh))}
		for i, r := range fresh {
			body.Rows[i] = RetentionNoticeRow{Key: json.RawMessage(r.Key), Since: r.Since}
		}
		b, _ := json.Marshal(body)
		if err := postNotice(set, b); err != nil {
			out.Error = "the notice could not be delivered, so nothing new will be erased: " + err.Error()
			s.Audit(auth.EvRetentionNotice, by, "main", "", fmt.Sprintf("%s: a notice of %d row(s) not delivered: %v", where, len(fresh), err))
		} else {
			for _, r := range fresh {
				if added, err := s.AddRetentionNotice(auth.RetentionNotice{Schema: t.Schema, Table: t.Table, Key: r.Key, Since: r.Since, Noticed: now, EraseAfter: after}); err == nil && added {
					out.Noticed++
				}
			}
			out.Waiting += out.Noticed
			s.Audit(auth.EvRetentionNotice, by, "main", "", fmt.Sprintf("%s: %d row(s) noticed, to be erased after %s", where, out.Noticed, after.Format(time.RFC3339)))
		}
	}
	// Told, and their time up: erased if still past the period. A row no
	// longer past it (its date moved: the person came back) is renewed.
	if len(ripe) == 0 {
		return out
	}
	keys := make([]string, 0, len(ripe))
	var still []auth.RetentionNotice
	for _, n := range ripe {
		if _, ok := stillDue[normKey(n.Key)]; ok || isStillDue(eng, t, cut, n.Key, erased) {
			still = append(still, n)
			keys = append(keys, n.Key)
			continue
		}
		_ = s.CloseRetentionNotice(n.ID, auth.NoticeRenewed, 0, "")
		out.Renewed++
	}
	if len(keys) == 0 {
		return out
	}
	v, err := applyRetention(s, eng, where, e.Keep.String(), t.Column, keys, by)
	if err != nil {
		for _, n := range still {
			_ = s.CloseRetentionNotice(n.ID, auth.NoticeFailed, v.ID, firstLine(err.Error()))
		}
		if out.Error == "" {
			out.Error = err.Error()
		}
		out.Request = v.ID
		return out
	}
	for _, n := range still {
		_ = s.CloseRetentionNotice(n.ID, auth.NoticeErased, v.ID, "")
	}
	out.Request = v.ID
	if v.Result != nil {
		out.Erased = len(keys)
	}
	return out
}

// isStillDue asks for one row beyond the batch: still dated before the cutoff.
func isStillDue(eng *ErasureEngine, t auth.RetentionTable, cut time.Time, key string, erased []string) bool {
	d, err := eng.Due("main", RetentionQuery{Schema: t.Schema, Table: t.Table, Column: t.Column, Cutoff: cut, Limit: 100000, Exclude: erased})
	if err != nil {
		return false
	}
	for _, r := range d.Rows {
		if normKey(r.Key) == normKey(key) {
			return true
		}
	}
	return false
}

// erasedKeys are the rows of a table retention erased, by key.
func erasedKeys(s *auth.Store, schema, table string) []string {
	if s == nil {
		return nil
	}
	ns, err := s.RetentionNotices(schema, table, false, 1000000)
	if err != nil {
		return nil
	}
	var out []string
	for _, n := range ns {
		if n.State == auth.NoticeErased {
			out = append(out, n.Key)
		}
	}
	return out
}

// normKey compares keys as JSON, as the store keeps them compacted.
func normKey(k string) string {
	var v any
	if json.Unmarshal([]byte(k), &v) != nil {
		return k
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// applyRetention erases a table's rows by key on main and every branch, as
// an erasure request made by the run: the request records it, so a restore
// past it is refused or re-applied, and its outcomes and evidence read as
// any request's.
func applyRetention(s *auth.Store, eng *ErasureEngine, table, kept, column string, keys []string, by string) (ErasureView, error) {
	seed := ErasureSeed{table: keys}
	plan, fp, _, err := eng.PlanRetention("main", table, seed, by)
	if err != nil {
		return ErasureView{}, err
	}
	pj, _ := json.Marshal(plan)
	note := fmt.Sprintf("retention of %s: %d row(s) past %s (dated by %s), noticed under Rule 8(2)", table, len(keys), kept, column)
	rec, err := s.CreateErasure(auth.NewErasureRequest{Branch: "main", Refs: "[]", Events: "{}", Note: note, Plan: string(pj), Fingerprint: fp, Actor: by})
	if err != nil {
		return ErasureView{}, err
	}
	v, err := ViewErasure(rec)
	if err != nil {
		return v, err
	}
	s.Audit(auth.EvErasurePlanned, by, "main", "", fmt.Sprintf("request #%d planned by retention: %s", v.ID, plan.Summary()))
	if plan.Blocked {
		_, _ = s.WithdrawErasure(v.ID, by)
		return v, fmt.Errorf("%w: %s", ErrErasureBlocked, firstProblem(plan))
	}
	if err := s.ClaimErasure(v.ID, fp, by); err != nil {
		return v, err
	}
	var res ErasureResult
	err = withErasingLock("main", func() error {
		var aerr error
		plan, fp, res, aerr = eng.Apply("main", ErasureApply{ID: v.ID, UID: v.UID, Fingerprint: fp, Actor: by, Seed: seed, Only: table, Retention: true})
		if aerr != nil {
			return aerr
		}
		res.Notes = append(res.Notes, "Erased by retention: only "+table+"'s rows past their period, by key; logs follow their own retention.")
		rj, _ := json.Marshal(res)
		if _, ferr := s.FinishErasure(v.ID, string(rj), by); ferr != nil {
			return &recordErr{fmt.Errorf("the erasure was applied on main, but recording it failed: %w", ferr)}
		}
		res = eng.Settle("main", plan, res, nil)
		return nil
	})
	var rerr *recordErr
	if errors.As(err, &rerr) {
		return v, rerr.err
	}
	if err != nil {
		_ = s.ReleaseErasure(v.ID)
		_, _ = s.WithdrawErasure(v.ID, by)
		return v, err
	}
	rj, _ := json.Marshal(res)
	if _, err := s.SaveErasureResult(v.ID, string(rj)); err != nil {
		return v, err
	}
	s.Audit(auth.EvErasureApplied, by, "main", "", fmt.Sprintf("request #%d applied by retention: %d row(s) of %s", v.ID, res.Rows, table))
	// Every other branch, by the same keys, each on its own.
	bs := retentionBranches(eng, v, table, seed, by)
	bj, _ := json.Marshal(bs)
	if _, err := s.SaveErasureBranches(v.ID, string(bj)); err != nil {
		return v, err
	}
	return GetErasure(s, v.ID)
}

// retentionBranches applies a retention run to every branch but main, by key.
func retentionBranches(eng *ErasureEngine, v ErasureView, table string, seed ErasureSeed, by string) []ErasureBranch {
	out := []ErasureBranch{}
	infos, err := erasureBranchNames()
	if err != nil {
		return append(out, ErasureBranch{Branch: "(every branch)", State: BranchListed, Why: "the branches could not be listed: " + err.Error()})
	}
	for _, info := range infos {
		e := ErasureBranch{Branch: info.Name, Parent: branchParentOf(info.Name), Masked: info.Masked != ""}
		if t, ok := branchMadeOf(info.Name); ok {
			e.Made = &t
		}
		if info.Masked == MaskedMaking || info.Masked == MaskedFailed {
			e.State, e.Why = BranchListed, "a masked branch being made, or whose making failed: not erased"
			out = append(out, e)
			continue
		}
		if err := wakeForErase(info.Name); err != nil {
			e.State, e.Why = BranchListed, "it could not be started: "+firstLine(err.Error())
			out = append(out, e)
			continue
		}
		plan, fp, _, err := eng.PlanRetention(info.Name, table, seed, by)
		if err != nil {
			e.State, e.Why = BranchListed, "it could not be planned: "+firstLine(err.Error())
			out = append(out, e)
			continue
		}
		e.Plan, e.Fingerprint = &plan, fp
		if plan.Rows == 0 {
			e.State, e.Why = BranchSkipped, "none of the rows is on it"
			out = append(out, e)
			continue
		}
		if plan.Blocked {
			e.State, e.Why = BranchSkipped, "its plan has a problem: "+firstProblem(plan)
			out = append(out, e)
			continue
		}
		err = withErasingLock(info.Name, func() error {
			p, _, res, err := eng.Apply(info.Name, ErasureApply{ID: v.ID, UID: v.UID, Fingerprint: fp, Actor: by, Seed: seed, Only: table, Retention: true})
			if err != nil {
				return err
			}
			res = eng.Settle(info.Name, p, res, nil)
			e.State, e.Result = BranchApplied, &res
			return nil
		})
		if err != nil {
			e.State, e.Why = BranchSkipped, "applying it failed, and nothing was changed there: "+firstLine(err.Error())
		}
		out = append(out, e)
	}
	return out
}

// ---- the scheduler ----------------------------------------------------------------------

// retentionInterval is how often a run is due: daily, or
// FOX_RETENTION_INTERVAL (a duration, a minute or more).
func retentionInterval() time.Duration {
	if v := strings.TrimSpace(brand.Getenv("RETENTION_INTERVAL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= time.Minute {
			return d
		}
	}
	return 24 * time.Hour
}

// StartRetentionScheduler runs retention once a day while it is on (decided
// 28 Nov 2026: a scheduler of its own, point 10's being parked). It checks
// every ten minutes, or each interval if that is shorter; a run that fails
// is said in the log and tried at the next check.
func StartRetentionScheduler(s *auth.Store) {
	if s == nil {
		return
	}
	check := 10 * time.Minute
	if iv := retentionInterval(); iv < check {
		check = iv
	}
	go func() {
		time.Sleep(time.Minute) // let the stack settle after a start
		for {
			safego.Run("retention", func() { retentionIfDue(s) })
			time.Sleep(check)
		}
	}()
}

// retentionPrimaryUp says main can be read now; a test stands it in.
var retentionPrimaryUp = func() bool { return ContainerState(PrimaryContainer()) == "running" }

func retentionIfDue(s *auth.Store) {
	set := LoadRetentionSettings()
	// A day after it was turned on, then a day after each run: turning it on
	// is setting it up, and a run is asked for by hand (run) until then.
	last := set.Since
	if set.LastRun != nil && set.LastRun.After(last) {
		last = *set.LastRun
	}
	if !set.On || time.Since(last) < retentionInterval() {
		return
	}
	if _, err := dueEngine(); err != nil {
		return // the licence lapsed: nothing is erased, and status says why
	}
	if !retentionPrimaryUp() {
		return
	}
	run, err := RunRetention(s, "retention scheduler")
	if err != nil {
		log.Printf("retention: %v", err)
		return
	}
	log.Printf("retention: %s", run.Summary())
}
