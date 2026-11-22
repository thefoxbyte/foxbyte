// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// Moving a branch's Aadhaar numbers into the vault (point 13, step 13.3;
// docs/FOX_P13_Vault_Design.md, section 15). Decided on 21 November 2026:
//
//   - On a branch first. A branch's changes reach main by change request, and
//     a request carries schema, not a rewrite of rows. The vault gives a
//     number one reference key, so the same migration run again on main
//     writes the same keys the branch got. Main is moved only once a branch
//     made from main has moved the same columns with nothing left, and only by
//     an admin or the operator.
//   - A column holding only the number has its value replaced by the number's
//     reference key; a number inside text or JSON is replaced where it stands,
//     and the rest kept.
//   - A column that cannot hold an opaque key (a number type, char(12), a short
//     varchar) gets the legacy format: 12 digits starting with 1, which never
//     passes Aadhaar's check.
//   - A rehearsal branch deleted leaves keys in the vault no table holds. They
//     are listed (VaultOrphans), and an admin may delete them; the vault keeps
//     any key its access log shows someone else was handed.
//
// The reading and rewriting is Enterprise (enterprise/pii, through
// SetVaultMigrator); this file decides who may, records each run in the
// install's store, and holds the orphans.

// VaultMigrateKind is the kind 13.3 moves. Other kinds come from the PII
// scan's confirmed marks, a later step.
const VaultMigrateKind = "aadhaar"

// VaultMigrateColumn is one column in a migration's report.
type VaultMigrateColumn struct {
	Schema string `json:"schema"`
	Table  string `json:"table"`
	Column string `json:"column"`
	Type   string `json:"type"`
	// Format is the reference keys written: opaque, legacy, or mixed (a JSON
	// column: legacy for a number that is a JSON number, opaque in text).
	Format string `json:"format"`
	// Skipped says why the column was not moved; "" when it was.
	Skipped string `json:"skipped,omitempty"`
	// Rows and Numbers are what the first read found: rows holding a number,
	// and the numbers in them.
	Rows    int64 `json:"rows"`
	Numbers int64 `json:"numbers"`
	// Replaced is rows rewritten; Left is rows still holding a number at the
	// end, with why (LeftWhy).
	Replaced int64            `json:"replaced"`
	Left     int64            `json:"left"`
	LeftWhy  map[string]int64 `json:"left_why,omitempty"`
}

// Where is the column as a reader writes it.
func (c VaultMigrateColumn) Where() string { return c.Schema + "." + c.Table + "." + c.Column }

// Clean is a column moved with no number left in it.
func (c VaultMigrateColumn) Clean() bool { return c.Skipped == "" && c.Left == 0 }

// VaultMigration is a run's report.
type VaultMigration struct {
	ID       int64      `json:"id"`
	Branch   string     `json:"branch"`
	Kind     string     `json:"kind"`
	Actor    string     `json:"actor"`
	Dry      bool       `json:"dry"`
	State    string     `json:"state"`
	Started  time.Time  `json:"started"`
	Finished *time.Time `json:"finished,omitempty"`
	Error    string     `json:"error,omitempty"`
	Format   string     `json:"format,omitempty"` // the format asked for; "" lets each column choose

	Columns []VaultMigrateColumn `json:"columns"`
	// Distinct is the distinct numbers the first read found; Made the
	// reference keys new to the vault, Reused the ones it held already.
	Distinct int64 `json:"distinct"`
	Made     int64 `json:"made"`
	Reused   int64 `json:"reused"`
	// Passes is how many times the columns were read and rewritten: a row
	// written while the run ran is picked up by the next.
	Passes int `json:"passes"`
	// Vacuumed lists the tables vacuumed afterwards, so the rows' old versions
	// are gone from them.
	Vacuumed []string `json:"vacuumed,omitempty"`
	// Rehearsals are the branch runs main's run relied on.
	Rehearsals []int64  `json:"rehearsals,omitempty"`
	Limits     []string `json:"limits"`
}

// Clean is a run that moved every column it planned, with nothing left.
func (m VaultMigration) Clean() bool {
	if m.Dry || m.State != "done" || len(m.Columns) == 0 {
		return false
	}
	for _, c := range m.Columns {
		if !c.Clean() {
			return false
		}
	}
	return true
}

// Summary is the run in a line, for the security log.
func (m VaultMigration) Summary() string {
	what := "migration"
	if m.Dry {
		what = "preview"
	}
	moved, left, skipped := 0, int64(0), 0
	var replaced int64
	for _, c := range m.Columns {
		switch {
		case c.Skipped != "":
			skipped++
		default:
			moved++
		}
		left += c.Left
		replaced += c.Replaced
	}
	s := fmt.Sprintf("%s %d on %s: %d column(s), %d skipped; %d distinct number(s)", what, m.ID, m.Branch, moved, skipped, m.Distinct)
	if !m.Dry {
		s += fmt.Sprintf("; %d key(s) made, %d reused; %d row(s) rewritten, %d left", m.Made, m.Reused, replaced, left)
	}
	if m.Error != "" {
		s += "; failed: " + m.Error
	}
	return s
}

// VaultMigrateOptions are a run's choices.
type VaultMigrateOptions struct {
	Actor string // the account running it
	IP    string
	// Columns limits the run to these (schema.table.column); none means
	// every column the branch's latest exposure report found a number in.
	Columns []string
	// Format forces opaque or legacy keys everywhere; "" lets each column
	// choose.
	Format string
	DryRun bool
	// Call makes the run's calls to the vault as vaultActor: the operator's
	// go straight to it (VaultCallActor), an API caller's through their
	// grants (VaultCallAs).
	Call func(vaultActor, path string, body []byte) ([]byte, int, error)
}

// VaultMigrateRun is what the Enterprise half is given.
type VaultMigrateRun struct {
	Columns []string
	Format  string
	DryRun  bool
	// Tokenise puts numbers in the vault and returns their keys, in order,
	// and how many of them the vault made new.
	Tokenise func(values []string, format string) ([]string, int, error)
	// Check is asked, with the plan, before anything is put in the vault or
	// written: main's rehearsal rule.
	Check func(cols []VaultMigrateColumn) error
}

var migrateVault func(name string, r VaultMigrateRun) (VaultMigration, error)

// SetVaultMigrator installs the migration's Enterprise half.
func SetVaultMigrator(fn func(name string, r VaultMigrateRun) (VaultMigration, error)) {
	migrateVault = fn
}

// ErrVaultRehearsal is a run on main with no rehearsal on a branch.
var ErrVaultRehearsal = errors.New("not rehearsed")

// CheckVaultFormat reads --format.
func CheckVaultFormat(f string) (string, error) {
	switch f = strings.ToLower(strings.TrimSpace(f)); f {
	case "", "opaque", "legacy":
		return f, nil
	}
	return "", fmt.Errorf("%w: a format is opaque or legacy, not %q", ErrInvalidRequest, f)
}

// MigrateToVault moves a branch's Aadhaar numbers into the vault, or with
// DryRun says what it would move. The run is in the install's store and the
// security log.
func MigrateToVault(st *auth.Store, name string, o VaultMigrateOptions) (VaultMigration, error) {
	if err := requireVault(); err != nil {
		return VaultMigration{}, err
	}
	if migrateVault == nil {
		return VaultMigration{}, notLicensed{edition.Vault}
	}
	if st == nil {
		return VaultMigration{}, errors.New("the install's store is not open, and a migration is kept there")
	}
	if !Exists(name) {
		return VaultMigration{}, fmt.Errorf("%w: no branch %q", ErrInvalidRequest, name)
	}
	if IsMaskedBranch(name) {
		return VaultMigration{}, fmt.Errorf("%w: %s is a masked branch, whose marked columns hold masks, not numbers: move the branch it was made from", ErrInvalidRequest, name)
	}
	var err error
	if o.Format, err = CheckVaultFormat(o.Format); err != nil {
		return VaultMigration{}, err
	}
	for i, c := range o.Columns {
		if o.Columns[i], err = parseVaultColumn(c); err != nil {
			return VaultMigration{}, err
		}
	}
	if o.Call == nil {
		return VaultMigration{}, errors.New("a migration needs a way to call the vault")
	}
	run := auth.VaultMigrationRun{Branch: name, Parent: BranchParent(name), Kind: VaultMigrateKind, Actor: o.Actor, Dry: o.DryRun}
	if t, ok := branchMadeAt(name); ok {
		run.BranchMade = t.Unix()
	}
	if run, err = st.StartVaultMigration(run); err != nil {
		return VaultMigration{}, err
	}
	var rehearsals []int64
	r := VaultMigrateRun{Columns: o.Columns, Format: o.Format, DryRun: o.DryRun}
	r.Tokenise = func(values []string, format string) ([]string, int, error) {
		return vaultMigrateTokenise(st, run, o.Call, values, format)
	}
	r.Check = func(cols []VaultMigrateColumn) error {
		if name != "main" || o.DryRun {
			return nil
		}
		ids, err := vaultRehearsed(st, cols)
		rehearsals = ids
		return err
	}
	m, runErr := migrateVault(name, r)
	m.ID, m.Branch, m.Kind, m.Actor, m.Dry, m.Started, m.Format = run.ID, name, VaultMigrateKind, o.Actor, o.DryRun, run.Started, o.Format
	m.Rehearsals = rehearsals
	if m.Columns == nil {
		m.Columns = []VaultMigrateColumn{}
	}
	if m.Limits == nil {
		m.Limits = []string{}
	}
	m.State = "done"
	if runErr != nil {
		m.State, m.Error = "failed", runErr.Error()
	}
	now := time.Now().UTC()
	m.Finished = &now
	b, _ := json.Marshal(m)
	if err := st.FinishVaultMigration(run.ID, string(b), runErr); err != nil && runErr == nil {
		runErr = err
	}
	st.Audit(auth.EvVaultMigrate, o.Actor, name, o.IP, m.Summary())
	return m, runErr
}

// parseVaultColumn reads schema.table.column, the schema public when left
// out.
func parseVaultColumn(s string) (string, error) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	switch {
	case len(parts) == 2 && parts[0] != "" && parts[1] != "":
		return "public." + parts[0] + "." + parts[1], nil
	case len(parts) == 3 && parts[0] != "" && parts[1] != "" && parts[2] != "":
		return strings.Join(parts, "."), nil
	}
	return "", fmt.Errorf("%w: a column is schema.table.column (or table.column in public), not %q", ErrInvalidRequest, s)
}

// vaultMigrateTokenise puts a batch of numbers in the vault for a run, and
// keeps the keys the vault made for it.
func vaultMigrateTokenise(st *auth.Store, run auth.VaultMigrationRun, call func(string, string, []byte) ([]byte, int, error), values []string, format string) ([]string, int, error) {
	body, err := json.Marshal(map[string]any{"kind": VaultMigrateKind, "values": values, "format": format})
	if err != nil {
		return nil, 0, err
	}
	reply, code, err := call(run.VaultActor, "tokenise", body)
	if err != nil {
		return nil, 0, err
	}
	var r struct {
		Refs    []string `json:"refs"`
		New     []bool   `json:"new"`
		Results []string `json:"results"`
		Error   string   `json:"error"`
	}
	if err := json.Unmarshal(reply, &r); err != nil {
		return nil, 0, fmt.Errorf("the vault's reply: %w", err)
	}
	if code != 200 || r.Error != "" {
		return nil, 0, fmt.Errorf("the vault: %d %s", code, r.Error)
	}
	if len(r.Refs) != len(values) || len(r.Results) != len(values) {
		return nil, 0, fmt.Errorf("the vault answered %d keys for %d numbers", len(r.Refs), len(values))
	}
	var made []string
	for i := range values {
		if r.Results[i] != "done" || r.Refs[i] == "" {
			return nil, 0, fmt.Errorf("the vault did not take a number that passes Aadhaar's check: %s", r.Results[i])
		}
		if i < len(r.New) && r.New[i] {
			made = append(made, r.Refs[i])
		}
	}
	if err := st.AddVaultMigrationRefs(run.ID, made); err != nil {
		return nil, 0, fmt.Errorf("keeping the keys the run made: %w", err)
	}
	return r.Refs, len(made), nil
}

// vaultRehearsed checks main's rule: each column the run would move has been
// moved, with nothing left, by a finished run on a branch made from main. It
// returns the runs relied on.
func vaultRehearsed(st *auth.Store, cols []VaultMigrateColumn) ([]int64, error) {
	runs, err := st.VaultMigrations("", 1000)
	if err != nil {
		return nil, err
	}
	var reports []VaultMigration
	for _, r := range runs {
		if r.Dry || r.State != "done" || r.Branch == "main" || r.Parent != "main" {
			continue
		}
		var m VaultMigration
		if json.Unmarshal([]byte(r.Report), &m) == nil {
			m.ID = r.ID
			reports = append(reports, m)
		}
	}
	return rehearsalFor(cols, reports)
}

// rehearsalFor finds, for each column to move, the newest branch run that
// moved it clean. Skipped columns are not moved, so need none.
func rehearsalFor(cols []VaultMigrateColumn, reports []VaultMigration) ([]int64, error) {
	var missing []string
	used := map[int64]bool{}
	for _, c := range cols {
		if c.Skipped != "" {
			continue
		}
		found := int64(0)
		for _, m := range reports {
			for _, x := range m.Columns {
				if x.Where() == c.Where() && x.Clean() {
					found = m.ID
					break
				}
			}
			if found != 0 {
				break
			}
		}
		if found == 0 {
			missing = append(missing, c.Where())
		} else {
			used[found] = true
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%w: main is moved into the vault only after a branch made from main has moved the same columns with no number left, and nothing on main changes until then. Not yet rehearsed: %s. Make a branch of main, move it (%s vault migrate --branch <branch>), check it, then move main",
			ErrVaultRehearsal, strings.Join(missing, ", "), brand.CLI)
	}
	ids := make([]int64, 0, len(used))
	for id := range used {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
}

// VaultMigrations lists a branch's runs (every branch's for ""), newest
// first, as their reports.
func VaultMigrations(st *auth.Store, name string, limit int) ([]VaultMigration, error) {
	if err := requireFeature(edition.Vault); err != nil {
		return nil, err
	}
	runs, err := st.VaultMigrations(name, limit)
	if err != nil {
		return nil, err
	}
	out := []VaultMigration{}
	for _, r := range runs {
		out = append(out, vaultMigrationOf(r))
	}
	return out, nil
}

func vaultMigrationOf(r auth.VaultMigrationRun) VaultMigration {
	var m VaultMigration
	_ = json.Unmarshal([]byte(r.Report), &m)
	m.ID, m.Branch, m.Kind, m.Actor, m.Dry, m.State, m.Started, m.Finished, m.Error =
		r.ID, r.Branch, r.Kind, r.Actor, r.Dry, r.State, r.Started, r.Finished, r.Error
	if m.Columns == nil {
		m.Columns = []VaultMigrateColumn{}
	}
	if m.Limits == nil {
		m.Limits = []string{}
	}
	return m
}

// --- orphans -----------------------------------------------------------------

// VaultOrphan is a run whose branch is gone, and what became of the keys it
// made.
type VaultOrphan struct {
	Run    int64                        `json:"run"`
	Branch string                       `json:"branch"`
	Actor  string                       `json:"actor"`
	Ran    time.Time                    `json:"ran"`
	Why    string                       `json:"why"` // the branch was deleted, or made again
	Keys   auth.VaultMigrationRefCounts `json:"keys"`
	// incarnation names the branch as the run knew it, so runs on the same
	// branch share their keys' ownership.
	incarnation string
	vaultActor  string
}

// branchGone says why a run's branch is no longer the one it ran on: deleted,
// or made again (a reset, or a new branch of the same name). "" while it is.
func branchGone(r auth.VaultMigrationRun) string {
	if !Exists(r.Branch) {
		return "the branch was deleted"
	}
	if r.BranchMade != 0 {
		if t, ok := branchMadeAt(r.Branch); ok && t.Unix() != r.BranchMade {
			return "the branch was made again (reset, or deleted and created anew)"
		}
	}
	return ""
}

// VaultOrphans lists the runs whose branch is gone and that made keys: the
// keys still to settle are in the vault with no table to hold them, unless
// someone else was handed them too.
func VaultOrphans(st *auth.Store) ([]VaultOrphan, error) {
	if err := requireFeature(edition.Vault); err != nil {
		return nil, err
	}
	runs, err := st.VaultMigrations("", 1000)
	if err != nil {
		return nil, err
	}
	out := []VaultOrphan{}
	for _, r := range runs {
		if r.Dry || r.Branch == "main" {
			continue
		}
		why := branchGone(r)
		if why == "" {
			continue
		}
		c, err := st.VaultMigrationRefCounts(r.ID)
		if err != nil {
			return nil, err
		}
		if c.Made == 0 {
			continue
		}
		out = append(out, VaultOrphan{Run: r.ID, Branch: r.Branch, Actor: r.Actor, Ran: r.Started, Why: why, Keys: c,
			incarnation: fmt.Sprintf("%s@%d", r.Branch, r.BranchMade), vaultActor: r.VaultActor})
	}
	return out, nil
}

// VaultOrphansDeleted is what a delete of orphans did.
type VaultOrphansDeleted struct {
	Runs    []int64 `json:"runs"`
	Deleted int     `json:"deleted"`
	Kept    int     `json:"kept"` // someone else was handed them, so they stay
}

// DeleteVaultOrphans deletes the orphaned keys of one run (or of all, for
// run 0) from the vault. The vault deletes a key only if the run's branch's
// own migrations made it and nobody else was handed it; the rest are kept,
// and said so.
func DeleteVaultOrphans(st *auth.Store, actor, ip string, run int64) (VaultOrphansDeleted, error) {
	res := VaultOrphansDeleted{Runs: []int64{}}
	if err := requireVault(); err != nil {
		return res, err
	}
	// An older service ignores the owners and deletes whatever it is named.
	if r := vaultServiceRevision(); r < 3 {
		return res, fmt.Errorf("the vault service runs image revision %d, which cannot delete only a migration's own unused keys: restart the install (%s stop, then %s start) so it runs revision %d first",
			r, brand.CLI, brand.CLI, VaultImageRevision)
	}
	orphans, err := VaultOrphans(st)
	if err != nil {
		return res, err
	}
	// The owners of a branch's keys are all its runs: a key one run made and
	// the next run on the same branch was handed again is still the branch's.
	owners := map[string][]string{}
	for _, o := range orphans {
		owners[o.incarnation] = append(owners[o.incarnation], o.vaultActor)
	}
	found := false
	for _, o := range orphans {
		if run != 0 && o.Run != run {
			continue
		}
		found = true
		if o.Keys.Pending == 0 {
			continue
		}
		d, k, err := deleteRunOrphans(st, actor, ip, o, owners[o.incarnation])
		res.Deleted += d
		res.Kept += k
		res.Runs = append(res.Runs, o.Run)
		if err != nil {
			return res, err
		}
	}
	if run != 0 && !found {
		return res, fmt.Errorf("%w: run %d has no orphaned keys: its branch is still there, it made none, or there is no such run", ErrInvalidRequest, run)
	}
	st.Audit(auth.EvVaultOrphans, actor, "", ip, fmt.Sprintf("orphaned keys of run(s) %v: %d deleted, %d kept (someone else was handed them)", res.Runs, res.Deleted, res.Kept))
	return res, nil
}

func deleteRunOrphans(st *auth.Store, actor, ip string, o VaultOrphan, owners []string) (deleted, kept int, err error) {
	secret, err := vaultSecret()
	if err != nil {
		return 0, 0, err
	}
	for {
		refs, err := st.PendingVaultMigrationRefs(o.Run, 1000)
		if err != nil || len(refs) == 0 {
			return deleted, kept, err
		}
		body, _ := json.Marshal(map[string]any{"kind": VaultMigrateKind, "refs": refs, "owners": owners,
			"purpose": fmt.Sprintf("orphaned by vault migration %d on branch %s", o.Run, o.Branch)})
		reply, head, code, err := vaulter.Call(VaultSocket(), secret, actor, "delete", body)
		if err != nil && code == 0 {
			return deleted, kept, fmt.Errorf("the vault service: %w", err)
		}
		var r vaultReply
		_ = json.Unmarshal(reply, &r)
		detail := fmt.Sprintf("delete orphans of run %d, %d reference keys: %s", o.Run, len(refs), vaultSummary(r))
		if head != "" {
			detail += "; head " + head
		}
		st.Audit(auth.EvVaultCall, actor, VaultMigrateKind, ip, detail)
		if code != 200 || len(r.Results) != len(refs) {
			return deleted, kept, fmt.Errorf("the vault refused the delete: %d %s", code, r.Error)
		}
		var gone, stay []string
		for i, x := range r.Results {
			switch x {
			case "done", "not found":
				gone = append(gone, refs[i])
			default: // in use, not made by them
				stay = append(stay, refs[i])
			}
		}
		if err := st.SettleVaultMigrationRefs(o.Run, gone, stay); err != nil {
			return deleted, kept, err
		}
		deleted += len(gone)
		kept += len(stay)
	}
}
