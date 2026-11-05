// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// Masking (F5, point 7; docs/FOX_F5_Masking_Design.md). Gate 1, step 1: rules
// on confirmed marks, masked readers, and masks kept on a branch.
//
// What is here is what every edition needs once masks exist: the key's mount
// into the containers, and the masked reader's role, which the code that makes
// every account's role (EnsureUserRole) has to know about, and reading the
// rules and the masked accounts. Setting rules up, masking an account and
// making the masks are Enterprise (enterprise/masking). Masks already made
// keep working in every edition, as anchors and findings do: a masked account
// stays masked, and its role says so.

const (
	// The roles (design, sections 6 and 10). Brand-free, like every stored name.
	MaskedRole = "db_masked" // what a masked account's role is in, instead of db_client
	MaskerRole = "bb_masker" // owns the shadows, the triggers and the views; nobody logs in as it
	// MaskSchema holds the views a masked reader reads, the shadows and the
	// lookup; first in a masked reader's search_path.
	MaskSchema = "bb_mask"
	// maskKeysInContainer is where bb_identity reads the keys (bbid_mask_hmac).
	maskKeysInContainer = "/run/bb-mask"
)

// MaskKeyDir is where the install keeps its masking keys: the state directory,
// owned by the server's user (uid 999 in the image) and readable by nobody
// else, mounted read-only into every database container.
var MaskKeyDir = func() string { return brand.StatePath("mask") }

// MaskOn reports whether masking has been set up on this install: the default
// key exists.
func MaskOn() bool {
	_, err := os.Stat(MaskKeyDir())
	return err == nil
}

// maskMount is the containers' key mount, once masking is set up. Read-only:
// nothing in a database may change a key.
func maskMount() []string {
	if !MaskOn() {
		return nil
	}
	return []string{"-v", MaskKeyDir() + ":" + maskKeysInContainer + ":ro"}
}

// runsWithMaskKeys reports whether a running database has the key mount: one
// started before masking was set up has not, until it starts again.
func runsWithMaskKeys(name string) bool {
	out, err := capture("docker", "inspect", "-f", "{{range .Mounts}}{{.Destination}} {{end}}", container(name))
	return err == nil && strings.Contains(out, maskKeysInContainer)
}

// MaskPending lists the running databases started before masking was set up,
// which have no key until they next start.
func MaskPending() ([]string, error) {
	if !MaskOn() {
		return nil, nil
	}
	names, err := RunningBranches()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, n := range names {
		if !runsWithMaskKeys(n) {
			out = append(out, n)
		}
	}
	return out, nil
}

// MaskNeedsRestart reports whether a running database must start again before
// it can be masked: it was started before masking was set up, so it has no
// key, or on an image older than the masking hash.
func MaskNeedsRestart(name string) bool {
	if ContainerState(name) != "running" {
		return false
	}
	if !runsWithMaskKeys(name) {
		return true
	}
	out, err := capture("docker", "inspect", "-f", "{{index .Config.Labels \""+imageRevisionLabel+"\"}}", container(name))
	return err != nil || parseImageRevision(out) < 4
}

// RestartForMask starts a database again, on the current image and with the
// key mount. Its connections drop while it does.
func RestartForMask(name string) error {
	if name == "main" {
		return RestartPrimary()
	}
	if err := startContainer(name, false); err != nil {
		return err
	}
	return waitReady(name)
}

// MaskHAGuard refuses a setup that would restart main while the promoted
// standby is serving it.
func MaskHAGuard() error {
	if ServingBranch("main") != "standby" {
		return nil
	}
	return fmt.Errorf("refusing `%s mask setup`: 'main' is being served by the promoted standby "+
		"since `%s ha failover`, and this restarts it.\nRun `%s ha failback` first", brand.CLI, brand.CLI, brand.CLI)
}

// ---- masked accounts ----

// MaskedAccount is one account an admin has masked.
type MaskedAccount struct {
	Email string `json:"email"`
	By    string `json:"by"`
	At    string `json:"at"` // RFC 3339
}

var maskedPath = func() string { return brand.StatePath("masked-accounts.json") }

// The file is read by every process that makes roles (the control plane, the
// Gateway, the CLI), so it is read again when it changes, not cached for good.
var masked struct {
	sync.Mutex
	mod   time.Time
	size  int64
	byKey map[string]MaskedAccount
}

func loadMasked() map[string]MaskedAccount {
	masked.Lock()
	defer masked.Unlock()
	st, err := os.Stat(maskedPath())
	if err != nil {
		masked.byKey, masked.mod, masked.size = nil, time.Time{}, 0
		return nil
	}
	if masked.byKey != nil && st.ModTime().Equal(masked.mod) && st.Size() == masked.size {
		return masked.byKey
	}
	m := map[string]MaskedAccount{}
	if b, err := os.ReadFile(maskedPath()); err == nil {
		var list []MaskedAccount
		if json.Unmarshal(b, &list) == nil {
			for _, a := range list {
				m[strings.ToLower(a.Email)] = a
			}
		}
	}
	masked.byKey, masked.mod, masked.size = m, st.ModTime(), st.Size()
	return m
}

// MaskedAccounts lists the masked accounts, by email. Free: reading who is
// masked is reading.
func MaskedAccounts() []MaskedAccount {
	m := loadMasked()
	out := make([]MaskedAccount, 0, len(m))
	for _, a := range m {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out
}

// SaveMaskedAccounts writes the list. Enterprise calls it; a Standard install
// never changes it.
func SaveMaskedAccounts(list []MaskedAccount) error {
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := maskedPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, maskedPath())
}

// accountMasked reports whether an account's role on a branch is a masked
// reader's: masked by an admin, and neither an install admin nor the branch's
// owner, who always see real values (design, decision 3).
func accountMasked(branchName, email string) bool {
	if _, ok := loadMasked()[strings.ToLower(email)]; !ok {
		return false
	}
	return !maskExempt(branchName, email)
}

// maskExempt: an install admin, or the branch's owner. A variable so the
// tests need neither a database nor an account store.
var maskExempt = func(branchName, email string) bool {
	if ok, err := IsAdmin("main", email); err == nil && ok {
		return true
	}
	st, err := auth.OpenFromEnv()
	if err != nil {
		return false
	}
	defer st.Close()
	owner, ok := st.BranchOwner(branchName)
	if !ok {
		return false
	}
	u, ok := st.UserByEmail(email)
	return ok && u.ID == owner
}

// maskedRoleSQL makes a masked reader's login role, or turns an account's
// role into one: in db_masked and not in db_client (whose rights it would
// inherit, or SET ROLE to), the masks first in its search_path, and its
// failing statements never logged with their text, where a lookup's value or
// a guess would land (design, section 17, item 1). Superuser-only settings, so
// the reader cannot undo them. db_masked is made if this branch has not got it:
// a masked account on a branch with no masks reads nothing there, rather than
// everything.
func maskedRoleSQL(email, password string) string {
	return retryingRoleDO(fmt.Sprintf("r text := %s;", quoteLiteral(email)), fmt.Sprintf(`      IF to_regrole('%[2]s') IS NULL THEN
        EXECUTE 'CREATE ROLE %[2]s NOLOGIN';
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
        EXECUTE format('CREATE ROLE %%I LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS INHERIT IN ROLE %[2]s', r);
      END IF;
      EXECUTE format('ALTER ROLE %%I WITH LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS PASSWORD %%L', r, %[1]s);
      IF pg_has_role(r, 'db_client', 'MEMBER') THEN
        EXECUTE format('REVOKE db_client FROM %%I', r);
      END IF;
      EXECUTE format('GRANT %[2]s TO %%I', r);
      EXECUTE format('ALTER ROLE %%I SET role = %[2]s', r);
      EXECUTE format('ALTER ROLE %%I SET search_path = %[3]s, public', r);
      EXECUTE format('ALTER ROLE %%I SET log_min_error_statement = panic', r);`,
		quoteLiteral(password), MaskedRole, MaskSchema))
}

// unmaskedRoleSQL turns a masked reader's role back into an ordinary
// account's, for an account unmasked, or exempt on this branch.
func unmaskedRoleSQL(email string) string {
	return fmt.Sprintf(`DO $do$
DECLARE r text := %s;
BEGIN
  IF to_regrole(r) IS NOT NULL AND to_regrole('%[2]s') IS NOT NULL AND pg_has_role(r, '%[2]s', 'MEMBER') THEN
    EXECUTE format('REVOKE %[2]s FROM %%I', r);
    EXECUTE format('GRANT db_client TO %%I', r);
    EXECUTE format('ALTER ROLE %%I SET role = db_client', r);
    EXECUTE format('ALTER ROLE %%I RESET search_path', r);
    EXECUTE format('ALTER ROLE %%I RESET log_min_error_statement', r);
  END IF;
END $do$;`, quoteLiteral(email), MaskedRole)
}

// endSessionsSQL ends an account's sessions on a branch: a session opened
// before its role changed keeps the rights it logged in with.
func endSessionsSQL(email string) string {
	return fmt.Sprintf("SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE usename = %s AND pid <> pg_backend_pid();",
		quoteLiteral(email))
}

// ApplyAccountMask makes an account's role on a running branch match whether
// it is masked there now, and ends its open sessions when that changed it. A
// branch not running gets it when the role is next used (EnsureUserRole).
func ApplyAccountMask(branchName, email string) error {
	if ContainerState(branchName) != "running" {
		forgetUserRole(branchName, email)
		return nil
	}
	sql := unmaskedRoleSQL(email)
	if accountMasked(branchName, email) {
		sql = maskedRoleSQL(email, UserRolePassword(email))
	}
	if err := provisionRole(branchName, sql+"\n"+endSessionsSQL(email)); err != nil {
		return err
	}
	forgetUserRole(branchName, email)
	return nil
}

func forgetUserRole(branchName, email string) {
	for _, m := range []string{"masked", "plain"} {
		ensuredRoles.Delete(branchName + "\x00" + email + "\x00" + m)
	}
	ensuredRoles.Delete(branchName + "\x00" + email)
}

// ---- rules ----

// The rules (design, section 7).
const (
	MaskPartial = "partial"
	MaskHash    = "hash"
	MaskFake    = "fake"
	MaskEmpty   = "empty"
)

// MaskRules lists the rules a choice can name.
var MaskRules = []string{MaskPartial, MaskHash, MaskFake, MaskEmpty}

// MaskRule is one column's rule, or a JSON path's inside it, on a branch.
type MaskRule struct {
	Schema   string `json:"schema"`
	Table    string `json:"table"`
	Column   string `json:"column"`
	Path     string `json:"path,omitempty"` // a JSON path, $.a.b; "" for the column itself
	Rule     string `json:"rule"`
	Category string `json:"category"` // point 4's, from the confirmed finding it was set on
	By       string `json:"by"`
	At       string `json:"at"`
}

// Where is the rule's place, as point 4 writes it: schema.table.column[path].
func (r MaskRule) Where() string {
	w := r.Schema + "." + r.Table + "." + r.Column
	if r.Path != "" {
		w += " " + r.Path
	}
	return w
}

// MaskCost is what a rule costs, as measured (design, section 17), said
// before a rule is set (decision 9).
func MaskCost(rule, path string) string {
	if path == "" && (rule == MaskPartial || rule == MaskEmpty) {
		return "What it costs: nothing on writes, as a partial or empty mask is made as\n" +
			"it is read. A masked reader's reads of the table are about a quarter slower.\n"
	}
	s := "What it costs, as measured (PostgreSQL 18, 16 clients):\n" +
		"  - writes to the table: about a fifth to a third fewer single-row writes a\n" +
		"    second; a 10,000-row UPDATE takes about 3.6 times as long. Other tables\n" +
		"    are not touched.\n" +
		"  - a masked reader's reads of the table: about a quarter slower.\n" +
		"  - making the masks of rows already there: about 14 seconds a million rows,\n" +
		"    without holding up writers.\n"
	if path != "" {
		s += "  - a JSON path costs with the size of the documents: in documents over 64 KB\n" +
			"    a write can take hundreds of times as long (100 documents of 250 KB:\n" +
			"    1.4 ms without, 544 ms with).\n"
	}
	return s
}

// ErrAadhaarHash is a rule that would hash or fake Aadhaar (design, section 7):
// a keyed hash of Aadhaar that applications join on is a hash used as a
// reference key, which UIDAI forbids.
var ErrAadhaarHash = errors.New("Aadhaar is masked by display only (partial or empty), never hashed or faked: joins on Aadhaar go through the vault's tokens")

// CheckMaskRule refuses what a rule may not be, before anything is asked of a
// database.
func CheckMaskRule(rule, category string) error {
	switch rule {
	case MaskPartial, MaskHash, MaskFake, MaskEmpty:
	default:
		return fmt.Errorf("%w: a rule is %s, not %q", ErrInvalidRequest, strings.Join(MaskRules, ", "), rule)
	}
	if strings.EqualFold(category, "aadhaar") && (rule == MaskHash || rule == MaskFake) {
		return fmt.Errorf("%w: %v", ErrInvalidRequest, ErrAadhaarHash)
	}
	return nil
}

// DefaultMaskRule is the rule a category gets when none is named (design,
// section 7).
func DefaultMaskRule(category string) string {
	switch strings.ToLower(category) {
	case "aadhaar", "pan", "card", "mobile", "gstin", "ifsc":
		return MaskPartial
	case "email":
		return MaskHash
	case "name":
		return MaskFake
	}
	return MaskEmpty
}

// maskRulesSQL reads a branch's rules; a branch with masking never set up has
// no table, and so none.
const maskRulesSQL = `SELECT CASE WHEN to_regclass('bb.mask_rules') IS NULL THEN '[]'::json ELSE
  (SELECT coalesce(json_agg(json_build_object('schema', schema_name, 'table', table_name, 'column', column_name,
     'path', json_path, 'rule', rule, 'category', category, 'by', set_by, 'at', set_at)
     ORDER BY schema_name, table_name, column_name, json_path), '[]'::json) FROM bb.mask_rules) END`

// MaskRulesOn reads a branch's rules. Free.
func MaskRulesOn(name string) ([]MaskRule, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	out, err := QuerySQL(name, maskRulesSQL)
	if err != nil {
		return nil, fmt.Errorf("reading the masking rules on %s: %w (%s)", name, err, strings.TrimSpace(out))
	}
	var rules []MaskRule
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &rules); err != nil {
		return nil, fmt.Errorf("reading the masking rules: %w", err)
	}
	if rules == nil {
		rules = []MaskRule{}
	}
	return rules, nil
}

// ---- the paid half ----

// Masker is what enterprise/masking supplies.
type Masker struct {
	Setup      func(branch, actor string) error
	SetRule    func(branch string, r MaskRule) error
	DropRule   func(branch, schema, table, column, path, actor string) error
	MaskTables func(branch string) ([]string, error) // the tables whose masks are ready
}

var masker *Masker

// SetMasker installs it. Called from enterprise/masking's init, and from
// nowhere else.
func SetMasker(m *Masker) { masker = m }

// ErrMaskingNotLicensed is the refusal for masking.
var ErrMaskingNotLicensed = notLicensed{edition.Masking}

func requireMasker() error {
	if err := requireFeature(edition.Masking); err != nil {
		return err
	}
	if masker == nil {
		return ErrMaskingNotLicensed
	}
	return nil
}

// SetupMasking makes the install's default key, if there is none, and the
// masked reader's roles, schema and grants on a branch. Enterprise.
func SetupMasking(branchName, actor string) error {
	if err := requireMasker(); err != nil {
		return err
	}
	return masker.Setup(branchName, actor)
}

// SetMaskRule sets a rule on a confirmed mark and makes the table's masks.
// Enterprise.
func SetMaskRule(branchName string, r MaskRule) error {
	if err := requireMasker(); err != nil {
		return err
	}
	// An unnamed rule is the category's default, chosen once the confirmed
	// finding's category is read.
	if r.Rule != "" {
		if err := CheckMaskRule(r.Rule, r.Category); err != nil {
			return err
		}
	}
	return masker.SetRule(branchName, r)
}

// DropMaskRule takes a rule off; a table left with none is no longer masked.
// Enterprise.
func DropMaskRule(branchName, schema, table, column, path, actor string) error {
	if err := requireMasker(); err != nil {
		return err
	}
	return masker.DropRule(branchName, schema, table, column, path, actor)
}

// MaskAccount masks an account, or with off unmasks it, and makes its role on
// every running branch match. Install admins are refused: they can change the
// masks, so masking them would only pretend (decision 3). Enterprise.
func MaskAccount(email, actor string, off bool) error {
	if err := requireMasker(); err != nil {
		return err
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return fmt.Errorf("%w: an account is named by its email", ErrInvalidRequest)
	}
	if !off {
		if ok, err := IsAdmin("main", email); err == nil && ok {
			return fmt.Errorf("%w: %s is an admin, and admins always see real values: they can change the masks", ErrInvalidRequest, email)
		}
	}
	m := loadMasked()
	var list []MaskedAccount
	for e, a := range m {
		if e != email {
			list = append(list, a)
		}
	}
	if !off {
		list = append(list, MaskedAccount{Email: email, By: actor, At: time.Now().UTC().Format(time.RFC3339)})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Email < list[j].Email })
	if err := SaveMaskedAccounts(list); err != nil {
		return err
	}
	names, err := RunningBranches()
	if err != nil {
		return err
	}
	var failed []string
	for _, n := range names {
		if err := ApplyAccountMask(n, email); err != nil {
			failed = append(failed, fmt.Sprintf("%s (%v)", n, err))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("the account's role could not be changed on %s: it is changed when next used", strings.Join(failed, ", "))
	}
	return nil
}

// MaskStatus is masking on an install and one branch.
type MaskStatus struct {
	On       bool            `json:"on"`
	Pending  []string        `json:"pending"` // running without the key mount
	Branch   string          `json:"branch"`
	Rules    []MaskRule      `json:"rules"`
	Ready    []string        `json:"ready"`    // tables whose masks are made
	Accounts []MaskedAccount `json:"accounts"` // install-wide
	Writes   bool            `json:"writes"`   // whether this install sets rules (Enterprise)
}

// MaskingStatus reads it. Free.
func MaskingStatus(branchName string) (MaskStatus, error) {
	if branchName == "" {
		branchName = "main"
	}
	st := MaskStatus{On: MaskOn(), Branch: branchName, Pending: []string{}, Rules: []MaskRule{}, Ready: []string{},
		Accounts: MaskedAccounts(), Writes: requireMasker() == nil}
	if p, err := MaskPending(); err == nil && p != nil {
		st.Pending = p
	}
	if ContainerState(branchName) != "running" {
		return st, nil
	}
	rules, err := MaskRulesOn(branchName)
	if err != nil {
		return st, err
	}
	st.Rules = rules
	if masker != nil && masker.MaskTables != nil {
		if t, err := masker.MaskTables(branchName); err == nil && t != nil {
			st.Ready = t
		}
	}
	return st, nil
}

// ---- the primitives enterprise/masking makes masks with ----

// EnsureMaskKey makes a key domain's key if it has none: 32 random bytes, in a
// file of the server's user (uid 999), readable by nobody else, in a directory
// only that user can enter. The engine never reads it back.
func EnsureMaskKey(domain string) error {
	if !maskDomainOK(domain) {
		return fmt.Errorf("%w: a key domain is 1 to 32 of a-z, 0-9, _ and -", ErrInvalidRequest)
	}
	dir := MaskKeyDir()
	if err := run("install", "-d", "-o", postgresUID, "-g", postgresUID, "-m", "0700", dir); err != nil {
		return err
	}
	path := dir + "/" + domain + ".key"
	if quietOK("test", "-s", path) {
		return nil
	}
	tmp := path + ".new"
	script := fmt.Sprintf("set -e; umask 077; head -c 32 /dev/urandom > %[1]s; chown %[2]s:%[2]s %[1]s; chmod 0400 %[1]s; mv %[1]s %[3]s",
		shellQuote(tmp), postgresUID, shellQuote(path))
	return run("sh", "-c", script)
}

func maskDomainOK(d string) bool {
	if len(d) == 0 || len(d) > 32 {
		return false
	}
	for _, c := range d {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// quietOK runs a privileged command and reports whether it succeeded.
func quietOK(name string, args ...string) bool {
	cmd, _, cancel := sudoCmd(execClean, name, args...)
	defer cancel()
	return cmd.Run() == nil
}

// RunMaskSQL runs the statements that make or change a table's masks in one
// transaction, recorded in the Blackbox under the person who asked. replace
// lets it drop the masks it is replacing (views, triggers and shadows in
// bb_mask), which the guardrail refuses by default.
func RunMaskSQL(name, actor string, stmts []string, replace bool) error {
	body := strings.Join(stmts, ";\n") + ";"
	return trackExec(name, trackSQL(actor, brand.CLI+" mask", body, replace))
}

// RunMaskScript runs a script as the superuser, a statement at a time, for
// what commits as it goes: filling a table's masks in batches.
func RunMaskScript(name, script string) error { return psqlQuiet(name, script) }

// EnsureMaskImage makes sure the engine image has the masking hash: revision
// 4 or later, fetched or built if the one in hand is older.
func EnsureMaskImage() error {
	img := pgImage()
	if err := ensureImageRef(img); err != nil {
		return err
	}
	if ours(img) && imageRevision(img) < 4 {
		return fmt.Errorf("the engine image %s is revision %d and has no masking hash; "+
			"revision 4 could not be fetched or built", img, imageRevision(img))
	}
	return nil
}

// MaskColumn is one column of a table, as the masks need it.
type MaskColumn struct {
	Name string `json:"name"`
	Type string `json:"type"` // format_type
	Key  bool   `json:"key"`  // in the primary key
}

// MaskColumns reads a table's columns in order, and which are its key.
func MaskColumns(name, schema, table string) ([]MaskColumn, error) {
	out, err := QuerySQL(name, fmt.Sprintf(`SELECT coalesce(json_agg(json_build_object('name', a.attname, 'type', format_type(a.atttypid, a.atttypmod),
    'key', coalesce(a.attnum = ANY (i.indkey), false)) ORDER BY a.attnum), '[]'::json)
  FROM pg_attribute a
  LEFT JOIN pg_index i ON i.indrelid = a.attrelid AND i.indisprimary
 WHERE a.attrelid = to_regclass(%s) AND a.attnum > 0 AND NOT a.attisdropped`, quoteLiteral(QuoteIdent(schema)+"."+QuoteIdent(table))))
	if err != nil {
		return nil, fmt.Errorf("reading %s.%s's columns: %w (%s)", schema, table, err, strings.TrimSpace(out))
	}
	var cols []MaskColumn
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &cols); err != nil {
		return nil, err
	}
	return cols, nil
}
