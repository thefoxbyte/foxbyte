// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// Masking keys (F5, Gate 1 step 2; design, section 8): the install's key
// domains, each one HMAC key, and rotating them.
//
// A key is a file the database server reads, <MaskKeyDir>/<domain>.key, and
// the engine never reads it back: what is kept here is about the keys, never
// a key. Every branch shares the install's keys, because the directory is
// mounted into every database.
//
// Rotation makes the new key beside the old one, as <domain>--next.key, has
// each table's masks written again under it while masked readers keep reading
// the old ones, swaps each table over when it is done, then moves the new key
// onto <domain>.key, which replaces the old key's file, so the old key is gone.
// A domain a person names is never a next key's name: it has no "-".

// DefaultMaskDomain is the install's first domain, made by `fox mask setup`.
const DefaultMaskDomain = "default"

// nextKeySuffix names a rotation's new key until it replaces the old one.
const nextKeySuffix = "--next"

// MaskDomainRE is a domain a person may name: a file name, short enough that
// its next key's name is one too (bb_identity takes 1 to 32 characters).
var MaskDomainRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,23}$`)

// NextMaskKey is the name a domain's new key has during a rotation.
func NextMaskKey(domain string) string { return domain + nextKeySuffix }

// MaskKey is what is kept about one domain's key.
type MaskKey struct {
	Domain  string `json:"domain"`
	Gen     int    `json:"gen"` // 1 for the key first made, one more at each rotation
	Made    string `json:"made"`
	By      string `json:"by"`
	Rotated string `json:"rotated,omitempty"`
	RotBy   string `json:"rotatedBy,omitempty"`
	// Pending: a rotation began and has not finished, so <domain>--next.key
	// is its new key, which running it again carries on with.
	Pending bool `json:"pending,omitempty"`
}

var maskKeysPath = func() string { return brand.StatePath("mask-keys.json") }

// MaskKeys lists the install's domains. The default domain made before key
// records were kept (step 1) is its first key. Free: reading about the keys
// is reading.
func MaskKeys() []MaskKey {
	var keys []MaskKey
	if b, err := os.ReadFile(maskKeysPath()); err == nil {
		_ = json.Unmarshal(b, &keys)
	}
	if MaskOn() && findMaskKey(keys, DefaultMaskDomain) < 0 {
		keys = append(keys, MaskKey{Domain: DefaultMaskDomain, Gen: 1})
	}
	sort.Slice(keys, func(i, j int) bool {
		if (keys[i].Domain == DefaultMaskDomain) != (keys[j].Domain == DefaultMaskDomain) {
			return keys[i].Domain == DefaultMaskDomain
		}
		return keys[i].Domain < keys[j].Domain
	})
	return keys
}

func findMaskKey(keys []MaskKey, domain string) int {
	for i, k := range keys {
		if k.Domain == domain {
			return i
		}
	}
	return -1
}

// MaskKeyFor is one domain's record, and whether the install has it.
func MaskKeyFor(domain string) (MaskKey, bool) {
	keys := MaskKeys()
	if i := findMaskKey(keys, domain); i >= 0 {
		return keys[i], true
	}
	return MaskKey{}, false
}

// SaveMaskKeys writes the records. Enterprise calls it.
func SaveMaskKeys(keys []MaskKey) error {
	b, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return err
	}
	tmp := maskKeysPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, maskKeysPath())
}

// RecordMaskKey keeps, or replaces, one domain's record.
func RecordMaskKey(k MaskKey) error {
	keys := MaskKeys()
	if i := findMaskKey(keys, k.Domain); i >= 0 {
		keys[i] = k
	} else {
		keys = append(keys, k)
	}
	return SaveMaskKeys(keys)
}

// ForgetMaskKey drops a domain's record.
func ForgetMaskKey(domain string) error {
	keys := MaskKeys()
	if i := findMaskKey(keys, domain); i >= 0 {
		keys = append(keys[:i], keys[i+1:]...)
	}
	return SaveMaskKeys(keys)
}

// CheckMaskDomain refuses a name a person may not give a domain.
func CheckMaskDomain(d string) error {
	if !MaskDomainRE.MatchString(d) {
		return fmt.Errorf("%w: a key domain is a lowercase letter, then up to 23 of a-z, 0-9 and _, not %q", ErrInvalidRequest, d)
	}
	return nil
}

func maskKeyFile(name string) string { return MaskKeyDir() + "/" + name + ".key" }

// MaskKeyFileExists reports whether a key's file is there (the directory is
// the server's, so it is asked as root).
func MaskKeyFileExists(name string) bool { return quietOK("test", "-s", maskKeyFile(name)) }

// MakeNextMaskKey makes a domain's rotation key. With resume, a rotation cut
// short carries on with the key it made, so the masks it already wrote stay
// right; otherwise a next key left from before (kept for a branch stopped
// during a rotation: it is the key now in use) is replaced by a new one.
func MakeNextMaskKey(domain string, resume bool) error {
	if err := CheckMaskDomain(domain); err != nil {
		return err
	}
	if !resume {
		if err := RemoveMaskKey(NextMaskKey(domain)); err != nil {
			return err
		}
	}
	return EnsureMaskKey(NextMaskKey(domain))
}

// PromoteMaskKey puts a domain's rotation key in place of its key: a copy
// moved over the old file, so the old key is gone and, from then on, both
// names hold the new one until the next key is removed.
func PromoteMaskKey(domain string) error {
	if err := CheckMaskDomain(domain); err != nil {
		return err
	}
	next, cur := maskKeyFile(NextMaskKey(domain)), maskKeyFile(domain)
	tmp := cur + ".new"
	script := fmt.Sprintf("set -e; umask 077; cp %[1]s %[2]s; chown %[3]s:%[3]s %[2]s; chmod 0400 %[2]s; mv %[2]s %[4]s",
		shellQuote(next), shellQuote(tmp), postgresUID, shellQuote(cur))
	return run("sh", "-c", script)
}

// RemoveMaskKey removes a key's file: a rotation's next key once nothing
// reads it, or a domain's key once no table uses it.
func RemoveMaskKey(name string) error {
	if !maskDomainOK(name) {
		return fmt.Errorf("%w: %q is not a key's name", ErrInvalidRequest, name)
	}
	return run("rm", "-f", "--", maskKeyFile(name))
}

// StoppedBranches lists the branches that are not running: their masks cannot
// be read or written until they start.
func StoppedBranches() ([]string, error) {
	usages, err := activeStorage().usage()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, u := range usages {
		if strings.Contains(u.Name, "/") || u.Name == "restore" || u.Name == "standby" {
			continue
		}
		if ContainerState(u.Name) != "running" {
			out = append(out, u.Name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// stoppedAt is when a branch's database last stopped, if it has one.
var stoppedAt = func(name string) (time.Time, bool) {
	out, err := capture("docker", "inspect", "-f", "{{.State.FinishedAt}}", container(name))
	if err != nil {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(out))
	if err != nil || t.Year() < 2000 { // never started: 0001-01-01
		return time.Time{}, false
	}
	return t, true
}

// MaskTableKey is a masked table's key on a branch.
type MaskTableKey struct {
	Branch string `json:"branch"`
	Schema string `json:"schema"`
	Table  string `json:"table"`
	Domain string `json:"domain"`
	Gen    int    `json:"gen"`   // the key its masks were made under
	Keyed  bool   `json:"keyed"` // whether it has hashed or faked masks, which the key makes
}

// maskTablesSQL reads a branch's masked tables and their keys: every table
// with a rule, and every table a domain was chosen for.
const maskTablesSQL = `SELECT coalesce(json_agg(json_build_object('schema', s, 'table', t, 'domain', coalesce(d, 'default'),
     'gen', coalesce(g, 1), 'keyed', coalesce(k, false)) ORDER BY s, t), '[]'::json)
  FROM (SELECT coalesce(r.s, m.schema_name) s, coalesce(r.t, m.table_name) t, m.key_domain d, m.key_gen g, r.k
          FROM (SELECT schema_name s, table_name t, bool_or(rule IN ('hash', 'fake') OR json_path <> '') k
                  FROM bb.mask_rules GROUP BY 1, 2) r
          FULL JOIN bb.mask_tables m ON m.schema_name = r.s AND m.table_name = r.t) x`

// maskTablesNoKeysSQL is the same on a branch set up before key domains
// (step 1): every table is the default domain's, under its first key.
const maskTablesNoKeysSQL = `SELECT coalesce(json_agg(json_build_object('schema', schema_name, 'table', table_name, 'domain', 'default',
     'gen', 1, 'keyed', k) ORDER BY schema_name, table_name), '[]'::json)
  FROM (SELECT schema_name, table_name, bool_or(rule IN ('hash', 'fake') OR json_path <> '') k FROM bb.mask_rules GROUP BY 1, 2) x`

// MaskTableKeys reads a running branch's masked tables and their keys. Free.
func MaskTableKeys(name string) ([]MaskTableKey, error) {
	if ok, err := RelationExists(name, "bb.mask_rules"); err != nil || !ok {
		return []MaskTableKey{}, err
	}
	sql := maskTablesNoKeysSQL
	if ok, err := RelationExists(name, "bb.mask_tables"); err != nil {
		return nil, err
	} else if ok {
		sql = maskTablesSQL
	}
	out, err := QuerySQL(name, sql)
	if err != nil {
		return nil, fmt.Errorf("reading the masked tables on %s: %w (%s)", name, err, strings.TrimSpace(out))
	}
	var ts []MaskTableKey
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &ts); err != nil {
		return nil, err
	}
	for i := range ts {
		ts[i].Branch = name
	}
	if ts == nil {
		ts = []MaskTableKey{}
	}
	return ts, nil
}

// MaskKeyUse is a domain with where it is used.
type MaskKeyUse struct {
	MaskKey
	Tables []MaskTableKey `json:"tables"` // on running branches
	Stale  []MaskTableKey `json:"stale"`  // keyed masks made under an older key
	Next   bool           `json:"next"`   // a rotation was cut short: run it again to finish it
}

// MaskKeysStatus is the install's keys, with the tables using each on the
// running branches, and the branches that could not be read. Free.
type MaskKeysStatus struct {
	Keys    []MaskKeyUse `json:"keys"`
	Stopped []string     `json:"stopped"`
	Writes  bool         `json:"writes"`
}

// MaskKeysState reads it.
func MaskKeysState() (MaskKeysStatus, error) {
	st := MaskKeysStatus{Keys: []MaskKeyUse{}, Stopped: []string{}, Writes: requireMasker() == nil}
	keys := MaskKeys()
	if len(keys) == 0 {
		return st, nil
	}
	byDomain := map[string]*MaskKeyUse{}
	for _, k := range keys {
		st.Keys = append(st.Keys, MaskKeyUse{MaskKey: k, Tables: []MaskTableKey{}, Stale: []MaskTableKey{}, Next: k.Pending})
	}
	for i := range st.Keys {
		byDomain[st.Keys[i].Domain] = &st.Keys[i]
	}
	names, err := RunningBranches()
	if err != nil {
		return st, err
	}
	for _, n := range names {
		ts, err := MaskTableKeys(n)
		if err != nil {
			return st, err
		}
		for _, t := range ts {
			u, ok := byDomain[t.Domain]
			if !ok {
				continue
			}
			u.Tables = append(u.Tables, t)
			if t.Keyed && t.Gen < u.Gen {
				u.Stale = append(u.Stale, t)
			}
		}
	}
	if s, err := StoppedBranches(); err == nil && s != nil {
		st.Stopped = s
	}
	return st, nil
}

// MaskRotateCost is what a rotation costs and changes, said before it runs.
func MaskRotateCost(domain string) string {
	return fmt.Sprintf("What it does and costs:\n"+
		"  - a new key for %[1]s is made, and every hashed or faked mask under the old\n"+
		"    one is written again, a batch at a time: about 21 seconds a million rows,\n"+
		"    as measured. Partial and empty masks use no key and are not touched.\n"+
		"  - masked readers keep reading the old masks until each table is done, then\n"+
		"    the new ones. Writers are not held up; a table's writes cost about twice\n"+
		"    the usual masking while its masks are written again.\n"+
		"  - every hash and fake changes, so masks copied out before do not match\n"+
		"    masks read after. That is the point of rotating.\n"+
		"  - the old key is deleted once every table is done. There is no undo.\n", domain)
}

// ---- the paid half ----

// ErrMaskDomainInUse refuses deleting a domain a table uses.
var ErrMaskDomainInUse = errors.New("a key domain is deleted only when no table uses it")

// CreateMaskDomain makes a new key domain. Enterprise.
func CreateMaskDomain(domain, actor string) error {
	if err := requireMasker(); err != nil {
		return err
	}
	if err := CheckMaskDomain(domain); err != nil {
		return err
	}
	if !MaskOn() {
		return fmt.Errorf("%w: masking is not set up on this install: %s mask setup", ErrInvalidRequest, brand.CLI)
	}
	if _, ok := MaskKeyFor(domain); ok || MaskKeyFileExists(domain) {
		return fmt.Errorf("%w: the install already has a key domain %q", ErrInvalidRequest, domain)
	}
	if err := EnsureMaskKey(domain); err != nil {
		return fmt.Errorf("making %s's key: %w", domain, err)
	}
	return RecordMaskKey(MaskKey{Domain: domain, Gen: 1, Made: time.Now().UTC().Format(time.RFC3339), By: actor})
}

// DropMaskDomain deletes a key domain no table uses. A branch stopped since
// the domain was made is not asked, so it is refused: its tables might use
// the domain, and could not be written once the key is gone. Enterprise.
func DropMaskDomain(domain, actor string) error {
	if err := requireMasker(); err != nil {
		return err
	}
	if domain == DefaultMaskDomain {
		return fmt.Errorf("%w: the default domain is the install's own and stays", ErrInvalidRequest)
	}
	k, ok := MaskKeyFor(domain)
	if !ok {
		return fmt.Errorf("%w: the install has no key domain %q", ErrInvalidRequest, domain)
	}
	stopped, err := StoppedBranches()
	if err != nil {
		return err
	}
	// A table is put under a domain on a running branch, so a branch that
	// stopped before the domain was made cannot use it. Any other stopped
	// branch might (a branch made from one that does has its tables).
	made, _ := time.Parse(time.RFC3339, k.Made)
	var unread []string
	for _, n := range stopped {
		if t, ok := stoppedAt(n); !ok || made.IsZero() || !t.Before(made) {
			unread = append(unread, n)
		}
	}
	if len(unread) > 0 {
		return fmt.Errorf("%w: %s stopped after %s was made, so whether a table there uses it cannot be read: start or delete it first",
			ErrMaskDomainInUse, strings.Join(unread, ", "), domain)
	}
	names, err := RunningBranches()
	if err != nil {
		return err
	}
	var using []string
	for _, n := range names {
		ts, err := MaskTableKeys(n)
		if err != nil {
			return err
		}
		for _, t := range ts {
			if t.Domain == domain {
				using = append(using, n+":"+t.Schema+"."+t.Table)
			}
		}
	}
	if len(using) > 0 {
		return fmt.Errorf("%w: %s uses %s (%s mask key use default --table …)", ErrMaskDomainInUse, strings.Join(using, ", "), domain, brand.CLI)
	}
	for _, n := range []string{NextMaskKey(domain), domain} {
		if err := RemoveMaskKey(n); err != nil {
			return err
		}
	}
	return ForgetMaskKey(domain)
}

// RotateMaskKey rotates a domain's key on every running branch. say reports
// each table as it is done. Enterprise.
func RotateMaskKey(domain, actor string, say func(string)) error {
	if err := requireMasker(); err != nil {
		return err
	}
	if _, ok := MaskKeyFor(domain); !ok {
		return fmt.Errorf("%w: the install has no key domain %q", ErrInvalidRequest, domain)
	}
	if masker.Rotate == nil {
		return ErrMaskingNotLicensed
	}
	return masker.Rotate(domain, actor, say)
}

// UseMaskDomain puts a table's masks on a branch under a domain's key: they
// are made again under it, and only that table's. Enterprise.
func UseMaskDomain(branchName, schema, table, domain, actor string) error {
	if err := requireMasker(); err != nil {
		return err
	}
	if _, ok := MaskKeyFor(domain); !ok {
		return fmt.Errorf("%w: the install has no key domain %q: %s mask key create %s", ErrInvalidRequest, domain, brand.CLI, domain)
	}
	if masker.UseDomain == nil {
		return ErrMaskingNotLicensed
	}
	return masker.UseDomain(branchName, schema, table, domain, actor)
}
