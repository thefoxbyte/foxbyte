// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// Unmask and the lookup (F5, Gate 1 step 3; design, section 10).
//
// Unmask is a right on a branch, given by an admin to a masked account: there
// it sees real values, as an owner does, and every read it makes of a marked
// table is audited: its role's pgaudit.role is bb_audit_read, which holds
// SELECT on every masked table (and on every table marked for audit), so
// pgAudit logs those reads, and only that account's. The setting is a
// superuser's, so the account cannot undo it. Reads are logged while the
// audit log is on (F6); the right holds either way, and says so.
//
// The lookup finds a person by an exact value without unmasking:
// bb_mask.find(table, column, value) is SECURITY DEFINER, returns the
// matching rows masked, allows 30 calls a minute for each account, and
// records each call, who, when, which column and how many rows, never the
// value (enterprise/masking).

// UnmaskGrant is one account's unmask right on one branch.
type UnmaskGrant struct {
	Email  string `json:"email"`
	Branch string `json:"branch"`
	By     string `json:"by"`
	At     string `json:"at"`
}

var unmaskPath = func() string { return brand.StatePath("unmask-grants.json") }

// Read again when it changes, as the masked accounts' file is: every process
// that makes roles reads it.
var unmasks struct {
	sync.Mutex
	mod   time.Time
	size  int64
	byKey map[string]UnmaskGrant // branch \x00 email
}

func unmaskKey(branchName, email string) string {
	return branchName + "\x00" + strings.ToLower(email)
}

func loadUnmasks() map[string]UnmaskGrant {
	unmasks.Lock()
	defer unmasks.Unlock()
	st, err := os.Stat(unmaskPath())
	if err != nil {
		unmasks.byKey, unmasks.mod, unmasks.size = nil, time.Time{}, 0
		return nil
	}
	if unmasks.byKey != nil && st.ModTime().Equal(unmasks.mod) && st.Size() == unmasks.size {
		return unmasks.byKey
	}
	m := map[string]UnmaskGrant{}
	if b, err := os.ReadFile(unmaskPath()); err == nil {
		var list []UnmaskGrant
		if json.Unmarshal(b, &list) == nil {
			for _, g := range list {
				m[unmaskKey(g.Branch, g.Email)] = g
			}
		}
	}
	unmasks.byKey, unmasks.mod, unmasks.size = m, st.ModTime(), st.Size()
	return m
}

// UnmaskGrants lists the unmask rights, by account then branch. Free.
func UnmaskGrants() []UnmaskGrant {
	m := loadUnmasks()
	out := make([]UnmaskGrant, 0, len(m))
	for _, g := range m {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Email != out[j].Email {
			return out[i].Email < out[j].Email
		}
		return out[i].Branch < out[j].Branch
	})
	return out
}

// UnmaskGrantsOf lists the branches an account may unmask on.
func UnmaskGrantsOf(email string) []string {
	var out []string
	for _, g := range UnmaskGrants() {
		if strings.EqualFold(g.Email, email) {
			out = append(out, g.Branch)
		}
	}
	return out
}

func saveUnmasks(list []UnmaskGrant) error {
	if list == nil {
		list = []UnmaskGrant{} // [], not null, for whoever reads the file
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := unmaskPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, unmaskPath())
}

// hasUnmask reports whether an account holds unmask on a branch.
func hasUnmask(branchName, email string) bool {
	_, ok := loadUnmasks()[unmaskKey(branchName, email)]
	return ok
}

// changeUnmasks keeps the grants that keep says to.
func changeUnmasks(keep func(UnmaskGrant) bool, add *UnmaskGrant) error {
	var list []UnmaskGrant
	for _, g := range loadUnmasks() {
		if keep(g) {
			list = append(list, g)
		}
	}
	if add != nil {
		list = append(list, *add)
	}
	sort.Slice(list, func(i, j int) bool {
		return unmaskKey(list[i].Branch, list[i].Email) < unmaskKey(list[j].Branch, list[j].Email)
	})
	return saveUnmasks(list)
}

// forgetBranchUnmasks drops the unmask rights on a branch being deleted: a
// branch made later with its name is another branch.
func forgetBranchUnmasks(name string) {
	if len(loadUnmasks()) == 0 {
		return
	}
	_ = changeUnmasks(func(g UnmaskGrant) bool { return g.Branch != name }, nil)
}

// auditedReadsSQL sets, or takes off, an account's role's audit role: an
// unmask holder's reads of marked tables are logged through bb_audit_read.
func auditedReadsSQL(email string, on bool) string {
	set := "RESET pgaudit.role"
	if on {
		set = "SET pgaudit.role = " + AuditReadRole
	}
	return fmt.Sprintf(`DO $do$
DECLARE r text := %s;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
    EXECUTE format('ALTER ROLE %%I %s', r);
  END IF;
END $do$;`, bodyLiteral(email), set)
}

// Unmask gives an account unmask on a branch, or with off takes it. Only a
// masked account is given it: any other sees real values already. Its role
// there changes at once, its open sessions there end, and its reads of
// marked tables are audited from then on. Enterprise.
func Unmask(email, branchName, actor string, off bool) error {
	if err := requireMasker(); err != nil {
		return err
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || branchName == "" {
		return fmt.Errorf("%w: unmask is an account's right on a branch: both are needed", ErrInvalidRequest)
	}
	if err := checkName(branchName); err != nil {
		return err
	}
	if !off {
		if _, ok := loadMasked()[email]; !ok {
			return fmt.Errorf("%w: %s is not masked, so it sees real values already: unmask is for a masked account", ErrInvalidRequest, email)
		}
		if !Exists(branchName) {
			return fmt.Errorf("%w: there is no branch %q", ErrInvalidRequest, branchName)
		}
	}
	var add *UnmaskGrant
	if !off {
		add = &UnmaskGrant{Email: email, Branch: branchName, By: actor, At: time.Now().UTC().Format(time.RFC3339)}
	}
	if err := changeUnmasks(func(g UnmaskGrant) bool { return unmaskKey(g.Branch, g.Email) != unmaskKey(branchName, email) }, add); err != nil {
		return err
	}
	if ContainerState(branchName) != "running" {
		forgetUserRole(branchName, email)
		return nil
	}
	if !off && masker.AuditReads != nil {
		// Every masked table's reads by an unmask holder are logged.
		if err := masker.AuditReads(branchName); err != nil {
			return err
		}
	}
	return ApplyAccountMask(branchName, email)
}

// Lookup is one call of the lookup, as recorded: never the value.
type Lookup struct {
	At     string `json:"at"`
	Who    string `json:"who"`
	Table  string `json:"table"`
	Column string `json:"column"`
	Found  int    `json:"found"`
}

// Lookups reads a running branch's lookup record, newest first. Free.
func Lookups(name string, limit int) ([]Lookup, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 10000 {
		limit = 100
	}
	if ok, err := RelationExists(name, MaskSchema+".lookups"); err != nil || !ok {
		return []Lookup{}, err
	}
	out, err := QuerySQL(name, fmt.Sprintf(`SELECT coalesce(json_agg(json_build_object('at', at, 'who', who, 'table', rel, 'column', col, 'found', found)
     ORDER BY at DESC), '[]'::json) FROM (SELECT * FROM %s.lookups ORDER BY at DESC LIMIT %d) l`, MaskSchema, limit))
	if err != nil {
		return nil, fmt.Errorf("reading the lookups on %s: %w (%s)", name, err, strings.TrimSpace(out))
	}
	var ls []Lookup
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &ls); err != nil {
		return nil, err
	}
	if ls == nil {
		ls = []Lookup{}
	}
	return ls, nil
}

// LookupsPerMinute is how many lookups an account may make a minute.
const LookupsPerMinute = 30
