//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package hardening

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

func init() { branch.SetHardeningFixer(plan, apply) }

// kind is how a fix is made.
type kind int

const (
	settings kind = iota // ALTER SYSTEM, then a reload
	recorded             // statements in the Blackbox, under the person who asked
	roles                // ALTER ROLE: the cluster's, which the Blackbox does not record
	datadir              // the data directory's mode
)

// fixer is one check's fix: what it will run, worked out from the branch as
// it is now.
type fixer struct {
	kind kind
	plan func(b string) (changes, sql []string, note string, ok bool, err error)
}

// setting is a fix that sets server settings to the given values.
func setting(pairs ...string) fixer {
	return fixer{kind: settings, plan: func(b string) ([]string, []string, string, bool, error) {
		var changes, sql []string
		for i := 0; i+1 < len(pairs); i += 2 {
			name, want := pairs[i], pairs[i+1]
			cur, err := branch.ShowSetting(b, name)
			if err != nil {
				return nil, nil, "", false, err
			}
			if cur == want {
				continue
			}
			changes = append(changes, fmt.Sprintf("%s: %s → %s", name, show(cur), want))
			sql = append(sql, fmt.Sprintf("ALTER SYSTEM SET %s = %s", name, branch.QuoteLiteral(want)))
		}
		return changes, sql, "", len(sql) > 0, nil
	}}
}

func show(v string) string {
	if v == "" {
		return "(empty)"
	}
	return v
}

// The fixes, by check. A check that is not here has none that is safe to make
// without more than a "yes": its report gives the command for a person.
var fixers = map[string]fixer{
	"log.connections":    setting("log_connections", "on"),
	"log.disconnections": setting("log_disconnections", "on"),
	"log.min_messages":   setting("log_min_messages", "warning"),
	"log.error_statement": {kind: settings, plan: func(b string) ([]string, []string, string, bool, error) {
		// With the audit log on, statement text stays out of the server log
		// on purpose (F6); the check is manual then, and never comes here
		// failing. Turning audit off resets it.
		return setting("log_min_error_statement", "error").plan(b)
	}},
	"log.verbosity":     setting("log_error_verbosity", "default"),
	"log.hostname":      setting("log_hostname", "off"),
	"log.prefix":        setting("log_line_prefix", "%m [%p] %q%u@%d "),
	"conn.idle":         setting("idle_in_transaction_session_timeout", "10min"),
	"conn.ssl_protocol": setting("ssl_min_protocol_version", "TLSv1.2"),
	"set.durability":    setting("fsync", "on", "full_page_writes", "on"),
	"roles.scram": {kind: settings, plan: func(b string) ([]string, []string, string, bool, error) {
		// Only the setting: a password already kept as an MD5 hash can only
		// be set again by whoever knows it.
		md5, err := md5Roles(b)
		if err != nil || len(md5) > 0 {
			return nil, nil, "", false, err
		}
		return setting("password_encryption", "scram-sha-256").plan(b)
	}},
	"roles.public_schema": {kind: recorded, plan: func(string) ([]string, []string, string, bool, error) {
		return []string{"PUBLIC: CREATE on schema public taken away"},
			[]string{"REVOKE CREATE ON SCHEMA public FROM PUBLIC"},
			"The roles that create tables there through the Gateway are granted CREATE themselves, so they keep it.", true, nil
	}},
	"roles.bypassrls": {kind: roles, plan: func(b string) ([]string, []string, string, bool, error) {
		names, err := bypassRoles(b)
		if err != nil || len(names) == 0 {
			return nil, nil, "", false, err
		}
		var changes, sql []string
		for _, n := range names {
			changes = append(changes, n+": BYPASSRLS → NOBYPASSRLS")
			sql = append(sql, "ALTER ROLE "+branch.QuoteIdent(n)+" NOBYPASSRLS")
		}
		return changes, sql, "Row-level policies apply to these roles from now on: an application that relied on reading past them will see only the rows the policies allow.", true, nil
	}},
	"files.datadir": {kind: datadir, plan: func(string) ([]string, []string, string, bool, error) {
		return []string{"the data directory: mode → 700, owned by postgres"}, nil, "", true, nil
	}},
}

// plan is the preview for a failing check, false when it has no safe fix.
func plan(b string, c branch.HardeningCheck) (branch.HardeningFix, bool, error) {
	fx, ok := fixers[c.ID]
	if !ok {
		return branch.HardeningFix{}, false, nil
	}
	changes, sql, note, ok, err := fx.plan(b)
	if err != nil || !ok {
		return branch.HardeningFix{}, false, err
	}
	return branch.HardeningFix{ID: c.ID, Title: c.Title, Level: c.Level, Changes: changes, SQL: sql, Note: note}, true, nil
}

// apply makes a fix, from a plan made again now: the preview a person saw may
// be older than the branch.
func apply(b, actor string, f branch.HardeningFix) error {
	fx, ok := fixers[f.ID]
	if !ok {
		return fmt.Errorf("%w: %s", branch.ErrNoHardeningFix, f.ID)
	}
	_, sql, _, ok, err := fx.plan(b)
	if err != nil {
		return err
	}
	if !ok {
		return nil // already as the fix would leave it
	}
	switch fx.kind {
	case settings:
		return branch.SetSystemSettings(b, sql)
	case recorded:
		return branch.RunRecorded(b, actor, "fox hardening", sql)
	case roles:
		return branch.RunStatements(b, sql)
	case datadir:
		return branch.SetDataDirMode(b)
	}
	return nil
}

func md5Roles(b string) ([]string, error) {
	return roleNames(b, "rolpassword LIKE 'md5%'")
}

// bypassRoles are the roles other than superusers that bypass row-level
// security: the check's own definition.
func bypassRoles(b string) ([]string, error) {
	return roleNames(b, "rolbypassrls AND NOT rolsuper")
}

func roleNames(b, where string) ([]string, error) {
	out, err := branch.QuerySQL(b, "SELECT coalesce(json_agg(rolname ORDER BY rolname), '[]'::json) FROM pg_authid WHERE rolname NOT LIKE 'pg\\_%' AND "+where)
	if err != nil {
		return nil, fmt.Errorf("%w (%s)", err, strings.TrimSpace(out))
	}
	var names []string
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &names); err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

// Fixable lists the checks with a fix, for the docs and the tests.
func Fixable() []string {
	ids := make([]string, 0, len(fixers))
	for id := range fixers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
