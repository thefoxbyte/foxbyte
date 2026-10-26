// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

// Application identity (F1) on the engine's side: the account store holds which
// applications may assert and with which keys (auth/apps.go), and each branch
// checks tokens against its own copy, bb.app_issuers, with the install id and
// its own name in bb_f1.install (ledger/identity.sql).
//
// The copy is refreshed whenever it could be stale:
//
//   - a branch made, restored or whose container is made again (SyncIdentity
//     with the SQL itself, which also puts the checking functions in place when
//     the container's image now has the extension);
//   - a suspended branch woken (Resume), before it accepts a connection, so a
//     key revoked while it slept is refused on its first transaction;
//   - every running branch, at once, when a registration changes
//     (SyncIdentityAll).
//
// A branch is a copy of main, so until it is refreshed it would answer to
// main's name: a token for main alone would be accepted there. Create
// refreshes it before it returns, which is before any client can reach it.

// identityState is what a branch is given: the install's id and the
// registrations. Read from the account store each time, so every process
// (control plane, gateway, CLI) hands out the same.
type identityState struct {
	installID string
	apps      []auth.App
}

// loadIdentityState reads it. It is a variable so tests can supply one.
var loadIdentityState = func() (identityState, error) {
	s, err := auth.OpenFromEnv()
	if err != nil {
		return identityState{}, err
	}
	defer s.Close()
	id, err := s.InstallID()
	if err != nil {
		return identityState{}, err
	}
	apps, err := s.Apps()
	if err != nil {
		return identityState{}, err
	}
	return identityState{installID: id, apps: apps}, nil
}

// identityBranch is the name a branch's tokens must name in their branch
// claim. A promoted standby serves main.
func identityBranch(name string) string {
	if name == "standby" {
		return "main"
	}
	return name
}

// identityDataSQL writes a branch's copy: its install id and name, and every
// registered key, in one transaction, so a branch never has half of a change.
// Guarded: on a branch whose Blackbox predates application identity it does
// nothing (`fox ledger upgrade` installs it). Pure, so it is tested.
func identityDataSQL(branch string, st identityState) string {
	var b strings.Builder
	b.WriteString("DO $id$\nBEGIN\n")
	b.WriteString("  IF to_regclass('bb_f1.install') IS NULL OR to_regclass('bb.app_issuers') IS NULL THEN RETURN; END IF;\n")
	fmt.Fprintf(&b, "  INSERT INTO bb_f1.install (id, install_id, branch) VALUES (1, %s, %s)\n", quoteLiteral(st.installID), quoteLiteral(branch))
	b.WriteString("    ON CONFLICT (id) DO UPDATE SET install_id = excluded.install_id, branch = excluded.branch;\n")
	b.WriteString("  DELETE FROM bb.app_issuers;\n")
	for _, a := range st.apps {
		if a.Account == "" {
			continue // its account is gone, so nothing can log in as it
		}
		for _, k := range a.Keys {
			fmt.Fprintf(&b, "  INSERT INTO bb.app_issuers (issuer, kid, db_role, public_key, max_life, on_invalid, revoked_at, compromised_since)\n")
			fmt.Fprintf(&b, "    VALUES (%s, %s, %s, decode(%s, 'hex'), make_interval(secs => %d), %s, %s, %s);\n",
				quoteLiteral(a.Name), quoteLiteral(k.Kid), quoteLiteral(a.Account), quoteLiteral(k.PublicKey),
				a.MaxLife, quoteLiteral(a.OnInvalid), sqlTime(k.Revoked), sqlTime(k.CompromisedSince))
		}
	}
	b.WriteString("END\n$id$;\n")
	return b.String()
}

func sqlTime(unix *int64) string {
	if unix == nil {
		return "NULL"
	}
	return fmt.Sprintf("to_timestamp(%d)", *unix)
}

// SyncIdentity refreshes one branch's copy. With full, it runs the SQL too
// (ledger.SchemaIdentity, idempotent), for a container that may be new.
func SyncIdentity(name string, full bool) error {
	st, err := loadIdentityState()
	if err != nil {
		return fmt.Errorf("reading application registrations: %w", err)
	}
	sql := identityDataSQL(identityBranch(name), st)
	if full {
		sql = ledger.SchemaIdentity + "\n" + sql
	}
	if err := psqlQuiet(name, sql); err != nil {
		return fmt.Errorf("application identity on %q: %w", name, err)
	}
	return nil
}

// syncIdentityBestEffort is SyncIdentity where a failure must not stop the
// branch being used: it is reported, and that branch keeps the copy it had.
func syncIdentityBestEffort(name string, full bool) {
	if err := SyncIdentity(name, full); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}
}

// SyncIdentityAll refreshes every running branch, and the promoted standby
// when it is the primary. A suspended branch is refreshed when it is woken.
// Returns the branches it could not reach, with why.
func SyncIdentityAll() map[string]error {
	failed := map[string]error{}
	names, err := RunningBranches()
	if err != nil {
		failed["(listing branches)"] = err
		return failed
	}
	if PrimaryContainer() == container("standby") && ContainerState("standby") == "running" {
		names = append(names, "standby")
	}
	for _, n := range names {
		if err := SyncIdentity(n, false); err != nil {
			failed[n] = err
		}
	}
	return failed
}

// IdentityReadiness is, per running branch, whether it can check a token:
// "checked", "unavailable" (its container was made from an image without the
// extension; restarting the engine fixes it) or "not installed" (its Blackbox
// predates application identity; `fox ledger upgrade <branch>`).
func IdentityReadiness() (map[string]string, error) {
	names, err := RunningBranches()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, n := range names {
		v, err := Query(n, "SELECT CASE WHEN to_regprocedure('bb.app_identity_mode()') IS NULL THEN 'not installed' ELSE bb.app_identity_mode() END")
		if err != nil {
			out[n] = "unknown: " + firstLine(err.Error())
			continue
		}
		out[n] = v
	}
	return out, nil
}

// psqlQuiet runs SQL as the superuser with nothing printed unless it fails,
// bounded like any other question the engine asks.
func psqlQuiet(name, sql string) error {
	cmd, ctx, cancel := sudoCmd(30*time.Second, "docker", "exec", "-i",
		"--env-file", pgEnvFile(), container(name),
		"psql", "-X", "-q", "-U", pgUser, "-d", pgDatabase, "-v", "ON_ERROR_STOP=1")
	defer cancel()
	cmd.Stdin = strings.NewReader(sql)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return execErr(ctx, 30*time.Second, "psql", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out))))
	}
	return nil
}

// CompromisedKey is a key reported compromised, and since when.
type CompromisedKey struct {
	Issuer, Kid string
	Since       int64 // Unix seconds
}

// CompromisedKeys lists them from the registrations, the source of truth.
func CompromisedKeys(apps []auth.App) []CompromisedKey {
	var out []CompromisedKey
	for _, a := range apps {
		for _, k := range a.Keys {
			if k.CompromisedSince != nil {
				out = append(out, CompromisedKey{Issuer: a.Name, Kid: k.Kid, Since: *k.CompromisedSince})
			}
		}
	}
	return out
}

// AppForSQL is what a Blackbox listing adds to say who each change was for:
// a join, and the columns app_for (the user), app_state ("asserted by
// <application>", with "(key reported compromised)" for what a compromised key
// asserted after it was reported; "claimed"; "none"; or NULL for a record made
// before application identity), app_kid and app_note; and session_for, whom
// the agent session the change was made in was started for ("alice, asserted
// by shop", or "none: <why>"), where an application said so (Agent API
// act_for), else NULL.
//
// Read through to_jsonb, so a branch whose capture table predates these columns
// lists them as NULL rather than failing. The compromised keys are written into
// the query from the account store, so reading a Blackbox needs no access to
// the branch's copy of the keys. ledgerTable is the listed table's name or
// alias, whose id and at the join uses.
func AppForSQL(ledgerTable string, compromised []CompromisedKey) (cols, join string) {
	vals := "SELECT NULL::text, NULL::text, NULL::bigint WHERE false"
	if len(compromised) > 0 {
		rows := make([]string, len(compromised))
		for i, c := range compromised {
			rows[i] = fmt.Sprintf("(%s, %s, %d::bigint)", quoteLiteral(c.Issuer), quoteLiteral(c.Kid), c.Since)
		}
		vals = "VALUES " + strings.Join(rows, ", ")
	}
	join = fmt.Sprintf(" LEFT JOIN LATERAL (SELECT to_jsonb(x) AS j FROM bb.ledger_ext x WHERE x.ledger_id = %s.id) app_ext ON true"+
		" LEFT JOIN LATERAL (SELECT to_jsonb(y) AS j FROM bb.agent_sessions y WHERE y.session_id = %s.session) app_sess ON true",
		ledgerTable, ledgerTable)
	cols = fmt.Sprintf(`app_ext.j->>'app_actor' AS app_for,
		CASE WHEN app_ext.j->>'app_state' = 'asserted' AND EXISTS (
		       SELECT 1 FROM (%s) c(issuer, kid, since)
		        WHERE c.issuer = app_ext.j->>'app_issuer' AND c.kid = app_ext.j->>'app_kid'
		          AND extract(epoch FROM %s.at) >= c.since)
		     THEN 'asserted by ' || (app_ext.j->>'app_issuer') || ' (key reported compromised)'
		     WHEN app_ext.j->>'app_state' = 'asserted' THEN 'asserted by ' || (app_ext.j->>'app_issuer')
		     ELSE app_ext.j->>'app_state' END AS app_state,
		app_ext.j->>'app_kid' AS app_kid, app_ext.j->>'app_note' AS app_note,
		CASE WHEN app_sess.j->>'app_state' = 'asserted' THEN (app_sess.j->>'app_actor') || ', asserted by ' || (app_sess.j->>'app_issuer') ||
		       CASE WHEN EXISTS (SELECT 1 FROM (%s) c(issuer, kid, since)
		                          WHERE c.issuer = app_sess.j->>'app_issuer' AND c.kid = app_sess.j->>'app_kid'
		                            AND extract(epoch FROM (app_sess.j->>'started_at')::timestamptz) >= c.since)
		            THEN ' (key reported compromised)' ELSE '' END
		     WHEN app_sess.j->>'app_state' = 'none' THEN 'none: ' || (app_sess.j->>'app_note') END AS session_for`, vals, ledgerTable, vals)
	return cols, join
}

// compromisedNow reads the compromised keys from the account store; none when
// it cannot be opened, which shows a compromised key's records as plain
// "asserted" — said here because it is the one way that can happen.
func compromisedNow() []CompromisedKey {
	st, err := loadIdentityState()
	if err != nil {
		return nil
	}
	return CompromisedKeys(st.apps)
}
