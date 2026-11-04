// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"strings"
)

// Who is allowed to copy the database, and from where.
//
// Phase 1 of docs/FOX_HA_Plan.md asks for "a dedicated replication role rather
// than widening allowReplication", and that sentence is doing a lot of work.
// What `ha enable` used to do was append this to the primary's pg_hba.conf:
//
//	host replication all all scram-sha-256
//
// Any role, from any address. And the standby then connected as the bootstrap
// superuser, because that is the only role that existed with REPLICATION. On a
// single machine with no published port the reach of that is small, which is
// why it lasted — but it means the credential that copies the database is the
// credential that owns it, and the rule that admits it admits everything.
//
// So: a role that can replicate and cannot read anything, and a rule that names
// it. Measured against a live install rather than reasoned about:
//
//   - the superuser attempting physical replication over the network now gets
//     "no pg_hba.conf entry for replication connection ... user dbadmin", while
//     its ordinary connections are untouched;
//   - db_replica attempting to read a user table gets "permission denied", and
//     IDENTIFY_SYSTEM answers.
//
// The address stays `samenet` rather than `all`. samenet is the subnets the
// server is directly attached to, which inside a container is the docker
// network the engine made — so a replication connection has to come from
// something on this install's own network. Narrowing it further means knowing
// the address of a standby on another machine, which is the rest of phase 1.

// ReplicationRole copies the database and can read none of it.
const ReplicationRole = "db_replica"

// ReplicationRolePassword is derived from the install secret like every other
// role's, so it is never stored and never travels: anything on this machine can
// work it out, and nothing off it can. The same reason RealtimeRolePassword
// works this way.
//
// Which is also the next thing phase 1 has to solve. A standby on another
// machine cannot derive this, because the secret is this install's — so the
// secret has to reach that machine, which is the plan's third bullet and a
// decision about key distribution rather than a function.
func ReplicationRolePassword() string { return rolePassword("replication", ReplicationRole) }

// EnsureReplicationRole creates the role on a server, or resets its password to
// the derived one. Idempotent, and cheap next to the base backup that follows.
//
// LOGIN REPLICATION and nothing else — no table grants, not a member of
// db_client, NOINHERIT so it cannot pick any up. The shape EnsureRealtimeRole
// already uses for the decode role, for the same reason: a credential that
// leaks should be able to do the one thing it was made for.
func EnsureReplicationRole(server string) error {
	sql := fmt.Sprintf(`DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = %s) THEN
    EXECUTE format('CREATE ROLE %%I LOGIN REPLICATION NOSUPERUSER NOBYPASSRLS NOINHERIT', %s);
  END IF;
  EXECUTE format('ALTER ROLE %%I PASSWORD %%L', %s, %s);
END $$`, bodyLiteral(ReplicationRole), bodyLiteral(ReplicationRole),
		bodyLiteral(ReplicationRole), bodyLiteral(ReplicationRolePassword()))
	out, err := captureCombined("docker", "exec", "--env-file", pgEnvFile(), server,
		"psql", "-U", pgUser, "-d", pgDatabase, "-tAq", "-v", "ON_ERROR_STOP=1", "-c", sql)
	if err != nil {
		return fmt.Errorf("preparing the %s role on %s: %w\n%s", ReplicationRole, server, err, strings.TrimSpace(out))
	}
	return nil
}

// replicationHBALine is the rule that admits the standby, and nothing else.
const replicationHBALine = "host replication " + ReplicationRole + " samenet scram-sha-256"

// legacyHBAPattern matches the rule this replaces, in whatever spacing a past
// version of the engine wrote it. Removed rather than left below the narrow one,
// because pg_hba is first-match-wins and a wide rule above or below still
// admits everyone it names.
const legacyHBAPattern = `^host[[:space:]]\+replication[[:space:]]\+all[[:space:]]\+all`

// peerHBALine admits the standby on another machine: TLS required, this role
// only, that address only.
//
// `hostssl` rather than `host` is the whole of "TLS on replication traffic".
// `host` would match a plaintext connection too, so a standby that silently
// failed to negotiate TLS would still be admitted and would still send its
// password. Measured: with this rule, sslmode=disable is refused outright.
func peerHBALine(peer string) string {
	if strings.TrimSpace(peer) == "" {
		return ""
	}
	return "hostssl replication " + ReplicationRole + " " + peer + " scram-sha-256"
}

// hbaScript is the shell that narrows a primary's replication rule. Separate
// and pure so a test can read what will run against a database it has no way to
// start.
//
// peer is "" on an install that publishes nothing, which is every install until
// somebody runs `node expose` — and then the file says exactly what it said
// before this existed.
func hbaScript(peer string) string {
	sh := `set -e
sed -i '/` + legacyHBAPattern + `/d' "$PGDATA/pg_hba.conf"
grep -qF '` + replicationHBALine + `' "$PGDATA/pg_hba.conf" || echo '` + replicationHBALine + `' >> "$PGDATA/pg_hba.conf"`
	// Stale peer rules go first: an address that is no longer the standby's
	// must stop being admitted, and `node expose` run twice with a different
	// peer would otherwise leave both.
	sh += `
sed -i '/^hostssl[[:space:]]\+replication[[:space:]]\+` + ReplicationRole + `/d' "$PGDATA/pg_hba.conf"`
	if line := peerHBALine(peer); line != "" {
		sh += `
echo '` + line + `' >> "$PGDATA/pg_hba.conf"`
	}
	return sh
}

// ReplicationOpenToEveryone reports whether a server still carries the wide
// rule. For `fox check`: an install whose HA was enabled by an older version
// keeps that rule in its data directory until something rewrites it, and
// nothing in a routine upgrade does.
func ReplicationOpenToEveryone(server string) bool {
	out, err := capture("docker", "exec", "-u", "postgres", server, "bash", "-c",
		`grep -c '`+legacyHBAPattern+`' "$PGDATA/pg_hba.conf" || true`)
	if err != nil {
		return false // a server that cannot be asked is not a finding
	}
	n := strings.TrimSpace(out)
	return n != "" && n != "0"
}

// The replication role's password reaches the base backup through a 0600 env
// file rather than `docker run -e PGPASSWORD=...`, because a command line is
// visible in `docker inspect` and in ps to anything on the machine. That writer
// lives in pgenv.go beside the superuser's, which is where this engine keeps
// the one piece of code that knows how to write a credential file —
// replicaEnvFile().
