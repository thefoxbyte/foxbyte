// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"net"
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

// hbaManagedMarker is the first line of a pg_hba.conf that `node expose` wrote.
// Its presence is how the script knows the file on disk is already ours, so a
// second expose does not back up its own output over the original.
const hbaManagedMarker = "# fox-node-expose: written by node expose, put back by node unexpose"

// hbaBackupName is where the rules from before the exposure wait, beside the
// file they came from. Inside PGDATA, so a base backup copies it too. That is
// harmless, because pg_hba.conf holds rules and no secrets, and it means a
// promoted copy can be un-exposed the same way.
const hbaBackupName = "pg_hba.conf.fox-unexposed"

// exposedHBA is the whole of pg_hba.conf while main is published.
//
// The stock file ends with `host all all all scram-sha-256`. On a published
// port that admits every role from every network, which goes around the
// gateway's API keys, ACL and attribution. Narrowing only the replication rule
// left it in place. So while main is published the file is replaced rather
// than edited, and it keeps exactly what the engine itself uses:
//
//   - the socket and loopback rules the image ships, trusted as before. They
//     are reachable only from inside the container, and every `docker exec
//     psql` this engine runs goes through them;
//   - `host all all samenet`: the gateway reaches main over the docker network,
//     and so do the engine's one-off helper containers (backups, import,
//     export). samenet is the subnets the server is attached to, which is that
//     network. Docker's port publishing keeps a remote client's own source
//     address (measured across two machines, docs/FOX_HA_Plan.md), so a
//     connection arriving on the published port does not match it;
//   - the replication role from samenet, for a standby on this machine;
//   - the replication role from the peer, over TLS only;
//   - and an explicit reject for everything else, so nothing depends on a rule
//     that merely happens to be missing.
//
// The peer must already be a CIDR. Anything else is an error, rather than a
// rule that matches nothing, or worse, something.
func exposedHBA(peer string) (string, error) {
	p := strings.TrimSpace(peer)
	if _, _, err := net.ParseCIDR(p); err != nil {
		return "", fmt.Errorf("the peer %q is not a CIDR range, so no rule was written: %w", peer, err)
	}
	lines := []string{
		hbaManagedMarker,
		"# The rules from before are in " + hbaBackupName + " beside this file.",
		"local   all          all                          trust",
		"host    all          all          127.0.0.1/32    trust",
		"host    all          all          ::1/128         trust",
		"local   replication  all                          trust",
		"host    replication  all          127.0.0.1/32    trust",
		"host    replication  all          ::1/128         trust",
		"host    all          all          samenet         scram-sha-256",
		replicationHBALine,
		peerHBALine(p),
		"host    all          all          all             reject",
		"host    replication  all          all             reject",
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// hbaScript is the shell that writes a primary's pg_hba.conf. Separate and pure
// so a test can read what will run against a database it has no way to start.
//
// With a peer, main is published: the original file is set aside, once (a
// second run sees the marker and leaves the backup alone), and replaced with
// exposedHBA. Without one, the original comes back and the replication rule is
// narrowed inside it, which is what this did before exposure existed. Both are
// idempotent, because `ha enable` and `node expose` run this every time.
//
// The caller reloads Postgres afterwards. pg_hba is re-read on a reload, so a
// change of rules restarts nothing.
func hbaScript(peer string) (string, error) {
	head := `set -e
f="$PGDATA/pg_hba.conf"
keep="$PGDATA/` + hbaBackupName + `"`
	if strings.TrimSpace(peer) != "" {
		body, err := exposedHBA(peer)
		if err != nil {
			return "", err
		}
		// Written to a temporary file and renamed, so a reload never reads a
		// half-written file. The heredoc's delimiter is quoted, so the shell
		// expands nothing inside it.
		return head + `
grep -qxF '` + hbaManagedMarker + `' "$f" || cp -p "$f" "$keep"
cat > "$f.fox-new" <<'FOXHBA'
` + body + `FOXHBA
mv "$f.fox-new" "$f"`, nil
	}
	// Putting the original back. A managed file with no backup beside it
	// (somebody removed it) gets the image's own rules, rather than staying
	// in its published shape on an install that publishes nothing.
	sh := head + `
if [ -f "$keep" ]; then mv "$keep" "$f"
elif grep -qxF '` + hbaManagedMarker + `' "$f"; then cat > "$f" <<'FOXHBA'
` + stockHBA + `FOXHBA
fi
sed -i '/` + legacyHBAPattern + `/d' "$f"
grep -qF '` + replicationHBALine + `' "$f" || echo '` + replicationHBALine + `' >> "$f"`
	// Stale peer rules go too: an install that stops publishing must stop
	// admitting the peer it used to.
	sh += `
sed -i '/^hostssl[[:space:]]\+replication[[:space:]]\+` + ReplicationRole + `/d' "$f"`
	return sh, nil
}

// stockHBA is what the official image writes, for the one case where the
// original is gone and something has to stand in for it.
const stockHBA = `local   all             all                                     trust
host    all             all             127.0.0.1/32            trust
host    all             all             ::1/128                 trust
local   replication     all                                     trust
host    replication     all             127.0.0.1/32            trust
host    replication     all             ::1/128                 trust
host    all             all             all                     scram-sha-256
`

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
