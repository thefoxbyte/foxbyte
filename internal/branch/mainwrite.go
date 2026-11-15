// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// Who may change main, enforced by Postgres (audit LIVE-1; the mode and the
// grants are kept in the accounts store, internal/auth/mainwrite.go).
//
// Every account's role on main was a member of db_client and acted as it, and
// db_client may write everything on main: it owns every table clients have
// made, and holds ALL on the rest. So any account could change main.
//
// The obvious design is to take the writes away from db_client and give them
// to a new role that only granted accounts are in. It does not hold: db_client
// owns what clients made, and an owner may always alter its tables and grant
// itself back whatever was taken. So db_client stays exactly what it is, the
// role that owns and writes, and keeps every path that logs in as it working
// unchanged: promotion (enterprise/promote applies a change request as
// db_client), imports, the engine's own sessions, db_agent.
//
// What changes is which accounts are in it. On main, when the mode is
// "granted", an account that may not write is taken out of db_client and put
// in db_main_reader instead, and acts as that. db_main_reader is given SELECT
// on what db_client can read, USAGE on the schemas db_client can use, and
// EXECUTE on the functions it was granted, and nothing that writes. An admin,
// an account granted write, and every account in mode "all" stay in db_client,
// as before.
//
// Only main. A branch belongs to whoever made it, and is cloned from main with
// main's roles, so a branch's roles are put back in db_client: when it is made
// (buildBranch) and whenever a role is used there (EnsureUserRole).
//
// A masked account is left to masking, which already keeps it out of
// db_client (mask.go). Its reader role can write the tables it is not masked
// from on main; that is masking's rule and is not changed here.

// MainReaderRole is what an account's role on main is in, instead of
// db_client, while main is read-only for it.
const MainReaderRole = "db_main_reader"

// ErrMainReadOnly: main is read-only for this account.
var ErrMainReadOnly = errors.New("main is read-only for your account")

// MainReadOnlyError is the error for email, with the command that lifts it.
func MainReadOnlyError(email string) error {
	return fmt.Errorf("%w; an admin can grant write with `%s access write grant %s`", ErrMainReadOnly, brand.CLI, email)
}

// mainWriteStore is a store handle kept for the process's lifetime: the state
// is read whenever a role on main is made, which is on every Gateway login, and
// opening the store each time would take its write lock each time.
var mainWriteStore struct {
	sync.Mutex
	s *auth.Store
}

// mainWriteState reads the mode ("all" is true) and the granted accounts'
// emails, lower case. A variable so tests need no store.
var mainWriteState = func() (all bool, writers []string, err error) {
	mainWriteStore.Lock()
	defer mainWriteStore.Unlock()
	if mainWriteStore.s == nil {
		s, err := auth.OpenFromEnv()
		if err != nil {
			return false, nil, fmt.Errorf("reading who may change main: %w", err)
		}
		mainWriteStore.s = s
	}
	mode, ws, err := mainWriteStore.s.MainWriteState()
	if err != nil {
		return false, nil, fmt.Errorf("reading who may change main: %w", err)
	}
	return mode == auth.MainWriteAll, ws, nil
}

// mainWriteFor is what the engine knows, without asking Postgres, about
// whether email may change a branch: true off main, in mode "all", or with a
// grant. false still leaves an admin able to: the role SQL asks Postgres who
// is one, where it is the truth.
func mainWriteFor(branchName, email string) (bool, error) {
	if branchName != "" && branchName != "main" {
		return true, nil
	}
	all, writers, err := mainWriteState()
	if err != nil {
		return false, err
	}
	if all {
		return true, nil
	}
	email = strings.ToLower(strings.TrimPrefix(email, agentKeyRolePrefix))
	for _, w := range writers {
		if w == email {
			return true, nil
		}
	}
	return false, nil
}

// isAdminOnMain is IsAdmin on main, a variable so tests need no database.
var isAdminOnMain = func(email string) bool {
	ok, err := IsAdmin("main", email)
	return err == nil && ok
}

// MayWriteMain reports whether an account may change main: in mode "all",
// with a grant, or as an admin. For the Go-side checks that answer before
// Postgres does; Postgres is still what refuses.
func MayWriteMain(email string) (bool, error) {
	ok, err := mainWriteFor("main", email)
	if err != nil || ok {
		return ok, err
	}
	return isAdminOnMain(strings.TrimPrefix(email, agentKeyRolePrefix)), nil
}

// mainWriteRefusal is the error for a session on main that would otherwise
// fall back to a shared role, db_client or db_agent, both of which write: nil
// when the account may write main anyway, or the branch is not main.
func mainWriteRefusal(branchName, email string) error {
	if branchName != "" && branchName != "main" {
		return nil
	}
	ok, err := MayWriteMain(email)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMainReadOnly, err)
	}
	if ok {
		return nil
	}
	return MainReadOnlyError(strings.TrimPrefix(email, agentKeyRolePrefix))
}

// MainWriteRefusal is mainWriteRefusal for the Gateway, which must not fall
// back to the shared client role on main for an account that may not write.
func MainWriteRefusal(branchName, email string) error { return mainWriteRefusal(branchName, email) }

// sqlTextArray renders a list as a text[] expression safe inside a DO body.
func sqlTextArray(xs []string) string {
	if len(xs) == 0 {
		return "'{}'::text[]"
	}
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = bodyLiteral(x)
	}
	return "ARRAY[" + strings.Join(parts, ", ") + "]::text[]"
}

// mainAccessSQL puts account roles in db_client or in db_main_reader. all is
// mode "all" (everybody writes); writers are the granted emails; only names
// the roles to look at, or nil for every account role (a name with '@' in it:
// a person's role, or an agent key's "agent:<email>").
//
// It only moves a role between the two. A role in neither, such as one an
// admin took out of db_client by hand, is left as it is, so on an install in
// mode "all", where nobody is in db_main_reader, it changes nothing at all.
//
// A role it takes out of db_client also loses what was granted to it by name
// that writes (a GRANT INSERT straight to the role), and the objects it owns
// pass to db_client (a table made after SET ROLE NONE is its owner's to change),
// and its sessions end: a session that has already become db_client keeps
// db_client's rights until it does.
//
// The Blackbox's capture is off for the length of the block: these are the
// engine's own plumbing, recorded in the security log by whoever asked for
// them, not changes to the schema.
func mainAccessSQL(all bool, writers []string, only []string) string {
	onlyExpr := "NULL::text[]"
	if only != nil {
		onlyExpr = sqlTextArray(only)
	}
	lower := make([]string, len(writers))
	for i, w := range writers {
		lower[i] = strings.ToLower(w)
	}
	return fmt.Sprintf(`DO $mw$
DECLARE
  all_write boolean := %[1]t;
  writers text[] := %[2]s;
  only_roles text[] := %[3]s;
  pg16 boolean := current_setting('server_version_num')::int >= 160000;
  pg17 boolean := current_setting('server_version_num')::int >= 170000;
  client oid; reader oid; agent_role oid; masked oid; admin oid;
  r record; o record; acct text; agent boolean; w boolean;
BEGIN
  PERFORM set_config('client_min_messages', 'warning', true);
  PERFORM set_config('session_replication_role', 'replica', true);
  client := to_regrole('db_client');
  IF client IS NULL THEN
    RETURN;
  END IF;
  IF to_regrole('%[4]s') IS NULL THEN
    BEGIN
      CREATE ROLE %[4]s NOLOGIN;
    EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; -- another session made it
    END;
  END IF;
  reader := to_regrole('%[4]s');
  agent_role := to_regrole('%[5]s');
  masked := to_regrole('%[6]s');
  admin := to_regrole('db_admin');
  FOR r IN SELECT oid, rolname FROM pg_roles
            WHERE rolcanlogin AND NOT rolsuper AND position('@' in rolname) > 0
              AND (only_roles IS NULL OR rolname = ANY (only_roles))
            ORDER BY rolname LOOP
    -- A masked reader's rights are masking's to decide (mask.go).
    CONTINUE WHEN masked IS NOT NULL AND pg_has_role(r.oid, masked, 'MEMBER');
    agent := r.rolname LIKE '%[7]s%%';
    acct := CASE WHEN agent THEN substr(r.rolname, %[8]d) ELSE r.rolname END;
    w := all_write OR lower(acct) = ANY (writers)
         OR EXISTS (SELECT 1 FROM pg_roles a WHERE a.rolname = acct
                     AND (a.rolsuper OR (admin IS NOT NULL AND pg_has_role(a.oid, admin, 'MEMBER'))));
    IF w THEN
      IF EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.roleid = reader AND m.member = r.oid) THEN
        EXECUTE format('REVOKE %[4]s FROM %%I', r.rolname);
        EXECUTE format('GRANT db_client TO %%I', r.rolname);
        IF agent AND agent_role IS NOT NULL THEN
          IF pg16 THEN
            EXECUTE format('GRANT %[5]s TO %%I WITH INHERIT TRUE, SET TRUE', r.rolname);
          ELSE
            EXECUTE format('GRANT %[5]s TO %%I', r.rolname);
          END IF;
        END IF;
        EXECUTE format('ALTER ROLE %%I SET role = db_client', r.rolname);
      END IF;
    ELSIF EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.roleid = client AND m.member = r.oid) THEN
      EXECUTE format('REVOKE db_client FROM %%I', r.rolname);
      -- An agent key's role stays an agent to the Blackbox (bb._ctx reads its
      -- membership of db_agent), but db_agent is in db_client, so it may
      -- neither inherit from it nor become it. Before 16 there is no way to
      -- keep the one without the other.
      IF agent AND agent_role IS NOT NULL
         AND EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.roleid = agent_role AND m.member = r.oid) THEN
        IF pg16 THEN
          EXECUTE format('GRANT %[5]s TO %%I WITH INHERIT FALSE, SET FALSE', r.rolname);
        ELSE
          EXECUTE format('REVOKE %[5]s FROM %%I', r.rolname);
        END IF;
      END IF;
      FOR o IN SELECT c.oid, c.relkind FROM pg_class c
                WHERE EXISTS (SELECT 1 FROM aclexplode(c.relacl) x WHERE x.grantee = r.oid AND x.privilege_type <> 'SELECT')
                   OR EXISTS (SELECT 1 FROM pg_attribute t, aclexplode(t.attacl) x
                               WHERE t.attrelid = c.oid AND x.grantee = r.oid AND x.privilege_type <> 'SELECT') LOOP
        IF o.relkind = 'S' THEN
          EXECUTE format('REVOKE USAGE, UPDATE ON SEQUENCE %%s FROM %%I', o.oid::regclass, r.rolname);
        ELSE
          EXECUTE format('REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER%%s ON TABLE %%s FROM %%I',
                         CASE WHEN pg17 THEN ', MAINTAIN' ELSE '' END, o.oid::regclass, r.rolname);
        END IF;
      END LOOP;
      FOR o IN SELECT n.nspname FROM pg_namespace n
                WHERE EXISTS (SELECT 1 FROM aclexplode(n.nspacl) x WHERE x.grantee = r.oid AND x.privilege_type = 'CREATE') LOOP
        EXECUTE format('REVOKE CREATE ON SCHEMA %%I FROM %%I', o.nspname, r.rolname);
      END LOOP;
      IF EXISTS (SELECT 1 FROM pg_shdepend d JOIN pg_database db ON db.oid = d.dbid
                  WHERE db.datname = current_database() AND d.refobjid = r.oid AND d.deptype = 'o') THEN
        EXECUTE format('REASSIGN OWNED BY %%I TO db_client', r.rolname);
      END IF;
      EXECUTE format('GRANT %[4]s TO %%I', r.rolname);
      EXECUTE format('ALTER ROLE %%I SET role = %[4]s', r.rolname);
      PERFORM pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = r.rolname AND pid <> pg_backend_pid();
    END IF;
  END LOOP;
END $mw$;`, all, sqlTextArray(lower), onlyExpr, MainReaderRole, AgentClientRole, MaskedRole,
		agentKeyRolePrefix, len(agentKeyRolePrefix)+1)
}

// mainReaderSyncSQL gives db_main_reader what db_client may read on main, and
// takes from it what db_client may no longer read. Run whenever main is put in
// mode "granted" and on every start in it, which is how a grant made to
// db_client by hand since reaches the readers. Default privileges cover what
// is made in between: tables, sequences and schemas db_client makes, and what
// the superuser makes in public (imports), as ledger.sql's grants to db_client
// do.
//
// Row-level security policies for db_client are extended to db_main_reader
// too: without that a reader would see none of the rows such a policy lets
// db_client see. A policy cannot give it more than SELECT, which is all it is
// granted.
//
// Postgres before 15 lets everybody create in public; that is taken away, or
// any reader could make tables on main. From 15 it is already so.
func mainReaderSyncSQL() string {
	return fmt.Sprintf(`DO $mrs$
DECLARE
  rd text := '%[1]s';
  o record; cols text;
BEGIN
  PERFORM set_config('client_min_messages', 'warning', true);
  PERFORM set_config('session_replication_role', 'replica', true);
  IF to_regrole('db_client') IS NULL THEN
    RETURN;
  END IF;
  IF to_regrole(rd) IS NULL THEN
    BEGIN
      CREATE ROLE %[1]s NOLOGIN;
    EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
    END;
  END IF;
  -- Schemas.
  FOR o IN SELECT n.oid, n.nspname FROM pg_namespace n
            WHERE n.nspname NOT LIKE 'pg\_%%' AND n.nspname <> 'information_schema' LOOP
    IF has_schema_privilege('db_client', o.oid, 'USAGE') THEN
      IF NOT has_schema_privilege(rd, o.oid, 'USAGE') THEN
        EXECUTE format('GRANT USAGE ON SCHEMA %%I TO %%I', o.nspname, rd);
      END IF;
    ELSE
      EXECUTE format('REVOKE USAGE ON SCHEMA %%I FROM %%I', o.nspname, rd);
    END IF;
  END LOOP;
  -- Tables, views, materialized views, foreign tables, sequences: the whole
  -- relation where db_client may read it all, else the columns it may read.
  FOR o IN SELECT c.oid, c.relkind FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
              AND n.nspname NOT LIKE 'pg\_%%' AND n.nspname <> 'information_schema' LOOP
    IF o.relkind = 'S' THEN
      IF has_sequence_privilege('db_client', o.oid, 'SELECT') THEN
        IF NOT has_sequence_privilege(rd, o.oid, 'SELECT') THEN
          EXECUTE format('GRANT SELECT ON SEQUENCE %%s TO %%I', o.oid::regclass, rd);
        END IF;
      ELSE
        EXECUTE format('REVOKE ALL ON SEQUENCE %%s FROM %%I', o.oid::regclass, rd);
      END IF;
      CONTINUE;
    END IF;
    IF has_table_privilege('db_client', o.oid, 'SELECT') THEN
      IF NOT has_table_privilege(rd, o.oid, 'SELECT') THEN
        EXECUTE format('GRANT SELECT ON TABLE %%s TO %%I', o.oid::regclass, rd);
      END IF;
      CONTINUE;
    END IF;
    -- Not the whole relation: take any table-wide grant back (which takes
    -- column grants with it) and give the columns db_client may read.
    IF EXISTS (SELECT 1 FROM pg_class c2, aclexplode(c2.relacl) x
                WHERE c2.oid = o.oid AND x.grantee = to_regrole(rd)::oid)
       OR EXISTS (SELECT 1 FROM pg_attribute t, aclexplode(t.attacl) x
                   WHERE t.attrelid = o.oid AND x.grantee = to_regrole(rd)::oid) THEN
      EXECUTE format('REVOKE ALL ON TABLE %%s FROM %%I', o.oid::regclass, rd);
    END IF;
    SELECT string_agg(quote_ident(a.attname), ', ' ORDER BY a.attnum) INTO cols
      FROM pg_attribute a
     WHERE a.attrelid = o.oid AND a.attnum > 0 AND NOT a.attisdropped
       AND has_column_privilege('db_client', o.oid, a.attnum, 'SELECT');
    IF cols IS NOT NULL THEN
      EXECUTE format('GRANT SELECT (%%s) ON TABLE %%s TO %%I', cols, o.oid::regclass, rd);
    END IF;
  END LOOP;
  -- Functions granted to db_client by name: the Blackbox's allow-list
  -- (bb._client_callable), and anything an admin granted. What everybody may
  -- call needs nothing.
  FOR o IN SELECT p.oid,
                  EXISTS (SELECT 1 FROM aclexplode(p.proacl) x WHERE x.grantee = 'db_client'::regrole::oid AND x.privilege_type = 'EXECUTE') AS client_has,
                  EXISTS (SELECT 1 FROM aclexplode(p.proacl) x WHERE x.grantee = to_regrole(rd)::oid AND x.privilege_type = 'EXECUTE') AS reader_has
             FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE p.proacl IS NOT NULL AND n.nspname NOT LIKE 'pg\_%%' AND n.nspname <> 'information_schema' LOOP
    IF o.client_has AND NOT o.reader_has THEN
      EXECUTE format('GRANT EXECUTE ON FUNCTION %%s TO %%I', o.oid::regprocedure, rd);
    ELSIF o.reader_has AND NOT o.client_has THEN
      EXECUTE format('REVOKE EXECUTE ON FUNCTION %%s FROM %%I', o.oid::regprocedure, rd);
    END IF;
  END LOOP;
  -- Row-level security policies that name db_client.
  FOR o IN SELECT p.polname, p.polrelid,
                  (SELECT string_agg(quote_ident(rolname), ', ') FROM pg_roles WHERE oid = ANY (p.polroles)) AS roles
             FROM pg_policy p
            WHERE 'db_client'::regrole::oid = ANY (p.polroles) AND NOT to_regrole(rd)::oid = ANY (p.polroles)
              AND NOT 0::oid = ANY (p.polroles)
              AND p.polcmd IN ('r', '*') LOOP
    EXECUTE format('ALTER POLICY %%I ON %%s TO %%s, %%I', o.polname, o.polrelid::regclass, o.roles, rd);
  END LOOP;
  -- What is made from now on.
  EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE db_client GRANT SELECT ON TABLES TO %%I', rd);
  EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE db_client GRANT SELECT ON SEQUENCES TO %%I', rd);
  EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE db_client GRANT USAGE ON SCHEMAS TO %%I', rd);
  IF to_regnamespace('public') IS NOT NULL THEN
    EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %%I IN SCHEMA public GRANT SELECT ON TABLES TO %%I', current_user, rd);
    EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %%I IN SCHEMA public GRANT SELECT ON SEQUENCES TO %%I', current_user, rd);
    REVOKE CREATE ON SCHEMA public FROM PUBLIC;
  END IF;
END $mrs$;`, MainReaderRole)
}

// mainWriteScript is everything that applies the mode to main's roles.
func mainWriteScript(all bool, writers []string) string {
	s := ""
	if !all {
		s = mainReaderSyncSQL() + "\n"
	}
	return s + mainAccessSQL(all, writers, nil) + "\n"
}

// applyMainScript runs SQL on main without psqlQuiet's 30-second bound: the
// grants walk every relation on main, which on a large schema takes longer.
var applyMainScript = func(sql string) error { return psqlStdin("main", sql) }

// mainRunning reports whether main's database is up, a variable for tests.
var mainRunning = func() bool { return ContainerState("main") == "running" }

// ApplyMainWrite applies the install's mode and grants to every account role
// on main: after the mode changes, and on every start. Idempotent. A main that
// is not running is left to its next start, which applies it.
func ApplyMainWrite() error {
	all, writers, err := mainWriteState()
	if err != nil {
		return err
	}
	if !mainRunning() {
		return nil
	}
	if err := applyMainScript(mainWriteScript(all, writers)); err != nil {
		return fmt.Errorf("applying who may change main: %w", err)
	}
	forgetBranchRoles("main")
	return nil
}

// ApplyMainWriteFor applies them to one account's roles on main, its own and
// its agent keys': after its grant, or its admin grant, changes.
func ApplyMainWriteFor(email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	all, writers, err := mainWriteState()
	if err != nil {
		return err
	}
	if !mainRunning() {
		return nil
	}
	if err := applyMainScript(mainAccessSQL(all, writers, []string{email, AgentKeyRole(email)})); err != nil {
		return fmt.Errorf("applying who may change main for %s: %w", email, err)
	}
	forgetUserRole("main", email)
	return nil
}

// applyMainWriteAtStart is ApplyMainWrite for `fox start`, which must not stop
// on it: the roles keep what they were last given.
func applyMainWriteAtStart() {
	if err := ApplyMainWrite(); err != nil {
		log.Printf("main write: %v (roles on main keep what they had; `%s access main-write` applies it again)", err, brand.CLI)
	}
}

// restoreBranchWriters puts a new branch's account roles back in db_client:
// it was cloned from main, and on main some may be readers. Best-effort, as
// EnsureUserRole does it again whenever a role is used there.
func restoreBranchWriters(name string) {
	if name == "main" {
		return
	}
	if err := psqlQuiet(name, mainAccessSQL(true, nil, nil)); err != nil {
		log.Printf("branch %s: giving its account roles back write: %v", name, err)
	}
}

// MainWriteSQL is the SQL each mode applies to main, for the tests and for
// anyone checking it against a database of their own.
func MainWriteSQL(all bool, writers []string) string { return mainWriteScript(all, writers) }

// MainReaders lists the account roles on main that are read-only now.
func MainReaders() ([]string, error) {
	out, err := Query("main", fmt.Sprintf(`SELECT r.rolname FROM pg_auth_members m
  JOIN pg_roles r ON r.oid = m.member
  WHERE m.roleid = (SELECT oid FROM pg_roles WHERE rolname = '%s') ORDER BY 1`, MainReaderRole))
	if err != nil {
		return nil, err
	}
	return strings.Fields(out), nil
}
