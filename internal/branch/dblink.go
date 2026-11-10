// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

// The Blackbox records what its guardrails refused through dblink: a second
// connection, so the record survives the rollback the refusal causes. The
// triggers look for it on their pinned search_path (pg_catalog, public, bb),
// and ledger.sql installs it in public.
//
// Two things took it away. An import resets the new branch's public schema
// (prepareTarget: DROP SCHEMA public CASCADE), and dblink went with it; a
// pipeline then renames public to raw, and would carry it out of reach the
// same way. On such a branch a refused change still did not run, but the
// client was told "function dblink_exec(text, text) does not exist" instead of
// the guardrail's message, and the Blackbox kept no record of the attempt. The
// policy gate's own recording is wrapped and only warned.

// ensureDblinkSQL puts dblink where the triggers look: installed if it is
// missing, moved back to public if something carried it elsewhere. Left alone
// in public or bb, so it changes nothing on a branch that is already right.
//
// It also takes dblink away from clients: only the Blackbox's SECURITY DEFINER
// triggers call it, as the owner, and a client holding it could open
// connections from inside the database to anything the container can reach
// (audit GW-1). healDblink runs this on every start, so a branch made before
// the change loses the grant the next time it starts.
const ensureDblinkSQL = `DO $do$
DECLARE s name; f regprocedure;
BEGIN
  SELECT n.nspname INTO s FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace
   WHERE e.extname = 'dblink';
  IF s IS NULL THEN
    CREATE EXTENSION dblink SCHEMA public;
  ELSIF s NOT IN ('public', 'bb') THEN
    ALTER EXTENSION dblink SET SCHEMA public;
  END IF;
  FOR f IN SELECT p.oid::regprocedure
             FROM pg_depend d
             JOIN pg_extension e ON e.oid = d.refobjid
             JOIN pg_proc p ON p.oid = d.objid
            WHERE d.classid = 'pg_proc'::regclass AND d.refclassid = 'pg_extension'::regclass
              AND d.deptype = 'e' AND e.extname = 'dblink' LOOP
    EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', f);
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'db_client') THEN
      EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM db_client', f);
    END IF;
  END LOOP;
END $do$;`

// ensureDblink restores the Blackbox's dblink on a branch.
func ensureDblink(target string) error { return psqlAdmin(target, ensureDblinkSQL) }

// healDblink is ensureDblink for a branch that is (re)starting: best-effort and
// quiet. It is what mends a branch imported before this was fixed, the next
// time it starts. On a standby, where nothing can be written, it fails quietly
// and changes nothing.
func healDblink(name string) {
	quiet("docker", "exec", "-e", pgImportOptions, container(name),
		"psql", "-q", "-U", pgUser, "-d", pgDatabase, "-c", ensureDblinkSQL)
}
