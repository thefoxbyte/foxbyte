-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- FoxByte Blackbox agent provenance (Blackbox 2.0 Phase 6) — installed AFTER
-- ledger.sql, ledger_v2.sql and policy.sql.
--
-- An agent session is one run of an agent against a branch: an Agent API branch
-- created with a task, or one MCP server process calling execute_change. The
-- Blackbox entries it causes carry the session id in schema_ledger.session and
-- the task, parent session and tool-call hash in ledger_ext, which checkpoints
-- anchor. This table records who each session was and what it started for.
--
-- Append-only and written only by the engine; clients may read it. Nothing here
-- changes an existing object. Idempotent: safe to re-apply on every start.

SET session_replication_role = replica;

CREATE TABLE IF NOT EXISTS bb.agent_sessions (
  session_id        text PRIMARY KEY CHECK (length(session_id) BETWEEN 1 AND 200),
  agent_id          text NOT NULL,       -- the ledger actor, e.g. 'agent-alice' or an MCP client name
  parent_session_id text,                -- the session that spawned this one
  task_id           text,                -- the task the session started for
  tool              text,                -- 'agent-api' | 'mcp' | …
  started_at        timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS agent_sessions_task_idx ON bb.agent_sessions (task_id);
-- Whom the session was started for (application identity, F1): an application
-- that created the agent's branch through the Agent API with a token naming its
-- user, checked by the engine by bb.act_for's rules. asserted, or none with why.
-- Added columns: a session recorded before them has none.
ALTER TABLE bb.agent_sessions
  ADD COLUMN IF NOT EXISTS app_actor  text,
  ADD COLUMN IF NOT EXISTS app_state  text,
  ADD COLUMN IF NOT EXISTS app_issuer text,
  ADD COLUMN IF NOT EXISTS app_kid    text,
  ADD COLUMN IF NOT EXISTS app_tenant text,
  ADD COLUMN IF NOT EXISTS app_note   text;
CREATE INDEX IF NOT EXISTS agent_sessions_parent_idx ON bb.agent_sessions (parent_session_id);

CREATE OR REPLACE TRIGGER key_agent_sessions_append_only BEFORE UPDATE OR DELETE ON bb.agent_sessions
  FOR EACH ROW EXECUTE FUNCTION bb.deny_ext_change();
CREATE OR REPLACE TRIGGER key_agent_sessions_no_truncate BEFORE TRUNCATE ON bb.agent_sessions
  FOR EACH STATEMENT EXECUTE FUNCTION bb.deny_ext_change();
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON bb.agent_sessions FROM PUBLIC;
GRANT SELECT ON bb.agent_sessions TO db_client;

-- Change requests applied to this database (enterprise/promote). The engine
-- applies a request as db_client, in one transaction, and writes the request's
-- id here in that same transaction. So the record and the changes commit
-- together or not at all, and the database itself can answer "was request N
-- applied?" even when the engine's own store failed to note the outcome.
--
-- The key is what stops a request being applied twice: a second apply of the
-- same request finds the row (or waits on the first apply's uncommitted one)
-- and is refused before any statement runs.
--
-- A request is its id and the random name its store gave it (request_uid):
-- the id alone repeats once a store is recreated, or restored from an older
-- backup, and a new request would be refused as an old one already applied.
-- A request made before stores named them has no name, and two without one
-- are one request as before (NULLS NOT DISTINCT); a row without a name is
-- never a request that has one, since only requests made since have one.
--
-- db_client may add rows and read them, and nothing else: the table is owned
-- by the Blackbox's owner, UPDATE, DELETE and TRUNCATE are not granted, and the
-- append-only triggers refuse them anyway (only a superuser can step past a
-- trigger, with session_replication_role). Any
-- client of this database can add a row, so a row is a claim and not proof; the
-- worst a made-up one can do is make the engine refuse to apply that id, which
-- is the safe direction to fail in.
CREATE TABLE IF NOT EXISTS bb.applied_requests (
  request_id  bigint NOT NULL CHECK (request_id > 0),
  source      text NOT NULL,              -- the branch the statements came from
  approver    text NOT NULL,              -- who approved it, as the engine names them
  statements  integer NOT NULL CHECK (statements >= 0),
  xid         bigint NOT NULL DEFAULT txid_current(),
  applied_at  timestamptz NOT NULL DEFAULT clock_timestamp()
);
-- Added: a table made before it has the id as its primary key, which is
-- replaced by the id and the name together.
ALTER TABLE bb.applied_requests ADD COLUMN IF NOT EXISTS request_uid text
  CHECK (request_uid IS NULL OR length(request_uid) BETWEEN 1 AND 100);
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'bb.applied_requests'::regclass
              AND conname = 'applied_requests_pkey') THEN
    ALTER TABLE bb.applied_requests DROP CONSTRAINT applied_requests_pkey;
    -- On PostgreSQL 18 the key's NOT NULL can go with it.
    ALTER TABLE bb.applied_requests ALTER COLUMN request_id SET NOT NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'bb.applied_requests'::regclass
                  AND conname = 'applied_requests_request_key') THEN
    ALTER TABLE bb.applied_requests ADD CONSTRAINT applied_requests_request_key
      UNIQUE NULLS NOT DISTINCT (request_id, request_uid);
  END IF;
END $$;
CREATE OR REPLACE TRIGGER key_applied_requests_append_only BEFORE UPDATE OR DELETE ON bb.applied_requests
  FOR EACH ROW EXECUTE FUNCTION bb.deny_ext_change();
CREATE OR REPLACE TRIGGER key_applied_requests_no_truncate BEFORE TRUNCATE ON bb.applied_requests
  FOR EACH STATEMENT EXECUTE FUNCTION bb.deny_ext_change();
REVOKE ALL ON bb.applied_requests FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON bb.applied_requests FROM db_client;
GRANT SELECT, INSERT ON bb.applied_requests TO db_client;

-- Which provenance definition is installed. 2: bb.applied_requests. 3: a
-- request recorded by its id and its store's name for it.
CREATE OR REPLACE FUNCTION bb.blackbox_provenance_version() RETURNS text
LANGUAGE sql IMMUTABLE AS $$ SELECT '3' $$;
GRANT EXECUTE ON FUNCTION bb.blackbox_provenance_version() TO db_client;

SET session_replication_role = DEFAULT;
