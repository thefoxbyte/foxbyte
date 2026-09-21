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
CREATE INDEX IF NOT EXISTS agent_sessions_parent_idx ON bb.agent_sessions (parent_session_id);

CREATE OR REPLACE TRIGGER key_agent_sessions_append_only BEFORE UPDATE OR DELETE ON bb.agent_sessions
  FOR EACH ROW EXECUTE FUNCTION bb.deny_ext_change();
CREATE OR REPLACE TRIGGER key_agent_sessions_no_truncate BEFORE TRUNCATE ON bb.agent_sessions
  FOR EACH STATEMENT EXECUTE FUNCTION bb.deny_ext_change();
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON bb.agent_sessions FROM PUBLIC;
GRANT SELECT ON bb.agent_sessions TO db_client;

-- Which provenance definition is installed.
CREATE OR REPLACE FUNCTION bb.blackbox_provenance_version() RETURNS text
LANGUAGE sql IMMUTABLE AS $$ SELECT '1' $$;
GRANT EXECUTE ON FUNCTION bb.blackbox_provenance_version() TO db_client;

SET session_replication_role = DEFAULT;
