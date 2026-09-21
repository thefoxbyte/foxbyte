-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- FoxByte Blackbox 2.0 — additive objects, installed AFTER ledger.sql.
--
-- Nothing here changes an object ledger.sql owns: bb.schema_ledger, its hash
-- chain (_ledger_hash / chain_row) and its event triggers are untouched, so every
-- existing chain keeps verifying. 2.0 data lives in side tables keyed by the
-- ledger row id.
--
-- Safety rules for everything in this file:
--   * Fail-safe: a 2.0 trigger never aborts the statement that fired it. Errors
--     are downgraded to a WARNING and the original change goes through.
--   * Kill switch: ALTER DATABASE foxbyte SET bb.v2 = 'off' makes every 2.0
--     trigger skip its work (see bb._capture_disabled: honoured database-wide
--     or in a superuser's session, never from a client's own SET) —
--     trigger return immediately (new sessions).
--   * Idempotent: safe to re-apply on every start.
--
-- The install runs with session_replication_role = replica so the ledger's own
-- event triggers don't record this plumbing (that setting is session-local and
-- only a superuser can set it).

SET session_replication_role = replica;

-- ── Capture: extra context for every ledger row ─────────────────────────────
-- xid/lsn pin the exact moment of the change (Phase 4 branches from just before
-- it); task/parent_session/call_hash carry agent provenance (Phase 6);
-- override_used records that the destructive-DDL override was in effect.
CREATE TABLE IF NOT EXISTS bb.ledger_ext (
  ledger_id      bigint PRIMARY KEY,   -- bb.schema_ledger.id
  xid            bigint,               -- top-level transaction of the change
  lsn            pg_lsn,               -- WAL insert position when it was recorded
  task_id        text,                 -- bb.task
  parent_session text,                 -- bb.parent_session
  call_hash      text,                 -- bb.call_hash (sha256 of an agent tool call)
  override_used  boolean NOT NULL DEFAULT false,
  captured_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
  ext_hash       text                  -- sha256 over the fields above (for checkpoints)
);
CREATE INDEX IF NOT EXISTS ledger_ext_xid_idx ON bb.ledger_ext (xid);

-- _ext_hash is the single source of truth for a capture row's hash.
CREATE OR REPLACE FUNCTION bb._ext_hash(e bb.ledger_ext) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
  SELECT encode(sha256(convert_to(
    coalesce(e.ledger_id::text,'')      || '|' || coalesce(e.xid::text,'')        || '|' ||
    coalesce(e.lsn::text,'')            || '|' || coalesce(e.task_id,'')          || '|' ||
    coalesce(e.parent_session,'')       || '|' || coalesce(e.call_hash,'')        || '|' ||
    coalesce(e.override_used::text,''), 'UTF8')), 'hex');
$$;

-- The kill switch. bb.v2 = 'off' is honoured only when it is set for the whole
-- database (ALTER DATABASE … SET bb.v2 = 'off', which needs the database owner
-- or a superuser) or in a superuser's own session. Any other session setting it
-- is ignored, so a client cannot hide the capture details of its own changes.
CREATE OR REPLACE FUNCTION bb._capture_disabled() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT coalesce(current_setting('bb.v2', true), '') = 'off'
     AND (EXISTS (SELECT 1
                    FROM pg_db_role_setting s, unnest(s.setconfig) AS c(cfg)
                   WHERE s.setdatabase = (SELECT oid FROM pg_database WHERE datname = current_database())
                     AND s.setrole = 0
                     AND c.cfg = 'bb.v2=off')
          OR coalesce((SELECT rolsuper FROM pg_roles WHERE rolname = session_user), false));
$$;

CREATE OR REPLACE FUNCTION bb.capture_ext() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, bb AS $$
DECLARE e bb.ledger_ext;
BEGIN
  BEGIN
    IF bb._capture_disabled() THEN
      RETURN NULL;
    END IF;
    e.ledger_id      := NEW.id;
    e.xid            := txid_current();
    e.lsn            := pg_current_wal_insert_lsn();
    e.task_id        := nullif(current_setting('bb.task', true), '');
    e.parent_session := nullif(current_setting('bb.parent_session', true), '');
    e.call_hash      := nullif(current_setting('bb.call_hash', true), '');
    -- The guardrail override was set, or the policy gate let a blocking rule
    -- through for an admin (bb.policy_override_used, set by policy.sql).
    e.override_used  := coalesce(nullif(current_setting('bb.allow_destructive', true), ''), 'off')
                          IN ('on','true','1')
                        OR coalesce(current_setting('bb.policy_override_used', true), '') = 'on';
    e.captured_at    := clock_timestamp();
    e.ext_hash       := bb._ext_hash(e);
    INSERT INTO bb.ledger_ext SELECT (e).*;
  EXCEPTION WHEN OTHERS THEN
    RAISE WARNING 'ledger 2.0: capture skipped for ledger row %: %', NEW.id, SQLERRM;
  END;
  RETURN NULL;
END;
$$;
CREATE OR REPLACE TRIGGER bb_ext_capture AFTER INSERT ON bb.schema_ledger
  FOR EACH ROW EXECUTE FUNCTION bb.capture_ext();

-- Append-only, like the ledger itself.
CREATE OR REPLACE FUNCTION bb.deny_ext_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is append-only — its history cannot be modified', TG_TABLE_NAME;
END;
$$;
CREATE OR REPLACE TRIGGER key_ext_append_only BEFORE UPDATE OR DELETE ON bb.ledger_ext
  FOR EACH ROW EXECUTE FUNCTION bb.deny_ext_change();
CREATE OR REPLACE TRIGGER key_ext_no_truncate BEFORE TRUNCATE ON bb.ledger_ext
  FOR EACH STATEMENT EXECUTE FUNCTION bb.deny_ext_change();
REVOKE UPDATE, DELETE, TRUNCATE ON bb.ledger_ext FROM PUBLIC;
GRANT SELECT ON bb.ledger_ext TO db_client;
GRANT EXECUTE ON FUNCTION bb._ext_hash(bb.ledger_ext) TO db_client;

-- ── Checkpoints: tamper-evidence anchored outside the database ─────────────
-- A checkpoint commits to a contiguous range of ledger ids with a Merkle root
-- over each row's recomputed hash and capture hash. The engine writes the same
-- record to a read-only anchor file outside the database
-- (docs/ledger-anchor-format.md). Integrity checks trust the anchor files, so
-- edits, deletions (including of the newest anchored rows) and a wiped ledger are
-- detected even by someone able to rewrite this database and its hash chain.
CREATE TABLE IF NOT EXISTS bb.ledger_checkpoints (
  id            bigserial PRIMARY KEY,
  from_id       bigint  NOT NULL,             -- first ledger id covered
  to_id         bigint  NOT NULL,             -- last ledger id covered
  entry_count   integer NOT NULL,             -- ledger rows present in [from_id, to_id]
  last_row_hash text,                         -- recomputed hash of the row at to_id
  merkle_root   text    NOT NULL,
  prev_root     text    NOT NULL DEFAULT '',  -- merkle_root of the previous checkpoint
  algorithm     text    NOT NULL,
  anchor_uri    text,                         -- where the engine wrote the anchor
  created_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (to_id >= from_id AND entry_count > 0)
);
CREATE UNIQUE INDEX IF NOT EXISTS ledger_checkpoints_from_idx ON bb.ledger_checkpoints (from_id);

-- Checkpoints must continue exactly where the previous one ended, chained by
-- root, so a concurrent or replayed checkpoint can't overlap or fork the sequence.
CREATE OR REPLACE FUNCTION bb.checkpoint_contiguous() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE last_to bigint; last_root text;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('bb.ledger_checkpoints'));
  SELECT to_id, merkle_root INTO last_to, last_root
    FROM bb.ledger_checkpoints ORDER BY to_id DESC LIMIT 1;
  IF NEW.from_id <> coalesce(last_to, 0) + 1 THEN
    RAISE EXCEPTION 'checkpoint must start at ledger id % (got %)', coalesce(last_to, 0) + 1, NEW.from_id;
  END IF;
  IF NEW.prev_root <> coalesce(last_root, '') THEN
    RAISE EXCEPTION 'checkpoint prev_root does not match the previous checkpoint';
  END IF;
  RETURN NEW;
END;
$$;
CREATE OR REPLACE TRIGGER key_checkpoint_contiguous BEFORE INSERT ON bb.ledger_checkpoints
  FOR EACH ROW EXECUTE FUNCTION bb.checkpoint_contiguous();
CREATE OR REPLACE TRIGGER key_checkpoint_append_only BEFORE UPDATE OR DELETE ON bb.ledger_checkpoints
  FOR EACH ROW EXECUTE FUNCTION bb.deny_ext_change();
CREATE OR REPLACE TRIGGER key_checkpoint_no_truncate BEFORE TRUNCATE ON bb.ledger_checkpoints
  FOR EACH STATEMENT EXECUTE FUNCTION bb.deny_ext_change();
REVOKE UPDATE, DELETE, TRUNCATE ON bb.ledger_checkpoints FROM PUBLIC;
GRANT SELECT ON bb.ledger_checkpoints TO db_client;

-- Which 2.0 definition is installed (for `fox ledger upgrade` / diagnostics).
CREATE OR REPLACE FUNCTION bb.ledger_v2_version() RETURNS text
LANGUAGE sql IMMUTABLE AS $$ SELECT '2.0-phase3' $$;
GRANT EXECUTE ON FUNCTION bb.ledger_v2_version() TO db_client;

SET session_replication_role = DEFAULT;
