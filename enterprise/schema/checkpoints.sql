-- SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0
--
-- FoxByte Blackbox checkpoints: tamper-evidence anchored outside the database.
--
-- Split out of ledger_v2.sql, and installed only by the Enterprise edition.
-- Everything in ledger_ext.sql stays in Standard: that is richer *recording*,
-- and this is *proof*. A branch that was checkpointed before an install changed
-- edition keeps this table and every anchor already written, and both still
-- verify -- reading the record is free in every edition.
--
-- The same safety rules as ledger_ext.sql apply: fail-safe, kill-switchable,
-- idempotent. Installed with session_replication_role = replica so the ledger's
-- own event triggers do not record this plumbing.

SET session_replication_role = replica;

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
SET session_replication_role = DEFAULT;
