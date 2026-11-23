-- SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0
--
-- FoxByte's DPDP personal-data inventory (point 11.1): for each table that
-- holds personal data a reviewer confirmed (point 4.6), why it is held, under
-- which basis of the Digital Personal Data Protection Act, 2023, whose data it
-- is, and how long it is kept. Installed only by the Enterprise edition, when
-- the licence covers the DPDP compliance manager.
--
-- One entry per table (column_name = ''). A column may carry its own entry,
-- which replaces the table's for that column: a KYC column kept for the period
-- a law sets, in a table otherwise kept until its purpose is served. Never a
-- value: only names, and what the customer wrote about them.
--
-- In the branch, as the findings it describes are, so a branch made from main
-- carries main's inventory. Not granted to db_client: the engine reads it for
-- whoever may manage the branch.
--
-- Idempotent, and installed with session_replication_role = replica so the
-- Blackbox's own event triggers do not record this plumbing.

SET session_replication_role = replica;
SET client_min_messages = warning;

CREATE TABLE IF NOT EXISTS bb.dpdp_entries (
  id          bigserial   PRIMARY KEY,
  schema_name text        NOT NULL,
  table_name  text        NOT NULL,
  column_name text        NOT NULL DEFAULT '',   -- '' for the table's entry
  -- The basis of processing (s.4(1)): consent (s.6), or one of the legitimate
  -- uses of s.7, by its clause.
  basis       text        NOT NULL CHECK (basis IN ('consent', '7a', '7b', '7c', '7d', '7e', '7f', '7g', '7h', '7i')),
  purpose     text        NOT NULL CHECK (length(purpose) BETWEEN 1 AND 1000),
  -- Whose data: customer, employee, applicant, vendor, child, disability,
  -- other. Checked by the engine; a list here would need changing with it.
  principals  text[]      NOT NULL CHECK (cardinality(principals) >= 1),
  -- Retention: keep_count keep_unit after keep_from, for keep_reason, which
  -- keep_citation names when it is a law or a contract. 0 after
  -- purpose_served is "until the purpose is served".
  keep_count    integer   NOT NULL CHECK (keep_count BETWEEN 0 AND 1200),
  keep_unit     text      NOT NULL CHECK (keep_unit IN ('days', 'months', 'years')),
  keep_from     text      NOT NULL CHECK (keep_from IN ('collection', 'last_contact', 'account_closed', 'contract_end', 'purpose_served')),
  keep_reason   text      NOT NULL CHECK (keep_reason IN ('law', 'contract', 'purpose')),
  keep_citation text      NOT NULL DEFAULT '' CHECK (length(keep_citation) <= 500),
  note        text        NOT NULL DEFAULT '' CHECK (length(note) <= 1000),
  set_by      text        NOT NULL,
  set_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (schema_name, table_name, column_name),
  CHECK (keep_reason = 'purpose' OR keep_citation <> '')
);

-- Every change, append-only: the entry as it was set, or the one removed.
CREATE TABLE IF NOT EXISTS bb.dpdp_history (
  id          bigserial   PRIMARY KEY,
  schema_name text        NOT NULL,
  table_name  text        NOT NULL,
  column_name text        NOT NULL DEFAULT '',
  action      text        NOT NULL CHECK (action IN ('set', 'removed')),
  entry       jsonb       NOT NULL,
  actor       text        NOT NULL,
  at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS dpdp_history_place ON bb.dpdp_history (schema_name, table_name, column_name, id);

CREATE OR REPLACE FUNCTION bb.dpdp_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'bb.dpdp_history is append-only: an entry is changed by recording another';
END;
$$;
CREATE OR REPLACE TRIGGER dpdp_history_append_only BEFORE UPDATE OR DELETE ON bb.dpdp_history
  FOR EACH ROW EXECUTE FUNCTION bb.dpdp_append_only();
CREATE OR REPLACE TRIGGER dpdp_history_no_truncate BEFORE TRUNCATE ON bb.dpdp_history
  FOR EACH STATEMENT EXECUTE FUNCTION bb.dpdp_append_only();

REVOKE ALL ON bb.dpdp_entries, bb.dpdp_history FROM PUBLIC;
REVOKE ALL ON SEQUENCE bb.dpdp_entries_id_seq, bb.dpdp_history_id_seq FROM PUBLIC;

SET client_min_messages = DEFAULT;
SET session_replication_role = DEFAULT;
