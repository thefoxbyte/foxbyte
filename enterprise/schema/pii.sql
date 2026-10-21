-- SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0
--
-- FoxByte personal-data discovery (point 4.1): what each scan covered, and what
-- it found. Installed only by the Enterprise edition, when the licence covers
-- personal-data discovery.
--
-- No value is ever stored. A finding says where personal data is, what kind,
-- the rule that matched and how much of the sample matched; storing the samples
-- would make a new copy of the very data this exists to find.
--
-- In the branch, so a branch's findings, and the decisions a reviewer makes on
-- them (step 4.6), travel with it when it is cloned. Not granted to db_client:
-- a map of where personal data sits is itself sensitive, and the engine reads it
-- for whoever may manage the branch.
--
-- Idempotent, and installed with session_replication_role = replica so the
-- Blackbox's own event triggers do not record this plumbing.

SET session_replication_role = replica;
-- Quiet on a branch that has it already: a scan runs this first, and "already
-- exists, skipping" twice is noise above its results.
SET client_min_messages = warning;

CREATE TABLE IF NOT EXISTS bb.pii_scans (
  id              bigserial   PRIMARY KEY,
  started_at      timestamptz NOT NULL,
  finished_at     timestamptz NOT NULL,
  actor           text        NOT NULL DEFAULT '',
  sample_size     integer     NOT NULL,
  tables_scanned  integer     NOT NULL,
  columns_scanned integer     NOT NULL,
  skipped         jsonb       NOT NULL DEFAULT '[]',  -- [{object, reason}]
  limits          jsonb       NOT NULL DEFAULT '[]'   -- ["what this scan cannot claim", ...]
);

CREATE TABLE IF NOT EXISTS bb.pii_findings (
  id          bigserial   PRIMARY KEY,
  schema_name text        NOT NULL,
  table_name  text        NOT NULL,
  column_name text        NOT NULL,
  json_path   text        NOT NULL DEFAULT '',        -- inside a JSON column (step 4.2); '' for the column
  category    text        NOT NULL,
  rule        text        NOT NULL CHECK (rule IN ('name', 'value', 'name+value')),
  confidence  text        NOT NULL CHECK (confidence IN ('high', 'medium', 'low')),
  why         text        NOT NULL DEFAULT '',
  matched     integer     NOT NULL,
  sampled     integer     NOT NULL,
  state       text        NOT NULL DEFAULT 'suggested'
              CHECK (state IN ('suggested', 'confirmed', 'rejected')),
  first_scan  bigint      NOT NULL REFERENCES bb.pii_scans (id),
  last_scan   bigint      NOT NULL REFERENCES bb.pii_scans (id),
  first_seen  timestamptz NOT NULL DEFAULT now(),
  last_seen   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (schema_name, table_name, column_name, json_path, category)
);

-- Review (point 4.6): a reviewer confirms or rejects each finding. The
-- finding carries the latest decision; bb.pii_decisions keeps every one,
-- append-only, so "who said this column holds Aadhaar, and when" always has
-- an answer. Added columns, so a branch scanned before review existed gains
-- them on its next start and keeps its findings.
ALTER TABLE bb.pii_findings ADD COLUMN IF NOT EXISTS decided_by text NOT NULL DEFAULT '';
ALTER TABLE bb.pii_findings ADD COLUMN IF NOT EXISTS decided_at timestamptz;
ALTER TABLE bb.pii_findings ADD COLUMN IF NOT EXISTS note text NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS bb.pii_decisions (
  id         bigserial   PRIMARY KEY,
  finding_id bigint      NOT NULL REFERENCES bb.pii_findings (id),
  state      text        NOT NULL CHECK (state IN ('suggested', 'confirmed', 'rejected')),
  actor      text        NOT NULL,
  note       text        NOT NULL DEFAULT '',
  decided_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS pii_decisions_finding ON bb.pii_decisions (finding_id, id);

CREATE OR REPLACE FUNCTION bb.pii_decisions_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'bb.pii_decisions is append-only: a decision is changed by recording another';
END;
$$;
CREATE OR REPLACE TRIGGER pii_decisions_append_only BEFORE UPDATE OR DELETE ON bb.pii_decisions
  FOR EACH ROW EXECUTE FUNCTION bb.pii_decisions_append_only();
CREATE OR REPLACE TRIGGER pii_decisions_no_truncate BEFORE TRUNCATE ON bb.pii_decisions
  FOR EACH STATEMENT EXECUTE FUNCTION bb.pii_decisions_append_only();

REVOKE ALL ON bb.pii_scans, bb.pii_findings, bb.pii_decisions FROM PUBLIC;
REVOKE ALL ON SEQUENCE bb.pii_scans_id_seq, bb.pii_findings_id_seq, bb.pii_decisions_id_seq FROM PUBLIC;

SET client_min_messages = DEFAULT;
SET session_replication_role = DEFAULT;
