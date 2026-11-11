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

-- Keeping it current (point 4.7): an inventory of every column, and every
-- JSON path inside one, that a scan has seen, so the next scan can tell what is
-- new. The first scan of a branch is its baseline (known). Whatever appears
-- after it is unclassified until a person has looked: by deciding every finding
-- at it, or by saying it holds nothing to classify. Never a value; only names.
ALTER TABLE bb.pii_scans ADD COLUMN IF NOT EXISTS new_only boolean NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS bb.pii_columns (
  id          bigserial   PRIMARY KEY,
  schema_name text        NOT NULL,
  table_name  text        NOT NULL,
  column_name text        NOT NULL,
  json_path   text        NOT NULL DEFAULT '',
  status      text        NOT NULL CHECK (status IN ('known', 'unclassified', 'reviewed')),
  first_scan  bigint      NOT NULL REFERENCES bb.pii_scans (id),
  last_scan   bigint      NOT NULL REFERENCES bb.pii_scans (id),
  first_seen  timestamptz NOT NULL DEFAULT now(),
  reviewed_by text        NOT NULL DEFAULT '',
  reviewed_at timestamptz,
  note        text        NOT NULL DEFAULT '',
  UNIQUE (schema_name, table_name, column_name, json_path)
);

-- Every change of a column's status, append-only, as bb.pii_decisions is for
-- findings.
CREATE TABLE IF NOT EXISTS bb.pii_column_reviews (
  id          bigserial   PRIMARY KEY,
  column_id   bigint      NOT NULL REFERENCES bb.pii_columns (id),
  status      text        NOT NULL CHECK (status IN ('unclassified', 'reviewed')),
  actor       text        NOT NULL,
  note        text        NOT NULL DEFAULT '',
  reviewed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS pii_column_reviews_column ON bb.pii_column_reviews (column_id, id);

CREATE OR REPLACE FUNCTION bb.pii_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'bb.% is append-only: it is changed by recording another row', TG_TABLE_NAME;
END;
$$;
CREATE OR REPLACE TRIGGER pii_column_reviews_append_only BEFORE UPDATE OR DELETE ON bb.pii_column_reviews
  FOR EACH ROW EXECUTE FUNCTION bb.pii_append_only();
CREATE OR REPLACE TRIGGER pii_column_reviews_no_truncate BEFORE TRUNCATE ON bb.pii_column_reviews
  FOR EACH STATEMENT EXECUTE FUNCTION bb.pii_append_only();

-- The Aadhaar exposure report (point 4.5): every Aadhaar number in the
-- branch's tables, found by reading every row, and kept as places. A place is
-- where a number sits (a column, or a JSON path in one, and the row's primary
-- key) and the number's last four digits, which UIDAI's own masked form shows.
-- Never the number, and never a hash of it: a hash of Aadhaar is the reference
-- key UIDAI forbids, and a number has few enough values to be found from one.
--
-- A place keeps when a run first and last saw it, so the report can say since
-- when a number has been exposed. person groups the places of one number,
-- within the run that last saw them, by the number held in memory for the run
-- only: it is a run's numbering, not an identity kept across runs.
CREATE TABLE IF NOT EXISTS bb.aadhaar_runs (
  id           bigserial   PRIMARY KEY,
  started_at   timestamptz NOT NULL,
  finished_at  timestamptz NOT NULL,
  actor        text        NOT NULL DEFAULT '',
  tables_read  integer     NOT NULL,
  columns_read integer     NOT NULL,
  rows_read    bigint      NOT NULL,   -- rows the database's filter passed on
  numbers      bigint      NOT NULL,   -- Aadhaar numbers found, place by place
  people       integer     NOT NULL,   -- distinct numbers
  listed       integer     NOT NULL,   -- places kept
  skipped      jsonb       NOT NULL DEFAULT '[]',  -- [{object, reason}]
  limits       jsonb       NOT NULL DEFAULT '[]'
);

-- What each run found in each column or path, counted in full even where
-- only the first places were kept (capped).
CREATE TABLE IF NOT EXISTS bb.aadhaar_columns (
  run_id      bigint  NOT NULL REFERENCES bb.aadhaar_runs (id),
  schema_name text    NOT NULL,
  table_name  text    NOT NULL,
  column_name text    NOT NULL,
  json_path   text    NOT NULL DEFAULT '',
  numbers     bigint  NOT NULL,
  rows_with   bigint  NOT NULL,
  listed      integer NOT NULL,
  capped      boolean NOT NULL DEFAULT false,
  PRIMARY KEY (run_id, schema_name, table_name, column_name, json_path)
);

CREATE TABLE IF NOT EXISTS bb.aadhaar_places (
  id          bigserial   PRIMARY KEY,
  schema_name text        NOT NULL,
  table_name  text        NOT NULL,
  column_name text        NOT NULL,
  json_path   text        NOT NULL DEFAULT '',
  row_key     text        NOT NULL,   -- id=42, or (a, b)=(1, x); ctid=(0,7) for a table with no primary key
  last4       text        NOT NULL CHECK (last4 ~ '^[0-9]{4}$'),
  person      integer     NOT NULL,
  first_run   bigint      NOT NULL REFERENCES bb.aadhaar_runs (id),
  last_run    bigint      NOT NULL REFERENCES bb.aadhaar_runs (id),
  first_seen  timestamptz NOT NULL,
  last_seen   timestamptz NOT NULL,
  row_created timestamptz,             -- the row's created_at, on a tracked table (point 6.1)
  UNIQUE (schema_name, table_name, column_name, json_path, row_key, last4)
);
CREATE INDEX IF NOT EXISTS aadhaar_places_run ON bb.aadhaar_places (last_run, person);

REVOKE ALL ON bb.aadhaar_runs, bb.aadhaar_columns, bb.aadhaar_places FROM PUBLIC;
REVOKE ALL ON SEQUENCE bb.aadhaar_runs_id_seq, bb.aadhaar_places_id_seq FROM PUBLIC;

REVOKE ALL ON bb.pii_scans, bb.pii_findings, bb.pii_decisions, bb.pii_columns, bb.pii_column_reviews FROM PUBLIC;
REVOKE ALL ON SEQUENCE bb.pii_scans_id_seq, bb.pii_findings_id_seq, bb.pii_decisions_id_seq,
  bb.pii_columns_id_seq, bb.pii_column_reviews_id_seq FROM PUBLIC;

SET client_min_messages = DEFAULT;
SET session_replication_role = DEFAULT;
