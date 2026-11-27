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

-- What an erasure request does to the person's rows here (F4, decision 1):
-- clear their personal columns (the default) or delete the row; and, on a
-- column's entry, what a NOT NULL column with no default is cleared to.
ALTER TABLE bb.dpdp_entries ADD COLUMN IF NOT EXISTS on_erasure text NOT NULL DEFAULT 'clear'
  CHECK (on_erasure IN ('clear', 'delete'));
ALTER TABLE bb.dpdp_entries ADD COLUMN IF NOT EXISTS clear_to text
  CHECK (clear_to IS NULL OR length(clear_to) <= 200);

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

-- The erasure requests applied to this branch (F4): written in the same
-- transaction as the erasure, so the branch itself says whether a request's
-- changes are in when the install's store could not record it. The request's
-- name and counts only; what was erased is in the store, not here.
CREATE TABLE IF NOT EXISTS bb.erasures_applied (
  request_uid text        PRIMARY KEY,
  request_id  bigint      NOT NULL,
  rows        integer     NOT NULL,
  applied_at  timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON bb.erasures_applied FROM PUBLIC;

REVOKE ALL ON bb.dpdp_entries, bb.dpdp_history FROM PUBLIC;

-- ── The Blackbox's text, for an erasure (F4, Gate 1 step 3; design, section 9)
-- What holds a value: an entry's statement, or an original text kept beside
-- the chain (bb.ledger_text), compared case-blind.
CREATE OR REPLACE FUNCTION bb._holds_any(t text, vals text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
  SELECT EXISTS (SELECT 1 FROM unnest(vals) v WHERE length(v) >= 4 AND position(lower(v) IN lower(coalesce(t, ''))) > 0)
$$;

-- What a redaction would do, changing nothing: data changes to redact,
-- schema changes holding a value (kept, flagged), and original texts to delete.
CREATE OR REPLACE FUNCTION bb.erasure_redact_preview(vals text[], OUT redact int, OUT flagged int, OUT originals int)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, bb AS $$
  SELECT
    (SELECT count(*)::int FROM bb.schema_ledger l WHERE bb._holds_any(l.statement, vals)
       AND l.command_tag IN ('UPDATE', 'DELETE', 'INSERT', 'TRUNCATE', 'MERGE')
       AND NOT EXISTS (SELECT 1 FROM bb.ledger_seals z WHERE z.id = l.id)),
    (SELECT count(*)::int FROM bb.schema_ledger l WHERE bb._holds_any(l.statement, vals)
       AND l.command_tag NOT IN ('UPDATE', 'DELETE', 'INSERT', 'TRUNCATE', 'MERGE')),
    (SELECT count(*)::int FROM bb.ledger_text t WHERE bb._holds_any(t.statement, vals))
$$;

-- Redacts the entries holding any of vals, with a seal each, and deletes the
-- original texts holding one. Schema changes are never redacted (branch
-- comparison and promotion replay their text): they come back as flagged, as
-- does an entry whose placeholders still hold a value (one in an identifier).
-- The ERASURE REDACT entry, chained like any other, records how many and a
-- digest of the seals it wrote; none is written when nothing was redacted.
-- Run as the superuser, inside the erasure's own transaction.
CREATE OR REPLACE FUNCTION bb.erasure_redact(request text, vals text[])
RETURNS TABLE (redacted int, flagged bigint[], entry bigint, originals int)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, bb AS $$
DECLARE
  r bb.schema_ledger;
  now_row bb.schema_ledger;
  fl bigint[] := '{}';
  ids bigint[] := '{}';
  origs text[] := '{}';
  seals text[] := '{}';
  e bigint;
  gone int;
  ph text;
BEGIN
  -- Arrays, not a temporary table: nothing here may need the guardrail's
  -- override (the prototype's finding, design section 21).
  PERFORM pg_advisory_xact_lock(hashtext('bb.schema_ledger'));
  INSERT INTO bb.ledger_unlock VALUES (request);
  FOR r IN SELECT * FROM bb.schema_ledger l WHERE bb._holds_any(l.statement, vals) ORDER BY id LOOP
    IF r.command_tag NOT IN ('UPDATE', 'DELETE', 'INSERT', 'TRUNCATE', 'MERGE') THEN
      fl := fl || r.id;
      CONTINUE;
    END IF;
    IF EXISTS (SELECT 1 FROM bb.ledger_seals z WHERE z.id = r.id) THEN
      CONTINUE;   -- redacted once already
    END IF;
    ph := bb._placeholders(r.statement);
    IF ph IS NOT DISTINCT FROM r.statement OR bb._holds_any(ph, vals) THEN
      fl := fl || r.id;   -- placeholders cannot take it out (an identifier, or no lexer here)
      CONTINUE;
    END IF;
    UPDATE bb.schema_ledger SET statement = ph WHERE id = r.id RETURNING * INTO now_row;
    ids := ids || r.id;
    origs := origs || r.row_hash;
    seals := seals || bb._seal(r.row_hash, bb._ledger_hash(now_row));
  END LOOP;
  DELETE FROM bb.ledger_unlock;
  DELETE FROM bb.ledger_text t WHERE bb._holds_any(t.statement, vals);
  GET DIAGNOSTICS gone = ROW_COUNT;
  IF cardinality(ids) > 0 THEN
    INSERT INTO bb.schema_ledger (actor, actor_kind, tool, command_tag, object_type, object_identity, statement, status)
    VALUES (coalesce(nullif(current_setting('bb.actor', true), ''), session_user), 'human', 'fox dpdp erase',
            'ERASURE REDACT', 'erasure', request,
            format('redacted %s entries; seals sha256:%s', cardinality(ids),
                   (SELECT encode(sha256(convert_to(coalesce(string_agg(i || ':' || z, ',' ORDER BY i), ''), 'UTF8')), 'hex')
                    FROM unnest(ids, seals) AS t(i, z))),
            'APPLIED')
    RETURNING id INTO e;
    INSERT INTO bb.ledger_seals SELECT i, o, z, e FROM unnest(ids, origs, seals) AS t(i, o, z);
  END IF;
  RETURN QUERY SELECT cardinality(ids), fl, e, gone;
END;
$$;

-- The same redaction on a copy restored from before an erasure (F4 step 4):
-- the entries the erasure redacted, by id, as the request keeps no value;
-- and the originals it deleted, by id. A schema change is never redacted, nor
-- an entry sealed already, nor one whose placeholders change nothing.
CREATE OR REPLACE FUNCTION bb.erasure_redact_ids(request text, want bigint[], gone_ids bigint[])
RETURNS TABLE (redacted int, entry bigint, originals int)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, bb AS $$
DECLARE
  r bb.schema_ledger;
  now_row bb.schema_ledger;
  ids bigint[] := '{}';
  origs text[] := '{}';
  seals text[] := '{}';
  e bigint;
  gone int;
  ph text;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('bb.schema_ledger'));
  INSERT INTO bb.ledger_unlock VALUES (request);
  FOR r IN SELECT * FROM bb.schema_ledger l WHERE l.id = ANY(want) ORDER BY id LOOP
    CONTINUE WHEN r.command_tag NOT IN ('UPDATE', 'DELETE', 'INSERT', 'TRUNCATE', 'MERGE');
    CONTINUE WHEN EXISTS (SELECT 1 FROM bb.ledger_seals z WHERE z.id = r.id);
    ph := bb._placeholders(r.statement);
    CONTINUE WHEN ph IS NOT DISTINCT FROM r.statement;
    UPDATE bb.schema_ledger SET statement = ph WHERE id = r.id RETURNING * INTO now_row;
    ids := ids || r.id;
    origs := origs || r.row_hash;
    seals := seals || bb._seal(r.row_hash, bb._ledger_hash(now_row));
  END LOOP;
  DELETE FROM bb.ledger_unlock;
  DELETE FROM bb.ledger_text t WHERE t.id = ANY(gone_ids);
  GET DIAGNOSTICS gone = ROW_COUNT;
  IF cardinality(ids) > 0 THEN
    INSERT INTO bb.schema_ledger (actor, actor_kind, tool, command_tag, object_type, object_identity, statement, status)
    VALUES (coalesce(nullif(current_setting('bb.actor', true), ''), session_user), 'human', 'fox dpdp erase',
            'ERASURE REDACT', 'erasure', request,
            format('redacted %s entries; seals sha256:%s', cardinality(ids),
                   (SELECT encode(sha256(convert_to(coalesce(string_agg(i || ':' || z, ',' ORDER BY i), ''), 'UTF8')), 'hex')
                    FROM unnest(ids, seals) AS t(i, z))),
            'APPLIED')
    RETURNING id INTO e;
    INSERT INTO bb.ledger_seals SELECT i, o, z, e FROM unnest(ids, origs, seals) AS t(i, o, z);
  END IF;
  RETURN QUERY SELECT cardinality(ids), e, gone;
END;
$$;
REVOKE EXECUTE ON FUNCTION bb.erasure_redact(text, text[]), bb.erasure_redact_preview(text[]) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION bb.erasure_redact_ids(text, bigint[], bigint[]) FROM PUBLIC;
REVOKE ALL ON SEQUENCE bb.dpdp_entries_id_seq, bb.dpdp_history_id_seq FROM PUBLIC;

SET client_min_messages = DEFAULT;
SET session_replication_role = DEFAULT;
