-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- F4's prototype (docs/FOX_F4_Erasure_Design.md, section 9): redacting the
-- Blackbox entries that hold an erased person's values, with a seal, so that the
-- chain and every anchor already signed still verify. Installed on top of the
-- real Blackbox (internal/ledger/*.sql) by scripts/integration_f4.sh; Gate 1
-- moves it into the engine.
--
-- How it holds together, as the security log's pseudonymisation does
-- (internal/auth/seclogprivacy.go):
--   - an entry's statement is rewritten with placeholders; its row_hash is left
--     as it was, so the chain's links and the anchors' Merkle roots are
--     unchanged;
--   - a seal is written for it: sha256(original row_hash | the hash of the entry
--     as it now stands);
--   - an ERASURE REDACT entry, chained like any other, records the request, how
--     many entries were redacted, and a digest of every seal it wrote, so a seal
--     cannot be added, changed or removed afterwards without breaking an entry
--     the chain covers;
--   - verification checks an entry by its hash until it is redacted, and by its
--     seal afterwards.
-- Schema changes are never redacted (branch comparison and promotion replay
-- their text); one holding a value is returned as flagged.

CREATE TABLE IF NOT EXISTS bb.ledger_seals (
  id            bigint PRIMARY KEY,  -- the entry redacted
  orig_row_hash text NOT NULL,       -- its row_hash, which stays in the entry
  seal          text NOT NULL,       -- sha256(orig_row_hash | the entry's hash as it now stands)
  by_entry      bigint NOT NULL      -- the ERASURE REDACT entry that wrote it
);
REVOKE ALL ON bb.ledger_seals FROM PUBLIC;

-- Written and emptied inside the redaction's own transaction, so nothing
-- outside it ever sees the ledger unlocked.
CREATE TABLE IF NOT EXISTS bb.ledger_unlock (request text PRIMARY KEY);
REVOKE ALL ON bb.ledger_unlock FROM PUBLIC;

CREATE OR REPLACE FUNCTION bb._ledger_unlocked() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT EXISTS (SELECT 1 FROM bb.ledger_unlock)
$$;

-- The append-only guard, with one way through: while a redaction runs, an
-- UPDATE of schema_ledger that changes the statement and nothing else.
CREATE OR REPLACE FUNCTION bb.deny_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND TG_TABLE_SCHEMA = 'bb' AND TG_TABLE_NAME = 'schema_ledger'
     AND bb._ledger_unlocked()
     AND (to_jsonb(NEW) - 'statement') = (to_jsonb(OLD) - 'statement') THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'bb.schema_ledger is append-only — its history cannot be modified';
END;
$$;

CREATE OR REPLACE FUNCTION bb._seal(orig text, now_hash text) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
  SELECT encode(sha256(convert_to(orig || '|' || now_hash, 'UTF8')), 'hex')
$$;

-- The digest an ERASURE REDACT entry records: every seal it wrote, in order.
CREATE OR REPLACE FUNCTION bb._seals_digest(entry bigint) RETURNS text
LANGUAGE sql STABLE AS $$
  SELECT encode(sha256(convert_to(coalesce(string_agg(id || ':' || seal, ',' ORDER BY id), ''), 'UTF8')), 'hex')
  FROM bb.ledger_seals WHERE by_entry = entry
$$;

-- Redact the entries holding any of vals. Returns how many were redacted, the
-- ids of entries that hold a value but are not redacted (schema changes, and
-- any whose placeholders still hold it), and the ERASURE REDACT entry's id.
CREATE OR REPLACE FUNCTION bb.erasure_redact(request text, vals text[])
RETURNS TABLE (redacted int, flagged bigint[], entry bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, bb AS $$
DECLARE
  r bb.schema_ledger;
  now_row bb.schema_ledger;
  fl bigint[] := '{}';
  ids bigint[] := '{}';
  origs text[] := '{}';
  seals text[] := '{}';
  e bigint;
BEGIN
  -- Arrays, not a temporary table: the Blackbox's own guardrail refuses DROP
  -- TABLE, a temporary one's included, and a redaction must not need an override.
  PERFORM pg_advisory_xact_lock(hashtext('bb.schema_ledger'));
  INSERT INTO bb.ledger_unlock VALUES (request);
  FOR r IN SELECT * FROM bb.schema_ledger l
           WHERE EXISTS (SELECT 1 FROM unnest(vals) v WHERE v <> '' AND position(v IN coalesce(l.statement, '')) > 0)
           ORDER BY id LOOP
    IF r.command_tag NOT IN ('UPDATE', 'DELETE', 'INSERT') THEN
      fl := fl || r.id;
      CONTINUE;
    END IF;
    IF EXISTS (SELECT 1 FROM unnest(vals) v WHERE v <> '' AND position(v IN bb_f1.bbid_placeholders(r.statement)) > 0) THEN
      fl := fl || r.id; -- a value in an identifier: placeholders cannot take it out
      CONTINUE;
    END IF;
    -- Redacted once already: its statement holds placeholders, no values.
    IF EXISTS (SELECT 1 FROM bb.ledger_seals s WHERE s.id = r.id) THEN
      CONTINUE;
    END IF;
    UPDATE bb.schema_ledger SET statement = bb_f1.bbid_placeholders(r.statement) WHERE id = r.id
      RETURNING * INTO now_row;
    ids := ids || r.id;
    origs := origs || r.row_hash;
    seals := seals || bb._seal(r.row_hash, bb._ledger_hash(now_row));
  END LOOP;
  DELETE FROM bb.ledger_unlock;
  -- The record of it, chained like any entry. Its statement holds the digest of
  -- the seals, so they are covered by the chain from here on.
  INSERT INTO bb.schema_ledger (actor, actor_kind, tool, command_tag, object_type, object_identity, statement, status)
  VALUES (session_user, 'human', 'fox dpdp erase', 'ERASURE REDACT', 'erasure', request,
          format('redacted %s entries; seals sha256:%s', cardinality(ids),
                 (SELECT encode(sha256(convert_to(coalesce(string_agg(i || ':' || s, ',' ORDER BY i), ''), 'UTF8')), 'hex')
                  FROM unnest(ids, seals) AS t(i, s))),
          'APPLIED')
  RETURNING id INTO e;
  INSERT INTO bb.ledger_seals SELECT i, o, s, e FROM unnest(ids, origs, seals) AS t(i, o, s);
  RETURN QUERY SELECT cardinality(ids), fl, e;
END;
$$;
REVOKE EXECUTE ON FUNCTION bb.erasure_redact(text, text[]) FROM PUBLIC;

-- Verification with seals: each entry's link, its hash or its seal, and each
-- ERASURE REDACT entry's digest. One row per problem; none means it verifies.
CREATE OR REPLACE FUNCTION bb.verify_sealed()
RETURNS TABLE (id bigint, problem text)
LANGUAGE sql STABLE AS $$
  WITH l AS (
    SELECT r AS e, r.id, r.prev_hash, r.row_hash, r.command_tag, r.statement,
           lag(r.row_hash) OVER (ORDER BY r.id) AS prev_row_hash,
           row_number() OVER (ORDER BY r.id) AS n
    FROM bb.schema_ledger r
  )
  SELECT l.id, 'link: prev_hash is not the previous entry''s hash'
    FROM l WHERE l.n > 1 AND l.prev_hash IS DISTINCT FROM l.prev_row_hash
  UNION ALL
  SELECT l.id, 'hash: the entry does not match its hash'
    FROM l LEFT JOIN bb.ledger_seals s ON s.id = l.id
    WHERE s.id IS NULL AND bb._ledger_hash(l.e) IS DISTINCT FROM l.row_hash
  UNION ALL
  SELECT l.id, 'seal: the redacted entry does not match its seal'
    FROM l JOIN bb.ledger_seals s ON s.id = l.id
    WHERE s.orig_row_hash IS DISTINCT FROM l.row_hash
       OR s.seal IS DISTINCT FROM bb._seal(s.orig_row_hash, bb._ledger_hash(l.e))
  UNION ALL
  SELECT l.id, 'digest: the seals are not the ones this entry recorded'
    FROM l WHERE l.command_tag = 'ERASURE REDACT'
      AND l.statement NOT LIKE '%seals sha256:' || bb._seals_digest(l.id)
  UNION ALL
  SELECT s.id, 'seal: written by no ERASURE REDACT entry'
    FROM bb.ledger_seals s LEFT JOIN bb.schema_ledger x ON x.id = s.by_entry AND x.command_tag = 'ERASURE REDACT'
    WHERE x.id IS NULL
  ORDER BY 1
$$;
