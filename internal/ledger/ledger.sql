-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- FoxByte Blackbox (RECORD layer) — a record the database keeps about
-- itself. Event triggers capture every DDL change, attribute it (human vs
-- agent, tool, session, branch), and enforce guardrails on destructive DDL.
--
-- The ledger lives in schema "bb". It carries no product name on purpose: it is
-- written into every database, so renaming the product must not reach it. It
-- must also differ from the Postgres role name, which is the "$user" default
-- schema — an unqualified user table must land in public and be captured, not
-- hidden inside our own schema.
--
-- Idempotent: event triggers are dropped first so re-installing never fires them
-- on its own DDL. Installed into `main`; inherited by every ZFS-clone branch,
-- each keeping its own per-branch history.

DROP EVENT TRIGGER IF EXISTS bb_guard_start;
DROP EVENT TRIGGER IF EXISTS bb_log_end;
DROP EVENT TRIGGER IF EXISTS bb_log_drop;
DROP EVENT TRIGGER IF EXISTS bb_seal_functions;

CREATE EXTENSION IF NOT EXISTS dblink;
CREATE SCHEMA IF NOT EXISTS bb;

CREATE TABLE IF NOT EXISTS bb.schema_ledger (
  id              bigserial PRIMARY KEY,
  at              timestamptz NOT NULL DEFAULT clock_timestamp(),
  actor           text,          -- e.g. 'priya' or 'agent-alice'
  actor_kind      text,          -- 'human' | 'agent'
  tool            text,          -- application_name, e.g. 'cursor/opus', 'psql'
  session         text,          -- gateway session id / backend pid
  branch          text,          -- routing branch name
  command_tag     text,          -- 'CREATE INDEX', 'ALTER TABLE', 'DROP TABLE'
  object_type     text,          -- 'table', 'index', ...
  object_identity text,          -- 'public.orders'
  statement       text,          -- the SQL (current_query)
  status          text NOT NULL, -- 'APPLIED' | 'FLAGGED' | 'BLOCKED'
  risk            text,          -- 'drop' | 'type-change' | 'policy' | NULL
  prev_hash       text,          -- row_hash of the previous ledger row
  row_hash        text           -- sha256 over this row's fields, chaining prev_hash
);
-- Add the chain columns to a ledger created before tamper-evidence existed.
ALTER TABLE bb.schema_ledger ADD COLUMN IF NOT EXISTS prev_hash text;
ALTER TABLE bb.schema_ledger ADD COLUMN IF NOT EXISTS row_hash  text;
CREATE INDEX IF NOT EXISTS schema_ledger_at_idx ON bb.schema_ledger (at DESC);

-- Guardrail policy: op (command tag) -> action.
--   block  refused unless a superuser or db_admin member sets bb.allow_destructive
--   flag   runs, and its Blackbox entry is recorded FLAGGED
--   allow  runs, recorded as usual (the same as not listing the command)
CREATE TABLE IF NOT EXISTS bb.policy (op text PRIMARY KEY, action text NOT NULL);
INSERT INTO bb.policy(op, action) VALUES
  ('DROP TABLE',  'block'),
  ('DROP SCHEMA', 'block')
ON CONFLICT (op) DO NOTHING;
-- Only the three actions mean anything. A typo such as 'blok' used to be stored
-- and silently let the command through. NOT VALID: rows written before this
-- constraint existed are left alone; every new or changed row is checked.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'policy_action_valid'
                 AND conrelid = 'bb.policy'::regclass) THEN
    ALTER TABLE bb.policy ADD CONSTRAINT policy_action_valid
      CHECK (action IN ('block','flag','allow')) NOT VALID;
  END IF;
END $$;

-- Every change to the guardrail policy, append-only. Turning DROP TABLE from
-- block to allow is exactly the change an audit needs to see, and it used to
-- leave no trace.
CREATE TABLE IF NOT EXISTS bb.policy_history (
  id         bigserial PRIMARY KEY,
  at         timestamptz NOT NULL DEFAULT clock_timestamp(),
  op         text,
  change     text NOT NULL,   -- insert | update | delete | truncate
  old_action text,
  new_action text,
  changed_by text
);
CREATE OR REPLACE FUNCTION bb.record_policy_change() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, bb AS $$
DECLARE who text := coalesce(nullif(current_setting('bb.actor', true), ''), session_user);
BEGIN
  IF TG_LEVEL = 'STATEMENT' THEN  -- TRUNCATE
    INSERT INTO bb.policy_history (op, change, changed_by) VALUES (NULL, 'truncate', who);
    RETURN NULL;
  END IF;
  INSERT INTO bb.policy_history (op, change, old_action, new_action, changed_by)
  VALUES (coalesce(NEW.op, OLD.op), lower(TG_OP),
          CASE WHEN TG_OP <> 'INSERT' THEN OLD.action END,
          CASE WHEN TG_OP <> 'DELETE' THEN NEW.action END, who);
  RETURN NULL;
END;
$$;
CREATE OR REPLACE TRIGGER key_policy_history AFTER INSERT OR UPDATE OR DELETE ON bb.policy
  FOR EACH ROW EXECUTE FUNCTION bb.record_policy_change();
CREATE OR REPLACE TRIGGER key_policy_history_truncate AFTER TRUNCATE ON bb.policy
  FOR EACH STATEMENT EXECUTE FUNCTION bb.record_policy_change();
CREATE OR REPLACE FUNCTION bb.deny_history_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'bb.% is append-only — its history cannot be modified', TG_TABLE_NAME;
END;
$$;
CREATE OR REPLACE TRIGGER bb_policy_history_append_only BEFORE UPDATE OR DELETE ON bb.policy_history
  FOR EACH ROW EXECUTE FUNCTION bb.deny_history_change();
CREATE OR REPLACE TRIGGER bb_policy_history_no_truncate BEFORE TRUNCATE ON bb.policy_history
  FOR EACH STATEMENT EXECUTE FUNCTION bb.deny_history_change();
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON bb.policy_history FROM PUBLIC;

-- How many rows one agent UPDATE or DELETE may change in a table before
-- bb.guard_impact refuses it (datachanges.sql, the expert review plan's G2).
-- '*' is every table without a row of its own; without a '*' row no default
-- limit applies. Changed with `fox guardrail limit`, and every change is in
-- bb.policy_history, like a change to bb.policy.
CREATE TABLE IF NOT EXISTS bb.dml_limits (
  rel      text PRIMARY KEY,   -- '*', or schema.table quoted as bb._table_identity quotes it
  max_rows bigint NOT NULL CHECK (max_rows >= 0)
);
INSERT INTO bb.dml_limits (rel, max_rows) VALUES ('*', 100) ON CONFLICT (rel) DO NOTHING;
-- Nothing is granted on it: only the superuser (`fox guardrail limit`) and
-- bb.guard_impact, which reads it, ever touch it.

CREATE OR REPLACE FUNCTION bb.record_limit_change() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, bb AS $$
DECLARE who text := coalesce(nullif(current_setting('bb.actor', true), ''), session_user);
BEGIN
  IF TG_LEVEL = 'STATEMENT' THEN  -- TRUNCATE
    INSERT INTO bb.policy_history (op, change, changed_by) VALUES ('AGENT DML ROWS', 'truncate', who);
    RETURN NULL;
  END IF;
  INSERT INTO bb.policy_history (op, change, old_action, new_action, changed_by)
  VALUES ('AGENT DML ROWS ' || coalesce(NEW.rel, OLD.rel), lower(TG_OP),
          CASE WHEN TG_OP <> 'INSERT' THEN OLD.max_rows::text END,
          CASE WHEN TG_OP <> 'DELETE' THEN NEW.max_rows::text END, who);
  RETURN NULL;
END;
$$;
CREATE OR REPLACE TRIGGER key_dml_limits_history AFTER INSERT OR UPDATE OR DELETE ON bb.dml_limits
  FOR EACH ROW EXECUTE FUNCTION bb.record_limit_change();
CREATE OR REPLACE TRIGGER key_dml_limits_history_truncate AFTER TRUNCATE ON bb.dml_limits
  FOR EACH STATEMENT EXECUTE FUNCTION bb.record_limit_change();

-- How many rows one agent may change in a table over a window, across all its
-- statements (bb.guard_impact; the expert review plan's F2): a per-statement
-- limit alone is evaded by changing 100 rows at a time. '*' is every table
-- without a row of its own, 1,000 rows per hour by default; without a '*' row
-- no default budget applies. Changed with `fox guardrail budget`, and every
-- change is in bb.policy_history.
CREATE TABLE IF NOT EXISTS bb.dml_budgets (
  rel      text PRIMARY KEY,   -- '*', or schema.table quoted as bb._table_identity quotes it
  max_rows bigint NOT NULL CHECK (max_rows >= 0),
  per_secs int NOT NULL CHECK (per_secs BETWEEN 60 AND 604800)  -- one minute to a week
);
INSERT INTO bb.dml_budgets (rel, max_rows, per_secs) VALUES ('*', 1000, 3600) ON CONFLICT (rel) DO NOTHING;

CREATE OR REPLACE FUNCTION bb.record_budget_change() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, bb AS $$
DECLARE who text := coalesce(nullif(current_setting('bb.actor', true), ''), session_user);
BEGIN
  IF TG_LEVEL = 'STATEMENT' THEN  -- TRUNCATE
    INSERT INTO bb.policy_history (op, change, changed_by) VALUES ('AGENT DML BUDGET', 'truncate', who);
    RETURN NULL;
  END IF;
  INSERT INTO bb.policy_history (op, change, old_action, new_action, changed_by)
  VALUES ('AGENT DML BUDGET ' || coalesce(NEW.rel, OLD.rel), lower(TG_OP),
          CASE WHEN TG_OP <> 'INSERT' THEN OLD.max_rows || ' rows per ' || OLD.per_secs || 's' END,
          CASE WHEN TG_OP <> 'DELETE' THEN NEW.max_rows || ' rows per ' || NEW.per_secs || 's' END, who);
  RETURN NULL;
END;
$$;
CREATE OR REPLACE TRIGGER key_dml_budgets_history AFTER INSERT OR UPDATE OR DELETE ON bb.dml_budgets
  FOR EACH ROW EXECUTE FUNCTION bb.record_budget_change();
CREATE OR REPLACE TRIGGER key_dml_budgets_history_truncate AFTER TRUNCATE ON bb.dml_budgets
  FOR EACH STATEMENT EXECUTE FUNCTION bb.record_budget_change();


-- Who may override a blocking policy with SET bb.allow_destructive=on: superusers
-- (the engine's own imports and pipelines connect as one) and members of
-- db_admin. Any other session stays blocked even with the override set. Membership
-- is granted per user with `fox admin grant <email>`.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'db_admin') THEN
    CREATE ROLE db_admin NOLOGIN;
  END IF;
END $$;

-- session_user, not current_user: the guard runs SECURITY DEFINER, and the login
-- identity is the one a client cannot change.
CREATE OR REPLACE FUNCTION bb._may_override() RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT coalesce((SELECT rolsuper FROM pg_roles WHERE rolname = session_user), false)
      OR pg_has_role(session_user, 'db_admin', 'MEMBER');
$$;

-- Attribution context. The actor is the login identity (session_user) when the
-- client logged in as a per-user role — a value a client CANNOT change (SET ROLE
-- leaves session_user untouched), so gateway attribution is non-forgeable. The
-- shared/admin roles fall back to the gateway-injected actor.
--
-- actor_kind follows the role for the same reason, rather than being read from
-- the connection: bb.actor_kind is an ordinary session setting, so a client
-- could `SET bb.actor_kind = 'human'` and have its changes recorded as a
-- person's — an agent could hide as one, which is exactly what this record
-- exists to prevent. An agent's own role is always 'agent' and a per-user role
-- is always 'human'.
--
-- The engine's agent sessions are agents by login, too. MCP's SQL tool and the
-- provenance-recorded agent calls used to log in as the shared db_client and
-- say "agent" in a setting, so an agent could `SET bb.actor_kind = 'human'` in
-- its own SQL and step out of the agent-only guardrails. They log in as
-- db_agent instead, and an agent key's per-account role ("agent:<email>") is a
-- member of db_agent: both are agents whatever the session says. Only the
-- remaining shared roles (dbadmin, db_client: the console, imports), which have
-- no identity of their own, still take the injected kind.
--
-- tool and session stay client-declared, and are labelled that way wherever
-- they are shown: application_name is a string any client chooses, and an
-- agent framework naming its own session is the point of bb.session. They
-- describe the change; actor and actor_kind attribute it.
CREATE OR REPLACE FUNCTION bb._ctx(
  OUT actor text, OUT actor_kind text, OUT tool text, OUT session text, OUT branch text
) LANGUAGE sql STABLE AS $$
  SELECT CASE WHEN session_user NOT IN ('dbadmin','db_client','db_agent')
              THEN session_user
              ELSE current_setting('bb.actor', true) END,
         CASE
           -- An agent branch's own role: agent-<id>. A per-user role is named
           -- for an email address, so one containing '@' is a person even if
           -- the address itself begins with "agent-".
           WHEN session_user LIKE 'agent-%' AND position('@' in session_user) = 0 THEN 'agent'
           -- The engine's agent role, and an agent key's role, which is a
           -- member of it. Direct membership, read from the catalogue:
           -- pg_has_role would also answer yes for every superuser.
           WHEN session_user = 'db_agent' OR EXISTS (
                  SELECT 1 FROM pg_auth_members m
                  JOIN pg_roles g ON g.oid = m.roleid AND g.rolname = 'db_agent'
                  JOIN pg_roles u ON u.oid = m.member AND u.rolname = session_user) THEN 'agent'
           WHEN session_user NOT IN ('dbadmin','db_client') THEN 'human'
           WHEN current_setting('bb.actor_kind', true) = 'agent' THEN 'agent'
           ELSE 'human'
         END,
         nullif(current_setting('application_name', true), ''),
         coalesce(nullif(current_setting('bb.session', true), ''), pg_backend_pid()::text),
         current_setting('bb.branch', true);
$$;

-- Should this DDL be recorded, or is it internal noise?
CREATE OR REPLACE FUNCTION bb._skip(schema_name text, command_tag text)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  -- GRANT/REVOKE and function DDL are recorded (a function that reads sensitive
  -- data, or a privilege change, is exactly what an audit wants). Only the
  -- ledger's own plumbing and pure-noise tags are skipped.
  SELECT schema_name = 'bb'   -- the ledger's own objects
      OR command_tag IN ('ALTER DATABASE','COMMENT','CREATE EXTENSION',
                         'CREATE EVENT TRIGGER','DROP EVENT TRIGGER','ALTER EVENT TRIGGER',
                         'CREATE SCHEMA');
$$;

-- ── Statement matching ──────────────────────────────────────────────────────
-- Risk flags here and policy rules (policy.sql) are about one statement, but an
-- event trigger only has current_query(): everything the client sent in one
-- message — every statement in it, with its comments and string literals. So
-- `ALTER TABLE t ADD COLUMN note text DEFAULT 'drop column later'` was flagged as
-- dropping a column, and in `ALTER TABLE a ADD x int; ALTER TABLE b DROP COLUMN y`
-- the harmless first statement was flagged (or blocked) for the second.
--
-- The functions below find the statement actually running and hand callers its
-- text with comments removed and literals emptied. Whenever that can't be
-- established with certainty they hand back the whole query as sent — what was
-- matched before — so nothing that matched before stops matching.

-- The statements in a query string, in order, split at top-level semicolons, with
-- comments removed and string literals (standard, E'…' and dollar-quoted) emptied.
-- Quoted identifiers are kept: they are object names, which rules may target.
-- Scans bytes, so its cost stays linear in multibyte text; strings over 256 KB
-- return nothing and callers fall back to the whole query.
CREATE OR REPLACE FUNCTION bb._sql_statements(q text)
RETURNS TABLE (pos int, body text)
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  b     bytea;
  n     int;
  i     int := 0;      -- byte offset (0-based)
  seg   int := 0;      -- start of the text not yet copied into parts
  parts text[] := '{}';
  c     int;
  pv    int;
  pp    int;
  j     int;
  dl    int;
  depth int;
  esc   boolean;
  delim bytea;
  stmt  text;
  p     int := 0;
BEGIN
  IF q IS NULL THEN
    RETURN;
  END IF;
  b := convert_to(q, 'UTF8');
  n := octet_length(b);
  IF n > 262144 THEN
    RETURN;
  END IF;
  WHILE i < n LOOP
    c := get_byte(b, i);
    IF c = 59 THEN                                        -- ;  end of statement
      parts := parts || convert_from(substring(b FROM seg + 1 FOR i - seg), 'UTF8');
      stmt := btrim(array_to_string(parts, ''), E' \t\r\n\f');
      IF stmt <> '' THEN
        p := p + 1; pos := p; body := stmt; RETURN NEXT;
      END IF;
      parts := '{}'; i := i + 1; seg := i;
    ELSIF c = 45 AND i + 1 < n AND get_byte(b, i + 1) = 45 THEN   -- -- comment
      parts := parts || convert_from(substring(b FROM seg + 1 FOR i - seg), 'UTF8') || ' '::text;
      i := i + 2;
      WHILE i < n AND get_byte(b, i) <> 10 LOOP i := i + 1; END LOOP;
      seg := i;
    ELSIF c = 47 AND i + 1 < n AND get_byte(b, i + 1) = 42 THEN   -- /* comment */ (nests)
      parts := parts || convert_from(substring(b FROM seg + 1 FOR i - seg), 'UTF8') || ' '::text;
      depth := 1; i := i + 2;
      WHILE i < n AND depth > 0 LOOP
        IF get_byte(b, i) = 47 AND i + 1 < n AND get_byte(b, i + 1) = 42 THEN
          depth := depth + 1; i := i + 2;
        ELSIF get_byte(b, i) = 42 AND i + 1 < n AND get_byte(b, i + 1) = 47 THEN
          depth := depth - 1; i := i + 2;
        ELSE
          i := i + 1;
        END IF;
      END LOOP;
      seg := i;
    ELSIF c = 39 THEN                                     -- ' string literal
      -- E'…' (an e/E that doesn't end an identifier) takes backslash escapes.
      pv := CASE WHEN i > 0 THEN get_byte(b, i - 1) ELSE 0 END;
      pp := CASE WHEN i > 1 THEN get_byte(b, i - 2) ELSE 0 END;
      esc := pv IN (69, 101) AND NOT (pp BETWEEN 48 AND 57 OR pp BETWEEN 65 AND 90 OR pp BETWEEN 97 AND 122
                                      OR pp IN (95, 36) OR pp >= 128);
      parts := parts || convert_from(substring(b FROM seg + 1 FOR i - seg), 'UTF8') || ''''''::text;
      i := i + 1;
      LOOP
        EXIT WHEN i >= n;
        c := get_byte(b, i);
        IF esc AND c = 92 THEN
          i := i + 2;
        ELSIF c = 39 THEN
          IF i + 1 < n AND get_byte(b, i + 1) = 39 THEN
            i := i + 2;
          ELSE
            i := i + 1; EXIT;
          END IF;
        ELSE
          i := i + 1;
        END IF;
      END LOOP;
      seg := i;
    ELSIF c = 34 THEN                                     -- "quoted identifier": kept
      i := i + 1;
      LOOP
        EXIT WHEN i >= n;
        IF get_byte(b, i) = 34 THEN
          IF i + 1 < n AND get_byte(b, i + 1) = 34 THEN
            i := i + 2;
          ELSE
            i := i + 1; EXIT;
          END IF;
        ELSE
          i := i + 1;
        END IF;
      END LOOP;
    ELSIF c = 36 THEN                                     -- $tag$ … $tag$
      pv := CASE WHEN i > 0 THEN get_byte(b, i - 1) ELSE 0 END;
      IF pv BETWEEN 48 AND 57 OR pv BETWEEN 65 AND 90 OR pv BETWEEN 97 AND 122 OR pv IN (95, 36) OR pv >= 128 THEN
        i := i + 1;                                       -- part of an identifier
      ELSE
        j := i + 1;
        IF j < n AND (get_byte(b, j) BETWEEN 65 AND 90 OR get_byte(b, j) BETWEEN 97 AND 122
                      OR get_byte(b, j) = 95 OR get_byte(b, j) >= 128) THEN
          j := j + 1;
          WHILE j < n AND (get_byte(b, j) BETWEEN 48 AND 57 OR get_byte(b, j) BETWEEN 65 AND 90
                           OR get_byte(b, j) BETWEEN 97 AND 122 OR get_byte(b, j) = 95 OR get_byte(b, j) >= 128) LOOP
            j := j + 1;
          END LOOP;
        END IF;
        IF j < n AND get_byte(b, j) = 36 THEN
          dl := j - i + 1;
          delim := substring(b FROM i + 1 FOR dl);
          parts := parts || convert_from(substring(b FROM seg + 1 FOR i - seg), 'UTF8') || ''''''::text;
          i := j + 1;
          LOOP
            EXIT WHEN i >= n;
            IF get_byte(b, i) = 36 AND substring(b FROM i + 1 FOR dl) = delim THEN
              i := i + dl; EXIT;
            END IF;
            i := i + 1;
          END LOOP;
          seg := i;
        ELSE
          i := i + 1;                                     -- a lone $, e.g. $1
        END IF;
      END IF;
    ELSE
      i := i + 1;
    END IF;
  END LOOP;
  parts := parts || convert_from(substring(b FROM seg + 1 FOR n - seg), 'UTF8');
  stmt := btrim(array_to_string(parts, ''), E' \t\r\n\f');
  IF stmt <> '' THEN
    p := p + 1; pos := p; body := stmt; RETURN NEXT;
  END IF;
END;
$$;

-- The leading keywords of a statement (quoted identifiers removed, so an object
-- called "table" can't pose as a keyword).
CREATE OR REPLACE FUNCTION bb._statement_words(body text) RETURNS text[]
LANGUAGE sql IMMUTABLE AS $$
  SELECT (array_remove(regexp_split_to_array(
            upper(regexp_replace(left(body, 400), '"([^"]|"")*"', ' ', 'g')), '[^A-Z_]+'), ''))[1:8];
$$;

-- Does a statement carry this command tag? The tag's words must follow the
-- statement's first word in order, among its leading keywords: CREATE UNIQUE
-- INDEX CONCURRENTLY is a CREATE INDEX, CREATE OR REPLACE VIEW a CREATE VIEW.
CREATE OR REPLACE FUNCTION bb._statement_has_tag(body text, tag text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  w  text[] := bb._statement_words(body);
  tw text[] := string_to_array(upper(tag), ' ');
  k  int := 2;
BEGIN
  IF cardinality(w) = 0 OR w[1] IS DISTINCT FROM tw[1] THEN
    RETURN false;
  END IF;
  FOR idx IN 2 .. cardinality(w) LOOP
    EXIT WHEN k > cardinality(tw);
    IF w[idx] = tw[k] THEN
      k := k + 1;
    END IF;
  END LOOP;
  RETURN k > cardinality(tw);
END;
$$;

-- Could this statement fire a DDL event trigger? Used to notice a run falling out
-- of step: skipping such a statement while looking for the next one means the
-- matching is no longer certain.
CREATE OR REPLACE FUNCTION bb._statement_fires_ddl(body text) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN w[1] IN ('CREATE','ALTER','DROP') THEN
      -- these objects fire no event triggers
      NOT (w[2] IN ('DATABASE','ROLE','USER','GROUP','TABLESPACE','SYSTEM','EVENT')
           OR (w[1] = 'CREATE' AND w[2] = 'OR' AND w[4] = 'EVENT'))
    WHEN w[1] IN ('GRANT','REVOKE') THEN ' ' || array_to_string(w, ' ') || ' ' LIKE '% ON %'
    WHEN w[1] IN ('COMMENT','SECURITY','REFRESH','IMPORT') THEN true
    ELSE false
  END
  FROM (SELECT bb._statement_words(body) AS w) x;
$$;

-- For a caller with only a SQL text and a tag (a policy preview): the statements
-- in it with that tag, or the text itself if none can be picked out.
CREATE OR REPLACE FUNCTION bb._statement_candidates(q text, tag text) RETURNS text[]
LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE WHEN cardinality(m) > 0 THEN m ELSE ARRAY[q] END
  FROM (SELECT ARRAY(SELECT s.body FROM bb._sql_statements(q) s
                     WHERE bb._statement_has_tag(s.body, tag) ORDER BY s.pos) AS m) x;
$$;

-- Where each backend is in the run it is executing, one row per event kind
-- ('start' for the policy gate, 'end' for the Blackbox recorder), each advanced
-- only by its own event. A table, not a session setting: a client can SET any
-- setting, and a moved position would let a blocked statement be judged by a
-- harmless one's text. Clients have no access to it, and the function that moves
-- it is not executable by them.
CREATE UNLOGGED TABLE IF NOT EXISTS bb.statement_cursor (
  pid        int     NOT NULL,
  event      text    NOT NULL,
  run_key    text    NOT NULL,
  statements text[]  NOT NULL,
  pos        int     NOT NULL,
  in_step    boolean NOT NULL,
  PRIMARY KEY (pid, event)
);
REVOKE ALL ON bb.statement_cursor FROM PUBLIC;

-- The texts a pattern should be matched against for the DDL event that is firing:
-- normally exactly one — the statement running, without comments or literals.
--   p_event  'start' or 'end'
--   p_tag    TG_TAG
--   p_ctx    the caller's GET DIAGNOSTICS … = PG_CONTEXT
-- DDL run from inside a function, a DO block or a trigger has a longer context
-- that names the statement Postgres actually ran (after any EXECUTE string was
-- built); it is matched by that text, plus the whole query, and never moves the
-- position of the top-level run. Anything uncertain returns the whole query.
CREATE OR REPLACE FUNCTION bb._statement_texts(p_event text, p_tag text, p_ctx text) RETURNS text[]
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, bb AS $$
DECLARE
  q      text := current_query();
  me     int  := pg_backend_pid();
  key    text;
  cur    bb.statement_cursor;
  nested text;
  st     int;
  k      int;
  e      int;
BEGIN
  IF strpos(coalesce(p_ctx, ''), E'\n') > 0 THEN
    st := strpos(p_ctx, 'SQL statement "');
    IF st = 0 THEN
      RETURN ARRAY[q];
    END IF;
    nested := substr(p_ctx, st + 15);
    -- The statement ends at the quote that closes it: the last one before the next
    -- context frame, or the end of the context.
    e := 0;
    FOR k IN SELECT unnest(ARRAY[strpos(nested, E'"\nPL/pgSQL function '), strpos(nested, E'"\nSQL function '),
                                 strpos(nested, E'"\nSQL statement "')]) LOOP
      IF k > 0 AND (e = 0 OR k < e) THEN
        e := k;
      END IF;
    END LOOP;
    IF e > 0 THEN
      nested := left(nested, e - 1);
    ELSIF right(nested, 1) = '"' THEN
      nested := left(nested, length(nested) - 1);
    END IF;
    RETURN bb._statement_candidates(nested, p_tag) || ARRAY[nested, q];
  END IF;

  key := md5(q) || '@' || statement_timestamp()::text;
  SELECT * INTO cur FROM bb.statement_cursor WHERE pid = me AND event = p_event;
  IF NOT FOUND OR cur.run_key <> key THEN
    cur := ROW(me, p_event, key, ARRAY(SELECT s.body FROM bb._sql_statements(q) s ORDER BY s.pos), 0, true);
    cur.in_step := cardinality(cur.statements) > 0;
    INSERT INTO bb.statement_cursor VALUES (cur.*)
    ON CONFLICT (pid, event) DO UPDATE
      SET run_key = EXCLUDED.run_key, statements = EXCLUDED.statements, pos = 0, in_step = EXCLUDED.in_step;
  END IF;
  IF NOT cur.in_step THEN
    RETURN ARRAY[q];
  END IF;
  FOR k IN cur.pos + 1 .. cardinality(cur.statements) LOOP
    IF bb._statement_has_tag(cur.statements[k], p_tag) THEN
      UPDATE bb.statement_cursor SET pos = k WHERE pid = me AND event = p_event;
      RETURN ARRAY[cur.statements[k]];
    END IF;
    EXIT WHEN bb._statement_fires_ddl(cur.statements[k]);
  END LOOP;
  UPDATE bb.statement_cursor SET in_step = false WHERE pid = me AND event = p_event;
  RETURN ARRAY[q];
END;
$$;

-- Does this session already hold the lock that serializes Blackbox appends
-- (bb.chain_row)? A blocked attempt is recorded through a second connection
-- (dblink), so the record survives the rollback the block causes. If this
-- transaction has already appended a row — BEGIN; CREATE TABLE …; DROP TABLE …; —
-- that connection waits for this one to finish, and this one waits for it: the
-- client hung forever, and Postgres can't see the deadlock across dblink.
-- Read from pg_locks, which a client cannot fake.
CREATE OR REPLACE FUNCTION bb._holds_chain_lock() RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT EXISTS (
    SELECT 1 FROM pg_locks
    WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND granted AND objsubid = 1
      AND ((classid::bigint << 32) | objid::bigint) = hashtext('bb.schema_ledger')::bigint);
$$;

-- The second connection a blocked attempt is recorded through. A wait inside it
-- is one Postgres cannot see as part of any deadlock (the client's backend is
-- waiting on a socket, not a lock), so nothing would ever break one: another
-- transaction sitting on the Blackbox's append lock used to hang the refused
-- client for as long as it stayed open. The timeouts are for that connection
-- alone, and short: a refusal should come back at once, and it comes back
-- whether or not the record could be written.
CREATE OR REPLACE FUNCTION bb._blocked_conn() RETURNS text
LANGUAGE sql STABLE AS $$
  SELECT 'host=/var/run/postgresql dbname=' || current_database() || ' user=' || current_user
      || $o$ options='-c lock_timeout=2s -c statement_timeout=5s'$o$;
$$;

-- Write a blocked attempt through that connection. Failing to record it is a
-- WARNING and never the reason the statement stops: every caller raises its
-- own refusal next, and a refusal must not turn into a hang or another error.
-- Not SECURITY DEFINER, and a client can't reach dblink: it is only of use from
-- the triggers, which run as the owner.
CREATE OR REPLACE FUNCTION bb._record_blocked(stmt text) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, public, bb AS $$
BEGIN
  PERFORM dblink_exec(bb._blocked_conn(), stmt);
EXCEPTION WHEN OTHERS THEN
  RAISE WARNING 'guardrail: this blocked attempt is not recorded in Blackbox: %', SQLERRM;
END;
$$;

-- ddl_command_start: enforce guardrails BEFORE the command runs.
-- SECURITY DEFINER: the ledger's triggers record history with the owner's
-- privileges, so a non-superuser client can trigger them (by running DDL) without
-- being granted any write access to the ledger itself. search_path is pinned.
CREATE OR REPLACE FUNCTION bb.guard_ddl_start() RETURNS event_trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, bb AS $$
DECLARE act text; c record; allow text;
BEGIN
  SELECT action INTO act FROM bb.policy WHERE op = TG_TAG;
  IF act IS DISTINCT FROM 'block' THEN
    RETURN; -- allowed (or flagged) — recorded in the end/drop triggers
  END IF;
  allow := coalesce(nullif(current_setting('bb.allow_destructive', true), ''), 'off');
  IF allow IN ('on','true','1') AND bb._may_override() THEN
    RETURN; -- approved override (a superuser or a db_admin member)
  END IF;
  SELECT * INTO c FROM bb._ctx();
  -- Record the blocked attempt durably via dblink (autonomous — survives the rollback),
  -- unless that would deadlock with this transaction (bb._holds_chain_lock).
  IF bb._holds_chain_lock() THEN
    RAISE WARNING 'guardrail: this blocked attempt is not recorded in Blackbox, because this transaction has already written to it';
  ELSE
    PERFORM bb._record_blocked(format($f$INSERT INTO bb.schema_ledger
              (actor,actor_kind,tool,session,branch,command_tag,statement,status,risk)
              VALUES (%L,%L,%L,%L,%L,%L,%L,'BLOCKED','policy')$f$,
        c.actor, c.actor_kind, c.tool, c.session, c.branch, TG_TAG, current_query()));
  END IF;
  RAISE EXCEPTION 'guardrail: % is blocked by policy (set bb.allow_destructive=on to override)', TG_TAG
    USING ERRCODE = 'insufficient_privilege',
          HINT = 'Only superusers and members of db_admin may override. Grant it with: fox admin grant <email>';
END;
$$;

-- ddl_command_end: record CREATE/ALTER changes (drops are recorded in sql_drop).
CREATE OR REPLACE FUNCTION bb.log_ddl_end() RETURNS event_trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, bb AS $$
DECLARE r record; c record; q text; st text; rk text; ctx text; t text[];
BEGIN
  SELECT * INTO c FROM bb._ctx();
  q := current_query();
  -- Risk is judged on the statement that ran, not everything sent with it (see
  -- bb._statement_texts); if that can't be established, on the whole query.
  BEGIN
    GET DIAGNOSTICS ctx = PG_CONTEXT;
    t := bb._statement_texts('end', TG_TAG, ctx);
  EXCEPTION WHEN OTHERS THEN
    t := ARRAY[q];
  END;
  FOR r IN SELECT * FROM pg_event_trigger_ddl_commands() LOOP
    IF r.command_tag LIKE 'DROP%' THEN CONTINUE; END IF;
    IF bb._skip(r.schema_name, r.command_tag) THEN CONTINUE; END IF;
    -- Skip `serial`/`primary key` byproducts so one user statement = one row:
    -- the auto sequence, its ALTER SEQUENCE OWNED BY, and the pkey index.
    IF r.command_tag IN ('CREATE SEQUENCE','ALTER SEQUENCE') THEN CONTINUE; END IF;
    IF r.command_tag = 'CREATE INDEX' AND r.object_identity ~ '_pkey$' THEN CONTINUE; END IF;
    -- The Blackbox's own data-change triggers (datachanges.sql), attached to
    -- every table: plumbing, like the objects in schema bb.
    IF r.command_tag = 'CREATE TRIGGER' AND r.object_identity ~ '^bb_(guard_truncate|record_dml|guard_dml|guard_impact) on ' THEN CONTINUE; END IF;
    st := 'APPLIED'; rk := NULL;
    IF r.command_tag = 'ALTER TABLE' AND EXISTS (SELECT 1 FROM unnest(t) x WHERE x ~* '\malter\M[^;]*\mtype\M') THEN
      st := 'FLAGGED'; rk := 'type-change';
    ELSIF r.command_tag = 'ALTER TABLE' AND EXISTS (SELECT 1 FROM unnest(t) x WHERE x ~* 'drop\s+column') THEN
      st := 'FLAGGED'; rk := 'drop-column';
    ELSIF r.command_tag IN ('CREATE FUNCTION','ALTER FUNCTION') AND EXISTS (SELECT 1 FROM unnest(t) x WHERE x ~* 'security\s+definer') THEN
      st := 'FLAGGED'; rk := 'security-definer';
    END IF;
    -- A command the guardrail policy marks 'flag' runs, and is recorded FLAGGED.
    IF st = 'APPLIED' AND EXISTS (SELECT 1 FROM bb.policy WHERE op = r.command_tag AND action = 'flag') THEN
      st := 'FLAGGED'; rk := 'policy';
    END IF;
    INSERT INTO bb.schema_ledger
      (actor,actor_kind,tool,session,branch,command_tag,object_type,object_identity,statement,status,risk)
    VALUES (c.actor,c.actor_kind,c.tool,c.session,c.branch,
            r.command_tag,r.object_type,r.object_identity,q,st,rk);
  END LOOP;
END;
$$;

-- sql_drop: record drops that were allowed through the guardrails.
CREATE OR REPLACE FUNCTION bb.log_ddl_drop() RETURNS event_trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, bb AS $$
DECLARE r record; c record; q text; st text := 'APPLIED';
BEGIN
  SELECT * INTO c FROM bb._ctx();
  q := current_query();
  IF EXISTS (SELECT 1 FROM bb.policy WHERE op = TG_TAG AND action = 'flag') THEN
    st := 'FLAGGED';   -- the guardrail policy marks this command 'flag'
  END IF;
  -- `original` = the object explicitly named in the command (not cascade artifacts
  -- like the sequence, primary-key index, or toast table).
  FOR r IN SELECT * FROM pg_event_trigger_dropped_objects() WHERE NOT is_temporary AND original LOOP
    IF bb._skip(r.schema_name, TG_TAG) THEN CONTINUE; END IF;
    IF r.object_type NOT IN ('table','view','index','sequence','schema','type','materialized view','function') THEN
      CONTINUE;
    END IF;
    INSERT INTO bb.schema_ledger
      (actor,actor_kind,tool,session,branch,command_tag,object_type,object_identity,statement,status,risk)
    VALUES (c.actor,c.actor_kind,c.tool,c.session,c.branch,
            TG_TAG,r.object_type,r.object_identity,q,st,'drop');
  END LOOP;
END;
$$;

-- ── Tamper-evidence ─────────────────────────────────────────────────────────
-- Every row is hash-chained to the one before it: row_hash = sha256(prev_hash ||
-- this row's fields). Deleting or editing a row breaks every hash after it, and
-- `fox ledger verify` recomputes the chain to catch it. Detection holds no matter
-- who did it; append-only enforcement (below) blocks the ordinary path. Full
-- prevention against a superuser needs the non-superuser app role (roadmap).

-- _ledger_hash is the single source of truth for a row's hash, used by both the
-- insert trigger and verification, so the two can never drift. `at` is rendered
-- in UTC so the hash is independent of the verifying session's timezone.
CREATE OR REPLACE FUNCTION bb._ledger_hash(r bb.schema_ledger) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
  SELECT encode(sha256(convert_to(
    coalesce(r.prev_hash,'')      || '|' || coalesce(r.id::text,'')              || '|' ||
    coalesce((r.at AT TIME ZONE 'UTC')::text,'')                                 || '|' ||
    coalesce(r.actor,'')          || '|' || coalesce(r.actor_kind,'')            || '|' ||
    coalesce(r.tool,'')           || '|' || coalesce(r.session,'')               || '|' ||
    coalesce(r.branch,'')         || '|' || coalesce(r.command_tag,'')           || '|' ||
    coalesce(r.object_type,'')    || '|' || coalesce(r.object_identity,'')       || '|' ||
    coalesce(r.statement,'')      || '|' || coalesce(r.status,'')                || '|' ||
    coalesce(r.risk,''), 'UTF8')), 'hex');
$$;

-- The head of the chain, one row: the last id handed out and its row_hash. The
-- tail used to be read with SELECT … ORDER BY id DESC, under whatever snapshot
-- the transaction had, and in REPEATABLE READ or SERIALIZABLE that snapshot can
-- be older than the lock: two rows chained off one parent, and verify called it
-- tampering. An UPDATE of a row changed since the snapshot fails with a
-- serialization error instead, so a stale writer retries rather than forks.
--
-- One transaction, under the lock appends take: an append by the previous
-- bb.chain_row must not fall between reading the tail here and the new one
-- going in. Seeded from the tail on an existing ledger; nothing written so far
-- changes. The head only ever moves forward here: a tail ahead of it was
-- written by an older engine, and a tail behind it has lost rows, which the
-- next entry's link should go on showing.
BEGIN;
DO $$ BEGIN PERFORM pg_advisory_xact_lock(hashtext('bb.schema_ledger')); END $$;
CREATE TABLE IF NOT EXISTS bb.ledger_head (
  id        boolean PRIMARY KEY DEFAULT true CHECK (id),
  last_id   bigint NOT NULL,
  last_hash text   NOT NULL
);
INSERT INTO bb.ledger_head (last_id, last_hash)
SELECT coalesce(t.id, 0), coalesce(t.row_hash, '')
FROM (SELECT 1) one LEFT JOIN LATERAL
     (SELECT id, row_hash FROM bb.schema_ledger ORDER BY id DESC LIMIT 1) t ON true
ON CONFLICT (id) DO UPDATE SET last_id = EXCLUDED.last_id, last_hash = EXCLUDED.last_hash
  WHERE EXCLUDED.last_id > bb.ledger_head.last_id;

-- The id comes from the head too, after the lock, so id order is chain order
-- (the column's default is taken before the lock, by whoever got there first)
-- and a rolled-back entry leaves no gap. The default stays: it costs a sequence
-- value and keeps the sequence ahead of every id, should an older engine ever
-- write here again.
--
-- A ledger emptied by the engine (a masked branch starts with a fresh one) starts
-- a new chain, with ids carrying on. Reading it is safe at this point: the UPDATE
-- above has proved this snapshot saw the head's latest change, and with it the
-- last entry.
CREATE OR REPLACE FUNCTION bb.chain_row() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE prev text;
BEGIN
  -- Serialize appends so two concurrent inserts can't chain off the same row.
  PERFORM pg_advisory_xact_lock(hashtext('bb.schema_ledger'));
  UPDATE bb.ledger_head SET last_id = last_id + 1 RETURNING last_id, last_hash INTO NEW.id, prev;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'bb.ledger_head has no row: restart the engine to restore it';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM bb.schema_ledger) THEN
    prev := '';
  END IF;
  NEW.prev_hash := coalesce(prev, '');
  NEW.row_hash  := bb._ledger_hash(NEW);
  UPDATE bb.ledger_head SET last_hash = NEW.row_hash;
  RETURN NEW;
END;
$$;
CREATE OR REPLACE TRIGGER bb_chain BEFORE INSERT ON bb.schema_ledger
  FOR EACH ROW EXECUTE FUNCTION bb.chain_row();
COMMIT;

-- Append-only: the ledger records history, so history cannot be rewritten.
CREATE OR REPLACE FUNCTION bb.deny_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'bb.schema_ledger is append-only — its history cannot be modified';
END;
$$;
CREATE OR REPLACE TRIGGER bb_append_only BEFORE UPDATE OR DELETE ON bb.schema_ledger
  FOR EACH ROW EXECUTE FUNCTION bb.deny_change();
CREATE OR REPLACE TRIGGER bb_no_truncate BEFORE TRUNCATE ON bb.schema_ledger
  FOR EACH STATEMENT EXECUTE FUNCTION bb.deny_change();
REVOKE UPDATE, DELETE, TRUNCATE ON bb.schema_ledger FROM PUBLIC;

-- ── Least-privilege client role ─────────────────────────────────────────────
-- The gateway logs clients in as this NON-superuser role, so a client session is
-- subject to RLS and GRANTs and cannot bypass the append-only ledger — only a
-- superuser can disable a trigger or flip session_replication_role. Roles are
-- cluster-global and copied with a branch's clone; the engine sets its password.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'db_client') THEN
    CREATE ROLE db_client LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS;
  END IF;
END $$;

-- The engine's agent role: db_client's access exactly (it is a member, and acts
-- as db_client, so what it creates belongs to db_client like everything else),
-- but an agent by login, which bb._ctx reads from session_user — a session
-- cannot change that. Its password is set by the engine (branch.syncAppRole).
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'db_agent') THEN
    CREATE ROLE db_agent LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS INHERIT IN ROLE db_client;
  END IF;
END $$;
ALTER ROLE db_agent SET role = db_client;

-- Defaults for client logins, for what the append lock does to everyone else. A
-- transaction that has recorded something holds that lock until it ends, and
-- every other session's DDL (and every agent write) queues behind it, so one
-- left open in a client stopped the database's history without an error.
--   idle_in_transaction_session_timeout = 10min  the value the hardening check
--     recommends (conn.idle); it ends only a session that sat idle mid-transaction
--   lock_timeout = 60s  a queued client gets an error, not an endless wait
-- No statement_timeout: long queries and migrations are legitimate work. These
-- are defaults a session can SET for itself. Set once for each role, so a value
-- an administrator chose stays; a role made since the last start has it from the
-- next one. The engine's own superuser logins are left without them.
DO $$
DECLARE r record; s text;
BEGIN
  FOR r IN SELECT oid, rolname FROM pg_roles
            WHERE rolcanlogin AND NOT rolsuper
              AND (rolname IN ('db_client', 'db_agent') OR pg_has_role(oid, 'db_client', 'MEMBER')) LOOP
    FOREACH s IN ARRAY ARRAY['lock_timeout=60s', 'idle_in_transaction_session_timeout=10min'] LOOP
      IF NOT EXISTS (SELECT 1 FROM pg_db_role_setting d, unnest(d.setconfig) c
                      WHERE d.setrole = r.oid AND d.setdatabase = 0
                        AND split_part(c, '=', 1) = split_part(s, '=', 1)) THEN
        EXECUTE format('ALTER ROLE %I SET %I = %L', r.rolname, split_part(s, '=', 1), split_part(s, '=', 2));
      END IF;
    END LOOP;
  END LOOP;
END $$;

-- Full access to application data (it owns what it creates; these cover what the
-- superuser created, e.g. imported tables, now and in future).
GRANT USAGE, CREATE ON SCHEMA public TO db_client;
GRANT ALL ON ALL TABLES IN SCHEMA public TO db_client;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO db_client;
ALTER DEFAULT PRIVILEGES FOR ROLE dbadmin IN SCHEMA public GRANT ALL ON TABLES TO db_client;
ALTER DEFAULT PRIVILEGES FOR ROLE dbadmin IN SCHEMA public GRANT ALL ON SEQUENCES TO db_client;

-- The ledger: read only. History is written by the SECURITY DEFINER triggers,
-- not by the client, so a client can read its history and run `verify` but has no
-- INSERT/UPDATE/DELETE on the table at all — it cannot forge or rewrite entries.
GRANT USAGE ON SCHEMA bb TO db_client;
GRANT SELECT ON bb.schema_ledger, bb.policy, bb.policy_history TO db_client;

-- Functions. A SECURITY DEFINER function runs as the Blackbox's owner, so being
-- able to call one is being able to do what it does: bb._record_impact takes its
-- actor as arguments and writes a chained entry, bb._statement_texts moves a
-- run's statement position so a blocked statement matches a harmless one's text.
-- Postgres gives every new function to PUBLIC, and everything in bb used to be
-- granted to db_client on top, so all of them were callable.
--
-- So: no client may call a SECURITY DEFINER function here unless it is listed.
-- The list is every function a client, the gateway or the console calls itself,
-- SECURITY DEFINER or not (bb.act_for is the only one that is today); nothing
-- else a client reaches needs its own grant. Trigger and event-trigger functions
-- are not on it: Postgres checks EXECUTE only when a trigger is made, and they
-- are made here, by the owner, so they fire for any client. So are the nested
-- calls among these functions: the inner call is checked against the owner.
-- SECURITY INVOKER helpers keep what they have; they can do no more than their caller.
CREATE OR REPLACE FUNCTION bb._client_callable() RETURNS name[]
LANGUAGE sql IMMUTABLE AS $$
  SELECT ARRAY[
    'act_for', 'app_actor', 'app_actor_label', 'app_identity_mode',  -- application identity
    '_ledger_hash', '_ext_hash',                                     -- verifying the record
    'track_table', 'untrack_table', 'tracked_tables', 'track_row',   -- row tracking, by a table's owner
    'policy_check', 'blast_radius',                                  -- previews in the console and MCP
    'ledger_v2_version', 'blackbox_provenance_version',
    'blackbox_policy_version', 'blackbox_impact_version'
  ]::name[];
$$;

-- Take EXECUTE from clients on one function, unless it is listed above.
-- session_replication_role: the REVOKE is the Blackbox's own plumbing, not a
-- change anybody made.
CREATE OR REPLACE FUNCTION bb._seal_function(f oid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog SET session_replication_role = replica AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_proc p WHERE p.oid = f AND p.prosecdef AND NOT p.proname = ANY (bb._client_callable())) THEN
    EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC, db_client', f::regprocedure);
  END IF;
END;
$$;

-- A function added later, by any of the schema files that run after this one
-- or by a future release, is sealed as it is made. The files that come after
-- are run with session_replication_role = replica or must not REVOKE at all
-- (see datachanges.sql), so the event trigger below is what covers a new
-- install, where those functions do not exist yet at this point in the file.
CREATE OR REPLACE FUNCTION bb.seal_new_functions() RETURNS event_trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE r record;
BEGIN
  FOR r IN SELECT objid FROM pg_event_trigger_ddl_commands()
            WHERE object_type IN ('function', 'procedure') AND schema_name = 'bb' LOOP
    PERFORM bb._seal_function(r.objid);
  END LOOP;
END;
$$;

-- And every function already here, on every start: this is what closes an
-- existing install. A CREATE OR REPLACE keeps a function's privileges, so what
-- is sealed stays sealed.
DO $seal$
DECLARE p record;
BEGIN
  FOR p IN SELECT f.oid, f.proname FROM pg_proc f JOIN pg_namespace n ON n.oid = f.pronamespace
            WHERE n.nspname = 'bb' AND f.prokind IN ('f', 'p') LOOP
    IF p.proname = ANY (bb._client_callable()) THEN
      EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO db_client', p.oid::regprocedure);
    ELSE
      PERFORM bb._seal_function(p.oid);
    END IF;
  END LOOP;
END $seal$;

-- dblink, too, wherever it lives. Only the Blackbox's SECURITY DEFINER triggers
-- call it, and they run as the owner. A client holding it could open
-- connections from inside the database to anywhere the container can reach,
-- with any credentials it has or has learned (audit GW-1).
DO $dbl$
DECLARE f regprocedure;
BEGIN
  FOR f IN SELECT p.oid::regprocedure
             FROM pg_depend d
             JOIN pg_extension e ON e.oid = d.refobjid
             JOIN pg_proc p ON p.oid = d.objid
            WHERE d.classid = 'pg_proc'::regclass AND d.refclassid = 'pg_extension'::regclass
              AND d.deptype = 'e' AND e.extname = 'dblink' LOOP
    EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC, db_client', f);
  END LOOP;
END $dbl$;

-- ── Capture on ───────────────────────────────────────────────────────────────
-- Last, deliberately. This script re-runs on every `fox start`, and its own
-- statements must not be recorded as schema changes: the header's promise is
-- that re-installing never fires the triggers on its own DDL. The privilege
-- block above is not on objects in bb, so bb._skip cannot filter it; with the
-- triggers created before it, every start appended its nine GRANT/REVOKE/
-- ALTER DEFAULT PRIVILEGES statements to the Blackbox as unattributed changes.
CREATE EVENT TRIGGER bb_guard_start ON ddl_command_start
  EXECUTE FUNCTION bb.guard_ddl_start();
CREATE EVENT TRIGGER bb_log_end ON ddl_command_end
  EXECUTE FUNCTION bb.log_ddl_end();
CREATE EVENT TRIGGER bb_log_drop ON sql_drop
  EXECUTE FUNCTION bb.log_ddl_drop();
-- ALWAYS: most of the schema files that follow run with session_replication_role
-- = replica, and a function they make must be sealed all the same.
CREATE EVENT TRIGGER bb_seal_functions ON ddl_command_end
  WHEN TAG IN ('CREATE FUNCTION', 'ALTER FUNCTION', 'CREATE PROCEDURE', 'ALTER PROCEDURE', 'ALTER ROUTINE')
  EXECUTE FUNCTION bb.seal_new_functions();
ALTER EVENT TRIGGER bb_seal_functions ENABLE ALWAYS;
