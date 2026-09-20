-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- FoxByte Blackbox policy gate (Blackbox 2.0 Phase 5) — installed AFTER
-- ledger.sql and ledger_v2.sql. What clients receive is a public contract:
-- docs/policy-errors.md (SQLSTATE BBX01 block / BBX02 warn, JSON DETAIL).
--
-- Rules are checked on ddl_command_start by the event trigger bb_policy_start,
-- which fires after the existing guardrail bb_guard_start (event triggers fire
-- in name order). Nothing here changes the guardrail, bb.policy or the ledger.
--
-- Safety rules for this file:
--   * Fail-safe: any error while matching or recording becomes a WARNING and the
--     statement runs. The one deliberate error is a policy block (BBX01).
--   * Every shipped rule warns; blocking is opt-in per rule.
--   * The gate does NOT honour the session setting bb.v2 (a client could set
--     it to skip a block). A superuser turns the gate off with:
--       ALTER EVENT TRIGGER bb_policy_start DISABLE;
--   * Idempotent: safe to re-apply on every start; rule changes are kept.

SET session_replication_role = replica;

-- A rule's pattern must be a valid PostgreSQL regular expression.
CREATE OR REPLACE FUNCTION bb._valid_regex(p text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
  PERFORM '' ~* p;
  RETURN true;
EXCEPTION WHEN OTHERS THEN
  RETURN false;
END;
$$;

-- ── Rules ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS bb.policy_rules (
  rule_id     text PRIMARY KEY CHECK (rule_id ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
  command_tag text NOT NULL,                 -- e.g. 'ALTER TABLE'
  pattern     text CHECK (pattern IS NULL OR bb._valid_regex(pattern)), -- case-insensitive, over the statement (comments and literals removed); NULL = any
  action      text NOT NULL DEFAULT 'warn' CHECK (action IN ('warn','block')),
  reason      text NOT NULL,
  hint        text,
  enabled     boolean NOT NULL DEFAULT true,
  builtin     boolean NOT NULL DEFAULT false,
  updated_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_by  text
);

INSERT INTO bb.policy_rules (rule_id, command_tag, pattern, action, reason, hint, builtin) VALUES
  ('alter-column-type', 'ALTER TABLE', '\malter\M[^;]*\mtype\M', 'warn',
   'changing a column type rewrites the table and can break code that reads it',
   'Try it on a branch first: fox branch create try-it', true),
  ('drop-column', 'ALTER TABLE',
   '\mdrop\s+(column\M|(?!constraint\M|default\M|not\M|expression\M|identity\M)\w)', 'warn',
   'dropping a column deletes its data and breaks code that reads it',
   'Check what uses the column first, or try it on a branch: fox branch create try-it', true),
  ('drop-index', 'DROP INDEX', NULL, 'warn',
   'dropping an index can make the queries that use it much slower',
   'Check the query plans that use it first, or try it on a branch: fox branch create try-it', true),
  ('grant-to-public', 'GRANT', '\mto\s+public\M', 'warn',
   'granting to PUBLIC gives every role, including every client, this privilege',
   'Grant to a specific role instead', true)
ON CONFLICT (rule_id) DO NOTHING;

REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON bb.policy_rules FROM PUBLIC;
GRANT SELECT ON bb.policy_rules TO db_client;

-- Every change to a rule, append-only. Rules are changed through the engine
-- (fox policy …, REST), which sets bb.actor for the transaction.
CREATE TABLE IF NOT EXISTS bb.policy_rule_history (
  id         bigserial PRIMARY KEY,
  at         timestamptz NOT NULL DEFAULT clock_timestamp(),
  rule_id    text NOT NULL,
  change     text NOT NULL,   -- insert | update | delete
  old_rule   jsonb,
  new_rule   jsonb,
  changed_by text
);
CREATE OR REPLACE FUNCTION bb.record_policy_rule_change() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, bb AS $$
BEGIN
  BEGIN
    INSERT INTO bb.policy_rule_history (rule_id, change, old_rule, new_rule, changed_by)
    VALUES (coalesce(NEW.rule_id, OLD.rule_id), lower(TG_OP),
            CASE WHEN TG_OP <> 'INSERT' THEN to_jsonb(OLD) END,
            CASE WHEN TG_OP <> 'DELETE' THEN to_jsonb(NEW) END,
            coalesce(nullif(current_setting('bb.actor', true), ''), session_user));
  EXCEPTION WHEN OTHERS THEN
    RAISE WARNING 'Blackbox policy: rule change not recorded: %', SQLERRM;
  END;
  RETURN NULL;
END;
$$;
CREATE OR REPLACE TRIGGER bb_policy_rule_history AFTER INSERT OR UPDATE OR DELETE ON bb.policy_rules
  FOR EACH ROW EXECUTE FUNCTION bb.record_policy_rule_change();
CREATE OR REPLACE TRIGGER bb_policy_history_append_only BEFORE UPDATE OR DELETE ON bb.policy_rule_history
  FOR EACH ROW EXECUTE FUNCTION bb.deny_ext_change();
CREATE OR REPLACE TRIGGER bb_policy_history_no_truncate BEFORE TRUNCATE ON bb.policy_rule_history
  FOR EACH STATEMENT EXECUTE FUNCTION bb.deny_ext_change();
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON bb.policy_rule_history FROM PUBLIC;
GRANT SELECT ON bb.policy_rule_history TO db_client;

-- ── Evaluations: every warning, block and override ─────────────────────────
CREATE TABLE IF NOT EXISTS bb.ledger_policy_evaluations (
  id            bigserial PRIMARY KEY,
  at            timestamptz NOT NULL DEFAULT clock_timestamp(),
  xid           bigint,        -- the statement's transaction (joins bb.ledger_ext.xid)
  rule_id       text NOT NULL,
  action        text NOT NULL, -- warn | block | allowed
  command_tag   text,
  statement_md5 text,
  actor         text,
  session       text,
  blackbox_id   bigint         -- the BLOCKED Blackbox entry (block only)
);
CREATE INDEX IF NOT EXISTS ledger_policy_evaluations_xid_idx ON bb.ledger_policy_evaluations (xid);
CREATE OR REPLACE TRIGGER key_policy_eval_append_only BEFORE UPDATE OR DELETE ON bb.ledger_policy_evaluations
  FOR EACH ROW EXECUTE FUNCTION bb.deny_ext_change();
CREATE OR REPLACE TRIGGER key_policy_eval_no_truncate BEFORE TRUNCATE ON bb.ledger_policy_evaluations
  FOR EACH STATEMENT EXECUTE FUNCTION bb.deny_ext_change();
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON bb.ledger_policy_evaluations FROM PUBLIC;
GRANT SELECT ON bb.ledger_policy_evaluations TO db_client;

-- ── The contract (docs/policy-errors.md) ────────────────────────────────────
CREATE OR REPLACE FUNCTION bb._policy_hint(r bb.policy_rules) RETURNS text
LANGUAGE sql STABLE AS $$
  SELECT coalesce(nullif(r.hint, ''), 'Try the change on a branch first: fox branch create try-it');
$$;

CREATE OR REPLACE FUNCTION bb._policy_detail(r bb.policy_rules, command text, evaluation_id bigint, blackbox_id bigint)
RETURNS jsonb LANGUAGE sql STABLE AS $$
  SELECT jsonb_build_object(
    'v', 1,
    'rule_id', r.rule_id,
    'action', r.action,
    'command', command,
    'matched', r.pattern,
    'reason', r.reason,
    'hint', bb._policy_hint(r),
    'override', CASE WHEN r.action = 'block' THEN 'db_admin' END,
    'evaluation_id', evaluation_id,
    'blackbox_id', blackbox_id,
    'impact', NULL::jsonb);
$$;

-- Preview: the rules a statement with this command tag would trigger, without
-- running it (fox policy check / REST …/policies/check / MCP policy_check).
-- Matched the way the gate matches: against each statement in the text with this
-- command tag, without comments or string literals (bb._statement_candidates).
CREATE OR REPLACE FUNCTION bb.policy_check(command text, statement text) RETURNS SETOF jsonb
LANGUAGE sql STABLE AS $$
  SELECT bb._policy_detail(r, command, NULL, NULL)
  FROM bb.policy_rules r
  WHERE r.enabled AND r.command_tag = command
    AND (r.pattern IS NULL OR EXISTS (
          SELECT 1 FROM unnest(bb._statement_candidates(statement, command)) x WHERE x ~* r.pattern))
  ORDER BY (r.action = 'block') DESC, r.rule_id;
$$;
GRANT EXECUTE ON FUNCTION bb.policy_check(text, text) TO db_client;

-- ── The gate ────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION bb.policy_ddl_start() RETURNS event_trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, bb AS $$
DECLARE
  q        text;
  texts    text[];
  ctx      text;
  r        bb.policy_rules;
  blk      bb.policy_rules;
  blocking boolean := false;
  allow    text[];
  may      boolean;
  c        record;
  conn     text;
  eval_id  bigint;
  bb_id    bigint;
BEGIN
  -- 1. Match and warn. Nothing in here may stop the statement.
  BEGIN
    q := current_query();
    -- A rule is about the statement being run, not everything sent with it: its
    -- pattern is matched against that statement without comments or string
    -- literals, or against the whole query when that can't be established
    -- (bb._statement_texts in ledger.sql).
    BEGIN
      GET DIAGNOSTICS ctx = PG_CONTEXT;
      texts := bb._statement_texts('start', TG_TAG, ctx);
    EXCEPTION WHEN OTHERS THEN
      texts := ARRAY[q];
    END;
    allow := string_to_array(regexp_replace(coalesce(current_setting('bb.policy_allow', true), ''), '\s', '', 'g'), ',');
    SELECT * INTO c FROM bb._ctx();
    FOR r IN SELECT * FROM bb.policy_rules
             WHERE enabled AND command_tag = TG_TAG
               AND (pattern IS NULL OR EXISTS (SELECT 1 FROM unnest(texts) x WHERE x ~* pattern))
             ORDER BY (action = 'block') DESC, rule_id LOOP
      IF r.action = 'block' THEN
        IF may IS NULL THEN
          may := bb._may_override();
        END IF;
        IF may AND r.rule_id = ANY (allow) THEN
          -- An approved override: record it and let the statement through.
          INSERT INTO bb.ledger_policy_evaluations (xid, rule_id, action, command_tag, statement_md5, actor, session)
          VALUES (txid_current(), r.rule_id, 'allowed', TG_TAG, md5(q), c.actor, c.session);
          PERFORM set_config('bb.policy_override_used', 'on', true);
          CONTINUE;
        END IF;
        blk := r;
        blocking := true;
        EXIT; -- a block wins; no warnings are sent for this statement
      END IF;
      INSERT INTO bb.ledger_policy_evaluations (xid, rule_id, action, command_tag, statement_md5, actor, session)
      VALUES (txid_current(), r.rule_id, 'warn', TG_TAG, md5(q), c.actor, c.session)
      RETURNING id INTO eval_id;
      RAISE NOTICE USING ERRCODE = 'BBX02',
        MESSAGE = format('Blackbox policy warning: %s (rule %s)', r.reason, r.rule_id),
        DETAIL  = bb._policy_detail(r, TG_TAG, eval_id, NULL)::text,
        HINT    = bb._policy_hint(r);
    END LOOP;
  EXCEPTION WHEN OTHERS THEN
    RAISE WARNING 'Blackbox policy: evaluation skipped: %', SQLERRM;
    RETURN;
  END;

  IF NOT blocking THEN
    RETURN;
  END IF;

  -- 2. Record the blocked attempt through a separate connection, so it survives
  -- the rollback the error below causes (the guardrail's mechanism).
  eval_id := NULL;
  BEGIN
    conn := 'host=/var/run/postgresql dbname=' || current_database() || ' user=' || current_user;
    -- Not when this transaction already wrote to Blackbox: the second connection
    -- would wait for this one forever (bb._holds_chain_lock). The evaluation row
    -- below takes no such lock and is still recorded.
    IF bb._holds_chain_lock() THEN
      RAISE WARNING 'Blackbox policy: this blocked attempt is not recorded in Blackbox, because this transaction has already written to it';
    ELSE
      SELECT t.id INTO bb_id FROM dblink(conn, format(
        $f$INSERT INTO bb.schema_ledger (actor,actor_kind,tool,session,branch,command_tag,statement,status,risk)
           VALUES (%L,%L,%L,%L,%L,%L,%L,'BLOCKED','policy') RETURNING id$f$,
        c.actor, c.actor_kind, c.tool, c.session, c.branch, TG_TAG, q)) AS t(id bigint);
    END IF;
    SELECT t.id INTO eval_id FROM dblink(conn, format(
      $f$INSERT INTO bb.ledger_policy_evaluations (xid, rule_id, action, command_tag, statement_md5, actor, session, blackbox_id)
         VALUES (%s,%L,'block',%L,%L,%L,%L,%s) RETURNING id$f$,
      txid_current(), blk.rule_id, TG_TAG, md5(q), c.actor, c.session, coalesce(bb_id::text, 'NULL'))) AS t(id bigint);
  EXCEPTION WHEN OTHERS THEN
    RAISE WARNING 'Blackbox policy: could not record the blocked attempt: %', SQLERRM;
  END;

  -- 3. Refuse the statement.
  RAISE EXCEPTION USING ERRCODE = 'BBX01',
    MESSAGE = format('Blackbox policy: %s (rule %s)', blk.reason, blk.rule_id),
    DETAIL  = bb._policy_detail(blk, TG_TAG, eval_id, bb_id)::text,
    HINT    = bb._policy_hint(blk)
              || format(' — or ask a Blackbox admin to allow this rule for the session: SET bb.policy_allow = %L', blk.rule_id);
END;
$$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_event_trigger WHERE evtname = 'bb_policy_start') THEN
    CREATE EVENT TRIGGER bb_policy_start ON ddl_command_start
      EXECUTE FUNCTION bb.policy_ddl_start();
  END IF;
END $$;

-- Which policy-gate definition is installed.
CREATE OR REPLACE FUNCTION bb.blackbox_policy_version() RETURNS text
LANGUAGE sql IMMUTABLE AS $$ SELECT '2' $$;  -- 2: rules match the running statement
GRANT EXECUTE ON FUNCTION bb.blackbox_policy_version() TO db_client;

SET session_replication_role = DEFAULT;
