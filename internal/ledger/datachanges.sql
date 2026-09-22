-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Blackbox: data changes (audit v2 G04). Installed after ledger.sql and the 2.0
-- files, on every start; idempotent.
--
-- The Blackbox's event triggers see DDL only. TRUNCATE fires no event trigger,
-- so `TRUNCATE orders` was neither refused like DROP TABLE nor recorded, and a
-- DELETE or UPDATE — the ordinary way an agent destroys data — left no trace.
-- Postgres runs table triggers for both, so every user table gets two:
--
--   bb_guard_truncate  BEFORE TRUNCATE, per statement: the guardrail and the
--                      record for TRUNCATE, for everyone (bb.guard_truncate)
--   bb_record_dml      AFTER UPDATE OR DELETE, per statement: records the
--                      statement when an agent ran it (bb.record_dml)
--
-- Humans' UPDATE and DELETE are not recorded: that would put a Blackbox write
-- in every data-changing statement on main. An agent's are, because proving
-- what an agent did is the point. Row counts are not recorded — counting needs
-- transition tables, which would copy every changed row of every statement.
--
-- The triggers are attached to every existing table here, and to each new one
-- by an event trigger (bb_data_attach). Dropping, disabling or renaming one is
-- refused unless the guardrail override is in force (a superuser or a db_admin
-- member with bb.allow_destructive=on). A superuser can still switch triggers
-- off for a session; the Blackbox has always had that limit.

-- TRUNCATE joins DROP TABLE and DROP SCHEMA as blocked by default. An install
-- whose policy already lists it keeps its choice.
INSERT INTO bb.policy(op, action) VALUES ('TRUNCATE', 'block') ON CONFLICT (op) DO NOTHING;

-- Is the guardrail on? Imports and pipelines switch it off for their own load
-- by disabling bb_guard_start; TRUNCATE follows the same switch.
CREATE OR REPLACE FUNCTION bb._guard_on() RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT coalesce((SELECT evtenabled <> 'D' FROM pg_event_trigger WHERE evtname = 'bb_guard_start'), true);
$$;

-- The identity event triggers give a table, for trigger functions: schema and
-- name, each quoted only when it has to be.
CREATE OR REPLACE FUNCTION bb._table_identity(schema_name name, table_name name) RETURNS text
LANGUAGE sql IMMUTABLE AS $$ SELECT quote_ident(schema_name) || '.' || quote_ident(table_name) $$;

CREATE OR REPLACE FUNCTION bb.guard_truncate() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, bb AS $$
DECLARE act text; allow text; c record; st text := 'APPLIED'; obj text;
BEGIN
  obj := bb._table_identity(TG_TABLE_SCHEMA, TG_TABLE_NAME);
  SELECT * INTO c FROM bb._ctx();
  SELECT action INTO act FROM bb.policy WHERE op = 'TRUNCATE';
  IF act = 'block' AND bb._guard_on() THEN
    allow := coalesce(nullif(current_setting('bb.allow_destructive', true), ''), 'off');
    IF NOT (allow IN ('on','true','1') AND bb._may_override()) THEN
      -- Recorded through a second connection so the record survives the
      -- rollback the refusal causes (as bb.guard_ddl_start does).
      IF bb._holds_chain_lock() THEN
        RAISE WARNING 'guardrail: this blocked attempt is not recorded in Blackbox, because this transaction has already written to it';
      ELSE
        PERFORM dblink_exec(
          'host=/var/run/postgresql dbname=' || current_database() || ' user=' || current_user,
          format($f$INSERT INTO bb.schema_ledger
                  (actor,actor_kind,tool,session,branch,command_tag,object_type,object_identity,statement,status,risk)
                  VALUES (%L,%L,%L,%L,%L,'TRUNCATE','table',%L,%L,'BLOCKED','policy')$f$,
            c.actor, c.actor_kind, c.tool, c.session, c.branch, obj, current_query()));
      END IF;
      RAISE EXCEPTION 'guardrail: TRUNCATE is blocked by policy (set bb.allow_destructive=on to override)'
        USING ERRCODE = 'insufficient_privilege',
              HINT = 'Only superusers and members of db_admin may override. Grant it with: fox admin grant <email>';
    END IF;
  END IF;
  IF act = 'flag' THEN
    st := 'FLAGGED';
  END IF;
  INSERT INTO bb.schema_ledger
    (actor,actor_kind,tool,session,branch,command_tag,object_type,object_identity,statement,status,risk)
  VALUES (c.actor,c.actor_kind,c.tool,c.session,c.branch,'TRUNCATE','table',obj,current_query(),st,'truncate');
  RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION bb.record_dml() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, bb AS $$
DECLARE c record;
BEGIN
  SELECT * INTO c FROM bb._ctx();
  IF c.actor_kind IS DISTINCT FROM 'agent' THEN
    RETURN NULL;
  END IF;
  INSERT INTO bb.schema_ledger
    (actor,actor_kind,tool,session,branch,command_tag,object_type,object_identity,statement,status,risk)
  VALUES (c.actor,c.actor_kind,c.tool,c.session,c.branch,TG_OP,'table',
          bb._table_identity(TG_TABLE_SCHEMA, TG_TABLE_NAME),current_query(),'APPLIED',NULL);
  RETURN NULL;
END;
$$;

-- Attach both triggers to one table, where they are missing. Found by function,
-- not name, so a trigger renamed out of the way still counts as present (and
-- bb.data_protect_end refuses the rename anyway).
CREATE OR REPLACE FUNCTION bb._attach_data_triggers(rel regclass) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, bb AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = rel AND tgfoid = 'bb.guard_truncate()'::regprocedure) THEN
    EXECUTE format('CREATE TRIGGER bb_guard_truncate BEFORE TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION bb.guard_truncate()', rel);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = rel AND tgfoid = 'bb.record_dml()'::regprocedure) THEN
    EXECUTE format('CREATE TRIGGER bb_record_dml AFTER UPDATE OR DELETE ON %s FOR EACH STATEMENT EXECUTE FUNCTION bb.record_dml()', rel);
  END IF;
END;
$$;

-- The tables the triggers belong on: ordinary and partitioned tables outside
-- the system schemas and the Blackbox's own.
CREATE OR REPLACE FUNCTION bb._data_tables() RETURNS SETOF regclass
LANGUAGE sql STABLE AS $$
  SELECT c.oid::regclass FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relkind IN ('r','p') AND c.relpersistence <> 't'
    AND n.nspname NOT IN ('bb','pg_catalog','information_schema','pg_toast')
    AND n.nspname NOT LIKE 'pg_temp%' AND n.nspname NOT LIKE 'pg_toast_temp%';
$$;

-- Is the override in force for this session? (Dropping a Blackbox trigger is as
-- destructive as anything the guardrail blocks.)
CREATE OR REPLACE FUNCTION bb._override_in_force() RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT coalesce(nullif(current_setting('bb.allow_destructive', true), ''), 'off') IN ('on','true','1')
     AND bb._may_override();
$$;

-- ddl_command_end: attach to new tables; refuse a disabled or renamed trigger.
CREATE OR REPLACE FUNCTION bb.data_protect_end() RETURNS event_trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, bb AS $$
DECLARE r record; bad text;
BEGIN
  FOR r IN SELECT * FROM pg_event_trigger_ddl_commands() LOOP
    IF r.object_type NOT IN ('table','trigger') OR r.schema_name IN ('bb','pg_catalog','information_schema')
       OR r.schema_name LIKE 'pg_temp%' THEN
      CONTINUE;
    END IF;
    IF r.object_type = 'table' AND r.command_tag IN ('CREATE TABLE','CREATE TABLE AS','SELECT INTO') THEN
      IF EXISTS (SELECT 1 FROM bb._data_tables() t WHERE t = r.objid::regclass) THEN
        PERFORM bb._attach_data_triggers(r.objid::regclass);
      END IF;
    END IF;
    -- ALTER TABLE … DISABLE TRIGGER, or ALTER TRIGGER … RENAME, on one of ours.
    IF r.command_tag IN ('ALTER TABLE','ALTER TRIGGER') AND NOT bb._override_in_force() THEN
      SELECT string_agg(t.tgname || ' on ' || t.tgrelid::regclass::text, ', ') INTO bad
      FROM pg_trigger t
      WHERE t.tgfoid IN ('bb.guard_truncate()'::regprocedure, 'bb.record_dml()'::regprocedure)
        AND (t.tgenabled = 'D' OR t.tgname NOT IN ('bb_guard_truncate','bb_record_dml'))
        AND t.tgrelid = CASE WHEN r.object_type = 'table' THEN r.objid
                             ELSE (SELECT tgrelid FROM pg_trigger WHERE oid = r.objid) END;
      IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'guardrail: the Blackbox''s data-change triggers cannot be disabled or renamed (%)', bad
          USING ERRCODE = 'insufficient_privilege',
                HINT = 'Only superusers and members of db_admin may, with bb.allow_destructive=on.';
      END IF;
    END IF;
  END LOOP;
END;
$$;

-- sql_drop: refuse DROP TRIGGER on one of ours. A table's own drop takes its
-- triggers with it (they are not `original` then), which is fine.
CREATE OR REPLACE FUNCTION bb.data_protect_drop() RETURNS event_trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, bb AS $$
DECLARE r record;
BEGIN
  FOR r IN SELECT * FROM pg_event_trigger_dropped_objects() WHERE original AND object_type = 'trigger' LOOP
    IF r.object_identity ~ '^bb_(guard_truncate|record_dml) on ' AND NOT bb._override_in_force() THEN
      RAISE EXCEPTION 'guardrail: the Blackbox''s data-change trigger % cannot be dropped', r.object_identity
        USING ERRCODE = 'insufficient_privilege',
              HINT = 'Only superusers and members of db_admin may, with bb.allow_destructive=on.';
    END IF;
  END LOOP;
END;
$$;

-- No REVOKE here: ledger.sql grants every bb function to db_client on each
-- start, so a REVOKE would have to run on each start too, and a privilege
-- change after the event triggers are on is recorded as an unattributed
-- change (integration-v2 §9). Calling bb._attach_data_triggers only adds
-- these protective triggers, which is harmless.

-- Every existing table, now. (Creating these triggers is DDL; ledger.sql's
-- recorder skips the Blackbox's own triggers, so a start records nothing.)
SELECT bb._attach_data_triggers(t) FROM bb._data_tables() t;

-- Last, as in ledger.sql: nothing above should be seen by these.
DROP EVENT TRIGGER IF EXISTS bb_data_attach;
DROP EVENT TRIGGER IF EXISTS bb_data_protect_drop;
CREATE EVENT TRIGGER bb_data_attach ON ddl_command_end EXECUTE FUNCTION bb.data_protect_end();
CREATE EVENT TRIGGER bb_data_protect_drop ON sql_drop EXECUTE FUNCTION bb.data_protect_drop();
