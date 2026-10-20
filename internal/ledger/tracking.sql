-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Row tracking (points 5.1, 5.2's first half, 6.1): who last changed each row,
-- and when it was made and last changed, kept by Postgres itself. Installed
-- after datachanges.sql, on every start; idempotent; touches no user table.
--
-- A tracked table has three columns (names chosen when tracking starts):
--
--   created_at        timestamptz  set on INSERT, never changed after
--   updated_at        timestamptz  set on INSERT and on every UPDATE
--   last_modified_by  text         session_user: the login that changed the row
--
-- and one row trigger, bb_track, that writes them. It overrides whatever a
-- statement put there, so a client cannot backdate a row or name someone else.
-- session_user is the authenticated login, which a session cannot change
-- (SET ROLE changes current_user; SET SESSION AUTHORIZATION needs a
-- superuser). Who a login was acting for, an application's own user, is
-- last_modified_for, which needs the expert review plan's F1: not here.
--
-- Opt-in, per table. Adding columns to a table that exists breaks an INSERT
-- written without a column list and changes SELECT *, so it is never done
-- unasked. New tables can be tracked as they are made, when that is turned on
-- (bb.track_settings, off by default). Rows from before tracking began are
-- left empty, or labelled with the moment it began, as the person chooses.
--
-- Turning tracking off drops the trigger and keeps the columns: the history
-- they hold is the user's data. Dropping, disabling or renaming bb_track
-- otherwise is refused unless the guardrail override is in force, or anyone
-- who can alter the table could switch it off, write a name, and switch it
-- back on.
--
-- Rules for this file, as for datachanges.sql: no GRANT or REVOKE, and no
-- triggers on bb tables (both would be recorded as changes on every start).

CREATE TABLE IF NOT EXISTS bb.track_settings (
  id boolean PRIMARY KEY DEFAULT true CHECK (id),
  track_new boolean NOT NULL DEFAULT false,
  created_col text NOT NULL DEFAULT 'created_at',
  updated_col text NOT NULL DEFAULT 'updated_at',
  by_col text NOT NULL DEFAULT 'last_modified_by'
);
INSERT INTO bb.track_settings DEFAULT VALUES ON CONFLICT (id) DO NOTHING;

-- The row trigger. Its arguments are the three column names; an empty one is
-- a column this table does not keep.
CREATE OR REPLACE FUNCTION bb.track_row() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE patch jsonb := '{}';
BEGIN
  IF TG_ARGV[0] <> '' THEN
    IF TG_OP = 'INSERT' THEN
      patch := patch || jsonb_build_object(TG_ARGV[0], now());
    ELSE
      patch := patch || jsonb_build_object(TG_ARGV[0], to_jsonb(OLD) -> TG_ARGV[0]);
    END IF;
  END IF;
  IF TG_ARGV[1] <> '' THEN
    patch := patch || jsonb_build_object(TG_ARGV[1], now());
  END IF;
  IF TG_ARGV[2] <> '' THEN
    patch := patch || jsonb_build_object(TG_ARGV[2], session_user::text);
  END IF;
  NEW := jsonb_populate_record(NEW, patch);
  RETURN NEW;
END;
$$;

-- What a tracked table keeps: its trigger's arguments, read back.
CREATE OR REPLACE FUNCTION bb.tracked_tables()
RETURNS TABLE (rel regclass, created_col text, updated_col text, by_col text, enabled boolean)
LANGUAGE sql STABLE AS $$
  SELECT t.tgrelid::regclass, a[1], a[2], a[3], t.tgenabled <> 'D'
  FROM pg_trigger t,
       LATERAL (SELECT string_to_array(encode(t.tgargs, 'escape'), '\000') AS a) x
  -- A partitioned table's partitions carry clones of its trigger: one entry, the table's.
  WHERE t.tgfoid = 'bb.track_row()'::regprocedure AND NOT t.tgisinternal AND t.tgparentid = 0;
$$;

-- Start tracking a table: add the columns it lacks, then the trigger. A
-- column that exists already must be of the right type. label_existing gives
-- rows already there the moment tracking began (a stable default, so the table
-- is not rewritten), and the default is taken off again at once.
--
-- Not SECURITY DEFINER: run by the engine as a superuser, or by the event
-- trigger below (which is), and anyone else needs to own the table.
CREATE OR REPLACE FUNCTION bb.track_table(rel regclass, created_col text, updated_col text, by_col text, label_existing boolean)
RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE c record; typ text; adds text[] := '{}'; drops text[] := '{}';
BEGIN
  IF (SELECT relkind FROM pg_class WHERE oid = rel) NOT IN ('r','p') THEN
    RAISE EXCEPTION '% is not a table', rel;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = rel AND tgfoid = 'bb.track_row()'::regprocedure) THEN
    RETURN; -- already tracked
  END IF;
  IF coalesce(created_col, '') = '' AND coalesce(updated_col, '') = '' AND coalesce(by_col, '') = '' THEN
    RAISE EXCEPTION 'tracking keeps at least one column';
  END IF;
  FOR c IN SELECT * FROM (VALUES (created_col, 'timestamp with time zone', true),
                                 (updated_col, 'timestamp with time zone', true),
                                 (by_col, 'text', false)) v(name, want, stamp)
           WHERE coalesce(v.name, '') <> '' LOOP
    SELECT format_type(atttypid, atttypmod) INTO typ FROM pg_attribute
      WHERE attrelid = rel AND attname = c.name AND attnum > 0 AND NOT attisdropped;
    IF typ IS NULL THEN
      IF label_existing AND c.stamp THEN
        adds := adds || format('ADD COLUMN %I timestamptz DEFAULT now()', c.name);
        drops := drops || format('ALTER COLUMN %I DROP DEFAULT', c.name);
      ELSE
        adds := adds || format('ADD COLUMN %I %s', c.name, c.want);
      END IF;
    ELSIF typ <> c.want THEN
      RAISE EXCEPTION 'column % of % is %, and tracking keeps % there', c.name, rel, typ, c.want;
    END IF;
  END LOOP;
  -- One ALTER TABLE for the columns, so the Blackbox records one change
  -- rather than one per column.
  IF cardinality(adds) > 0 THEN
    EXECUTE format('ALTER TABLE %s %s', rel, array_to_string(adds, ', '));
  END IF;
  IF cardinality(drops) > 0 THEN
    EXECUTE format('ALTER TABLE %s %s', rel, array_to_string(drops, ', '));
  END IF;
  EXECUTE format('CREATE TRIGGER bb_track BEFORE INSERT OR UPDATE ON %s FOR EACH ROW EXECUTE FUNCTION bb.track_row(%L, %L, %L)',
                 rel, coalesce(created_col, ''), coalesce(updated_col, ''), coalesce(by_col, ''));
END;
$$;

-- Stop tracking: the trigger goes, the columns and what they hold stay.
CREATE OR REPLACE FUNCTION bb.untrack_table(rel regclass) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE t name;
BEGIN
  FOR t IN SELECT tgname FROM pg_trigger WHERE tgrelid = rel AND tgfoid = 'bb.track_row()'::regprocedure LOOP
    EXECUTE format('DROP TRIGGER %I ON %s', t, rel);
  END LOOP;
END;
$$;

-- New tables, as they are made, when that is on. Partitions take the trigger
-- from their parent, and the Blackbox's own schema is never tracked.
CREATE OR REPLACE FUNCTION bb.track_new_end() RETURNS event_trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, bb AS $$
DECLARE r record; s record; bad text;
BEGIN
  SELECT * INTO s FROM bb.track_settings;
  FOR r IN SELECT * FROM pg_event_trigger_ddl_commands() LOOP
    IF r.object_type NOT IN ('table','trigger') OR r.schema_name IN ('bb','pg_catalog','information_schema')
       OR r.schema_name LIKE 'pg_temp%' OR r.schema_name LIKE 'bb\_%' THEN
      CONTINUE;
    END IF;
    IF s.track_new AND r.object_type = 'table' AND r.command_tag IN ('CREATE TABLE','CREATE TABLE AS','SELECT INTO')
       AND (SELECT relkind IN ('r','p') AND NOT relispartition AND relpersistence <> 't' FROM pg_class WHERE oid = r.objid) THEN
      PERFORM bb.track_table(r.objid::regclass, s.created_col, s.updated_col, s.by_col, false);
    END IF;
    -- Disabled, made replica-only, or renamed: refused, as for the guardrails.
    IF r.command_tag IN ('ALTER TABLE','ALTER TRIGGER') AND NOT bb._override_in_force() THEN
      SELECT string_agg(t.tgname || ' on ' || t.tgrelid::regclass::text, ', ') INTO bad
      FROM pg_trigger t
      WHERE t.tgfoid = 'bb.track_row()'::regprocedure
        AND (t.tgenabled IN ('D','R') OR t.tgname <> 'bb_track')
        AND t.tgrelid = CASE WHEN r.object_type = 'table' THEN r.objid
                             ELSE (SELECT tgrelid FROM pg_trigger WHERE oid = r.objid) END;
      IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'tracking: the row-tracking trigger cannot be disabled or renamed, nor made replica-only (%)', bad
          USING ERRCODE = 'insufficient_privilege',
                HINT = 'Turn tracking off with fox track <table> --off, or as a superuser or db_admin member with bb.allow_destructive=on.';
      END IF;
    END IF;
  END LOOP;
END;
$$;

CREATE OR REPLACE FUNCTION bb.track_protect_drop() RETURNS event_trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, bb AS $$
DECLARE r record;
BEGIN
  FOR r IN SELECT * FROM pg_event_trigger_dropped_objects() WHERE original AND object_type = 'trigger' LOOP
    IF r.object_identity ~ '^bb_track on ' AND NOT bb._override_in_force() THEN
      RAISE EXCEPTION 'tracking: the row-tracking trigger % cannot be dropped', r.object_identity
        USING ERRCODE = 'insufficient_privilege',
              HINT = 'Turn tracking off with fox track <table> --off, or as a superuser or db_admin member with bb.allow_destructive=on.';
    END IF;
  END LOOP;
END;
$$;

-- Last, as in the other files: nothing above should be seen by these.
DROP EVENT TRIGGER IF EXISTS bb_track_new;
DROP EVENT TRIGGER IF EXISTS bb_track_protect_drop;
CREATE EVENT TRIGGER bb_track_new ON ddl_command_end EXECUTE FUNCTION bb.track_new_end();
CREATE EVENT TRIGGER bb_track_protect_drop ON sql_drop EXECUTE FUNCTION bb.track_protect_drop();
