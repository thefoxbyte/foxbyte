-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Row tracking (points 5.1, 5.2's first half, 6.1): who last changed each row,
-- and when it was made and last changed, kept by Postgres itself. Installed
-- after datachanges.sql, on every start; idempotent; touches no user table.
--
-- A tracked table has up to four columns (names chosen when tracking starts):
--
--   created_at         timestamptz  set on INSERT, never changed after
--   updated_at         timestamptz  set on INSERT and on every UPDATE
--   last_modified_by   text         session_user: the login that changed the row
--   last_modified_for  text         whom it was changed for, where the
--                                   transaction said so (application identity,
--                                   identity.sql): asserted:<app>:<user>,
--                                   claimed:<user>, or NULL
--
-- and one row trigger, bb_track, that writes them. It overrides whatever a
-- statement put there, so a client cannot backdate a row or name someone else.
-- session_user is the authenticated login, which a session cannot change
-- (SET ROLE changes current_user; SET SESSION AUTHORIZATION needs a
-- superuser). Who a login was acting for, an application's own user, is
-- last_modified_for: bb.app_actor_label(), which checks the transaction's
-- assertion against its MAC, so a value set by hand never lands there as
-- asserted. In C, and remembered across rows: a statement that changes ten
-- thousand rows pays for one check (F1 design, section 14).
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
-- The fourth column for new tables (point 5.2). '' on a branch that chose its
-- columns before it existed, so turning on "track new tables" again is what
-- adds it, not an upgrade.
ALTER TABLE bb.track_settings ADD COLUMN IF NOT EXISTS for_col text NOT NULL DEFAULT '';

-- The row trigger. Its arguments are the column names; an empty one is a
-- column this table does not keep. A trigger made before last_modified_for
-- has three.
CREATE OR REPLACE FUNCTION bb.track_row() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  -- One jsonb_build_object for every column, not one per column joined with
  -- ||: each join copies the patch, and a trigger runs once per row. Measured
  -- on a 10,000-row UPDATE, 97 ms became 79, and the for column then cost
  -- nothing that could be measured. A column this table does not keep has
  -- the name '', which jsonb_populate_record matches to nothing.
  NEW := jsonb_populate_record(NEW, jsonb_build_object(
    -- created: now on INSERT; on UPDATE what it was, whatever the statement said
    TG_ARGV[0], CASE WHEN TG_OP = 'INSERT' THEN to_jsonb(now()) ELSE to_jsonb(OLD) -> TG_ARGV[0] END,
    TG_ARGV[1], now(),
    TG_ARGV[2], session_user,
    -- for: the asserted or claimed application actor, NULL for nobody
    CASE WHEN TG_NARGS > 3 THEN TG_ARGV[3] ELSE '' END,
    CASE WHEN TG_NARGS > 3 AND TG_ARGV[3] <> '' THEN nullif(bb.app_actor_label(), '') END));
  RETURN NEW;
END;
$$;

-- What a tracked table keeps: its trigger's arguments, read back. Made again
-- when it predates for_col, since a function's columns cannot be replaced.
DO $do$
BEGIN
  IF pg_get_function_result(to_regprocedure('bb.tracked_tables()')) NOT LIKE '%for_col%' THEN
    DROP FUNCTION bb.tracked_tables();
  END IF;
END
$do$;
CREATE OR REPLACE FUNCTION bb.tracked_tables()
RETURNS TABLE (rel regclass, created_col text, updated_col text, by_col text, enabled boolean, for_col text)
LANGUAGE sql STABLE AS $$
  SELECT t.tgrelid::regclass, a[1], a[2], a[3], t.tgenabled <> 'D', coalesce(a[4], '')
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
-- A table tracked already, without the for column, gains it (point 5.2): the
-- column is added and the trigger replaced in place (CREATE OR REPLACE, so it
-- is never dropped and its protection is not asked). Nothing else about a
-- tracked table is changed by tracking it again.
--
-- Not SECURITY DEFINER: run by the engine as a superuser, or by the event
-- trigger below (which is), and anyone else needs to own the table.
CREATE OR REPLACE FUNCTION bb.track_table(rel regclass, created_col text, updated_col text, by_col text, for_col text, label_existing boolean)
RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE c record; typ text; adds text[] := '{}'; drops text[] := '{}'; cur text[];
BEGIN
  IF (SELECT relkind FROM pg_class WHERE oid = rel) NOT IN ('r','p') THEN
    RAISE EXCEPTION '% is not a table', rel;
  END IF;
  IF coalesce(for_col, '') <> '' AND to_regprocedure('bb.app_actor_label()') IS NULL THEN
    RAISE EXCEPTION 'this branch predates application identity, which % needs', for_col
      USING HINT = 'Upgrade its Blackbox (fox ledger upgrade <branch>), or track the table without it.';
  END IF;
  SELECT string_to_array(encode(t.tgargs, 'escape'), '\000') INTO cur FROM pg_trigger t
    WHERE t.tgrelid = rel AND t.tgfoid = 'bb.track_row()'::regprocedure AND NOT t.tgisinternal LIMIT 1;
  IF cur IS NOT NULL THEN
    -- Tracked already. Only the for column is added to it, and only once.
    IF coalesce(for_col, '') = '' OR coalesce(cur[4], '') <> '' THEN
      RETURN;
    END IF;
    created_col := cur[1]; updated_col := cur[2]; by_col := cur[3];
    IF for_col IN (created_col, updated_col, by_col) THEN
      RAISE EXCEPTION 'column % of % is tracked already, as another of its columns', for_col, rel;
    END IF;
    SELECT format_type(atttypid, atttypmod) INTO typ FROM pg_attribute
      WHERE attrelid = rel AND attname = for_col AND attnum > 0 AND NOT attisdropped;
    IF typ IS NULL THEN
      EXECUTE format('ALTER TABLE %s ADD COLUMN %I text', rel, for_col);
    ELSIF typ <> 'text' THEN
      RAISE EXCEPTION 'column % of % is %, and tracking keeps text there', for_col, rel, typ;
    END IF;
    EXECUTE format('CREATE OR REPLACE TRIGGER bb_track BEFORE INSERT OR UPDATE ON %s FOR EACH ROW EXECUTE FUNCTION bb.track_row(%L, %L, %L, %L)',
                   rel, created_col, updated_col, by_col, for_col);
    RETURN;
  END IF;
  IF coalesce(created_col, '') = '' AND coalesce(updated_col, '') = '' AND coalesce(by_col, '') = '' AND coalesce(for_col, '') = '' THEN
    RAISE EXCEPTION 'tracking keeps at least one column';
  END IF;
  FOR c IN SELECT * FROM (VALUES (created_col, 'timestamp with time zone', true),
                                 (updated_col, 'timestamp with time zone', true),
                                 (by_col, 'text', false),
                                 (for_col, 'text', false)) v(name, want, stamp)
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
  -- Three arguments when there is no for column, as before it existed, so a
  -- table tracked without one is the table it always was.
  IF coalesce(for_col, '') = '' THEN
    EXECUTE format('CREATE TRIGGER bb_track BEFORE INSERT OR UPDATE ON %s FOR EACH ROW EXECUTE FUNCTION bb.track_row(%L, %L, %L)',
                   rel, coalesce(created_col, ''), coalesce(updated_col, ''), coalesce(by_col, ''));
  ELSE
    EXECUTE format('CREATE TRIGGER bb_track BEFORE INSERT OR UPDATE ON %s FOR EACH ROW EXECUTE FUNCTION bb.track_row(%L, %L, %L, %L)',
                   rel, coalesce(created_col, ''), coalesce(updated_col, ''), coalesce(by_col, ''), for_col);
  END IF;
END;
$$;

-- The five-argument form, from before last_modified_for: the same, without it.
CREATE OR REPLACE FUNCTION bb.track_table(rel regclass, created_col text, updated_col text, by_col text, label_existing boolean)
RETURNS void LANGUAGE sql SET search_path = pg_catalog AS $$
  SELECT bb.track_table(rel, created_col, updated_col, by_col, '', label_existing);
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
    IF r.object_type NOT IN ('table','trigger') OR r.schema_name IN ('bb','bb_f1','pg_catalog','information_schema')
       OR r.schema_name LIKE 'pg_temp%' OR r.schema_name LIKE 'bb\_%' THEN
      CONTINUE;
    END IF;
    IF s.track_new AND r.object_type = 'table' AND r.command_tag IN ('CREATE TABLE','CREATE TABLE AS','SELECT INTO')
       AND (SELECT relkind IN ('r','p') AND NOT relispartition AND relpersistence <> 't' FROM pg_class WHERE oid = r.objid) THEN
      PERFORM bb.track_table(r.objid::regclass, s.created_col, s.updated_col, s.by_col,
                             CASE WHEN to_regprocedure('bb.app_actor_label()') IS NULL THEN '' ELSE s.for_col END, false);
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
