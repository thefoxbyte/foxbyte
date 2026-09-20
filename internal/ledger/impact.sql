-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- FoxByte Blackbox impact analysis (Blackbox 2.0 Phase 7) — installed AFTER
-- the other Blackbox objects.
--
-- bb.blast_radius reports what depends on a table, view, materialized view,
-- index or sequence — or on one of its columns: the objects a change to it could
-- break. It follows views built on views up to a depth limit. It only reads the
-- catalog; nothing here changes an existing object. Idempotent.
--
-- It runs with the caller's rights and the caller's search_path (no SET
-- search_path), so an unqualified target resolves exactly as it would in the
-- caller's own statement; built-in catalog names always resolve first. Every
-- name it reports is schema-qualified.

SET session_replication_role = replica;

CREATE OR REPLACE FUNCTION bb.blast_radius(target text, target_column text DEFAULT NULL, max_depth integer DEFAULT 5)
RETURNS jsonb
LANGUAGE plpgsql STABLE AS $$
DECLARE
  rel        oid;
  att        int2;
  info       record;
  queue      oid[];
  subs       int[];
  depths     int[];
  seen_rel   oid[];
  seen       text[] := '{}';
  items      jsonb := '[]';
  truncated  boolean := false;
  i          int := 1;
  cur        oid;
  cur_sub    int;
  cur_depth  int;
  d          record;
  owner      oid;
  obj_type   text;
  obj_ident  text;
  obj_key    text;
BEGIN
  max_depth := least(greatest(coalesce(max_depth, 5), 1), 10);
  rel := to_regclass(target);
  IF rel IS NULL THEN
    RETURN jsonb_build_object('found', false, 'target', target, 'column', target_column);
  END IF;
  IF target_column IS NOT NULL THEN
    SELECT a.attnum INTO att FROM pg_attribute a
     WHERE a.attrelid = rel AND a.attname = target_column AND a.attnum > 0 AND NOT a.attisdropped;
    IF att IS NULL THEN
      RETURN jsonb_build_object('found', false,
        'target', (SELECT o.identity FROM pg_identify_object('pg_class'::regclass, rel, 0) o), 'column', target_column);
    END IF;
  END IF;
  SELECT o.type, o.identity, c.reltuples INTO info
    FROM pg_class c, pg_identify_object('pg_class'::regclass, c.oid, 0) o
   WHERE c.oid = rel;

  queue := ARRAY[rel]; subs := ARRAY[coalesce(att, 0)::int]; depths := ARRAY[0]; seen_rel := ARRAY[rel];
  WHILE i <= array_length(queue, 1) LOOP
    cur := queue[i]; cur_sub := subs[i]; cur_depth := depths[i];
    i := i + 1;
    -- Normal and automatic dependencies; internal ones are part of the object itself.
    FOR d IN SELECT dep.classid, dep.objid, dep.deptype
               FROM pg_depend dep
              WHERE dep.refclassid = 'pg_class'::regclass AND dep.refobjid = cur
                AND (cur_sub = 0 OR dep.refobjsubid = cur_sub)
                AND dep.deptype IN ('n', 'a')
              ORDER BY dep.classid, dep.objid LOOP
      owner := CASE d.classid
        -- an index belongs to the table it indexes; other relations (e.g. an owned sequence) to themselves
        WHEN 'pg_class'::regclass      THEN coalesce((SELECT x.indrelid FROM pg_index x WHERE x.indexrelid = d.objid), d.objid)
        WHEN 'pg_rewrite'::regclass    THEN (SELECT r.ev_class FROM pg_rewrite r WHERE r.oid = d.objid)
        WHEN 'pg_constraint'::regclass THEN (SELECT nullif(k.conrelid, 0) FROM pg_constraint k WHERE k.oid = d.objid)
        WHEN 'pg_trigger'::regclass    THEN (SELECT t.tgrelid FROM pg_trigger t WHERE t.oid = d.objid)
        WHEN 'pg_policy'::regclass     THEN (SELECT p.polrelid FROM pg_policy p WHERE p.oid = d.objid)
        WHEN 'pg_attrdef'::regclass    THEN (SELECT a.adrelid FROM pg_attrdef a WHERE a.oid = d.objid)
        ELSE NULL END;
      IF d.classid = 'pg_rewrite'::regclass THEN
        IF owner IS NULL OR owner = cur THEN
          CONTINUE; -- a view's own rule
        END IF;
        -- A view or materialized view is reported as itself, not as its rule.
        SELECT o.type, o.identity INTO obj_type, obj_ident FROM pg_identify_object('pg_class'::regclass, owner, 0) o;
      ELSE
        SELECT o.type, o.identity INTO obj_type, obj_ident FROM pg_identify_object(d.classid, d.objid, 0) o;
      END IF;
      obj_key := obj_type || ':' || obj_ident;
      IF obj_key = ANY (seen) THEN
        CONTINUE;
      END IF;
      seen := seen || obj_key;
      items := items || jsonb_build_object(
        'type', obj_type,
        'identity', obj_ident,
        'depth', cur_depth + 1,
        'relation', CASE WHEN owner IS NULL THEN NULL
                         ELSE (SELECT o.identity FROM pg_identify_object('pg_class'::regclass, owner, 0) o) END,
        'same_relation', coalesce(owner = rel, false),
        'dependency', CASE d.deptype WHEN 'a' THEN 'dropped with it' ELSE 'depends on it' END,
        'via', CASE WHEN cur = rel THEN NULL
                    ELSE (SELECT o.identity FROM pg_identify_object('pg_class'::regclass, cur, 0) o) END);
      -- Follow views built on this view.
      IF d.classid = 'pg_rewrite'::regclass AND NOT owner = ANY (seen_rel) THEN
        IF cur_depth + 1 < max_depth THEN
          queue := queue || owner; subs := subs || 0; depths := depths || (cur_depth + 1);
          seen_rel := seen_rel || owner;
        ELSIF EXISTS (SELECT 1 FROM pg_depend x WHERE x.refclassid = 'pg_class'::regclass
                         AND x.refobjid = owner AND x.deptype IN ('n', 'a')) THEN
          truncated := true;
        END IF;
      END IF;
    END LOOP;
  END LOOP;

  RETURN jsonb_build_object(
    'found', true,
    'target', info.identity,
    'type', info.type,
    'column', CASE WHEN att IS NULL THEN NULL ELSE target_column END,
    'rows_estimate', greatest(info.reltuples, 0)::bigint,
    'size_bytes', pg_total_relation_size(rel),
    'max_depth', max_depth,
    'truncated', truncated,
    'dependents', items);
END;
$$;
GRANT EXECUTE ON FUNCTION bb.blast_radius(text, text, integer) TO db_client;

-- Which impact-analysis definition is installed.
CREATE OR REPLACE FUNCTION bb.blackbox_impact_version() RETURNS text
LANGUAGE sql IMMUTABLE AS $$ SELECT '1' $$;
GRANT EXECUTE ON FUNCTION bb.blackbox_impact_version() TO db_client;

SET session_replication_role = DEFAULT;
