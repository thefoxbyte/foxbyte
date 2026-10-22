-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- The Blackbox's catalog scan: one row for everything it watches, read in the
-- same snapshot as the ledger's newest entry (internal/branch/catalogscan.go).
--
-- The event triggers record a change as it happens, but only when they run. A
-- superuser can stop them for a session (SET event_triggers = off on
-- PostgreSQL 17 and later, SET session_replication_role = replica on every
-- version) or for everyone (ALTER EVENT TRIGGER … DISABLE), and some changes
-- never reach an event trigger at all: roles, role memberships, databases,
-- tablespaces and settings are global objects, outside any one database. The
-- scan compares this snapshot with the last one, so a change shows up whatever
-- stopped it being recorded.
--
-- Each row: key (stable across renames: the catalogue and the object's oid),
-- kind, identity (the same text pg_event_trigger_ddl_commands gives, so a row
-- can be matched with the ledger entry that explains it), schema, parents (the
-- tables an index, trigger or policy belongs to, and a partition's ancestors),
-- def and acl (what the object is and who may use it), and global.
--
-- def is built from oids and stored expression trees, never from names, so
-- renaming a type, a sequence or a referenced table does not look like a change
-- to every table that uses it. Expression trees change between PostgreSQL
-- majors; the scan starts a new baseline after an upgrade.
--
-- Not watched: the Blackbox's own schema (bb), the system schemas, objects an
-- extension owns, sequences (their CREATE and ALTER are never recorded, by
-- design), schemas themselves (CREATE SCHEMA is skipped the same way), and the
-- triggers the Blackbox attaches to user tables. Passwords are not read.
WITH user_ns AS (
  SELECT oid, nspname FROM pg_namespace
  WHERE nspname NOT IN ('pg_catalog', 'information_schema', 'bb')
    AND nspname !~ '^(pg_toast|pg_temp_|pg_toast_temp_|bb_)'
),
ext AS (
  SELECT classid, objid FROM pg_depend WHERE deptype = 'e'
),
rels AS (
  SELECT c.*, n.nspname
  FROM pg_class c JOIN user_ns n ON n.oid = c.relnamespace
  WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'i', 'I')
    AND NOT EXISTS (SELECT 1 FROM ext e WHERE e.classid = 'pg_class'::regclass AND e.objid = c.oid)
    -- An index that backs a primary key, unique or exclusion constraint is part
    -- of its table's constraints; an index attached to a partitioned index is
    -- part of that one. Neither has a ledger entry of its own.
    AND NOT (c.relkind IN ('i', 'I') AND (
          EXISTS (SELECT 1 FROM pg_constraint k
                  WHERE k.conindid = c.oid AND k.conrelid = (SELECT indrelid FROM pg_index WHERE indexrelid = c.oid)
                    AND k.contype IN ('p', 'u', 'x'))
          OR EXISTS (SELECT 1 FROM pg_inherits h WHERE h.inhrelid = c.oid)))
)
-- Tables, views, materialized views, foreign tables and indexes.
SELECT 'c:' || r.oid AS key,
       CASE r.relkind WHEN 'r' THEN 'table' WHEN 'p' THEN 'table' WHEN 'v' THEN 'view'
                      WHEN 'm' THEN 'materialized view' WHEN 'f' THEN 'foreign table'
                      ELSE 'index' END AS kind,
       (pg_identify_object('pg_class'::regclass, r.oid, 0)).identity AS identity,
       r.nspname AS schema,
       CASE WHEN r.relkind IN ('i', 'I') THEN
              ARRAY(SELECT (pg_identify_object('pg_class'::regclass, i.indrelid, 0)).identity
                    FROM pg_index i WHERE i.indexrelid = r.oid)
            ELSE
              ARRAY(SELECT (pg_identify_object('pg_class'::regclass, a.relid, 0)).identity
                    FROM pg_partition_ancestors(r.oid) a WHERE a.relid <> r.oid)
              || ARRAY(SELECT (pg_identify_object('pg_class'::regclass, h.inhparent, 0)).identity
                       FROM pg_inherits h WHERE h.inhrelid = r.oid)
       END AS parents,
       md5(concat_ws('|', r.relkind, r.relowner, r.relpersistence, r.relreplident,
         r.relrowsecurity, r.relforcerowsecurity, r.reloptions::text, r.reltablespace, r.relam,
         (SELECT string_agg(concat_ws(':', a.attnum, a.attname, a.atttypid, a.atttypmod, a.attnotnull,
                   a.attidentity, a.attgenerated, a.attcollation, d.adbin::text), ',' ORDER BY a.attnum)
            FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
           WHERE a.attrelid = r.oid AND a.attnum > 0 AND NOT a.attisdropped),
         (SELECT string_agg(concat_ws(':', k.conname, k.contype, k.condeferrable, k.condeferred,
                   k.convalidated, k.confrelid, k.conkey::text, k.confkey::text, k.confupdtype,
                   k.confdeltype, k.confmatchtype, k.conbin::text, k.connoinherit), ',' ORDER BY k.conname)
            FROM pg_constraint k WHERE k.conrelid = r.oid),
         (SELECT concat_ws(':', p.partstrat, p.partattrs::text, p.partexprs::text)
            FROM pg_partitioned_table p WHERE p.partrelid = r.oid),
         r.relpartbound::text,
         (SELECT string_agg(h.inhparent::text, ',' ORDER BY h.inhseqno) FROM pg_inherits h WHERE h.inhrelid = r.oid),
         (SELECT string_agg(concat_ws(':', w.ev_type, w.ev_action::text), ',' ORDER BY w.rulename)
            FROM pg_rewrite w WHERE w.ev_class = r.oid),
         (SELECT concat_ws(':', i.indrelid, i.indkey::text, i.indclass::text, i.indcollation::text,
                   i.indoption::text, i.indisunique, i.indexprs::text, i.indpred::text)
            FROM pg_index i WHERE i.indexrelid = r.oid),
         (SELECT concat_ws(':', f.ftserver, f.ftoptions::text) FROM pg_foreign_table f WHERE f.ftrelid = r.oid)
       )) AS def,
       md5(concat_ws('|',
         (SELECT string_agg(concat_ws(':', x.grantor, x.grantee, x.privilege_type, x.is_grantable), ','
                   ORDER BY x.grantee, x.privilege_type, x.grantor) FROM aclexplode(r.relacl) x),
         (SELECT string_agg(concat_ws(':', a.attnum, x.grantor, x.grantee, x.privilege_type, x.is_grantable), ','
                   ORDER BY a.attnum, x.grantee, x.privilege_type, x.grantor)
            FROM pg_attribute a, aclexplode(a.attacl) x
           WHERE a.attrelid = r.oid AND a.attnum > 0 AND NOT a.attisdropped)
       )) AS acl,
       false AS global
FROM rels r

UNION ALL
-- Functions, procedures and aggregates.
SELECT 'p:' || p.oid,
       CASE p.prokind WHEN 'p' THEN 'procedure' WHEN 'a' THEN 'aggregate' ELSE 'function' END,
       (pg_identify_object('pg_proc'::regclass, p.oid, 0)).identity,
       n.nspname, '{}'::text[],
       md5(concat_ws('|', p.proowner, p.prolang, p.prokind, p.prosecdef, p.proleakproof, p.proisstrict,
         p.proretset, p.provolatile, p.proparallel, p.proargtypes::text, p.prorettype,
         p.proallargtypes::text, p.proargmodes::text, p.proargnames::text, p.proargdefaults::text,
         p.prosrc, p.probin, p.prosqlbody::text, p.proconfig::text, p.prosupport::oid)),
       md5(coalesce((SELECT string_agg(concat_ws(':', x.grantor, x.grantee, x.privilege_type, x.is_grantable), ','
                       ORDER BY x.grantee, x.privilege_type, x.grantor) FROM aclexplode(p.proacl) x), '')),
       false
FROM pg_proc p JOIN user_ns n ON n.oid = p.pronamespace
WHERE NOT EXISTS (SELECT 1 FROM ext e WHERE e.classid = 'pg_proc'::regclass AND e.objid = p.oid)

UNION ALL
-- Enums, domains, ranges and standalone composite types (not a table's row
-- type, not an array, not a range's implicit multirange).
SELECT 't:' || t.oid,
       CASE t.typtype WHEN 'd' THEN 'domain' ELSE 'type' END,
       (pg_identify_object('pg_type'::regclass, t.oid, 0)).identity,
       n.nspname, '{}'::text[],
       md5(concat_ws('|', t.typowner, t.typtype, t.typbasetype, t.typtypmod, t.typnotnull,
         t.typdefaultbin::text, t.typcollation,
         (SELECT string_agg(e.enumlabel, ',' ORDER BY e.enumsortorder) FROM pg_enum e WHERE e.enumtypid = t.oid),
         (SELECT string_agg(concat_ws(':', k.conname, k.conbin::text, k.convalidated), ',' ORDER BY k.conname)
            FROM pg_constraint k WHERE k.contypid = t.oid),
         (SELECT string_agg(concat_ws(':', a.attname, a.atttypid, a.atttypmod), ',' ORDER BY a.attnum)
            FROM pg_attribute a WHERE a.attrelid = t.typrelid AND a.attnum > 0 AND NOT a.attisdropped),
         (SELECT concat_ws(':', g.rngsubtype, g.rngsubopc, g.rngcollation) FROM pg_range g WHERE g.rngtypid = t.oid))),
       md5(coalesce((SELECT string_agg(concat_ws(':', x.grantor, x.grantee, x.privilege_type, x.is_grantable), ','
                       ORDER BY x.grantee, x.privilege_type, x.grantor) FROM aclexplode(t.typacl) x), '')),
       false
FROM pg_type t JOIN user_ns n ON n.oid = t.typnamespace
WHERE t.typtype IN ('e', 'd', 'r', 'c')
  AND (t.typtype <> 'c' OR (SELECT relkind FROM pg_class WHERE oid = t.typrelid) = 'c')
  AND NOT EXISTS (SELECT 1 FROM ext e WHERE e.classid = 'pg_type'::regclass AND e.objid = t.oid)

UNION ALL
-- Triggers on user tables: not the ones a partition inherits, and not the ones
-- the Blackbox itself attaches (datachanges.sql, tracking.sql).
SELECT 'g:' || g.oid, 'trigger',
       (pg_identify_object('pg_trigger'::regclass, g.oid, 0)).identity,
       r.nspname,
       ARRAY[(pg_identify_object('pg_class'::regclass, g.tgrelid, 0)).identity],
       md5(concat_ws('|', g.tgfoid, g.tgtype, g.tgenabled, g.tgattr::text, encode(g.tgargs, 'hex'),
         g.tgqual::text, g.tgdeferrable, g.tginitdeferred, g.tgoldtable, g.tgnewtable)),
       '',
       false
FROM pg_trigger g JOIN rels r ON r.oid = g.tgrelid
WHERE NOT g.tgisinternal AND g.tgparentid = 0
  AND g.tgname !~ '^bb_(guard_truncate|record_dml|guard_dml|guard_impact|track)$'

UNION ALL
-- Row-level security policies.
SELECT 'y:' || y.oid, 'policy',
       (pg_identify_object('pg_policy'::regclass, y.oid, 0)).identity,
       r.nspname,
       ARRAY[(pg_identify_object('pg_class'::regclass, y.polrelid, 0)).identity],
       md5(concat_ws('|', y.polcmd, y.polpermissive, y.polroles::text, y.polqual::text, y.polwithcheck::text)),
       '',
       false
FROM pg_policy y JOIN rels r ON r.oid = y.polrelid

UNION ALL
-- Default privileges: what every future table, function or type will grant.
SELECT 'd:' || d.oid, 'default privileges',
       (pg_identify_object('pg_default_acl'::regclass, d.oid, 0)).identity,
       coalesce((SELECT nspname FROM pg_namespace WHERE oid = d.defaclnamespace), ''), '{}'::text[],
       md5(concat_ws('|', d.defaclrole, d.defaclnamespace, d.defaclobjtype,
         (SELECT string_agg(concat_ws(':', x.grantor, x.grantee, x.privilege_type, x.is_grantable), ','
                   ORDER BY x.grantee, x.privilege_type, x.grantor) FROM aclexplode(d.defaclacl) x))),
       '',
       false
FROM pg_default_acl d

-- ── Global objects: no event trigger ever sees these ────────────────────────
UNION ALL
-- Roles, with what they may do; never a password.
SELECT 'r:' || a.oid, 'role', quote_ident(a.rolname), '', '{}'::text[],
       concat_ws(' ',
         CASE WHEN a.rolsuper THEN 'SUPERUSER' END, CASE WHEN a.rolcreaterole THEN 'CREATEROLE' END,
         CASE WHEN a.rolcreatedb THEN 'CREATEDB' END, CASE WHEN a.rolcanlogin THEN 'LOGIN' END,
         CASE WHEN a.rolreplication THEN 'REPLICATION' END, CASE WHEN a.rolbypassrls THEN 'BYPASSRLS' END,
         CASE WHEN NOT a.rolinherit THEN 'NOINHERIT' END,
         CASE WHEN a.rolconnlimit >= 0 THEN 'CONNECTION LIMIT ' || a.rolconnlimit END,
         CASE WHEN a.rolvaliduntil IS NOT NULL THEN 'VALID UNTIL ' || a.rolvaliduntil END),
       '',
       true
FROM pg_roles a
WHERE a.rolname !~ '^pg_'

UNION ALL
-- Role memberships: who acts as whom. A membership in a predefined role
-- (pg_read_all_data, pg_execute_server_program …) counts too.
SELECT 'm:' || m.oid, 'role membership',
       quote_ident(u.rolname) || ' in ' || quote_ident(g.rolname), '', '{}'::text[],
       concat_ws(' ',
         CASE WHEN m.admin_option THEN 'ADMIN' END,
         CASE WHEN NOT m.inherit_option THEN 'NOINHERIT' END,
         CASE WHEN NOT m.set_option THEN 'NOSET' END,
         'granted by ' || quote_ident(coalesce((SELECT rolname FROM pg_roles WHERE oid = m.grantor), m.grantor::text))),
       '',
       true
FROM pg_auth_members m
JOIN pg_roles g ON g.oid = m.roleid
JOIN pg_roles u ON u.oid = m.member
WHERE u.rolname !~ '^pg_'

UNION ALL
-- Settings attached to a role or a database (ALTER ROLE … SET, ALTER DATABASE
-- … SET): one of them can switch the record off for every later session.
SELECT 's:' || s.setdatabase || ':' || s.setrole, 'setting',
       CASE WHEN s.setrole = 0 THEN 'database ' || quote_ident((SELECT datname FROM pg_database WHERE oid = s.setdatabase))
            WHEN s.setdatabase = 0 THEN 'role ' || quote_ident((SELECT rolname FROM pg_roles WHERE oid = s.setrole))
            ELSE 'role ' || quote_ident((SELECT rolname FROM pg_roles WHERE oid = s.setrole))
                 || ' in database ' || quote_ident((SELECT datname FROM pg_database WHERE oid = s.setdatabase))
       END,
       '', '{}'::text[],
       array_to_string(s.setconfig, ', '),
       '',
       true
FROM pg_db_role_setting s

UNION ALL
-- Server-wide settings that stop the event triggers, as a new session sees them
-- (postgresql.conf, ALTER SYSTEM, the command line). event_triggers exists from
-- PostgreSQL 17.
SELECT 'f:' || g.name, 'server setting', g.name, '', '{}'::text[],
       g.setting, '', true
FROM pg_settings g
WHERE g.name IN ('event_triggers', 'session_replication_role')

UNION ALL
-- Event triggers, by name: the Blackbox drops and re-creates its own on every
-- start, so their oids change while nothing else does. bb_guard_start is left
-- out: an import or a pipeline switches it off and on again by design.
SELECT 'e:' || e.evtname, 'event trigger', quote_ident(e.evtname), '', '{}'::text[],
       concat_ws(' ', e.evtevent, CASE e.evtenabled WHEN 'D' THEN 'DISABLED' WHEN 'R' THEN 'REPLICA'
                                                      WHEN 'A' THEN 'ALWAYS' ELSE 'ENABLED' END,
                 e.evtfoid::regproc::text, e.evttags::text),
       '', true
FROM pg_event_trigger e
WHERE e.evtname <> 'bb_guard_start'

UNION ALL
-- Databases and tablespaces.
SELECT 'b:' || d.oid, 'database', quote_ident(d.datname), '', '{}'::text[],
       concat_ws(' ', 'owner ' || quote_ident(coalesce((SELECT rolname FROM pg_roles WHERE oid = d.datdba), d.datdba::text)),
         CASE WHEN NOT d.datallowconn THEN 'NOCONNECT' END,
         CASE WHEN d.datconnlimit >= 0 THEN 'CONNECTION LIMIT ' || d.datconnlimit END,
         CASE WHEN d.datistemplate THEN 'TEMPLATE' END),
       md5(coalesce((SELECT string_agg(concat_ws(':', x.grantor, x.grantee, x.privilege_type, x.is_grantable), ','
                       ORDER BY x.grantee, x.privilege_type, x.grantor) FROM aclexplode(d.datacl) x), '')),
       true
FROM pg_database d

UNION ALL
SELECT 'ts:' || s.oid, 'tablespace', quote_ident(s.spcname), '', '{}'::text[],
       concat_ws(' ', 'owner ' || quote_ident(coalesce((SELECT rolname FROM pg_roles WHERE oid = s.spcowner), s.spcowner::text)),
         s.spcoptions::text),
       md5(coalesce((SELECT string_agg(concat_ws(':', x.grantor, x.grantee, x.privilege_type, x.is_grantable), ','
                       ORDER BY x.grantee, x.privilege_type, x.grantor) FROM aclexplode(s.spcacl) x), '')),
       true
FROM pg_tablespace s
