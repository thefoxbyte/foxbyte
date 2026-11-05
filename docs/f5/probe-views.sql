-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- F5 design, section 3: masking computed in a view, checked on a throwaway
-- PostgreSQL 18.6 (postgres:18-bookworm). Run as the superuser with psql -f.
-- Its E4 and E7b blocks ran with search_path still set to the masked one and
-- are superseded by probe-shadow.sql; the results the design cites are from
-- E1-E3, E5, E8 and E11-E13 here.
\set ON_ERROR_STOP 0
\pset pager off
CREATE TABLE public.customers (id int PRIMARY KEY, name text, email text UNIQUE, phone text, city text);
INSERT INTO customers VALUES (1,'Asha Rao','asha@example.in','+91 98765 43210','Pune'),(2,'Ravi K','ravi@example.in','+91 91234 56789','Delhi');
ANALYZE customers;
CREATE ROLE masked LOGIN;
CREATE ROLE maskowner NOLOGIN;
CREATE SCHEMA mask AUTHORIZATION maskowner;
GRANT USAGE ON SCHEMA mask TO masked;
-- E3: a function a view uses, that the reader may not EXECUTE
CREATE FUNCTION public.hmac_secret(t text) RETURNS text LANGUAGE sql IMMUTABLE AS $$ SELECT md5('k' || t) $$;
REVOKE EXECUTE ON FUNCTION public.hmac_secret(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.hmac_secret(text) TO maskowner;
GRANT SELECT ON customers TO maskowner;
SET ROLE maskowner;
CREATE VIEW mask.customers AS SELECT id, name, public.hmac_secret(email) AS email, 'XXXXX' || right(phone, 4) AS phone, city FROM public.customers;
RESET ROLE;
GRANT SELECT ON mask.customers TO masked;
ALTER ROLE masked SET search_path = mask, public;
\echo '== E1/E2: masked reads customers unqualified (the view), then public.customers'
SET ROLE masked; SET search_path = mask, public;
SELECT * FROM customers ORDER BY id;
SELECT email FROM public.customers;
\echo '== E3: can masked call the hash function directly?'
SELECT public.hmac_secret('asha@example.in');
\echo '== E3b: WHERE on the masked column through the view'
SELECT id FROM customers WHERE email = md5('kasha@example.in');
\echo '== E5: pg_stats for the base table, as masked'
SELECT attname, most_common_vals FROM pg_stats WHERE tablename = 'customers' AND schemaname = 'public';
\echo '== E8: COPY'
COPY public.customers TO STDOUT;
COPY (SELECT * FROM customers) TO STDOUT;
\echo '== E7: masked writes the base table'
INSERT INTO public.customers VALUES (3,'x','asha@example.in','1','x');
RESET ROLE;
\echo '== E7b: a writer that may insert but not read: does a unique violation name the value?'
CREATE ROLE writer LOGIN; GRANT INSERT ON customers TO writer;
SET ROLE writer;
INSERT INTO public.customers VALUES (3,'x','asha@example.in','1','x');
RESET ROLE;
\echo '== E4: hidden masked column kept by a trigger (no function at read)'
ALTER TABLE customers ADD COLUMN email_mask text;
CREATE FUNCTION public.keep_mask() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN NEW.email_mask := public.hmac_secret(NEW.email); RETURN NEW; END $$;
CREATE TRIGGER keep_mask BEFORE INSERT OR UPDATE ON customers FOR EACH ROW EXECUTE FUNCTION public.keep_mask();
UPDATE customers SET email = email;
SET ROLE maskowner;
CREATE VIEW mask.customers2 AS SELECT id, name, email_mask AS email, city FROM public.customers;
RESET ROLE;
GRANT SELECT ON mask.customers2 TO masked;
SET ROLE masked;
SELECT * FROM mask.customers2 ORDER BY id;
\echo '== E4b: column privilege only: masked may read id and city of the base table'
RESET ROLE;
GRANT SELECT (id, city) ON public.customers TO masked;
SET ROLE masked;
SELECT id, city FROM public.customers ORDER BY id;
SELECT * FROM public.customers;
\echo '== E5b: pg_stats now, with column privileges on id and city'
SELECT attname FROM pg_stats WHERE tablename = 'customers' AND schemaname = 'public' ORDER BY 1;
\echo '== E11: a SECURITY DEFINER function owned by someone who can read, called by masked'
RESET ROLE;
CREATE FUNCTION public.find(e text) RETURNS SETOF mask.customers LANGUAGE sql SECURITY DEFINER AS $$ SELECT * FROM mask.customers WHERE email = public.hmac_secret(e) $$;
ALTER FUNCTION public.find(text) OWNER TO maskowner;
REVOKE EXECUTE ON FUNCTION public.find(text) FROM PUBLIC; GRANT EXECUTE ON FUNCTION public.find(text) TO masked;
SET ROLE masked;
SELECT id, email FROM public.find('ravi@example.in');
\echo '== E12: EXPLAIN as masked'
EXPLAIN (VERBOSE, COSTS OFF) SELECT * FROM customers;
RESET ROLE;
\echo '== E13: security_invoker view (PG15+) with masked reading'
SET ROLE maskowner;
CREATE VIEW mask.customers3 WITH (security_invoker = true) AS SELECT id, 'XXXX' || right(phone,4) AS phone FROM public.customers;
RESET ROLE;
GRANT SELECT ON mask.customers3 TO masked;
SET ROLE masked;
SELECT * FROM mask.customers3;
RESET ROLE;
