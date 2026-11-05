-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- F5 design, section 3: masked values kept in a shadow table by a trigger,
-- read through a view with no function at read time; and what a unique
-- violation tells a role that may insert but not read. Checked on a
-- throwaway PostgreSQL 18.6 (postgres:18-bookworm), as the superuser.
\set ON_ERROR_STOP 0
\pset pager off
CREATE TABLE public.customers (id int PRIMARY KEY, name text, email text UNIQUE, phone text, city text);
INSERT INTO public.customers VALUES (1,'Asha Rao','asha@example.in','+91 98765 43210','Pune'),(2,'Ravi K','ravi@example.in','+91 91234 56789','Delhi');
CREATE ROLE masked LOGIN; CREATE ROLE maskowner NOLOGIN; CREATE ROLE writer LOGIN; CREATE ROLE app LOGIN;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.customers TO app;
CREATE SCHEMA bb_mask AUTHORIZATION maskowner;
GRANT USAGE ON SCHEMA bb_mask TO masked;
CREATE FUNCTION public.hmac_secret(t text) RETURNS text LANGUAGE sql IMMUTABLE AS $$ SELECT md5('k' || t) $$;
REVOKE EXECUTE ON FUNCTION public.hmac_secret(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.hmac_secret(text) TO maskowner;
GRANT SELECT ON public.customers TO maskowner;
\echo '== E4: masked values kept in a shadow table by a trigger; the view joins it; no function at read'
CREATE TABLE bb_mask.customers_m (id int PRIMARY KEY REFERENCES public.customers(id) ON DELETE CASCADE, email text);
ALTER TABLE bb_mask.customers_m OWNER TO maskowner;
CREATE FUNCTION bb_mask.keep_customers() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
  INSERT INTO bb_mask.customers_m (id, email) VALUES (NEW.id, public.hmac_secret(NEW.email))
    ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email;
  RETURN NEW;
END $$;
ALTER FUNCTION bb_mask.keep_customers() OWNER TO maskowner;
CREATE TRIGGER bb_mask AFTER INSERT OR UPDATE ON public.customers FOR EACH ROW EXECUTE FUNCTION bb_mask.keep_customers();
UPDATE public.customers SET email = email;
SET ROLE maskowner;
CREATE VIEW bb_mask.customers AS SELECT c.id, c.name, m.email, 'XXXXX' || right(c.phone, 4) AS phone, c.city
  FROM public.customers c JOIN bb_mask.customers_m m USING (id);
RESET ROLE;
GRANT SELECT ON bb_mask.customers TO masked;
SET ROLE masked; SET search_path = bb_mask, public;
SELECT * FROM customers ORDER BY id;
\echo '== E4b: WHERE, ORDER BY, GROUP BY on the masked value; EXPLAIN'
SELECT id FROM customers WHERE email = (SELECT email FROM customers WHERE id = 2);
SELECT count(*) FROM customers GROUP BY email ORDER BY email;
EXPLAIN (COSTS OFF) SELECT * FROM customers WHERE id = 1;
\echo '== E4c: the hash function is still out of reach'
SELECT public.hmac_secret('asha@example.in');
RESET ROLE; SET search_path = public;
\echo '== E4d: the application writes as before, and the shadow keeps up'
SET ROLE app;
INSERT INTO public.customers VALUES (3, 'Meera', 'meera@example.in', '+91 90000 11111', 'Goa');
UPDATE public.customers SET email = 'asha.rao@example.in' WHERE id = 1;
RESET ROLE;
SET ROLE masked; SET search_path = bb_mask, public;
SELECT id, email FROM customers ORDER BY id;
RESET ROLE; SET search_path = public;
\echo '== E7b: a role that may insert but not read: does the unique violation name the value?'
GRANT INSERT ON public.customers TO writer;
SET ROLE writer;
INSERT INTO public.customers VALUES (9, 'x', 'ravi@example.in', '1', 'x');
RESET ROLE;
\echo '== E7c: the same with SELECT on the column'
GRANT SELECT (email) ON public.customers TO writer;
SET ROLE writer;
INSERT INTO public.customers VALUES (9, 'x', 'ravi@example.in', '1', 'x');
RESET ROLE;
\echo '== E16: TRUNCATE and the shadow'
SELECT count(*) AS shadow_rows FROM bb_mask.customers_m;
