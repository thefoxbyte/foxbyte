#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Masking's prototype suite (F5), Gate 0's exit
# (docs/FOX_F5_Masking_Design.md, sections 13 and 15): masks kept in shadow
# tables by triggers, read through views by a masked reader who can call no
# masking function; the keyed hash in bb_identity, its key a file the server
# reads; the lookup; what a masked reader can and cannot reach; the costs; and
# a masked branch on a ZFS clone, read afterwards for what is left.
#
# Self-contained, and touches no install: it builds the engine image under a tag
# of its own, runs throwaway containers from it, makes a ZFS pool of its own
# from a file for the masked branch, and removes all of it at the end. The
# shared stack in the test VM is never stopped, started or written to.
#
#   make integration-f5
set -uo pipefail

. "$(cd "$(dirname "$0")" && pwd)/lib/test_guard.sh" || exit 2

REPO="$(cd "$(dirname "$0")/.." && pwd)"
C=fox-f5-proto
WORK="$(mktemp -d)"
POOL=f5proto
PASS=0
FAIL=0

ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
assert_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }
assert_contains() { case "$2" in *"$3"*) ok "$1";; *) bad "$1 (got '$2', want something containing '$3')";; esac; }
note() { echo "  NOTE: $1"; }

gone() { sudo docker rm -fv "$1" >/dev/null 2>&1; }
cleanup() {
  for c in fox-f5-proto fox-f5-proto-src fox-f5-proto-branch fox-f5-proto-fresh; do gone "$c"; done
  sudo zpool destroy -f "$POOL" >/dev/null 2>&1
  sudo rm -rf "$WORK"
}
trap cleanup EXIT

# Synthetic values, made to pass their checks (Verhoeff for Aadhaar) as a real
# one would, and to be found if they leak. None is anyone's.
AADHAAR=739146258013
EMAIL1=asha.rao.f5@example.in
EMAIL2=ravi.kumar.f5@example.in
PHONE=9845012345
NAME1="Asha Rao"
NOTE1="called about the loan on Tuesday"
VALUES_RE="$AADHAAR|$EMAIL1|$EMAIL2|$PHONE|$NAME1|loan on Tuesday"

# The key: 32 bytes in a file of the server's own (uid 999 in the image),
# readable by nobody else, mounted read-only where bb_identity reads it.
KEYS="$WORK/keys"
sudo mkdir -p "$KEYS"
key() { sudo sh -c "head -c 32 /dev/urandom > '$KEYS/$1.key'; chown 999:999 '$KEYS/$1.key'; chmod 400 '$KEYS/$1.key'"; }
key default
key tenant2
sudo chown 999:999 "$KEYS"; sudo chmod 700 "$KEYS"
KEYHEX="$(sudo xxd -p -c 64 "$KEYS/default.key")"

start() {
  local name="$1" img="$2"; shift 2
  gone "$name"
  sudo docker run -d --name "$name" -e POSTGRES_USER=dbadmin -e POSTGRES_PASSWORD=f5proto -e POSTGRES_DB=appdb \
    -v "$KEYS:/run/bb-mask:ro" "$@" "$img" >/dev/null
  for _ in $(seq 90); do
    [ "$(sudo docker exec "$name" psql -X -tA -U dbadmin -d appdb -c 'SELECT 1' 2>/dev/null)" = "1" ] && return 0
    sleep 1
  done
  return 1
}
su() { sudo docker exec "$C" psql -X -q -tA -U dbadmin -d appdb -c "$1" 2>&1; }
sus() { sudo docker exec -i "$C" psql -X -q -tA -U dbadmin -d appdb -v ON_ERROR_STOP=1 2>&1; }
# as <role> <sql>: one statement as a login, over the container's socket.
as() { sudo docker exec "$C" psql -X -q -tA -U "$1" -d appdb -c "$2" 2>&1; }

digest() { sed -n '/PostgresBaseDigests/,/^}/p' "$REPO/internal/branch/images.go" | grep "\"$1\"" | sed 's/.*"\(sha256:[0-9a-f]*\)".*/\1/'; }

echo "### building the engine image, with the masking hash in bb_identity, under its own tag"
build_ok=1
for m in 18 16; do
  if ! sudo docker build -q -t "fox-f5-proto:$m" --build-arg PG_MAJOR="$m" --build-arg PG_DIGEST="$(digest $m)" \
       "$REPO/docker/postgres" >/dev/null 2>"$WORK/build-$m.log"; then
    build_ok=0; tail -20 "$WORK/build-$m.log"
  fi
done
assert_eq "the image builds for Postgres 18 and 16" "$build_ok" "1"

# The roles and grants a masked install has (design, sections 6 and 10):
#   db_client   what every account and application is in today, which owns the tables
#   db_masked   what a masked account is in instead: masks of marked tables only
#   bb_masker   owns the shadows, the triggers and the views; nobody logs in as it
# One table with every rule (section 7), one joined to it on a hashed column,
# and one that is not marked at all.
read -r -d '' SETUP <<'SQL' || true
CREATE SCHEMA bb_f1;
CREATE EXTENSION bb_identity WITH SCHEMA bb_f1;
CREATE ROLE db_client NOLOGIN;
CREATE ROLE app LOGIN IN ROLE db_client;
CREATE ROLE db_masked NOLOGIN;
CREATE ROLE support LOGIN IN ROLE db_masked;
CREATE ROLE bb_masker NOLOGIN;
GRANT USAGE ON SCHEMA bb_f1 TO bb_masker;
GRANT EXECUTE ON FUNCTION bb_f1.bbid_mask_hmac(text, text) TO bb_masker;
CREATE SCHEMA bb_mask AUTHORIZATION bb_masker;
GRANT USAGE ON SCHEMA bb_mask TO db_masked;
ALTER ROLE support SET search_path = bb_mask, public;
-- A masked login's failing statements are never logged with their text: a
-- lookup's value, or a guess, would land in the server log. Superuser-only,
-- so the masked reader cannot set it back.
ALTER ROLE support SET log_min_error_statement = panic;
GRANT CREATE ON SCHEMA public TO db_client;

CREATE TABLE public.customers (id bigint PRIMARY KEY, name text, email text UNIQUE, phone text, aadhaar text,
  notes text, prefs jsonb, city text);
CREATE TABLE public.orders (id bigint PRIMARY KEY, customer_email text, amount numeric);
CREATE TABLE public.products (id bigint PRIMARY KEY, title text);
ALTER TABLE public.customers OWNER TO db_client;
ALTER TABLE public.orders OWNER TO db_client;
ALTER TABLE public.products OWNER TO db_client;
GRANT SELECT ON public.products TO db_masked;
GRANT SELECT ON public.customers, public.orders TO bb_masker;

-- fake: a realistic value, the same for the same input, chosen by the hash.
CREATE FUNCTION bb_mask.fake(kind text, h text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT CASE kind
    WHEN 'name' THEN (ARRAY['Anil Mehta','Bina Das','Chetan Iyer','Divya Nair','Eshan Gupta','Farah Khan','Gopal Rao','Hema Pillai'])
                     [1 + ('x' || substr(h, 1, 7))::bit(28)::int % 8]
    ELSE 'x' END $f$;
ALTER FUNCTION bb_mask.fake(text, text) OWNER TO bb_masker;
REVOKE EXECUTE ON FUNCTION bb_mask.fake(text, text) FROM PUBLIC;

-- The shadows: the key, and one mask per column a mask is kept for.
CREATE TABLE bb_mask.public__customers (id bigint PRIMARY KEY, name text, email text, prefs jsonb);
CREATE TABLE bb_mask.public__orders (id bigint PRIMARY KEY, customer_email text);
ALTER TABLE bb_mask.public__customers OWNER TO bb_masker;
ALTER TABLE bb_mask.public__orders OWNER TO bb_masker;
CREATE INDEX ON bb_mask.public__customers (email);
CREATE INDEX ON bb_mask.public__orders (customer_email);

-- The triggers keep them: a row written, its key changed, deleted, or the table truncated.
CREATE FUNCTION bb_mask.keep__public__customers() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog AS $f$
BEGIN
  IF TG_OP = 'TRUNCATE' THEN TRUNCATE bb_mask.public__customers; RETURN NULL; END IF;
  IF TG_OP IN ('DELETE', 'UPDATE') AND (TG_OP = 'DELETE' OR OLD.id IS DISTINCT FROM NEW.id) THEN
    DELETE FROM bb_mask.public__customers WHERE id = OLD.id;
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  INSERT INTO bb_mask.public__customers (id, name, email, prefs) VALUES (NEW.id,
    bb_mask.fake('name', bb_f1.bbid_mask_hmac('default', NEW.name)),
    bb_f1.bbid_mask_hmac('default', NEW.email),
    CASE WHEN NEW.prefs #> '{contact,mobile}' IS NULL THEN NEW.prefs
         ELSE jsonb_set(NEW.prefs, '{contact,mobile}', to_jsonb('XXXXXX' || right(NEW.prefs #>> '{contact,mobile}', 4))) END)
  ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, email = EXCLUDED.email, prefs = EXCLUDED.prefs;
  RETURN NEW;
END $f$;
CREATE FUNCTION bb_mask.keep__public__orders() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog AS $f$
BEGIN
  IF TG_OP = 'TRUNCATE' THEN TRUNCATE bb_mask.public__orders; RETURN NULL; END IF;
  IF TG_OP IN ('DELETE', 'UPDATE') AND (TG_OP = 'DELETE' OR OLD.id IS DISTINCT FROM NEW.id) THEN
    DELETE FROM bb_mask.public__orders WHERE id = OLD.id;
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  INSERT INTO bb_mask.public__orders (id, customer_email) VALUES (NEW.id, bb_f1.bbid_mask_hmac('default', NEW.customer_email))
  ON CONFLICT (id) DO UPDATE SET customer_email = EXCLUDED.customer_email;
  RETURN NEW;
END $f$;
ALTER FUNCTION bb_mask.keep__public__customers() OWNER TO bb_masker;
ALTER FUNCTION bb_mask.keep__public__orders() OWNER TO bb_masker;
CREATE TRIGGER bb_mask AFTER INSERT OR UPDATE OR DELETE ON public.customers FOR EACH ROW EXECUTE FUNCTION bb_mask.keep__public__customers();
CREATE TRIGGER bb_mask_truncate AFTER TRUNCATE ON public.customers FOR EACH STATEMENT EXECUTE FUNCTION bb_mask.keep__public__customers();
CREATE TRIGGER bb_mask AFTER INSERT OR UPDATE OR DELETE ON public.orders FOR EACH ROW EXECUTE FUNCTION bb_mask.keep__public__orders();
CREATE TRIGGER bb_mask_truncate AFTER TRUNCATE ON public.orders FOR EACH STATEMENT EXECUTE FUNCTION bb_mask.keep__public__orders();

-- The views a masked reader reads, with the tables' own names. partial and
-- empty need no secret, so they are computed here.
CREATE VIEW bb_mask.customers AS
  SELECT c.id, m.name, m.email, 'XXXXXX' || right(c.phone, 4) AS phone, 'XXXX XXXX ' || right(c.aadhaar, 4) AS aadhaar,
         NULL::text AS notes, m.prefs, c.city
    FROM public.customers c JOIN bb_mask.public__customers m ON m.id = c.id;
CREATE VIEW bb_mask.orders AS
  SELECT o.id, m.customer_email, o.amount FROM public.orders o JOIN bb_mask.public__orders m ON m.id = o.id;
ALTER VIEW bb_mask.customers OWNER TO bb_masker;
ALTER VIEW bb_mask.orders OWNER TO bb_masker;
GRANT SELECT ON bb_mask.customers, bb_mask.orders TO db_masked;

-- The lookup (section 10): an exact value, hashed here, masked rows back;
-- 30 a minute for each login, and every call recorded without the value.
CREATE TABLE bb_mask.lookups (at timestamptz NOT NULL DEFAULT clock_timestamp(), who text NOT NULL,
  rel text NOT NULL, col text NOT NULL, found int NOT NULL);
ALTER TABLE bb_mask.lookups OWNER TO bb_masker;
CREATE FUNCTION bb_mask.find_customer_by_email(v text) RETURNS SETOF bb_mask.customers LANGUAGE plpgsql
SECURITY DEFINER SET search_path = pg_catalog AS $f$
DECLARE n int;
BEGIN
  IF (SELECT count(*) FROM bb_mask.lookups WHERE who = session_user AND at > clock_timestamp() - interval '1 minute') >= 30 THEN
    RAISE EXCEPTION 'too many lookups: 30 a minute' USING ERRCODE = '53400';
  END IF;
  RETURN QUERY SELECT * FROM bb_mask.customers WHERE email = bb_f1.bbid_mask_hmac('default', v);
  GET DIAGNOSTICS n = ROW_COUNT;
  INSERT INTO bb_mask.lookups (who, rel, col, found) VALUES (session_user, 'public.customers', 'email', n);
END $f$;
ALTER FUNCTION bb_mask.find_customer_by_email(text) OWNER TO bb_masker;
REVOKE EXECUTE ON FUNCTION bb_mask.find_customer_by_email(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION bb_mask.find_customer_by_email(text) TO db_masked;
SQL

on_major() {
  local m="$1" IMG="fox-f5-proto:$1"
  echo
  echo "################ PostgreSQL $m ################"
  start "$C" "$IMG" || { bad "a throwaway server starts with the key mounted ($m)"; return; }
  if ! echo "$SETUP" | sus >"$WORK/setup-$m.log"; then
    bad "the masking schema is made ($m): $(tail -3 "$WORK/setup-$m.log")"; return
  fi
  ok "the shadows, triggers, views, grants and the lookup are made ($m)"

  echo "### the application writes as it always did; the masks keep up"
  as app "INSERT INTO customers VALUES
    (1, '$NAME1', '$EMAIL1', '+91 $PHONE', '$AADHAAR', '$NOTE1', '{\"contact\": {\"mobile\": \"+91 $PHONE\"}, \"theme\": \"dark\"}', 'Pune'),
    (2, 'Ravi Kumar', '$EMAIL2', '+91 9123456789', '847261930525', NULL, '{\"theme\": \"light\"}', 'Delhi');
    INSERT INTO orders VALUES (10, '$EMAIL1', 500), (11, '$EMAIL1', 250), (12, '$EMAIL2', 99);
    INSERT INTO products VALUES (1, 'savings account');" >/dev/null
  assert_eq "every row has its shadow" "$(su "SELECT (SELECT count(*) FROM bb_mask.public__customers) || '|' || (SELECT count(*) FROM bb_mask.public__orders)")" "2|3"

  echo "### a masked reader"
  R="$(sudo docker exec "$C" psql -X -tA -F '|' -U support -d appdb -c "SELECT id, name, email, phone, aadhaar, coalesce(notes,'NULL'), prefs->'contact'->>'mobile', prefs->>'theme', city FROM customers WHERE id = 1" 2>&1)"
  assert_eq "reads the table's own name and gets masks: fake, hash, partial, partial, empty, the JSON path partial, the rest as it is" \
    "$(echo "$R" | awk -F'|' '{printf "%s|%d|%s|%s|%s|%s|%s|%s", ($2 ~ /^[A-Z][a-z]+ [A-Z][a-z]+$/ && $2 != "Asha Rao") ? "fake" : $2, length($3), $4, $5, $6, $7, $8, $9}')" \
    "fake|64|XXXXXX2345|XXXX XXXX 8013|NULL|XXXXXX2345|dark|Pune"
  assert_eq "…the same value always has the same fake and the same hash" \
    "$(as support "SELECT count(DISTINCT name) || '|' || count(DISTINCT email) FROM customers WHERE id = 1")|$(as support "SELECT email FROM customers WHERE id = 1")" \
    "1|1|$(su "SELECT bb_f1.bbid_mask_hmac('default', '$EMAIL1')")"
  assert_eq "…the real table, the shadows and the hash are out of reach" \
    "$(as support "SELECT email FROM public.customers" | grep -c 'permission denied for table customers')|$(as support "SELECT * FROM bb_mask.public__customers" | grep -c 'permission denied')|$(as support "SELECT bb_f1.bbid_mask_hmac('default', 'x')" | grep -c 'permission denied')|$(as support "SELECT bb_mask.fake('name', 'abc')" | grep -c 'permission denied')" \
    "1|1|1|1"
  assert_eq "…and so is the key file" "$(as support "SELECT pg_read_binary_file('/run/bb-mask/default.key')" | grep -c 'permission denied')" "1"
  assert_eq "…an unmarked table it reads as it is" "$(as support "SELECT title FROM products")" "savings account"
  assert_eq "filters, groups and joins work on masks: a customer's orders, by the hash" \
    "$(as support "SELECT count(*) FROM orders o JOIN customers c ON c.email = o.customer_email WHERE c.id = 1")|$(as support "SELECT string_agg(n::text, ',' ORDER BY n) FROM (SELECT count(*) n FROM orders GROUP BY customer_email) g")" \
    "2|1,2"
  assert_eq "…EXPLAIN works, and statistics show nothing of the real table" \
    "$(as support "EXPLAIN (COSTS OFF) SELECT * FROM customers WHERE id = 1" | grep -c 'Index Scan')|$(su "ANALYZE"; as support "SELECT count(*) FROM pg_stats WHERE schemaname = 'public' AND tablename = 'customers'")" "2|0"
  assert_eq "COPY of the real table is refused; COPY of a query copies masks" \
    "$(as support "COPY public.customers TO STDOUT" | grep -c 'permission denied')|$(as support "COPY (SELECT * FROM customers) TO STDOUT" | grep -cE "$VALUES_RE")" "1|0"
  assert_eq "a masked reader cannot write a marked table, through the view or around it" \
    "$(as support "INSERT INTO customers (id) VALUES (9)" | grep -c 'permission denied\|cannot insert')|$(as support "INSERT INTO public.customers (id) VALUES (9)" | grep -c 'permission denied')" "1|1"
  su "CREATE SCHEMA scratch; GRANT USAGE, CREATE ON SCHEMA scratch TO support" >/dev/null
  as support "SET check_function_bodies = off; CREATE FUNCTION scratch.leak() RETURNS SETOF text LANGUAGE sql SECURITY DEFINER AS 'SELECT email FROM public.customers'" >/dev/null 2>&1
  as support "CREATE VIEW scratch.mine AS SELECT email FROM customers" >/dev/null 2>&1
  assert_eq "what a masked reader makes runs as them: a function reading the real table is refused, a view of its own shows masks" \
    "$(as support "SELECT scratch.leak()" | grep -c 'permission denied')|$(as support "SELECT email FROM scratch.mine" | grep -cE "$VALUES_RE")" "1|0"

  echo "### the lookup"
  assert_eq "finds a person by an exact value, and returns the masked row" \
    "$(as support "SELECT id || '|' || length(email) || '|' || phone FROM bb_mask.find_customer_by_email('$EMAIL2')")" "2|64|XXXXXX6789"
  for _ in $(seq 29); do as support "SELECT count(*) FROM bb_mask.find_customer_by_email('nobody@example.in')" >/dev/null; done
  assert_eq "…30 a minute, then refused" "$(as support "SELECT count(*) FROM bb_mask.find_customer_by_email('$EMAIL1')" | grep -c 'too many lookups')" "1"
  assert_eq "…every call recorded, with who and what it found, and never the value" \
    "$(su "SELECT count(*) || '|' || count(*) FILTER (WHERE found = 1) || '|' || min(who) FROM bb_mask.lookups")|$(su "SELECT * FROM bb_mask.lookups" | grep -cE "$VALUES_RE")" \
    "30|1|support|0"

  echo "### writes, deletes, a key changed, and TRUNCATE"
  as app "UPDATE customers SET email = 'asha.new.f5@example.in' WHERE id = 1; UPDATE customers SET id = 3 WHERE id = 2; DELETE FROM orders WHERE id = 12" >/dev/null
  assert_eq "an update is masked again, a key moved moves its shadow, a delete removes it" \
    "$(as support "SELECT email = '$(su "SELECT bb_f1.bbid_mask_hmac('default', 'asha.new.f5@example.in')")' FROM customers WHERE id = 1")|$(su "SELECT string_agg(id::text, ',' ORDER BY id) FROM bb_mask.public__customers")|$(su "SELECT count(*) FROM bb_mask.public__orders")" \
    "t|1,3|2"
  as app "TRUNCATE orders" >/dev/null
  assert_eq "TRUNCATE by the application works, and empties the shadow" \
    "$(su "SELECT count(*) FROM public.orders")|$(su "SELECT count(*) FROM bb_mask.public__orders")" "0|0"

  echo "### the key"
  assert_eq "a key domain apart hashes the same value differently; one domain, the same everywhere" \
    "$(su "SELECT bb_f1.bbid_mask_hmac('default', 'x') = bb_f1.bbid_mask_hmac('tenant2', 'x')")|$(su "SELECT bb_f1.bbid_mask_hmac('default', 'x') = bb_f1.bbid_mask_hmac('default', 'x')")" "f|t"
  assert_eq "a domain with no key, or a name that is not a file name, is refused, saying nothing of a key" \
    "$(su "SELECT bb_f1.bbid_mask_hmac('nokey', 'x')" | grep -c 'cannot be read')|$(su "SELECT bb_f1.bbid_mask_hmac('../etc/passwd', 'x')" | grep -c '1 to 32 of a-z')" "1|1"
  sudo cp "$KEYS/default.key" "$KEYS/loose.key"; sudo chown 999:999 "$KEYS/loose.key"; sudo chmod 444 "$KEYS/loose.key"
  assert_eq "a key file others could read is refused" "$(su "SELECT bb_f1.bbid_mask_hmac('loose', 'x')" | grep -c 'readable by nobody else')" "1"
  sudo rm -f "$KEYS/loose.key"
  assert_eq "the key is in no log and no error" \
    "$(sudo docker logs "$C" 2>&1 | grep -c "$KEYHEX")|$(sudo docker logs "$C" 2>&1 | grep -cE "$VALUES_RE")" "0|0"

  echo "### rotation: a new key, the masks written again, a session that read the old one sees the new"
  # One session hashes, sleeps while the key file is replaced, and hashes again.
  sudo docker exec "$C" psql -X -q -tA -U dbadmin -d appdb -c "SELECT bb_f1.bbid_mask_hmac('default', 'x')" \
    -c "SELECT pg_sleep(3)" -c "SELECT bb_f1.bbid_mask_hmac('default', 'x')" >"$WORK/rotate-$m.out" 2>&1 &
  SESSION=$!
  sleep 1
  sudo sh -c "head -c 32 /dev/urandom > '$KEYS/default.key.new'; chown 999:999 '$KEYS/default.key.new'; chmod 400 '$KEYS/default.key.new'; mv '$KEYS/default.key.new' '$KEYS/default.key'"
  wait "$SESSION"
  assert_eq "a session that read the old key reads the new one once the file is replaced" \
    "$(grep -E '^[0-9a-f]{64}$' "$WORK/rotate-$m.out" | sort -u | wc -l | tr -d ' ')" "2"
  as app "UPDATE customers SET email = email" >/dev/null
  assert_eq "…and the masks written again are under the new key" \
    "$(as support "SELECT email = '$(su "SELECT bb_f1.bbid_mask_hmac('default', 'asha.new.f5@example.in')")' FROM customers WHERE id = 1")" "t"
  KEYHEX="$(sudo xxd -p -c 64 "$KEYS/default.key")"
  gone "$C"
}

on_major 18
on_major 16

echo
echo "################ measured, PostgreSQL 18 ################"
start "$C" fox-f5-proto:18 || bad "the server for measuring starts"
echo "$SETUP" | sus >/dev/null
# A twin of customers with no masks, to measure against.
su "CREATE TABLE public.plain (LIKE public.customers INCLUDING ALL); ALTER TABLE public.plain OWNER TO db_client" >/dev/null
fill() { su "INSERT INTO public.$1 SELECT g, 'Person ' || g, 'p' || g || '@example.in', '+91 9' || lpad(g::text, 9, '0'), lpad(g::text, 12, '7'),
  NULL, jsonb_build_object('contact', jsonb_build_object('mobile', '+91 9' || lpad(g::text, 9, '0'))), 'City' FROM generate_series(1, $2) g" >/dev/null; }
ms() { sudo docker exec "$C" psql -X -q -tA -U dbadmin -d appdb -c '\timing on' -c "$1" 2>&1 | sed -n 's/^Time: \([0-9.]*\) ms.*/\1/p' | tail -1; }
median() { sort -n | awk '{a[NR]=$1} END {print a[int((NR+1)/2)]}'; }
fill plain 10000; fill customers 10000
UPD_PLAIN="$(for _ in 1 2 3; do ms "UPDATE public.plain SET city = city || ''"; done | median)"
UPD_MASK="$(for _ in 1 2 3; do ms "UPDATE public.customers SET city = city || ''"; done | median)"
note "one 10,000-row UPDATE: $UPD_PLAIN ms without masks, $UPD_MASK ms with (three rounds, median)"
# Single-row writes from 16 clients, as an application makes them.
echo '\set id random(1, 10000)
UPDATE public.customers SET city = city WHERE id = :id;' | sudo docker exec -i "$C" sh -c 'cat > /tmp/mask.sql'
echo '\set id random(1, 10000)
UPDATE public.plain SET city = city WHERE id = :id;' | sudo docker exec -i "$C" sh -c 'cat > /tmp/plain.sql'
echo '\set id random(1, 10000)
SELECT * FROM bb_mask.customers WHERE id = :id;' | sudo docker exec -i "$C" sh -c 'cat > /tmp/read_mask.sql'
echo '\set id random(1, 10000)
SELECT * FROM public.customers WHERE id = :id;' | sudo docker exec -i "$C" sh -c 'cat > /tmp/read_plain.sql'
tps() { sudo docker exec "$C" pgbench -n -U dbadmin -c 16 -j 4 -T 15 -M prepared -f "$1" appdb 2>/dev/null | sed -n 's/^tps = \([0-9.]*\).*/\1/p' | cut -d. -f1; }
W_PLAIN="$(for _ in 1 2 3; do tps /tmp/plain.sql; done | median)"
W_MASK="$(for _ in 1 2 3; do tps /tmp/mask.sql; done | median)"
R_PLAIN="$(for _ in 1 2 3; do tps /tmp/read_plain.sql; done | median)"
R_MASK="$(for _ in 1 2 3; do tps /tmp/read_mask.sql; done | median)"
note "single-row writes, 16 clients: $W_PLAIN tps without masks, $W_MASK with ($(( (W_PLAIN - W_MASK) * 100 / (W_PLAIN > 0 ? W_PLAIN : 1) ))% fewer)"
note "indexed reads, 16 clients: $R_PLAIN tps from the table, $R_MASK through the view ($(( (R_PLAIN - R_MASK) * 100 / (R_PLAIN > 0 ? R_PLAIN : 1) ))% fewer)"
SCAN_PLAIN="$(for _ in 1 2 3; do ms "SELECT count(*), max(email) FROM public.customers"; done | median)"
SCAN_MASK="$(for _ in 1 2 3; do ms "SELECT count(*), max(email) FROM bb_mask.customers"; done | median)"
note "a full scan of 10,000 rows: $SCAN_PLAIN ms from the table, $SCAN_MASK ms through the view"
assert_eq "both measured" "$([ -n "$W_PLAIN" ] && [ -n "$W_MASK" ] && [ -n "$R_MASK" ] && echo yes)" "yes"

echo "### the other way to keep the masks: one trigger a statement, from its transition tables"
su "CREATE TABLE public.stmt (LIKE public.customers INCLUDING ALL); ALTER TABLE public.stmt OWNER TO db_client;
CREATE TABLE bb_mask.public__stmt (id bigint PRIMARY KEY, name text, email text, prefs jsonb); ALTER TABLE bb_mask.public__stmt OWNER TO bb_masker;
GRANT SELECT ON public.stmt TO bb_masker;
CREATE FUNCTION bb_mask.keep__public__stmt() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS \$f\$
BEGIN
  INSERT INTO bb_mask.public__stmt (id, name, email, prefs)
    SELECT n.id, bb_mask.fake('name', bb_f1.bbid_mask_hmac('default', n.name)), bb_f1.bbid_mask_hmac('default', n.email), n.prefs FROM n
  ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, email = EXCLUDED.email, prefs = EXCLUDED.prefs;
  RETURN NULL;
END \$f\$;
ALTER FUNCTION bb_mask.keep__public__stmt() OWNER TO bb_masker;
CREATE TRIGGER bb_mask_i AFTER INSERT ON public.stmt REFERENCING NEW TABLE AS n FOR EACH STATEMENT EXECUTE FUNCTION bb_mask.keep__public__stmt();
CREATE TRIGGER bb_mask_u AFTER UPDATE ON public.stmt REFERENCING NEW TABLE AS n FOR EACH STATEMENT EXECUTE FUNCTION bb_mask.keep__public__stmt()" >/dev/null
fill stmt 10000
UPD_STMT="$(for _ in 1 2 3; do ms "UPDATE public.stmt SET city = city || ''"; done | median)"
echo '\set id random(1, 10000)
UPDATE public.stmt SET city = city WHERE id = :id;' | sudo docker exec -i "$C" sh -c 'cat > /tmp/stmt.sql'
W_STMT="$(for _ in 1 2 3; do tps /tmp/stmt.sql; done | median)"
note "with one trigger a statement: the 10,000-row UPDATE $UPD_STMT ms (a row each: $UPD_MASK ms, none: $UPD_PLAIN ms); single-row writes $W_STMT tps ($(( (W_PLAIN - W_STMT) * 100 / (W_PLAIN > 0 ? W_PLAIN : 1) ))% fewer than none)"
assert_eq "…its masks are the same" \
  "$(su "SELECT count(*) FROM public.stmt s JOIN bb_mask.public__stmt m USING (id) WHERE m.email <> bb_f1.bbid_mask_hmac('default', s.email)")" "0"

echo "### filling the masks of a table that already has rows, in batches, while it is written"
su "ALTER TABLE public.customers DISABLE TRIGGER bb_mask; TRUNCATE bb_mask.public__customers; TRUNCATE public.customers" >/dev/null
fill customers 1000000
su "ALTER TABLE public.customers ENABLE TRIGGER bb_mask" >/dev/null
# A writer meanwhile, with a 1-second lock timeout: a fill that locked the
# table would make it fail.
sudo docker exec "$C" sh -c 'for i in $(seq 200); do psql -X -q -U dbadmin -d appdb -c "SET lock_timeout = '"'"'1s'"'"'; UPDATE public.customers SET city = city WHERE id = 5" 2>&1 | grep -c "lock timeout"; sleep 0.05; done' > "$WORK/writer.log" &
WRITER=$!
T0=$(date +%s%N)
sus >/dev/null <<'SQL'
DO $$
DECLARE lo bigint := 0; hi bigint;
BEGIN
  SELECT max(id) INTO hi FROM public.customers;
  WHILE lo < hi LOOP
    INSERT INTO bb_mask.public__customers (id, name, email, prefs)
      SELECT id, bb_mask.fake('name', bb_f1.bbid_mask_hmac('default', name)), bb_f1.bbid_mask_hmac('default', email), prefs
        FROM public.customers WHERE id > lo AND id <= lo + 10000
      ON CONFLICT (id) DO NOTHING;
    lo := lo + 10000;
    COMMIT;
  END LOOP;
END $$;
SQL
FILL_S=$(( ($(date +%s%N) - T0) / 1000000000 ))
wait "$WRITER"
note "filling 1,000,000 rows' masks in batches of 10,000: ${FILL_S}s"
assert_eq "…every row is masked, and the writer meanwhile was never held up by a lock" \
  "$(su "SELECT count(*) FROM bb_mask.public__customers")|$(awk '{s+=$1} END {print s+0}' "$WORK/writer.log")" "1000000|0"

echo "### rotation of 1,000,000 masks"
sudo sh -c "head -c 32 /dev/urandom > '$KEYS/default.key.new'; chown 999:999 '$KEYS/default.key.new'; chmod 400 '$KEYS/default.key.new'; mv '$KEYS/default.key.new' '$KEYS/default.key'"
T0=$(date +%s%N)
sus >/dev/null <<'SQL'
DO $$
DECLARE lo bigint := 0; hi bigint;
BEGIN
  SELECT max(id) INTO hi FROM public.customers;
  WHILE lo < hi LOOP
    UPDATE bb_mask.public__customers m SET email = bb_f1.bbid_mask_hmac('default', c.email)
      FROM public.customers c WHERE c.id = m.id AND m.id > lo AND m.id <= lo + 10000;
    lo := lo + 10000;
    COMMIT;
  END LOOP;
END $$;
SQL
ROT_S=$(( ($(date +%s%N) - T0) / 1000000000 ))
note "rotating 1,000,000 hashed masks in batches of 10,000: ${ROT_S}s"
assert_eq "…every mask is under the new key" \
  "$(su "SELECT count(*) FROM bb_mask.public__customers m JOIN public.customers c USING (id) WHERE m.email <> bb_f1.bbid_mask_hmac('default', c.email)")" "0"

echo "### a JSON path in large documents"
su "CREATE TABLE public.docs (id bigint PRIMARY KEY, body jsonb); CREATE TABLE public.docs_plain (LIKE public.docs INCLUDING ALL)" >/dev/null
# Random hex, so the documents do not compress to almost nothing.
su "INSERT INTO public.docs SELECT g, jsonb_build_object('contact', jsonb_build_object('mobile', '+91 9845012345'),
      'blob', (SELECT string_agg(md5(random()::text || g || i), '') FROM generate_series(1, 8000) i)) FROM generate_series(1, 100) g" >/dev/null
su "INSERT INTO public.docs_plain SELECT * FROM public.docs" >/dev/null
su "CREATE TABLE bb_mask.public__docs (id bigint PRIMARY KEY, body jsonb); ALTER TABLE bb_mask.public__docs OWNER TO bb_masker;
CREATE FUNCTION bb_mask.keep__public__docs() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS \$f\$
BEGIN INSERT INTO bb_mask.public__docs VALUES (NEW.id, jsonb_set(NEW.body, '{contact,mobile}', to_jsonb('XXXXXX' || right(NEW.body #>> '{contact,mobile}', 4))))
  ON CONFLICT (id) DO UPDATE SET body = EXCLUDED.body; RETURN NEW; END \$f\$;
ALTER FUNCTION bb_mask.keep__public__docs() OWNER TO bb_masker;
GRANT SELECT ON public.docs TO bb_masker;
CREATE TRIGGER bb_mask AFTER INSERT OR UPDATE ON public.docs FOR EACH ROW EXECUTE FUNCTION bb_mask.keep__public__docs()" >/dev/null
DOC_PLAIN="$(for _ in 1 2 3; do ms "UPDATE public.docs_plain SET body = body"; done | median)"
DOC_MASK="$(for _ in 1 2 3; do ms "UPDATE public.docs SET body = body"; done | median)"
note "updating 100 documents of $(su "SELECT pg_size_pretty(avg(pg_column_size(body))::bigint) FROM public.docs"): $DOC_PLAIN ms without masks, $DOC_MASK ms with"
assert_eq "…the masked copy has the path masked and the rest whole" \
  "$(su "SELECT body #>> '{contact,mobile}' || '|' || (length(body->>'blob') = 256000) FROM bb_mask.public__docs WHERE id = 1")" "XXXXXX2345|true"
gone "$C"

echo
echo "################ a masked branch on a ZFS clone, PostgreSQL 18 ################"
# A pool of its own, from a file, so the shared stack's is never touched.
sudo truncate -s 2G "$WORK/pool.img"
if ! sudo zpool create -f -o ashift=12 -m "$WORK/pool" "$POOL" "$WORK/pool.img" 2>"$WORK/zpool.log"; then
  bad "a pool of the suite's own: $(cat "$WORK/zpool.log")"
else
  sudo zfs create "$POOL/src"
  sudo chown 999:999 "$WORK/pool/src"
  start fox-f5-proto-src fox-f5-proto:18 -v "$WORK/pool/src:/var/lib/postgresql/data" -e PGDATA=/var/lib/postgresql/data/pg \
    || bad "the source server starts on the pool"
  C=fox-f5-proto-src
  su "CREATE TABLE public.customers (id bigint PRIMARY KEY, name text, email text, phone text, aadhaar text, notes text)" >/dev/null
  su "INSERT INTO public.customers SELECT g, '$NAME1', CASE WHEN g = 1 THEN '$EMAIL1' ELSE 'other' || g || '@example.org' END,
        '+91 $PHONE', '$AADHAAR', '$NOTE1' FROM generate_series(1, 20000) g; CHECKPOINT; ANALYZE" >/dev/null
  sudo docker stop -t 30 fox-f5-proto-src >/dev/null
  sudo zfs snapshot "$POOL/src@for-branch"
  sudo zfs clone "$POOL/src@for-branch" "$POOL/branch"
  start fox-f5-proto-branch fox-f5-proto:18 -v "$WORK/pool/branch:/var/lib/postgresql/data" -e PGDATA=/var/lib/postgresql/data/pg \
    || bad "the branch's server starts on the clone"
  C=fox-f5-proto-branch
  su "CREATE SCHEMA bb_f1; CREATE EXTENSION bb_identity WITH SCHEMA bb_f1" >/dev/null
  # Where real values are left, as bytes in the branch's own files.
  left() { sudo grep -rlaE "$AADHAAR|$EMAIL1|$PHONE|loan on Tuesday" "$WORK/pool/branch/pg/$1" 2>/dev/null | wc -l | tr -d ' '; }
  BEFORE_BASE="$(left base)"
  su "UPDATE public.customers SET name = 'Masked ' || id, email = bb_f1.bbid_mask_hmac('default', email),
        phone = 'XXXXXX' || right(phone, 4), aadhaar = 'XXXX XXXX ' || right(aadhaar, 4), notes = NULL" >/dev/null
  AFTER_UPDATE="$(left base)"
  su "VACUUM FULL public.customers" >/dev/null
  AFTER_VACUUM="$(left base)"
  su "ANALYZE; CHECKPOINT" >/dev/null
  AFTER_ANALYZE="$(left base)"
  # ANALYZE writes new statistics; the old rows, with the real most-common
  # values, stay in pg_statistic's file until it is rewritten too.
  su "VACUUM FULL pg_statistic" >/dev/null
  su "CHECKPOINT" >/dev/null
  AFTER_ANALYZE_BASE="$(left base)"
  AFTER_MASK_WAL="$(left pg_wal)"
  # The WAL from before: the parent's segments the clone came with, and the
  # full-page images of pages as they were before masking. With recycling off,
  # each checkpoint after a switch deletes the segments it no longer needs,
  # rather than renaming them for reuse with their old bytes in.
  su "ALTER SYSTEM SET wal_recycle = off" >/dev/null; su "SELECT pg_reload_conf()" >/dev/null
  for _ in 1 2 3; do su "SELECT pg_switch_wal()" >/dev/null; su "CHECKPOINT" >/dev/null; done
  su "ALTER SYSTEM RESET wal_recycle" >/dev/null; su "SELECT pg_reload_conf()" >/dev/null
  AFTER_ANALYZE_WAL="$(left pg_wal)"
  note "files in pg_wal/ holding a real value: $AFTER_MASK_WAL after masking, $AFTER_ANALYZE_WAL after recycling off, three switches and checkpoints"
  note "files in base/ holding a real value: $BEFORE_BASE before masking, $AFTER_UPDATE after the UPDATE, $AFTER_VACUUM after VACUUM FULL, $AFTER_ANALYZE after ANALYZE, $AFTER_ANALYZE_BASE after VACUUM FULL of pg_statistic"
  assert_eq "masked in place, then VACUUM FULL, ANALYZE and pg_statistic rewritten: no table or statistics file holds a real value" "$AFTER_ANALYZE_BASE" "0"
  assert_eq "…and, the old WAL removed, no WAL file holds one either" "$AFTER_ANALYZE_WAL" "0"
  assert_eq "…the statistics are of masks" \
    "$(su "SELECT count(*) FROM pg_stats WHERE tablename = 'customers' AND most_common_vals::text ~ '$AADHAAR|$PHONE|loan'")" "0"
  {
    # The other way, measured beside it: a fresh cluster, given only the masked rows. Nothing of
    # the parent's files comes with it.
    sudo zfs create "$POOL/fresh"; sudo chown 999:999 "$WORK/pool/fresh"
    start fox-f5-proto-fresh fox-f5-proto:18 -v "$WORK/pool/fresh:/var/lib/postgresql/data" -e PGDATA=/var/lib/postgresql/data/pg \
      || bad "a fresh server starts"
    T0=$(date +%s%N)
    sudo docker exec fox-f5-proto-branch pg_dump -U dbadmin -d appdb -t public.customers | sudo docker exec -i fox-f5-proto-fresh psql -X -q -U dbadmin -d appdb >/dev/null 2>&1
    sudo docker exec fox-f5-proto-fresh psql -X -q -U dbadmin -d appdb -c "ANALYZE; CHECKPOINT" >/dev/null 2>&1
    FRESH_S=$(( ($(date +%s%N) - T0) / 1000000 ))
    fresh_left() { sudo grep -rlaE "$AADHAAR|$EMAIL1|$PHONE|loan on Tuesday" "$WORK/pool/fresh/pg/$1" 2>/dev/null | wc -l | tr -d ' '; }
    note "a fresh cluster given only the masked rows (20,000): ${FRESH_S} ms"
    assert_eq "…holds no real value anywhere, in its tables or its WAL" "$(fresh_left base)|$(fresh_left pg_wal)" "0|0"
    assert_eq "…and every row arrived" "$(sudo docker exec fox-f5-proto-fresh psql -X -tA -U dbadmin -d appdb -c 'SELECT count(*) FROM public.customers')" "20000"
  }
fi

echo
echo "==== $PASS passed, $FAIL failed ===="
[ "$FAIL" = 0 ]
