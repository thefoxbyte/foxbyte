-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- F1 prototype: an application actor per transaction, asserted with a signed
-- token (docs/FOX_F1_Identity_Design.md, sections 3 to 5).
--
-- Gate 0 only. Installed by scripts/integration_f1.sh into a throwaway
-- container built WITH_F1=on, never by the engine, so nothing here reaches an
-- install. Gate 1 moves what survives the tests into internal/ledger.
--
-- Needs the Blackbox (internal/ledger/ledger.sql) installed first: the one
-- recording path wired here is its DDL record.

-- ── The private half ────────────────────────────────────────────────────────
-- ledger.sql grants db_client EXECUTE on every function in schema bb, on every
-- start. The MAC and the secret must never be callable by a client (a client
-- that could compute a MAC could forge an actor), so they live in a schema no
-- one but its owner can use.
CREATE SCHEMA IF NOT EXISTS bb_f1;
REVOKE ALL ON SCHEMA bb_f1 FROM PUBLIC;

-- Ed25519: the fox_ed25519 extension (docker/postgres/fox_ed25519), new, so it
-- can live in the private schema.
CREATE EXTENSION IF NOT EXISTS fox_ed25519 WITH SCHEMA bb_f1;

-- HMAC: pgcrypto, which a database can have only once and may already have
-- somewhere else (public, usually). Called by its qualified name, found here,
-- so nothing on a search path a client can write to is ever resolved.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
DO $do$
DECLARE s text;
BEGIN
  SELECT n.nspname INTO s FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace
  WHERE e.extname = 'pgcrypto';
  EXECUTE format($f$CREATE OR REPLACE FUNCTION bb_f1.hmac256(data bytea, key bytea) RETURNS bytea
    LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog AS 'SELECT %I.hmac(data, key, ''sha256'')'$f$, s);
  EXECUTE format($f$CREATE OR REPLACE FUNCTION bb_f1.random_bytes(n int) RETURNS bytea
    LANGUAGE sql VOLATILE STRICT SET search_path = pg_catalog AS 'SELECT %I.gen_random_bytes(n)'$f$, s);
END $do$;

-- The install secret the MACs are made with. Readable by its owner only.
CREATE TABLE IF NOT EXISTS bb_f1.secret (
  id  int   PRIMARY KEY CHECK (id = 1),
  key bytea NOT NULL CHECK (length(key) = 32)
);
INSERT INTO bb_f1.secret VALUES (1, bb_f1.random_bytes(32)) ON CONFLICT DO NOTHING;

-- What a token's aud and branch claims are checked against. The engine fills
-- this in Gate 1; the test fills it here.
CREATE TABLE IF NOT EXISTS bb_f1.install (
  id         int  PRIMARY KEY CHECK (id = 1),
  install_id text NOT NULL,
  branch     text NOT NULL
);

-- ── Registered applications ────────────────────────────────────────────────
-- One row per key: an application with two keys during a rotation has two.
CREATE TABLE IF NOT EXISTS bb.app_issuers (
  issuer            text        NOT NULL,
  kid               text        NOT NULL,
  db_role           text        NOT NULL,  -- the only session_user its tokens are accepted from
  public_key        bytea       NOT NULL CHECK (length(public_key) = 32),
  max_life          interval    NOT NULL DEFAULT '5 minutes' CHECK (max_life <= '60 minutes'),
  on_invalid        text        NOT NULL DEFAULT 'none' CHECK (on_invalid IN ('none', 'refuse')),
  revoked_at        timestamptz,
  compromised_since timestamptz,
  PRIMARY KEY (issuer, kid)
);
REVOKE ALL ON bb.app_issuers FROM PUBLIC;

-- ── Helpers ─────────────────────────────────────────────────────────────────
-- base64url to bytes; NULL for anything that is not base64url.
CREATE OR REPLACE FUNCTION bb_f1.b64url(s text) RETURNS bytea
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog AS $$
DECLARE t text;
BEGIN
  IF s !~ '^[A-Za-z0-9_-]*$' THEN
    RETURN NULL;
  END IF;
  t := translate(s, '-_', '+/');
  t := t || repeat('=', (4 - length(t) % 4) % 4);
  RETURN decode(t, 'base64');
EXCEPTION WHEN others THEN
  RETURN NULL;
END $$;

-- The MAC over an application actor and the transaction it was asserted in:
-- fox_txn_id() (the server's start, the backend, the virtual transaction id).
-- Each field is length-prefixed, so no choice of a user's name can make two
-- different assertions read the same.
--
-- Written out with pgcrypto's qualified name and no SET clause, so it costs
-- one HMAC and little else: it is checked once for every row a tracked table
-- records. The first version, through a wrapper and pg_locks, cost 51 µs a
-- call; most of that was reading the transaction's identity from pg_locks.
DO $do$
DECLARE s text;
BEGIN
  SELECT n.nspname INTO s FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace
  WHERE e.extname = 'pgcrypto';
  EXECUTE format($f$CREATE OR REPLACE FUNCTION bb_f1.mac(actor text, issuer text, kid text, tenant text) RETURNS text
    LANGUAGE sql VOLATILE AS $b$
      SELECT encode(%I.hmac(
        convert_to(length(t) || ':' || t || length(issuer) || ':' || issuer || length(kid) || ':' || kid
                   || length(tenant) || ':' || tenant || length(actor) || ':' || actor, 'UTF8'),
        (SELECT key FROM bb_f1.secret WHERE id = 1), 'sha256'), 'hex')
      FROM (SELECT bb_f1.fox_txn_id() AS t) x
    $b$$f$, s);
END $do$;

-- ── The two public functions ────────────────────────────────────────────────

-- bb.app_actor(): the application actor of this transaction, and its state.
-- What every recording function calls. The values are ordinary settings, which
-- a session can overwrite, so they are not trusted as values: the MAC is
-- recomputed on every call, and a value that does not match it is 'none'.
CREATE OR REPLACE FUNCTION bb.app_actor(
  OUT actor text, OUT state text, OUT issuer text, OUT kid text, OUT tenant text, OUT note text
) LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  a text := nullif(current_setting('fox.app.actor', true), '');
  i text := nullif(current_setting('fox.app.issuer', true), '');
  k text := nullif(current_setting('fox.app.kid', true), '');
  t text := coalesce(current_setting('fox.app.tenant', true), '');
  m text := nullif(current_setting('fox.app.mac', true), '');
  f text := nullif(current_setting('fox.app.failure', true), '');
  c text := nullif(current_setting('fox.claimed_actor', true), '');
BEGIN
  IF a IS NOT NULL OR m IS NOT NULL THEN
    IF a IS NOT NULL AND i IS NOT NULL AND k IS NOT NULL AND m IS NOT NULL
       AND m = bb_f1.mac(a, i, k, t) THEN
      actor := a; state := 'asserted'; issuer := i; kid := k; tenant := nullif(t, '');
      RETURN;
    END IF;
    state := 'none';
    note := 'an application actor was present and failed its check';
    RETURN;
  END IF;
  IF c IS NOT NULL THEN
    actor := c; state := 'claimed';
    note := CASE WHEN f IS NOT NULL THEN 'token refused: ' || f END;
    RETURN;
  END IF;
  state := 'none';
  note := CASE WHEN f IS NOT NULL THEN 'token refused: ' || f END;
END $$;

-- bb.act_for(token): assert this transaction's application actor. The token is
-- passed as a bind parameter, never in the SQL text. Returns the user it now
-- acts for, or NULL when the token was not accepted (the reason is kept for
-- the record); raises when the application registered on_invalid = 'refuse',
-- and always for a second assertion in one transaction.
CREATE OR REPLACE FUNCTION bb.act_for(token text) RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE
  parts  text[];
  hdr    jsonb;
  body   jsonb;
  sig    bytea;
  k      bb.app_issuers;
  inst   bb_f1.install;
  sub    text;
  tenant text;
  iat    numeric;
  exp    numeric;
  nowe   numeric;
  reason text;
  refuse boolean := false;
BEGIN
  IF (SELECT state FROM bb.app_actor()) = 'asserted' THEN
    RAISE EXCEPTION 'this transaction already acts for %; a transaction has one application actor',
      current_setting('fox.app.actor', true) USING ERRCODE = 'invalid_authorization_specification';
  END IF;

  IF token IS NULL OR length(token) > 8192 THEN
    reason := 'malformed';
  ELSE
    parts := string_to_array(token, '.');
    IF array_length(parts, 1) IS DISTINCT FROM 3 THEN
      reason := 'malformed';
    END IF;
  END IF;
  IF reason IS NULL THEN
    BEGIN
      hdr  := convert_from(bb_f1.b64url(parts[1]), 'UTF8')::jsonb;
      body := convert_from(bb_f1.b64url(parts[2]), 'UTF8')::jsonb;
      sig  := bb_f1.b64url(parts[3]);
    EXCEPTION WHEN others THEN
      reason := 'malformed';
    END;
    IF reason IS NULL AND (hdr IS NULL OR body IS NULL OR sig IS NULL
        OR jsonb_typeof(hdr) <> 'object' OR jsonb_typeof(body) <> 'object') THEN
      reason := 'malformed';
    END IF;
  END IF;

  -- The fixed header: Ed25519 and nothing else, a key id, no other fields.
  -- Refused before the payload is trusted for anything.
  IF reason IS NULL AND (
       hdr->>'alg' IS DISTINCT FROM 'EdDSA'
       OR (hdr ? 'typ' AND hdr->>'typ' IS DISTINCT FROM 'JWT')
       OR NOT hdr ? 'kid'
       OR EXISTS (SELECT 1 FROM jsonb_object_keys(hdr) AS x WHERE x NOT IN ('alg', 'typ', 'kid'))) THEN
    reason := 'header';
  END IF;

  IF reason IS NULL THEN
    SELECT * INTO k FROM bb.app_issuers WHERE issuer = body->>'iss' AND kid = hdr->>'kid';
    IF NOT FOUND THEN
      reason := 'unknown key';
    ELSE
      refuse := k.on_invalid = 'refuse';
    END IF;
  END IF;
  IF reason IS NULL AND NOT bb_f1.fox_ed25519_verify(k.public_key, convert_to(parts[1] || '.' || parts[2], 'UTF8'), sig) THEN
    reason := 'bad signature';
  END IF;
  IF reason IS NULL AND k.revoked_at IS NOT NULL AND k.revoked_at <= clock_timestamp() THEN
    reason := 'revoked key';
  END IF;
  -- Binding: only the application's own database role may assert with its key.
  IF reason IS NULL AND session_user <> k.db_role THEN
    reason := 'wrong session role';
  END IF;

  IF reason IS NULL THEN
    SELECT * INTO inst FROM bb_f1.install WHERE id = 1;
    sub := body->>'sub';
    tenant := coalesce(body->>'tenant', '');
    BEGIN
      iat := (body->>'iat')::numeric;
      exp := (body->>'exp')::numeric;
    EXCEPTION WHEN others THEN
      reason := 'malformed';
    END;
    nowe := extract(epoch FROM clock_timestamp());
    IF reason IS NOT NULL THEN
      NULL;
    ELSIF sub IS NULL OR sub = '' OR length(sub) > 256 THEN
      reason := 'malformed';
    ELSIF body->>'aud' IS DISTINCT FROM inst.install_id THEN
      reason := 'wrong audience';
    ELSIF body ? 'branch' AND body->>'branch' IS DISTINCT FROM inst.branch THEN
      reason := 'wrong branch';
    ELSIF iat IS NULL OR exp IS NULL OR exp < iat THEN
      reason := 'malformed';
    ELSIF iat > nowe + 30 THEN
      reason := 'not yet valid';
    ELSIF exp < nowe - 30 THEN
      reason := 'expired';
    ELSIF exp - iat > extract(epoch FROM k.max_life) THEN
      reason := 'life too long';
    END IF;
  END IF;

  IF reason IS NOT NULL THEN
    PERFORM set_config('fox.app.failure', reason, true);
    IF refuse THEN
      RAISE EXCEPTION 'application identity refused: %', reason
        USING ERRCODE = 'invalid_authorization_specification';
    END IF;
    RETURN NULL;
  END IF;

  PERFORM set_config('fox.app.actor', sub, true),
          set_config('fox.app.issuer', k.issuer, true),
          set_config('fox.app.kid', k.kid, true),
          set_config('fox.app.tenant', tenant, true),
          set_config('fox.app.failure', '', true);
  PERFORM set_config('fox.app.mac', bb_f1.mac(sub, k.issuer, k.kid, tenant), true);
  RETURN sub;
END $fn$;

-- ── The one recording path wired in Gate 0: the Blackbox's DDL record ───────
-- Gate 1 decides where these fields live for good (bb.ledger_ext rows carry
-- their own hash). Here they sit beside the record, keyed by its row, so the
-- record and its chain are untouched.
CREATE TABLE IF NOT EXISTS bb.f1_attribution (
  ledger_id  bigint PRIMARY KEY,
  app_actor  text,
  app_state  text NOT NULL,
  app_issuer text,
  app_kid    text,
  app_tenant text,
  note       text
);
REVOKE ALL ON bb.f1_attribution FROM PUBLIC;

-- Fires after the Blackbox's own ddl_command_end trigger (event triggers fire in
-- name order: bb_log_end, then bb_zz_f1_record), and attributes the rows it has
-- just written: the rows not yet attributed. Those are exactly this
-- transaction's own. Another transaction's rows are invisible until it commits,
-- and when it commits, its attributions (written by this same trigger in its
-- own transaction) commit with them.
--
-- Not by xmin: a row written inside a savepoint carries the savepoint's own
-- transaction id, not the top-level one (the first version matched on that, and
-- left every row written in a savepoint unattributed). And not by bb.session,
-- which a client can set to another session's name.
CREATE OR REPLACE FUNCTION bb_f1.record_ddl() RETURNS event_trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r record;
BEGIN
  SELECT * INTO r FROM bb.app_actor();
  INSERT INTO bb.f1_attribution (ledger_id, app_actor, app_state, app_issuer, app_kid, app_tenant, note)
  SELECT l.id, r.actor, r.state, r.issuer, r.kid, r.tenant, r.note
  FROM bb.schema_ledger l
  WHERE l.at >= now()
    AND NOT EXISTS (SELECT 1 FROM bb.f1_attribution a WHERE a.ledger_id = l.id)
  ON CONFLICT (ledger_id) DO NOTHING;
END $$;
DROP EVENT TRIGGER IF EXISTS bb_zz_f1_record;
CREATE EVENT TRIGGER bb_zz_f1_record ON ddl_command_end EXECUTE FUNCTION bb_f1.record_ddl();

-- What a report shows: the state as recorded, and, for a key since reported
-- compromised, never plain 'asserted' for what was asserted after that.
CREATE OR REPLACE VIEW bb.f1_report AS
SELECT l.id, l.at, l.command_tag, l.object_identity, l.actor AS db_actor,
       a.app_actor,
       CASE WHEN a.app_state = 'asserted' AND i.compromised_since IS NOT NULL AND l.at >= i.compromised_since
            THEN 'asserted by ' || a.app_issuer || ' (key reported compromised)'
            WHEN a.app_state = 'asserted' THEN 'asserted by ' || a.app_issuer
            ELSE a.app_state END AS app_state,
       a.app_kid, a.app_tenant, a.note
FROM bb.schema_ledger l
JOIN bb.f1_attribution a ON a.ledger_id = l.id
LEFT JOIN bb.app_issuers i ON i.issuer = a.app_issuer AND i.kid = a.app_kid;
REVOKE ALL ON bb.f1_report FROM PUBLIC;
