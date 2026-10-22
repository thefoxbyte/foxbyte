-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Application identity (F1): an application actor per transaction, asserted
-- with a signed token (docs/FOX_F1_Identity_Design.md, sections 3 to 5).
--
-- An application registered with the engine (`fox app register`) passes a
-- short-lived Ed25519 token naming its user, as a bind parameter:
--
--   SELECT bb.act_for($1);
--
-- and every change that transaction makes is recorded as made by the login
-- (session_user, as always) and for that user, "asserted by <application>".
-- The Blackbox's own capture trigger (ledger_ext.sql) asks bb.app_actor() for
-- each row it records.
--
-- Installed after ledger.sql and ledger_ext.sql (whose capture columns the
-- report below reads), on every start and on every branch the engine readies (internal/branch/identity.go), which also
-- fills bb_f1.install and bb.app_issuers from the account store. Idempotent.
--
-- The checking needs the bb_identity extension, which is in every engine image
-- from revision 2. A branch whose container was made from an older image has
-- no extension to load, and gets the same functions with nothing to check
-- with: bb.act_for refuses, saying how to get it, and bb.app_actor answers
-- claimed or none. The next run of this file on that branch, once its
-- container is made from the newer image, puts the checking ones in place.
--
-- Run with session_replication_role = replica, so the Blackbox's own event
-- triggers do not record this plumbing as somebody's schema change.

SET session_replication_role = replica;

-- ── The private half ────────────────────────────────────────────────────────
-- ledger.sql grants db_client EXECUTE on every function in schema bb, on every
-- start. The MAC and the secret must never be callable by a client (a client
-- that could compute a MAC could forge an actor), so they live in a schema no
-- one but its owner can use.
CREATE SCHEMA IF NOT EXISTS bb_f1;
REVOKE ALL ON SCHEMA bb_f1 FROM PUBLIC;

-- The install secret the MACs are made with. Readable by its owner only.
CREATE TABLE IF NOT EXISTS bb_f1.secret (
  id  int   PRIMARY KEY CHECK (id = 1),
  key bytea NOT NULL CHECK (length(key) = 32)
);

-- What a token's aud and branch claims are checked against. Written by the
-- engine whenever it readies a branch: a branch is a copy of main, and would
-- otherwise answer to main's name.
CREATE TABLE IF NOT EXISTS bb_f1.install (
  id         int  PRIMARY KEY CHECK (id = 1),
  install_id text NOT NULL,
  branch     text NOT NULL
);

-- ── Registered applications ────────────────────────────────────────────────
-- A copy of the account store's registrations (the source of truth, which the
-- HA standby replicates), refreshed by the engine. One row per key: an
-- application with two keys during a rotation has two.
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

-- ── The extension, where this branch's image has it ─────────────────────────
-- Ed25519, the transaction's identity, the MAC, and the secret's random bytes,
-- all in C (docker/postgres/bb_identity). In the private schema.
DO $do$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'bb_identity') THEN
    CREATE EXTENSION IF NOT EXISTS bb_identity WITH SCHEMA bb_f1;
    INSERT INTO bb_f1.secret VALUES (1, bb_f1.bbid_random_bytes(32)) ON CONFLICT DO NOTHING;
  END IF;
END
$do$;

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

-- ── bb.app_actor() and bb.app_actor_label() ─────────────────────────────────
-- bb.app_actor(): the application actor of this transaction, and its state.
-- What every recording function calls. The values are ordinary settings, which
-- a session can overwrite, so they are not trusted as values: the MAC is
-- checked, and a value that does not match it is 'none'. In C, remembering the
-- last set of values it checked (design, section 14).
--
-- bb.app_actor_label(): the same decision as one string, what row tracking's
-- last_modified_for holds: asserted:<issuer>:<user>, claimed:<user>, or ''.
--
-- Where the extension cannot be loaded, the same two functions with nothing to
-- check with: a value set by hand is never taken for an assertion.
DO $do$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'bb_identity') THEN
    EXECUTE $f$
      CREATE OR REPLACE FUNCTION bb.app_actor(
        OUT actor text, OUT state text, OUT issuer text, OUT kid text, OUT tenant text, OUT note text
      ) RETURNS record
      AS '$libdir/bb_identity', 'bbid_app_actor'
      LANGUAGE C VOLATILE PARALLEL UNSAFE $f$;
    EXECUTE $f$
      CREATE OR REPLACE FUNCTION bb.app_actor_label() RETURNS text
      AS '$libdir/bb_identity', 'bbid_app_actor_label'
      LANGUAGE C VOLATILE PARALLEL UNSAFE $f$;
  ELSE
    -- DROP first: CREATE OR REPLACE cannot turn a C function into PL/pgSQL
    -- when the library it named is the thing that is missing.
    DROP FUNCTION IF EXISTS bb.app_actor();
    DROP FUNCTION IF EXISTS bb.app_actor_label();
    EXECUTE $f$
      CREATE FUNCTION bb.app_actor(
        OUT actor text, OUT state text, OUT issuer text, OUT kid text, OUT tenant text, OUT note text
      ) RETURNS record
      LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog AS $b$
      DECLARE c text := nullif(current_setting('bb.claimed_actor', true), '');
      BEGIN
        state := 'none';
        IF c IS NOT NULL THEN
          actor := c; state := 'claimed';
        ELSIF nullif(current_setting('bb.app.actor', true), '') IS NOT NULL THEN
          note := 'an application actor was present, and this branch cannot check one';
        END IF;
      END $b$ $f$;
    EXECUTE $f$
      CREATE FUNCTION bb.app_actor_label() RETURNS text
      LANGUAGE sql VOLATILE SET search_path = pg_catalog AS $b$
        SELECT coalesce('claimed:' || nullif(current_setting('bb.claimed_actor', true), ''), '')
      $b$ $f$;
  END IF;
END
$do$;

-- bb.app_identity_mode(): 'checked' where this branch can check a token,
-- 'unavailable' where its image predates the extension. What `fox app` asks to
-- name the branches that are not ready.
CREATE OR REPLACE FUNCTION bb.app_identity_mode() RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
  SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'bb_identity')
               AND EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'bb_identity')
              THEN 'checked' ELSE 'unavailable' END
$$;

-- ── bb.act_for(token) ───────────────────────────────────────────────────────
-- Assert this transaction's application actor. The token is passed as a bind
-- parameter, never in the SQL text. Returns the user it now acts for, or NULL
-- when the token was not accepted (the reason is kept for the record); raises
-- when the application registered on_invalid = 'refuse', and always for a
-- second assertion in one transaction.
DO $do$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'bb_identity') THEN
    EXECUTE $f$
      CREATE OR REPLACE FUNCTION bb.act_for(token text) RETURNS text
      LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $b$
      BEGIN
        RAISE EXCEPTION 'this branch cannot check an application identity token yet'
          USING ERRCODE = 'feature_not_supported',
                DETAIL = 'Its container was made from an engine image older than revision 2, which has no bb_identity.',
                HINT = 'Restart the engine (stop it, then start it): each container is then made from the current image. Nothing is lost.';
      END $b$ $f$;
    RETURN;
  END IF;
  EXECUTE $f$
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
      current_setting('bb.app.actor', true) USING ERRCODE = 'invalid_authorization_specification';
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
  IF reason IS NULL AND NOT bb_f1.bbid_ed25519_verify(k.public_key, convert_to(parts[1] || '.' || parts[2], 'UTF8'), sig) THEN
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
    ELSIF inst IS NULL OR body->>'aud' IS DISTINCT FROM inst.install_id THEN
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
    PERFORM set_config('bb.app.failure', reason, true);
    IF refuse THEN
      RAISE EXCEPTION 'application identity refused: %', reason
        USING ERRCODE = 'invalid_authorization_specification';
    END IF;
    RETURN NULL;
  END IF;

  PERFORM set_config('bb.app.actor', sub, true),
          set_config('bb.app.issuer', k.issuer, true),
          set_config('bb.app.kid', k.kid, true),
          set_config('bb.app.tenant', tenant, true),
          set_config('bb.app.failure', '', true);
  PERFORM set_config('bb.app.mac', bb_f1.bbid_app_mac(sub, k.issuer, k.kid, tenant), true);
  RETURN sub;
END $fn$ $f$;
END
$do$;

-- Every login reaches these through db_client, which every account's role is a
-- member of. ledger.sql grants the same on every start; said here too, since a
-- branch readied on resume runs this file and not that one.
GRANT USAGE ON SCHEMA bb TO db_client;
GRANT EXECUTE ON FUNCTION bb.act_for(text), bb.app_actor(), bb.app_actor_label(), bb.app_identity_mode() TO db_client;

-- ── What a report shows ─────────────────────────────────────────────────────
-- Both identities beside each Blackbox record: the login, and the application
-- actor in the state it was recorded with. A key since reported compromised
-- never shows as plain 'asserted' for what was asserted after that.
CREATE OR REPLACE VIEW bb.app_report AS
SELECT l.id, l.at, l.command_tag, l.object_identity, l.actor AS db_actor,
       e.app_actor,
       CASE WHEN e.app_state = 'asserted' AND i.compromised_since IS NOT NULL AND l.at >= i.compromised_since
            THEN 'asserted by ' || e.app_issuer || ' (key reported compromised)'
            WHEN e.app_state = 'asserted' THEN 'asserted by ' || e.app_issuer
            ELSE e.app_state END AS app_state,
       e.app_issuer, e.app_kid, e.app_tenant, e.app_note AS note
FROM bb.schema_ledger l
JOIN bb.ledger_ext e ON e.ledger_id = l.id
LEFT JOIN bb.app_issuers i ON i.issuer = e.app_issuer AND i.kid = e.app_kid
WHERE e.app_state IS NOT NULL;
REVOKE ALL ON bb.app_report FROM PUBLIC;

SET session_replication_role = DEFAULT;
