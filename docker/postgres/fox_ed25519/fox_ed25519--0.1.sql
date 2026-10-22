-- SPDX-License-Identifier: AGPL-3.0-or-later
\echo Use "CREATE EXTENSION fox_ed25519" to load this file. \quit

-- True only when signature is a valid Ed25519 signature of message under
-- public_key (32 bytes); false for anything else, never an error.
CREATE FUNCTION fox_ed25519_verify(public_key bytea, message bytea, signature bytea)
RETURNS boolean
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

-- This transaction's identity: the server's start, the backend, and the virtual
-- transaction id. Parallel unsafe: a parallel worker has a process of its own.
CREATE FUNCTION fox_txn_id()
RETURNS text
AS 'MODULE_PATHNAME'
LANGUAGE C VOLATILE PARALLEL UNSAFE;

-- The MAC over an application actor and this transaction, under the install
-- secret (bb_f1.secret). Never granted: a client able to call it could forge.
CREATE FUNCTION fox_app_mac(actor text, issuer text, kid text, tenant text)
RETURNS text
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT VOLATILE PARALLEL UNSAFE;

-- n bytes from the server's strong random source, for the install secret.
CREATE FUNCTION fox_random_bytes(n integer)
RETURNS bytea
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT VOLATILE PARALLEL UNSAFE;
