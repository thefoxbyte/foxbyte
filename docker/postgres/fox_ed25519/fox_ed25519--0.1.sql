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
