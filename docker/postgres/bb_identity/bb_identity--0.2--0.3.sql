-- SPDX-License-Identifier: AGPL-3.0-or-later
\echo Use "ALTER EXTENSION bb_identity UPDATE TO '0.3'" to load this file. \quit

-- Erasure (F4): a statement with every literal replaced by a placeholder, for
-- the Blackbox's record of UPDATE and DELETE. It holds no secret, so any role
-- may call it.
CREATE FUNCTION bbid_placeholders(statement text)
RETURNS text
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;
