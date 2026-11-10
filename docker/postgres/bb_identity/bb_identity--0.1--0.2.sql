-- SPDX-License-Identifier: AGPL-3.0-or-later
\echo Use "ALTER EXTENSION bb_identity UPDATE TO '0.2'" to load this file. \quit

-- Masking (F5): the keyed hash a mask is made with, under a key domain's key
-- (/run/bb-mask/<domain>.key). Never granted to a masked reader: it would be
-- an oracle. Only the role that keeps the masks is given it.
CREATE FUNCTION bbid_mask_hmac(domain text, value text)
RETURNS text
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT STABLE PARALLEL SAFE;
REVOKE EXECUTE ON FUNCTION bbid_mask_hmac(text, text) FROM PUBLIC;
