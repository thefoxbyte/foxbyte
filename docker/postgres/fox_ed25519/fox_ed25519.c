/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * fox_ed25519: what F1's application identity needs from C
 * (docs/FOX_F1_Identity_Design.md, sections 5 and 6). Two functions:
 *
 *   fox_ed25519_verify  Ed25519 signature verification. PostgreSQL has none of
 *                       its own: pgcrypto does HMAC, not signatures, and
 *                       pgsodium is not in FoxByte's image. OpenSSL is, so this
 *                       is a thin wrapper over its EVP interface: no state, no
 *                       I/O, every length checked before OpenSSL sees a byte.
 *
 *   fox_txn_id          This transaction's identity, which the MAC binds an
 *                       application actor to. The same values are in pg_locks,
 *                       but reading them there costs about 33 microseconds a
 *                       call, and the MAC is checked once for every row a
 *                       tracked table records (the prototype measured it).
 */
#include "postgres.h"

#include "fmgr.h"
#include "miscadmin.h"
#include "storage/proc.h"
#include "utils/builtins.h"
#include "utils/timestamp.h"
#include "varatt.h"

#include <openssl/evp.h>

PG_MODULE_MAGIC;

#define ED25519_KEY_LEN 32
#define ED25519_SIG_LEN 64

PG_FUNCTION_INFO_V1(fox_ed25519_verify);

/*
 * fox_ed25519_verify(public_key bytea, message bytea, signature bytea) -> bool
 *
 * True only for a 32-byte public key, a 64-byte signature, and a signature that
 * OpenSSL verifies over the message. Anything else is false, never an error:
 * a malformed token is a refused token, and the caller says why.
 */
Datum
fox_ed25519_verify(PG_FUNCTION_ARGS)
{
	bytea	   *key = PG_GETARG_BYTEA_PP(0);
	bytea	   *msg = PG_GETARG_BYTEA_PP(1);
	bytea	   *sig = PG_GETARG_BYTEA_PP(2);
	EVP_PKEY   *pkey;
	EVP_MD_CTX *ctx;
	int			rc;

	if (VARSIZE_ANY_EXHDR(key) != ED25519_KEY_LEN ||
		VARSIZE_ANY_EXHDR(sig) != ED25519_SIG_LEN)
		PG_RETURN_BOOL(false);

	pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
									   (const unsigned char *) VARDATA_ANY(key),
									   ED25519_KEY_LEN);
	if (pkey == NULL)
		PG_RETURN_BOOL(false);

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
	{
		EVP_PKEY_free(pkey);
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("out of memory verifying a signature")));
	}

	/* Ed25519 hashes internally: no digest is named, and the message is
	 * passed whole (one-shot), as the algorithm requires. */
	rc = EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey);
	if (rc == 1)
		rc = EVP_DigestVerify(ctx,
							  (const unsigned char *) VARDATA_ANY(sig), ED25519_SIG_LEN,
							  (const unsigned char *) VARDATA_ANY(msg), VARSIZE_ANY_EXHDR(msg));

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	PG_RETURN_BOOL(rc == 1);
}

PG_FUNCTION_INFO_V1(fox_txn_id);

/*
 * fox_txn_id() -> text
 *
 * The server's start, this backend's pid, and the virtual transaction id
 * (process number and local transaction id): unique to this transaction for as
 * long as the server runs, and the start time separates one run from the next.
 * Needs no real transaction id, so a read-only transaction does not consume
 * one. PostgreSQL 17 grouped the two halves of the virtual transaction id into
 * MyProc->vxid; 16 kept them as separate fields.
 */
Datum
fox_txn_id(PG_FUNCTION_ARGS)
{
	char		buf[128];

#if PG_VERSION_NUM >= 170000
	snprintf(buf, sizeof(buf), INT64_FORMAT "/%d/%d/%u",
			 (int64) PgStartTime, MyProcPid,
			 (int) MyProc->vxid.procNumber, (unsigned int) MyProc->vxid.lxid);
#else
	snprintf(buf, sizeof(buf), INT64_FORMAT "/%d/%d/%u",
			 (int64) PgStartTime, MyProcPid,
			 (int) MyProc->backendId, (unsigned int) MyProc->lxid);
#endif
	PG_RETURN_TEXT_P(cstring_to_text(buf));
}
