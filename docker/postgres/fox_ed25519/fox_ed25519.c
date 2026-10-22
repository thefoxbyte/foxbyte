/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * fox_ed25519: what F1's application identity needs from C
 * (docs/FOX_F1_Identity_Design.md, sections 5, 6 and 13).
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
 *
 *   fox_app_mac         The MAC over an application actor and this transaction
 *                       (HMAC-SHA256 under the install secret). Private: only
 *                       bb.act_for calls it, from a schema clients cannot use.
 *
 *   fox_app_actor       bb.app_actor(): this transaction's application actor
 *                       and its state, with the MAC checked. Public: it only
 *                       reads, and says what a client could find out anyway.
 *                       It remembers the last set of values it checked, so a
 *                       statement touching ten thousand rows pays for one HMAC,
 *                       not ten thousand (section 13, item 4). A client can
 *                       change a setting but not this process's memory, so the
 *                       memory cannot be made to vouch for values it never
 *                       checked: any change to the transaction or a value is a
 *                       miss, and is checked again.
 *
 *   fox_app_actor_label bb.app_actor_label(): the same answer as one string,
 *                       what row tracking's last_modified_for holds
 *                       (asserted:<issuer>:<user>, claimed:<user>, or empty).
 *                       A record costs a tuple built and a field taken out of it
 *                       on every call, which was most of what checking the
 *                       actor cost a tracked row; a string does not.
 *
 *   fox_random_bytes    Bytes from the server's strong random source, for the
 *                       install secret.
 */
#include "postgres.h"

#include "access/htup_details.h"
#include "catalog/pg_authid_d.h"
#include "executor/spi.h"
#include "fmgr.h"
#include "funcapi.h"
#include "lib/stringinfo.h"
#include "miscadmin.h"
#include "port.h"
#include "storage/proc.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/memutils.h"
#include "utils/timestamp.h"
#include "varatt.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

PG_MODULE_MAGIC;

/*
 * The settings an application actor travels in. Defined here, when the library
 * loads, rather than left as placeholders, so reading one is a pointer and not
 * a lookup by name: bb.app_actor_label() reads five on every row a tracked
 * table records, and five lookups were most of what it cost (design, section
 * 13). They stay settings any session may set, as before; what makes a value
 * count is still the MAC. A value set before the library loaded is adopted
 * when it is defined, as PostgreSQL does for any custom setting.
 */
static char *g_actor = NULL;
static char *g_issuer = NULL;
static char *g_kid = NULL;
static char *g_tenant = NULL;
static char *g_mac = NULL;
static char *g_failure = NULL;
static char *g_claimed = NULL;

void		_PG_init(void);

void
_PG_init(void)
{
	static const struct
	{
		const char *name;
		const char *desc;
		char	  **var;
	}			vars[] = {
		{"fox.app.actor", "The application actor bb.act_for asserted for this transaction.", &g_actor},
		{"fox.app.issuer", "The application that asserted it.", &g_issuer},
		{"fox.app.kid", "The key the assertion was signed with.", &g_kid},
		{"fox.app.tenant", "The tenant the assertion named, if any.", &g_tenant},
		{"fox.app.mac", "The MAC binding the assertion to this transaction.", &g_mac},
		{"fox.app.failure", "Why the last token in this transaction was refused.", &g_failure},
		{"fox.claimed_actor", "An application actor the client claims, unchecked.", &g_claimed},
	};

	for (size_t n = 0; n < lengthof(vars); n++)
		DefineCustomStringVariable(vars[n].name, vars[n].desc, NULL, vars[n].var, "",
								   PGC_USERSET, GUC_NOT_IN_SAMPLE, NULL, NULL, NULL);
}

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
static void
txn_id(char *buf, size_t len)
{
#if PG_VERSION_NUM >= 170000
	snprintf(buf, len, INT64_FORMAT "/%d/%d/%u",
			 (int64) PgStartTime, MyProcPid,
			 (int) MyProc->vxid.procNumber, (unsigned int) MyProc->vxid.lxid);
#else
	snprintf(buf, len, INT64_FORMAT "/%d/%d/%u",
			 (int64) PgStartTime, MyProcPid,
			 (int) MyProc->backendId, (unsigned int) MyProc->lxid);
#endif
}

Datum
fox_txn_id(PG_FUNCTION_ARGS)
{
	char		buf[128];

	txn_id(buf, sizeof(buf));
	PG_RETURN_TEXT_P(cstring_to_text(buf));
}

/* ---- the install secret ------------------------------------------------- */

#define SECRET_LEN 32
#define MAC_HEX_LEN 64

static unsigned char secret[SECRET_LEN];
static bool secret_loaded = false;

/*
 * The install secret, read once per backend from bb_f1.secret. Read as the
 * bootstrap superuser, as a SECURITY DEFINER function would read it: the
 * caller of bb.app_actor() is usually a client, who must never read the
 * secret, and SPI runs as whoever is calling.
 */
static void
load_secret(void)
{
	Oid			save_userid;
	int			save_sec;

	if (secret_loaded)
		return;
	GetUserIdAndSecContext(&save_userid, &save_sec);
	SetUserIdAndSecContext(BOOTSTRAP_SUPERUSERID,
						   save_sec | SECURITY_LOCAL_USERID_CHANGE | SECURITY_RESTRICTED_OPERATION);
	PG_TRY();
	{
		bool		isnull;
		Datum		d;
		bytea	   *b;

		if (SPI_connect() != SPI_OK_CONNECT)
			elog(ERROR, "fox_ed25519: SPI_connect failed");
		if (SPI_execute("SELECT key FROM bb_f1.secret WHERE id = 1", true, 1) != SPI_OK_SELECT ||
			SPI_processed != 1)
			ereport(ERROR,
					(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
					 errmsg("the install secret for application identity is missing")));
		d = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &isnull);
		if (isnull)
			ereport(ERROR,
					(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
					 errmsg("the install secret for application identity is empty")));
		b = DatumGetByteaPP(d);
		if (VARSIZE_ANY_EXHDR(b) != SECRET_LEN)
			ereport(ERROR,
					(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
					 errmsg("the install secret for application identity is not %d bytes", SECRET_LEN)));
		memcpy(secret, VARDATA_ANY(b), SECRET_LEN);
		SPI_finish();
	}
	PG_FINALLY();
	{
		SetUserIdAndSecContext(save_userid, save_sec);
	}
	PG_END_TRY();
	secret_loaded = true;
}

/* ---- the MAC ------------------------------------------------------------ */

static void
add_field(StringInfo buf, const char *v)
{
	size_t		n = strlen(v);

	appendStringInfo(buf, "%zu:", n);
	appendBinaryStringInfo(buf, v, (int) n);
}

/*
 * mac_hex: HMAC-SHA256, as 64 hex characters into out (65 bytes with its
 * NUL), over the transaction and the four values, each length-prefixed so no
 * choice of a user's name can make two different assertions read the same.
 */
static void
mac_hex(const char *txn, const char *issuer, const char *kid, const char *tenant,
		const char *actor, char *out)
{
	StringInfoData buf;
	unsigned char mac[EVP_MAX_MD_SIZE];
	size_t		maclen = 0;
	static const char hex[] = "0123456789abcdef";

	load_secret();
	initStringInfo(&buf);
	add_field(&buf, txn);
	add_field(&buf, issuer);
	add_field(&buf, kid);
	add_field(&buf, tenant);
	add_field(&buf, actor);
	if (EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, secret, SECRET_LEN,
				  (const unsigned char *) buf.data, buf.len, mac, sizeof(mac), &maclen) == NULL ||
		maclen != MAC_HEX_LEN / 2)
	{
		pfree(buf.data);
		ereport(ERROR, (errmsg("computing an application identity MAC failed")));
	}
	pfree(buf.data);
	for (size_t i = 0; i < maclen; i++)
	{
		out[2 * i] = hex[mac[i] >> 4];
		out[2 * i + 1] = hex[mac[i] & 0x0f];
	}
	out[MAC_HEX_LEN] = '\0';
}

PG_FUNCTION_INFO_V1(fox_app_mac);

/* fox_app_mac(actor, issuer, kid, tenant) -> text: the MAC for this transaction. */
Datum
fox_app_mac(PG_FUNCTION_ARGS)
{
	char		txn[128];
	char		out[MAC_HEX_LEN + 1];

	txn_id(txn, sizeof(txn));
	mac_hex(txn,
			text_to_cstring(PG_GETARG_TEXT_PP(1)),
			text_to_cstring(PG_GETARG_TEXT_PP(2)),
			text_to_cstring(PG_GETARG_TEXT_PP(3)),
			text_to_cstring(PG_GETARG_TEXT_PP(0)),
			out);
	PG_RETURN_TEXT_P(cstring_to_text(out));
}

/* ---- bb.app_actor() ----------------------------------------------------- */

/* This transaction, as numbers: compared on every call, so not formatted. */
typedef struct
{
	TimestampTz start;
	int			pid;
	int			proc;
	uint32		lxid;
}			TxnKey;

static TxnKey
txn_key(void)
{
	TxnKey		k;

	k.start = PgStartTime;
	k.pid = MyProcPid;
#if PG_VERSION_NUM >= 170000
	k.proc = (int) MyProc->vxid.procNumber;
	k.lxid = (uint32) MyProc->vxid.lxid;
#else
	k.proc = (int) MyProc->backendId;
	k.lxid = (uint32) MyProc->lxid;
#endif
	return k;
}

/* The last set of values checked, and what the check said. */
static struct
{
	bool		set;
	bool		valid;
	TxnKey		txn;
	char	   *actor,
			   *issuer,
			   *kid,
			   *tenant,
			   *mac,
			   *label;			/* asserted:<issuer>:<actor>, when valid */
}			last;

/* A setting's value, or NULL when it is not set or empty. */
static const char *
opt(const char *v)
{
	return (v == NULL || v[0] == '\0') ? NULL : v;
}

static bool
same(const char *x, const char *y)
{
	return strcmp(x, y) == 0;
}

static char *
keep(const char *v)
{
	return MemoryContextStrdup(TopMemoryContext, v);
}

static void
forget(void)
{
	if (!last.set)
		return;
	pfree(last.actor);
	pfree(last.issuer);
	pfree(last.kid);
	pfree(last.tenant);
	pfree(last.mac);
	pfree(last.label);
	last.set = false;
}

/* checked: does the MAC match, from memory when these exact values were
 * checked last in this transaction, else by computing it. */
static bool
checked(const char *a, const char *i, const char *k, const char *t, const char *m)
{
	TxnKey		now = txn_key();
	char		txn[128];
	char		want[MAC_HEX_LEN + 1];
	bool		ok;

	if (last.set && last.txn.start == now.start && last.txn.pid == now.pid &&
		last.txn.proc == now.proc && last.txn.lxid == now.lxid &&
		same(last.actor, a) && same(last.issuer, i) && same(last.kid, k) &&
		same(last.tenant, t) && same(last.mac, m))
		return last.valid;

	txn_id(txn, sizeof(txn));
	mac_hex(txn, i, k, t, a, want);
	ok = strlen(m) == MAC_HEX_LEN && CRYPTO_memcmp(want, m, MAC_HEX_LEN) == 0;

	forget();
	last.txn = now;
	last.actor = keep(a);
	last.issuer = keep(i);
	last.kid = keep(k);
	last.tenant = keep(t);
	last.mac = keep(m);
	last.label = MemoryContextStrdup(TopMemoryContext, psprintf("asserted:%s:%s", i, a));
	last.valid = ok;
	last.set = true;
	return ok;
}

PG_FUNCTION_INFO_V1(fox_app_actor);

/*
 * fox_app_actor() -> (actor, state, issuer, kid, tenant, note)
 *
 * The same answer the prototype's PL/pgSQL gave: asserted when the values and
 * their MAC agree; none, with a note, when a value is present and does not;
 * claimed from fox.claimed_actor; none otherwise, with the reason a token was
 * refused when there was one.
 */
Datum
fox_app_actor(PG_FUNCTION_ARGS)
{
	TupleDesc	tupdesc;
	Datum		values[6];
	bool		nulls[6] = {true, false, true, true, true, true};
	const char *a = opt(g_actor);
	const char *i = opt(g_issuer);
	const char *k = opt(g_kid);
	const char *t = opt(g_tenant);
	const char *m = opt(g_mac);
	const char *f = opt(g_failure);
	const char *c = opt(g_claimed);
	const char *state = "none";
	const char *note = NULL;
	char	   *refused = NULL;

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "fox_app_actor must return a record");
	tupdesc = BlessTupleDesc(tupdesc);

	if (f != NULL)
		refused = psprintf("token refused: %s", f);

	if (a != NULL || m != NULL)
	{
		if (a != NULL && i != NULL && k != NULL && m != NULL && checked(a, i, k, t ? t : "", m))
		{
			state = "asserted";
			values[0] = CStringGetTextDatum(a), nulls[0] = false;
			values[2] = CStringGetTextDatum(i), nulls[2] = false;
			values[3] = CStringGetTextDatum(k), nulls[3] = false;
			if (t != NULL)
				values[4] = CStringGetTextDatum(t), nulls[4] = false;
		}
		else
			note = "an application actor was present and failed its check";
	}
	else if (c != NULL)
	{
		state = "claimed";
		values[0] = CStringGetTextDatum(c), nulls[0] = false;
		note = refused;
	}
	else
		note = refused;

	values[1] = CStringGetTextDatum(state);
	if (note != NULL)
		values[5] = CStringGetTextDatum(note), nulls[5] = false;
	PG_RETURN_DATUM(HeapTupleGetDatum(heap_form_tuple(tupdesc, values, nulls)));
}

PG_FUNCTION_INFO_V1(fox_app_actor_label);

/*
 * fox_app_actor_label() -> text
 *
 * asserted:<issuer>:<user> when the values and their MAC agree; claimed:<user>
 * for a client's own word; '' otherwise. The same decision as fox_app_actor,
 * read from the same settings and the same memory.
 */
Datum
fox_app_actor_label(PG_FUNCTION_ARGS)
{
	const char *a = opt(g_actor);
	const char *m = opt(g_mac);

	if (a != NULL || m != NULL)
	{
		const char *i = opt(g_issuer);
		const char *k = opt(g_kid);
		const char *t = opt(g_tenant);

		if (a != NULL && i != NULL && k != NULL && m != NULL && checked(a, i, k, t ? t : "", m))
			PG_RETURN_TEXT_P(cstring_to_text(last.label));
		PG_RETURN_TEXT_P(cstring_to_text(""));
	}
	{
		const char *c = opt(g_claimed);

		if (c != NULL)
			PG_RETURN_TEXT_P(cstring_to_text(psprintf("claimed:%s", c)));
	}
	PG_RETURN_TEXT_P(cstring_to_text(""));
}

/* ---- the secret's bytes -------------------------------------------------- */

PG_FUNCTION_INFO_V1(fox_random_bytes);

/* fox_random_bytes(n) -> bytea: n bytes (1 to 1024) from the strong source. */
Datum
fox_random_bytes(PG_FUNCTION_ARGS)
{
	int32		n = PG_GETARG_INT32(0);
	bytea	   *b;

	if (n < 1 || n > 1024)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("fox_random_bytes: 1 to 1024 bytes, not %d", n)));
	b = (bytea *) palloc(VARHDRSZ + n);
	SET_VARSIZE(b, VARHDRSZ + n);
	if (!pg_strong_random(VARDATA(b), n))
		ereport(ERROR, (errmsg("the server's strong random source failed")));
	PG_RETURN_BYTEA_P(b);
}
