# F1: identity and attribution — design

**Status:** draft for review, 22 October 2026. Written against `main` at
`d93492c`. It answers Gate 0's F1 item in the review plan
(`docs/FOX_Expert_Review_Plan.md`, sections 4 and 5): the token protocol written
down, the signature-checking choice made, and the prototype and its tests
defined.

**What a reader is asked to decide** (section 12 lists them with the
recommendation for each):

1. Ed25519 checked by a small FoxByte extension, with no shared-secret mode in
   Gate 1 (section 6).
2. Savepoints: an assertion rolled back with its savepoint is undone with it. This
   changes one sentence of the review plan (section 5.3).
3. Close the rest of G1 by giving every engine agent session a role of its own
   (section 9).

---

## 1. What "verified" will mean

Every record of a change will carry two identities:

- **The database actor**: the role the session authenticated as. The session
   cannot change it (`session_user`).
- **The application actor**: the end user an application is acting for.

The application actor always has a **state**, and every report, export and API
keeps the state beside the name, never upgrading it:

| State | Means | How it is set |
|---|---|---|
| `asserted by <app>` | Application `<app>` vouched for this user, with a token signed by its key and accepted from its own database role | `bb.act_for($1)` with a valid token (section 5) |
| `claimed` | The client said so, and nothing checked it | A plain setting, `fox.claimed_actor` |
| `none` | No application actor, or one that failed a check | The default; also every failure (section 5.5) |

`asserted` proves that the application vouched for the user. It does not prove
that the user was present. That is the claim, in those words, wherever it
appears.

A stronger tier, tokens taken straight from the customer's identity provider
(OIDC), can follow later. Nothing here prevents it.

---

## 2. Today: how each path is attributed

Checked against the code. "Setting" means a value the session itself can
overwrite.

| Path | Logs in as | Database actor | Agent or person | Gap |
|---|---|---|---|---|
| Gateway, account key | the account's own role | the account (`session_user`) | person, from the role | none |
| Gateway, agent key (#144) | `agent:<email>` | the account | agent, from the role | none |
| Agent branch | `agent-<id>` | the agent | agent, from the role | none |
| Console | the signed-in user's role | the user | person | falls back to `db_client` + setting if the role cannot be made |
| Engine agent sessions (MCP `run_sql`, provenance-recorded calls) | `db_agent` | **which** agent comes from `bb.actor`, a setting | agent, from the role | the agent's name is a setting |
| Engine's own changes (policy, tracking, pipelines) | `dbadmin` (superuser) | `bb.actor`, a setting | person | a superuser is outside any threat model the database enforces |
| Any application | its account's role | the account | person | no way to say whose request it was |

The last row is what F1 adds. The two "setting" rows are G1's remainder
(section 9).

---

## 3. The token

**Format:** JWS compact serialisation, `header.payload.signature`, base64url.

- **The header is fixed.** It is exactly `{"alg":"EdDSA","typ":"JWT","kid":"<key id>"}`, Ed25519 only. Any other `alg`, including `none` and every HMAC algorithm, is refused before anything else is read. Algorithm confusion is the classic JWT failure, and one fixed header removes it.
- **Ordinary libraries can mint it**, so an application needs no FoxByte code to produce one: `jose` (Node), `PyJWT`/`authlib` (Python), `golang-jwt` (Go), and Java's `nimbus-jose-jwt`.

**Claims:**

| Claim | Required | Checked against |
|---|---|---|
| `iss` | yes | a registered application (section 4) |
| `sub` | yes | the end user; recorded as the application actor (at most 256 characters) |
| `aud` | yes | this install's id, so a token for another install fails |
| `iat`, `exp` | yes | `exp - iat` at most the application's limit (default 5 minutes, at most 60); 30 seconds of clock skew allowed |
| `tenant` | no | recorded beside `sub` for multi-tenant applications |
| `branch` | no | if present, the token is good on that branch only |

**What the token is not:**

- **Not single-use.** Binding (section 4) is what makes a leaked token useless, so nothing is written per transaction to track tokens.
- **Not stored.** Only its `kid`, `iss`, `sub` and `tenant` are kept, never the token itself.

---

## 4. Binding to the application's own database role

An application is **registered** by an admin with:

- its name (`iss`);
- the database role its connections authenticate as;
- one or more public keys, each with a `kid`.

A token is accepted only from a session whose `session_user` is that registered
role.

A leaked token is therefore useless to anyone without that application's own
database credentials. That is what lets expiry be minutes rather than seconds,
with no replay table.

Replay *by the application itself* within the expiry window is possible, and is
documented as such: the application could assert the user anyway.

**Where registrations live:**

- **The source of truth is the install's account store.** It is replicated to the HA standby like every other account record.
- **The engine copies each registration into every running branch's `bb.app_issuers`.** A suspended branch gets it when it resumes, as roles are refreshed today.
- **A revocation is copied at once** (section 7).

---

## 5. One application actor per transaction

### 5.1 The call

```sql
SELECT bb.act_for($1);   -- $1 is the token, as a bind parameter
```

`bb.act_for` is `SECURITY DEFINER`, owned by the superuser, and does this:

1. Parses the fixed header, then checks the signature with the extension (section 6).
2. Checks the claims: `iss` and the session's role, `aud`, the times, and `branch`.
3. If this transaction already has an application actor, refuses: the first valid token wins, and a second, even for the same user, is an error.
4. Sets four transaction-local values: `fox.app.actor`, `fox.app.issuer`, `fox.app.kid`, and `fox.app.mac`, a MAC over the other three and the transaction's identity (5.2).
5. Returns the actor, so a client can see what was set.

### 5.2 Why nothing is written per transaction

The values are ordinary settings, which a session can overwrite. So they are not
trusted as values: the MAC is what is trusted.

- **The MAC is HMAC-SHA256 (pgcrypto) under an install secret.** Only `bb.act_for` and the recording functions can read the secret. They are `SECURITY DEFINER`, and the secret's table is revoked from everyone else.
- **The MAC covers four things:**
  - the actor, issuer and key;
  - the server's start time (`pg_postmaster_start_time()`);
  - the backend's pid;
  - the **virtual transaction id**, read from `pg_locks` without assigning a real one (checked: `89/6` while `pg_current_xact_id_if_assigned()` stayed null).
- **A forged value fails the check.** A session that sets `fox.app.actor` by hand cannot produce a matching MAC.
- **A value carried into a later transaction fails too.** A session-level `SET` names a transaction that is over, so its MAC no longer matches.

The recording functions (Blackbox, provenance, row tracking) call
`bb._app_actor()`, which recomputes the MAC every time. A match gives
`asserted by <issuer>`. A mismatch gives `none`, and the record notes that a
value was present and failed.

### 5.3 Savepoints: one change from the review plan

The review plan says "a savepoint rolled back does not reset it". On reflection,
it should, and Postgres already does the right thing.

Checked in the test VM:

- A local setting made inside a savepoint is undone by `ROLLBACK TO` and kept by `RELEASE`.
- The next transaction starts empty.

An assertion made inside a savepoint is therefore rolled back together with every
change it attributed. No surviving row can carry an actor that was never in force
when it was written, and that invariant is what the test checks. Keeping the
actor across the rollback would need a non-transactional store, and would attach
a name to a transaction whose changes under it no longer exist.

### 5.4 Keeping the token out of logs

- **The application passes the token as a bind parameter**, never inside the SQL text. So it is not in `current_query()`, the Blackbox's statement text, query history or `pg_stat_statements` (which normalises parameters).
- **FoxByte enables no statement or parameter logging.** Postgres's default, `log_parameter_max_length_on_error = 0`, keeps parameters out of error logs too. The tests assert both, so a later setting cannot quietly change it.
- **pgAudit (F6) must keep parameter logging off.** F6's design takes this as a constraint.

### 5.5 When a token fails

Each application chooses, at registration, what an invalid token does:

- **`none` (the default):** the transaction goes on, attributed `none`, and the reason is recorded.
- **`refuse`:** the transaction is aborted.

The reasons recorded are: bad signature, unknown key, revoked key, wrong
session role, expired, not yet valid, wrong audience, wrong branch, second
assertion, and malformed. A failure is never attributed to anyone else.

---

## 6. Signature checking: the decision

Postgres has no signature verification built in. Checked in the image:

- **pgcrypto 1.4** is available. It does HMAC, not signatures.
- **pgsodium is not available.**
- **OpenSSL 3.0.20 is present.** Ed25519 is in its EVP interface.

| Option | Only the application can mint? | New code in the database | Verdict |
|---|---|---|---|
| A. Per-application shared secret, HMAC in pgcrypto | **No**: the secret is in every branch and every backup; whoever reads it can mint | none | fallback only |
| **B. A small FoxByte extension, Ed25519 via OpenSSL** | **Yes**: only public keys in the database | about 100 lines of C | **chosen** |
| C. pgsodium | yes | a third-party extension | not in the image; a large surface for one function |
| D. Verify in the Gateway | yes | none in the database | the Gateway is a byte pipe after login; it cannot see transactions |
| E. PL/Python with a crypto library | yes | an untrusted language in every branch | too much power to grant for one check |
| F. Ed25519 in PL/pgSQL | yes | a hand-written cryptographic primitive | slow, and the riskiest code we could write |

**Chosen: B.** The extension is `fox_ed25519`, with one function:
`fox_ed25519_verify(public_key bytea, message bytea, signature bytea) RETURNS boolean`.

- **Strict, no side effects.** It is a strict, immutable function with no I/O and no global state. Lengths are checked before OpenSSL is called: 32-byte keys, 64-byte signatures.
- **Built into FoxByte's image** for each Postgres major (16 and 18), in a build stage with `postgresql-server-dev` and `libssl-dev`. The final image keeps only the `.so` and its control file. CI builds both architectures, and a fuzz test feeds it malformed input.
- **Installed per branch by `CREATE EXTENSION`,** like the Blackbox's other objects.

**No shared-secret mode in Gate 1.** It would add a second, weaker kind of
`asserted` that every report would need to tell apart. It is added only if a
customer runs their own Postgres image without the extension, and it would then be
labelled `asserted by <app> (shared secret)`.

---

## 7. Keys over their life

All of these are admin actions, each recorded in the security log:

- **Register:** `fox app register <name> --role <db role> --key <public key file> [--max-life 5m] [--on-invalid none|refuse]`.
- **Rotate:** add a second key with a new `kid`, and remove the old one once applications have moved. Both are valid in between.
- **Revoke:** `fox app key revoke <kid>`. It takes effect at once on every running branch, and on a suspended one before it accepts a connection.
- **Compromised:** `fox app key revoke <kid> --compromised-since <time>` revokes the key and also marks every record asserted under it since that time. Reports show those records as `asserted by <app> (key reported compromised)`, never as plain `asserted`.

---

## 8. What is recorded, where

- **Blackbox:** the four fields go into **`bb.ledger_ext`**, keyed by ledger row: `app_actor`, `app_state`, `app_issuer` and `app_kid`. They do not go into `bb.schema_ledger`, whose rows are hash-chained. Adding fields to the chain would change what every existing row's hash covers, and the additive rule forbids that. `ledger_ext` already holds the richer recording for this reason.
- **Agent provenance (`bb.agent_sessions`):** the same four fields.
- **Row tracking (point 5.2):** the new `last_modified_for` column holds the application actor, with its state as a prefix (`asserted:<app>:<user>`, `claimed:<user>`, or empty).
- **Reports:** the access review (4.8) gains an "Applications" table: each registration, its role, keys and their age, revocations, and how many records were asserted under each key. Blackbox views show both identities.
- **pgAudit (F6):** F6 decides how its entries are joined to the application actor. It must not log the token.

---

## 9. Closing the rest of G1

Two paths still name the actor with a setting (section 2):

- **Engine agent sessions:** each gets a role of its own, `agent-session:<agent id>`, a member of `db_agent`, created on first use as agent keys' roles are. The Blackbox then reads the agent's name from `session_user`. Where the role cannot be made, the name is recorded as `claimed`, never as the actor.
- **The console's fallback to `db_client`:** it is refused, with the reason, instead of falling back. A console query is then always the signed-in person's own role.

The engine's superuser changes (policy, tracking, pipelines) stay as they are. A
superuser can attribute anything to anyone, which section 10 says plainly.

---

## 10. Threat model

| Who | Can they put a false name on a record? |
|---|---|
| An end user of the application | no: they never hold the key or the role |
| Someone holding a stolen token but not the application's database credentials | no: binding refuses it |
| The application itself (its key and its role) | **yes**: `asserted by <app>` means the application vouched. Its compromise is reported with `--compromised-since` |
| A client setting `fox.app.*` by hand | no: the MAC fails, and it is recorded as `none` with the failure noted |
| A database superuser, or whoever holds the install secret | **yes**, and outside any threat model a database can enforce on itself. Anchors (F3) are what make the record tamper-evident against them |

---

## 11. Prototype and its tests (Gate 0 exit)

**The prototype:**

- the extension;
- `bb.act_for`, `bb._app_actor()` and the MAC;
- `bb.app_issuers`;
- one recording path (Blackbox DDL) wired through.

It sits behind a flag and is not in a release.

**The suite must pass before any claim is made.** Every row is an integration
test in the test VM:

| Area | Cases |
|---|---|
| Signature | valid; one bit changed; another key; unknown `kid`; header `alg` HS256, `none`, RS256; malformed base64; oversized |
| Binding | the right role; another role with the same token (refused); a superuser session (refused) |
| Claims | expired; not yet valid; skew at ±30 s; life over the application's limit; wrong `aud`; wrong `branch` |
| Per transaction | one assertion then changes (asserted); a second assertion (refused); a hand-set `fox.app.actor` (none, noted); a hand-set MAC copied from another transaction (none); a session-level value carried into the next transaction (none) |
| Savepoints | asserted inside a savepoint then rolled back: changes and actor both gone; released: kept; nested |
| Pooling | one connection alternating between two users' transactions; a transaction that forgets to assert after one that did (none) |
| Keys | rotation overlap; revocation effective on the next transaction of a running branch and on a resumed one; compromise marking |
| Logs | the token absent from `current_query()`, the Blackbox, query history, `pg_stat_statements`, and the server log on success and on error |
| Every path | Gateway, console, API, MCP, agent keys: each records the right database actor, and an application actor only where one was asserted |
| Cost | `bb.act_for` under 0.5 ms; a 10,000-row `UPDATE` on a tracked table within 5% of today |
| Extension | fuzzed inputs never crash a backend |

---

## 12. Decisions, and what follows

| Decision | Recommendation |
|---|---|
| Signature checking | B: the `fox_ed25519` extension. No shared-secret mode in Gate 1 |
| Savepoints | Rolled back with their changes (5.3), changing one sentence of the review plan |
| G1's remainder | A role per engine agent session; no console fallback (section 9) |
| Default on an invalid token | `none`, with the reason recorded; `refuse` per application |
| Token life | 5 minutes by default, at most 60 |

**Once these are agreed, the work in order, each its own PR:**

1. **Gate 0, the prototype and the suite above.** The extension in the image; `bb.act_for`; the MAC; Blackbox DDL wired.
2. **Gate 1, the product:**
   - `fox app` registration, the API and the console;
   - recording in provenance and row tracking, which delivers 5.2's `last_modified_for`;
   - the access review's Applications table;
   - G1's remainder (section 9);
   - client helpers in the TypeScript and Python SDKs (`withActor(token, fn)`);
   - the public wording in section 3 of the review plan.

**Still open, for the founders or the expert:**

- Whether `asserted` tokens should also be accepted from a customer's OIDC provider in Gate 1, or later.
- Whether `refuse` should become the default for applications registered after a date.
