# Point 13: the Aadhaar vault — design

**Status:** proposed for agreement. Two decisions were taken before writing,
on 13 November 2026 (section 16, decisions 1 and 2). This answers point 13 of
the review plan (`docs/FOX_Expert_Review_Plan.md`, point 13): an Aadhaar Data
Vault for entities that do not have one. It was written against `main` at
`8dc47ad`, after the Aadhaar exposure report (4.5, #232 and #233) shipped.

UIDAI's Circular No. 14 of 2025 was read in full (section 2). What this
design says about a PKCS#11 token was checked on SoftHSM2 2.6.1 in a
throwaway container in the test VM (section 3), not taken from documentation
alone. The scripts are in `docs/p13/`. Claims that still need the prototype
are marked **(prototype)**.

**What a reader is asked to decide** (section 16 lists each with the
recommendation):

1. *(agreed 13 Nov)* The vault talks to an HSM through PKCS#11 from the first
   build. FoxByte's own software key is a SoftHSM2 token behind the same
   interface, labelled "not UIDAI-compliant: trials and testing only".
2. *(agreed 13 Nov)* One vault per install: a separate database, in its own
   container and its own network, reached only through FoxByte's vault
   service. Never a schema inside each branch.
3. Each number is encrypted inside the HSM, one call per record, rather than
   with a data key unwrapped into memory (section 5).
4. One reference key per number, found again through a keyed index that is
   computed in the HSM and never leaves the vault (section 6).
5. Two reference-key formats: an opaque one by default, and a 12-digit one
   for legacy columns that cannot hold anything else (section 6).
6. Detokenising is its own permission, granted by admins only, with a stated
   purpose on every call, every call logged, and a rate limit (section 8).

---

## 1. What the vault will be, and what it will not

**It will be:** the one place where an install keeps Aadhaar numbers, and
the eKYC data that comes with them.
- Applications hand a number to the vault and keep the **reference key** it
  returns. Their own tables hold only reference keys.
- Each number is encrypted with AES-256 inside an HSM. FoxByte never holds
  the key, and neither does the vault's database.
- Getting the number back (**detokenising**) is a separate, audited
  permission.
- Every access is logged in a hash-chained log, and the evidence a UIDAI
  audit asks for comes from one command.
- Numbers already sitting in ordinary tables, which the exposure report (4.5)
  finds, can be moved into the vault, with reference keys left behind, on a
  branch first.

**It will not be:**
- **The HSM.** The customer supplies a FIPS 140-2 Level 3 HSM, on premises or
  on a MeitY-empanelled Government Community Cloud. FoxByte talks to it. The
  software token FoxByte ships is for trials and tests, and says so
  everywhere.
- **The customer's hosting, network zone or SOC 2 audit.** The circular puts
  these on the entity (section 2). FoxByte isolates the vault on the machine
  it runs on; the network zone around that machine is the customer's.
- **Protection from the HSM's own administrators**, or from someone who has
  both the token's PIN and the HSM. That is the HSM's job.
- **Masking.** Masking (point 7) hides values from people who should not see
  them. The vault takes the numbers out of the business database altogether.
- **An integration with another vault product.** That needs the other
  product's own API; one is named once a design partner picks it (plan,
  phase 3).

---

## 2. What UIDAI requires: Circular No. 14 of 2025

The circular is dated 4 November 2025. It supersedes the 2017 vault circular
(25 July 2017) and Circular 8 of 2025. It is read together with the 2017 HSM
circular (22 June 2017). This table is the mapping the plan asks to keep
under version control. Each row says whether FoxByte meets the clause, or
whose job it is.

| Para | What it requires | How the vault meets it | Whose |
|---|---|---|---|
| 2 | Aadhaar numbers and connected data (such as eKYC XML) are kept in a separate secure database or system, the only place they are kept | A separate vault database, its own container and network (section 4); connected data stored encrypted beside the number (section 7) | FoxByte |
| 3 | Reference keys, demographic data and photos may stay in the local database, encrypted, as long as the number is not there | Branches keep reference keys; the exposure report checks that no number is left (section 14) | FoxByte, then the customer |
| 4 | No storing the number or related data from what a holder typed into an authentication or eKYC request | The authentication application's job; the exposure report finds numbers left in logs and tables | Customer; FoxByte reports |
| 5 | The vault is on premises, on a MeitY-empanelled GCC cloud, or a vault-as-a-service from a requesting entity | FoxByte runs wherever the customer installs it | Customer |
| 6 | GCC or vault-as-a-service: an annual SOC 2 Type II audit by a CERT-In empanelled auditor | Not FoxByte's; the evidence lists it as declared by the customer | Customer |
| 7(a) | A GCC or vault-as-a-service provider keeps each entity's vault logically separate | One vault per install (section 4) | FoxByte, per install |
| 7(b) | Each number has a reference key; the mapping is kept in the vault | The vault's records table (section 7) | FoxByte |
| 7(c) | Business systems store only the reference key | Applications call the vault; migration replaces numbers (phase 3) | FoxByte and the customer |
| 7(d) | A single logical instance per entity; access through internal systems only | One vault per install; no published port (section 10) | FoxByte |
| 7(e) | Encrypted with AES-256 or stronger | AES-256-GCM in the HSM (section 5) | FoxByte |
| 7(f) | HA and DR, at the same level of security; dual redundant links to the ASAs | Backups and a standby of the vault database (section 12); the HSM's keys at the DR site; the links are the customer's | Both |
| 7(g) | The vault and the referencing system in a highly restricted network zone | Inside the machine: an internal network with only the vault service (section 10). Around it: the customer's | Both |
| 7(h) | Only trusted channels and secure APIs; all access through authenticated applications with authentication, authorisation and logging | The vault API, behind FoxByte's sign-in and API keys; every call logged (sections 8 and 9) | FoxByte |
| 7(i) | Access control, monitoring and alerting against unauthorised access; strict IAM; all access logged and monitored | Permissions by admins only, rate limits, findings in `fox check`, the access log (sections 8 and 9) | FoxByte |
| 7(j) | Secure deletion and update, as the entity's retention policy requires | Delete and update by reference key; what lingers in backups and how it is shredded (section 11) | FoxByte |
| 7(k) | Recovering the number from one or many reference keys must not be computationally feasible. **Hashing the number is not allowed as a reference key** | Reference keys are random, with no relation to the number (section 6) | FoxByte |
| 8 | An HSM is **mandatory** for encrypting and decrypting vault data, on premises, on GCC, or with a vault-as-a-service | PKCS#11 from the first build (section 5) | FoxByte talks to it; the customer supplies it |
| 9 | The HSM is FIPS 140-2 Level 3 or higher, logically separate per entity, and supports key generation, secure key storage, multi-factor multi-role access control and audit logging | The customer's HSM. FoxByte generates keys in it and reads back that they cannot leave it (section 3); the certificate is declared by the customer | Customer |
| 10 | Authentication applications are hosted on premises or on GCC only | Not the vault's | Customer |

**Still to read:** the circular points to a 2025 FAQ on the vault, but its
link is unreadable in the PDF, and the 2017 FAQ the plan cites now returns
404. Both are to be found and read before Gate 1. If either changes a row
above, the table changes with it.

---

## 3. Checked on a throwaway token

SoftHSM2 2.6.1 (Debian bookworm's package), driven through PKCS#11 from
Python, in a throwaway container in the test VM. The scripts are
`docs/p13/probe-token.py` and `docs/p13/probe-attributes.py`, and
`docs/p13/run-probes.sh` runs both.

| Check | Result |
|---|---|
| Mechanisms the design needs | `CKM_AES_GCM`, `CKM_SHA256_HMAC`, `CKM_GENERIC_SECRET_KEY_GEN`, `CKM_AES_KEY_WRAP(_PAD)`: all supported |
| A wrong PIN | refused, `CKR_PIN_INCORRECT` |
| Keys seen without logging in | none: the keys are private objects |
| Reading a key's value | refused |
| Wrapping a key out with another key | refused, `CKR_KEY_UNEXTRACTABLE` |
| Making a key extractable afterwards | refused, `CKR_ATTRIBUTE_READ_ONLY` |
| What an evidence report can read back | `sensitive`, `extractable` false, `always_sensitive`, `never_extractable`, and `local` (made inside the token), all as set; the same after a restart |
| AES-256-GCM of a 12-digit number | 28 bytes (12 + a 16-byte tag), plus a 12-byte nonce kept beside it; it decrypts back |
| A ciphertext with one bit changed | refused |
| The right ciphertext under another reference key as associated data | refused, so a ciphertext cannot be moved to another record |
| HMAC-SHA-256 of the same number twice | the same 32 bytes |
| Speed, one session, one thread, from Python | encrypt about 32,000 a second (31 µs), decrypt about 30,000 (33 µs), HMAC about 41,000 (24 µs) |

**What this does not show:**
- **A real HSM's speed.** A network HSM adds a round trip to every call,
  typically a millisecond or less on a local network. The prototype measures
  what migration and lookups cost at 1 ms a call (section 17).
- **SoftHSM2's error codes on a failed tag.** It answers `CKR_GENERAL_ERROR`,
  not `CKR_ENCRYPTED_DATA_INVALID`. The service treats any decrypt failure as
  a record that does not verify, and logs it as one.
- **SoftHSM2's limit as a key store.** Its token is files on disk, encrypted
  under the PIN. Whoever has both the files and the PIN has the key. That is
  why it is labelled for trials only.

---

## 4. The shape: one vault per install

```
 applications, console, `fox vault`
            │  HTTPS, FoxByte sign-in or API key
            ▼
 ┌──────── fox (the engine) ────────┐
 │ vault API: who may do what,      │
 │ rate limits, the security log    │
 └──────────────┬───────────────────┘
                │ a socket only the engine can reach, a per-install secret
                ▼
 ┌──── vault service (container) ───┐      ┌──── the HSM ────┐
 │ PKCS#11 session, encrypt,        │─────▶│ data key, index │
 │ decrypt, index, reference keys   │      │ key: never out  │
 └──────────────┬───────────────────┘      └─────────────────┘
                │ vault network (internal: no route out)
                ▼
 ┌──── vault database (container) ──┐
 │ reference key, nonce, ciphertext │
 │ index, the access log            │
 └──────────────────────────────────┘
```

- **The vault database** is its own PostgreSQL, in its own container, on its
  own Docker network created `--internal`. It has no published port, and
  `FOX_DEBUG_PORTS` does not apply to it. It is not a branch: it is never
  cloned, branched, reset or promoted, and the Gateway, the console's SQL
  editor, agents and MCP cannot reach it.
- **The vault service** is a small program in its own container, on the vault
  network and on a second network the engine reaches. It holds the PKCS#11
  session, and it is the only thing that connects to the vault database. It
  answers only the engine, which proves itself with a per-install secret
  made when the vault is set up.
- **The engine** decides who may do what (section 8), applies the rate limits,
  and writes the security log. It never sees a key. It sees a number only
  while passing it between a caller and the vault service.

**Why a separate service, and not in `fox` itself.** PKCS#11 libraries are C
libraries that HSM vendors ship for Linux. `fox` is built without cgo, so that
one binary runs on every platform (the reason it uses a pure-Go SQLite). The
vault service is the one piece built with cgo, for Linux only, inside an image
beside the database image. A customer's HSM client library is mounted into it
read-only.

**Why not a schema in each branch** (decided 13 November). The circular asks
for a separate system and a single logical instance (para 2 and 7(d)). A
schema inside the business database is neither. Every branch would also copy
it, multiplying the vault. And a branch's database can open network
connections through dblink, so the vault's network is kept apart from the
branches' network as well.

---

## 5. The keys

- **Two keys, both made inside the HSM, neither able to leave it**
  (`sensitive`, not `extractable`):
  - the **data key**, AES-256, which encrypts each number and its connected
    data;
  - the **index key**, a 256-bit HMAC key, which finds a number again
    (section 6).
- **Every encrypt and decrypt is one call to the HSM** (decision 3). The
  number goes in, the ciphertext comes out. The data key is never unwrapped
  into the service's memory. This is the plainest reading of para 8,
  "encryption/decryption of ADV data" in the HSM, and section 3 shows a
  token keeps up.
  - *The alternative*, a data key wrapped by the HSM and unwrapped into
    memory, is faster on a slow network HSM, but the key then lives in a
    process the HSM cannot see. It is not proposed.
- **AES-256-GCM, with the reference key as associated data.** A ciphertext
  only decrypts under its own reference key (section 3), so copying a
  ciphertext to another record gets nothing.
- **Nonces** are 96 bits from the HSM's random generator, one per encryption,
  kept beside the ciphertext. A data key is retired well before 2³² uses, the
  limit for random GCM nonces **(prototype: count uses per key)**.
- **The PIN.** The service logs in to the HSM with the token's user PIN, kept
  in a file in the state directory, readable by the service's user only, and
  mounted read-only. Multi-factor, multi-role control of the HSM itself
  (para 9(c)) is the HSM's. FoxByte never has the security officer's PIN.
- **FoxByte's own key custody** (decided 13 November) is a SoftHSM2 token in
  the state directory, made by `fox vault setup` when no HSM is named. It
  uses the same code, so a trial becomes a real deployment by pointing the
  service at another library, then rotating (below). Everywhere the vault
  appears (the status line, the console, the evidence) it reads
  **"Software token: not UIDAI-compliant (trials and testing only)"**.
- **Rotation.** A new data key, or a new index key, is made in the HSM. Every
  record is read and written again, in batches, while the vault keeps
  answering **(prototype)**. Then the old key is destroyed in the HSM, which
  is also what shreds deleted numbers left in old backups (section 11).
- **Moving from the software token to an HSM** is a rotation across two
  tokens. The service holds both sessions, decrypts with the old one and
  encrypts with the new one, then the software token is deleted.

---

## 6. Reference keys

**Random, from the HSM's generator, with no relation to the number** (para
7(k)). Knowing any number of reference keys tells nothing about any number.

**Two formats** (decision 5):

| Format | Looks like | For | Space |
|---|---|---|---|
| Opaque (default) | `AR` and 26 characters of Crockford base32, e.g. `AR7Q2M…` | new tables and applications | 130 bits |
| 12 digits | a 12-digit number starting with **1** | legacy columns typed `char(12)`, `numeric(12)` or `bigint` that cannot hold anything else | 11 random digits: 10¹¹ |

- An Aadhaar number never starts with 0 or 1, so a 12-digit reference key
  can never be mistaken for one. The exposure report's check (12 digits, the
  first 2 to 9, passing Verhoeff) never flags it.
- Starting with 1 rather than 0 keeps all 12 digits in a `bigint`.
- A collision is refused by the vault's unique index and a new key drawn.
- The smaller space of the 12-digit format matters only for guessing a key
  and then detokenising it, which needs the detokenise permission and is
  rate-limited (section 8). It is stated in the evidence.

**One reference key per number** (decision 4). Tokenising a number already in
the vault returns its existing reference key. Applications need that: "is this
customer already here?" is asked of the number.
- The vault finds a number through an **index**: HMAC-SHA-256 of the number
  under the index key, computed in the HSM.
- **The index is not a reference key.** It never leaves the vault database.
  No API returns it, and no business table holds it. The circular forbids a
  hash used *as a reference key* (para 7(k)). A keyed index inside the vault
  is how a vault finds its own records.
- An auditor may still ask about it, so the evidence states it plainly: what
  it is, that its key is in the HSM, and that it never leaves the vault.
- *The alternative* is no index: every tokenise makes a new reference key,
  and nobody can ask whether a number is already there. It is not proposed,
  because applications then keep their own copy of the number to answer that
  question, which is the exposure the vault exists to end.
- **Per-application reference keys**, so two applications cannot match their
  customers through the vault's keys, are left for later: named domains, as
  masking has (point 7). The default is one domain per install.

---

## 7. What the vault stores

The vault database has two tables, in a schema only the vault service's role
can use.

- **`records`**: the reference key; the index; the nonce; the ciphertext of
  the number; the nonce and ciphertext of the connected data, if any; which
  data key and index key were used; when it was made and by whom; and when it
  was last changed.
- **`access_log`**: one row per call (section 9).

**Connected data** (para 2's eKYC XML) is stored only if the caller sends it,
encrypted the same way, up to a size limit **(prototype: pick the limit)**. A
caller asks for it back with the same detokenise permission.

**What stays outside**, as para 3 allows: names, addresses, photos and
UIDAI's own UID tokens may stay in business tables, encrypted by the
customer as they choose. Masking (point 7) is how FoxByte hides them from
people who should not see them.

---

## 8. Who may do what

| Action | What it does | Who |
|---|---|---|
| Tokenise | a number in, its reference key out (made if new) | an account or application given *vault use* by an admin; admins |
| Find | a number in, its reference key out, or "not in the vault"; never makes one | the same |
| Detokenise | a reference key in, the number out (and its connected data if asked) | only an account or application given *detokenise* by an admin, **with a stated purpose on every call** |
| Update, delete | replace or remove a record by its reference key | admins |
| Setup, rotate, evidence | the vault itself | admins; rotation and setup also the operator |

- **Admins grant both permissions** (decision 6), the way they grant unmask
  (point 7). Each grant is recorded, shown in the access review (4.8), and
  can carry an expiry.
- **Admins do not detokenise by being admins.** An admin who needs a number
  grants themselves detokenise, which is itself recorded and reviewed.
- **Agents and MCP never detokenise.** An agent key may be given vault use,
  to tokenise what it writes.
- **Masked accounts** (point 7) are never given detokenise. Granting it to one
  is refused.
- **Rate limits.** Each holder of detokenise has a limit per hour (default
  100, set per grant). Past it, calls are refused and a finding is raised.
  Tokenise and find have a much higher default limit, for applications.
- **Monitoring** (para 7(i)): `fox check` raises findings for refused calls,
  limits reached, records that do not verify, a software token in use, and a
  grant unused for 90 days.
- **The console**:
  - a Vault page for admins: the HSM, the keys and their ages, counts, grants,
    and the access log;
  - a detokenise box for holders, which asks the purpose, and shows the
    number masked to its last four digits until the holder chooses to reveal
    it.

---

## 9. The access log

- **Every call is a row:** when, who (account, application key or operator),
  which action, which reference key, the purpose, and the result (done,
  refused, not found, did not verify). **No number, ever:** a find or
  tokenise logs the reference key it returned, or none.
- **Hash-chained**, as the Blackbox is. Each row carries a hash of itself and
  of the row before it, so a deleted or changed row breaks the chain, and
  `fox vault evidence` checks it.
- **Copied to the security log**, one line per call, so the install's log of
  who did what has it too. Detokenise lines say whose reference key was read,
  never the number.
- **Kept** as long as the customer's retention policy says, at least a year
  by default **(to confirm against the 2025 FAQ)**.

---

## 10. The network, inside the machine

- The vault network is a Docker network created `--internal`: its containers
  have no route out, and nothing outside reaches them.
- On it are only the vault database and the vault service. The branches'
  network (where dblink could reach) and the object store are not.
- The vault service is also on a second network, to which only the engine
  connects. It refuses any caller without the per-install secret.
- A network HSM is reached from the vault service through the HSM vendor's
  client, so the service needs a route to that one address. This is set at
  `fox vault setup --hsm …`, and is the only route the vault has out
  **(prototype: an internal network plus one route; else a third network)**.
- What surrounds the machine (the restricted zone of para 7(g), firewalls,
  the dual links of 7(f)) is the customer's, and the evidence says so.

---

## 11. Deleting a number

- **Delete** removes the record and logs it. The reference key then answers
  "not in the vault" to everyone.
- **What lingers:** the ciphertext stays in the vault database's WAL and its
  backups until they expire. It is unreadable without the data key, but the
  data key still exists.
- **Shredding:** rotating the data key, then destroying the old one in the
  HSM, makes every ciphertext under it unreadable, in backups too. The
  evidence shows when each key was destroyed. The customer's retention policy
  sets how often this happens.
- **Update** replaces the number under the same reference key, logged as
  such.

---

## 12. Backups, HA and DR

- **Backups:** the vault database is backed up with wal-g to the object
  store, like main. A backup holds ciphertext, nonces and the index only.
- **Restoring** a backup is useless without the HSM keys it was made under.
  This is the point, and the evidence says it.
- **DR:** the DR site needs the same keys in its own HSM. HSM vendors copy
  keys between their own devices; FoxByte cannot, and does not try. For the
  software token, the token's files are backed up with the state directory.
- **A standby** of the vault database, on a second node, uses the standbys
  FoxByte already makes for main (`fox node`). It comes after the four phases
  **(later)**.

---

## 13. What stays the customer's

The evidence (phase 4) lists these as declared by the customer, never as
checked by FoxByte:

- where the vault is hosted (para 5), and the SOC 2 Type II report if on GCC
  (para 6);
- the HSM's FIPS 140-2 Level 3 certificate, by its CMVP number (para 9(a));
- the HSM's own access control and audit log (para 9(c));
- the network zone around the machine (para 7(g));
- the DR site and the dual links to the ASAs (para 7(f)).

---

## 14. Branches, the exposure report and migration

- **Branches** hold reference keys only, so branching, masking and the
  Blackbox need nothing new. A reference key is not Aadhaar.
- **The exposure report (4.5)** already reads every table and log. With a
  vault, it also counts reference keys it recognises (the `AR` format, and
  12-digit values the vault confirms), so "exposed numbers: 0, reference
  keys: 12,408" is one line in the evidence.
- **Migration** (phase 3), on a branch first:
  1. the exposure report's places give the columns to move;
  2. each distinct number is tokenised (one HSM call for the index, one to
     encrypt if new);
  3. each row's number is replaced by its reference key, in batches;
  4. the report is run again, and must find none left in those columns;
  5. the branch is promoted (`fox promote`) once the owner has checked it.
- **What migration does not do:** numbers in query history, the audit log and
  the Blackbox stay where they are. The report keeps listing them. The
  Blackbox is hash-chained and is not rewritten. History and audit text
  follow their own retention.
- **A discarded migration branch** leaves records in the vault that no table
  points to. `fox vault orphans` lists reference keys made by a migration
  whose branch is gone, and an admin can delete them.

---

## 15. Edition

Enterprise, as the plan proposes. The vault service image is published beside
the engine image, and the engine starts it only with an Enterprise licence.
Reference keys already in a Standard install's tables stay where they are.
Without the vault they are only values.

---

## 16. Decisions

| # | Decision | Recommended | Status |
|---|---|---|---|
| 1 | Keys | PKCS#11 HSM from the first build; SoftHSM2 as FoxByte's own key custody, labelled not compliant | **Agreed 13 Nov** |
| 2 | Where the vault lives | One vault per install: its own database, container and internal network, reached only through the vault service | **Agreed 13 Nov** |
| 3 | How numbers are encrypted | One HSM call per record (AES-256-GCM, reference key as associated data), never a data key in memory | Proposed |
| 4 | One reference key per number | Yes, through a keyed index computed in the HSM that never leaves the vault | Proposed |
| 5 | Reference key formats | Opaque `AR…` by default; 12 digits starting with 1 for legacy columns | Proposed |
| 6 | Detokenise | Its own permission, granted by admins only (admins included), a purpose on every call, every call logged, a rate limit per grant (default 100 an hour); never agents or masked accounts | Proposed |

---

## 17. Gate 0: the prototype

Built after agreement, in the test VM, with SoftHSM2:

- the vault service in Go with cgo (`github.com/miekg/pkcs11`, BSD-3), in an
  image from the same Debian base as the database image;
- the vault database and the two networks; the engine reaching the service
  with its secret, and nothing else reaching either;
- tokenise, find, detokenise and delete, through a test-only API.

**What it measures:**
1. **Calls a second**, one service, with SoftHSM2 and with a simulated 1 ms
   HSM round trip: tokenise, find, detokenise.
2. **Migrating 1,000,000 rows** with 200,000 distinct numbers: time, and how
   long a table's writes wait.
3. **Rotation** of 1,000,000 records while the vault keeps answering.
4. **The network:** from a branch's container, from the object store and
   from the host, the vault database cannot be reached; the service cannot
   be reached without the secret.
5. **Uses per data key**, against GCM's nonce limit.

---

## 18. Gate 1: the steps

| Step | What | CLI | Console |
|---|---|---|---|
| 13.1 | The vault: setup with the software token or a named HSM, the vault database and service, tokenise, find, detokenise, the access log | `fox vault setup [--hsm lib --slot s]`, `fox vault status`, `fox vault tokenise`, `find`, `detokenise --purpose` | Vault page: status, keys, counts |
| 13.2 | Permissions and limits: vault use and detokenise grants, rate limits, findings, the access review | `fox vault grant`, `revoke`, `grants` | grants, the detokenise box, the access log |
| 13.3 | Migration on a branch, from the exposure report's places; orphans | `fox vault migrate --branch b --column c`, `fox vault orphans` | Migrate from the exposure page |
| 13.4 | Evidence for UIDAI audits; rotation; delete and update | `fox vault evidence`, `fox vault rotate`, `delete`, `update` | Evidence page and download |

Each step comes with its CLI and console tests, an integration section in
the test VM, and the docs, as every point has.

---

## References

- UIDAI Circular No. 14 of 2025, 4 November 2025, "Revised guidelines for
  hosting Hardware Security Module (HSM), Aadhaar Data Vault (ADV) and
  authentication application on premises and cloud infrastructure":
  https://www.uidai.gov.in/images/Circular-No.14_of-2025.pdf
- PKCS#11 v2.40 (OASIS): the mechanisms and attributes in section 3.
- SoftHSM2: https://www.opendnssec.org/softhsm/ (BSD-2-Clause).
- `github.com/miekg/pkcs11` (BSD-3-Clause), for the prototype's service.
