# Point 13: the vault (Aadhaar first) — design

**Status:** agreed (#234, #235, 13 November 2026); decisions 4 to 8 taken as
recommended when the design merged. The Gate 0 prototype is built and its
suite passes (`make integration-p13`, 75 checks); what it found is in section
20, and it changes sections 10 and 11 where marked. This answers point 13 of the review plan
(`docs/FOX_Expert_Review_Plan.md`, point 13). The plan asks for an Aadhaar
Data Vault for entities that do not have one. This design builds a **general
vault** for sensitive values, and Aadhaar is its first kind, held to UIDAI's
rules. It was written against `main` at `8dc47ad`, after the Aadhaar exposure
report (4.5, #232 and #233) shipped.

UIDAI's Circular No. 14 of 2025 was read in full (section 3). What this
design says about a PKCS#11 token was checked on SoftHSM2 2.6.1 in a
throwaway container in the test VM (section 4), not taken from documentation
alone. The scripts are in `docs/p13/`. Claims that still need the prototype
are marked **(prototype)**.

**What a reader is asked to decide** (section 17 lists each with the
recommendation):

1. *(agreed 13 Nov)* The vault talks to an HSM through PKCS#11 from the first
   build. FoxByte's own software key is a SoftHSM2 token behind the same
   interface, labelled as not compliant wherever a kind's rules require an
   HSM (Aadhaar's do).
2. *(agreed 13 Nov)* One vault per install: a separate database, in its own
   container and its own network, reached only through FoxByte's vault
   service. Never a schema inside each branch.
3. *(agreed 13 Nov)* A general vault with **kinds**. Each kind has its own
   check, keys, reference-key formats, permissions and rules. Aadhaar is the
   first kind, and keeps every UIDAI rule (section 2).
4. Each value is encrypted inside the HSM, one call per record, rather than
   with a data key unwrapped into memory (section 6).
5. One reference key per value within a kind, found again through a keyed
   index that is computed in the HSM and never leaves the vault (section 7).
6. Reference-key formats: an opaque one for every kind, with the kind in its
   prefix, and a format-preserving one per kind for legacy columns that
   cannot hold anything else (section 7).
7. Detokenising is its own permission per kind, granted by admins only, with
   a stated purpose on every call, every call logged, and a rate limit
   (section 9).
8. The first build ships two kinds: Aadhaar, and a general text kind with no
   check. PAN, card numbers and the others follow as small steps (section 2).

---

## 1. What the vault will be, and what it will not

**It will be:** the one place where an install keeps its most sensitive
values: Aadhaar numbers first, and then PAN, card numbers, bank accounts,
passport numbers, or any value a customer chooses.
- Applications hand a value to the vault and keep the **reference key** it
  returns. Their own tables hold only reference keys.
- Each value is encrypted with AES-256 inside an HSM. FoxByte never holds
  the key, and neither does the vault's database.
- Getting the value back (**detokenising**) is a separate, audited
  permission.
- Every access is logged in a hash-chained log. The evidence an auditor asks
  for comes from one command, against the rules of each kind (UIDAI's for
  Aadhaar).
- Values already sitting in ordinary tables can be moved into the vault, with
  reference keys left behind, on a branch first. For Aadhaar, the exposure
  report (4.5) finds them; for other kinds, the PII scanner's confirmed
  marks (4.1, 4.6) do.

**It will not be:**
- **A secrets manager.** Passwords, API keys and certificates that programs
  use belong in a secrets manager (HashiCorp Vault and the like). This vault
  keeps personal data that people and applications refer to by a reference
  key, and rarely read back.
- **The HSM.** For Aadhaar the customer supplies a FIPS 140-2 Level 3 HSM, on
  premises or on a MeitY-empanelled Government Community Cloud. FoxByte talks
  to it. The software token FoxByte ships is for trials and tests, and says so
  wherever a kind's rules require an HSM.
- **The customer's hosting, network zone or audits.** UIDAI's circular puts
  these on the entity (section 3). FoxByte isolates the vault on the machine
  it runs on; the network zone around that machine is the customer's.
- **Protection from the HSM's own administrators**, or from someone who has
  both the token's PIN and the HSM. That is the HSM's job.
- **Masking.** Masking (point 7) hides values from people who should not see
  them. The vault takes the values out of the business database altogether.
- **An integration with another vault product.** That needs the other
  product's own API; one is named once a design partner picks it (plan,
  phase 3).

---

## 2. Kinds

A **kind** is what a value is. The vault's machinery (the HSM, encryption,
reference keys, the access log, permissions, migration) is the same for
every kind. What differs is in the kind:

| Part of a kind | What it says | Aadhaar's |
|---|---|---|
| Check | what a value must look like before it is stored; a value that fails is refused | 12 digits, the first 2 to 9, passing Verhoeff (the PII scanner's own check, 4.1) |
| Normal form | how a value is written before it is indexed, so the same value is found again | digits only: spaces and hyphens removed |
| Keys | its own data key and index key in the HSM, so kinds never share a key | `vault-aadhaar-data-<n>`, `vault-aadhaar-index-<n>` |
| Reference-key formats | the opaque format, with the kind's prefix; a legacy format that can never pass the check | `AR…`; 12 digits starting with 1 |
| Connected data | what may be stored with a value | the eKYC XML (para 2) |
| HSM required | whether the kind's rules require an HSM; if so, a software token is shown as not compliant | yes (para 8) |
| Display | how a value is shown to someone allowed to see it, before they choose to reveal it | the last four digits |
| Where it is found | what finds values of the kind outside the vault | the exposure report (4.5) |
| Rules | the regulation its evidence is checked against | UIDAI Circular No. 14 of 2025 (section 3) |

**The kinds, and when** (decision 8):

| Kind | Check | Prefix | Rules | When |
|---|---|---|---|---|
| Aadhaar | as above | `AR` | UIDAI Circular No. 14 of 2025 | 13.1 |
| Text | none: any value up to a size limit, as given | `TX` | none of its own; the customer's | 13.1 |
| PAN | the scanner's PAN check | `PN` | mapped when built | after 13.4 |
| Card number | the scanner's Luhn check, 13 to 19 digits | `CN` | PCI DSS, mapped when built | after 13.4 |
| Bank account, passport, voter ID, phone, email | the scanner's checks, where it has one | own prefix | mapped when built | as customers ask |

- **The text kind** is for anything without a kind of its own. It has no
  check, so it cannot have a legacy format, and its evidence says only what
  the vault does, against no regulation.
- **A new kind is code, not configuration.** A kind's check and legacy
  format decide what is safe to store and what can never be mistaken for a
  real value, so each is reviewed and tested like any other feature. A
  customer cannot define one at run time **(later: customer-defined kinds
  with the text kind's limits)**.
- **Each kind's rules** are mapped clause by clause, as UIDAI's are in
  section 3, when the kind is built, never before. Until then the evidence
  says "no rules mapped".

---

## 3. Aadhaar's rules: UIDAI Circular No. 14 of 2025

The circular is dated 4 November 2025. It supersedes the 2017 vault circular
(25 July 2017) and Circular 8 of 2025. It is read together with the 2017 HSM
circular (22 June 2017). This table is the mapping the plan asks to keep
under version control. Each row says whether FoxByte meets the clause, or
whose job it is. It applies to the Aadhaar kind; most of it is how the vault
works for every kind.

| Para | What it requires | How the vault meets it | Whose |
|---|---|---|---|
| 2 | Aadhaar numbers and connected data (such as eKYC XML) are kept in a separate secure database or system, the only place they are kept | A separate vault database, its own container and network (section 5); connected data stored encrypted beside the number (section 8) | FoxByte |
| 3 | Reference keys, demographic data and photos may stay in the local database, encrypted, as long as the number is not there | Branches keep reference keys; the exposure report checks that no number is left (section 15) | FoxByte, then the customer |
| 4 | No storing the number or related data from what a holder typed into an authentication or eKYC request | The authentication application's job; the exposure report finds numbers left in logs and tables | Customer; FoxByte reports |
| 5 | The vault is on premises, on a MeitY-empanelled GCC cloud, or a vault-as-a-service from a requesting entity | FoxByte runs wherever the customer installs it | Customer |
| 6 | GCC or vault-as-a-service: an annual SOC 2 Type II audit by a CERT-In empanelled auditor | Not FoxByte's; the evidence lists it as declared by the customer | Customer |
| 7(a) | A GCC or vault-as-a-service provider keeps each entity's vault logically separate | One vault per install (section 5) | FoxByte, per install |
| 7(b) | Each number has a reference key; the mapping is kept in the vault | The vault's records table (section 8) | FoxByte |
| 7(c) | Business systems store only the reference key | Applications call the vault; migration replaces numbers (13.3) | FoxByte and the customer |
| 7(d) | A single logical instance per entity; access through internal systems only | One vault per install; no published port (section 11) | FoxByte |
| 7(e) | Encrypted with AES-256 or stronger | AES-256-GCM in the HSM (section 6) | FoxByte |
| 7(f) | HA and DR, at the same level of security; dual redundant links to the ASAs | Backups and a standby of the vault database (section 13); the HSM's keys at the DR site; the links are the customer's | Both |
| 7(g) | The vault and the referencing system in a highly restricted network zone | Inside the machine: an internal network with only the vault service (section 11). Around it: the customer's | Both |
| 7(h) | Only trusted channels and secure APIs; all access through authenticated applications with authentication, authorisation and logging | The vault API, behind FoxByte's sign-in and API keys; every call logged (sections 9 and 10) | FoxByte |
| 7(i) | Access control, monitoring and alerting against unauthorised access; strict IAM; all access logged and monitored | Permissions by admins only, rate limits, findings in `fox check`, the access log (sections 9 and 10) | FoxByte |
| 7(j) | Secure deletion and update, as the entity's retention policy requires | Delete and update by reference key; what lingers in backups and how it is shredded (section 12) | FoxByte |
| 7(k) | Recovering the number from one or many reference keys must not be computationally feasible. **Hashing the number is not allowed as a reference key** | Reference keys are random, with no relation to the number (section 7) | FoxByte |
| 8 | An HSM is **mandatory** for encrypting and decrypting vault data, on premises, on GCC, or with a vault-as-a-service | PKCS#11 from the first build (section 6) | FoxByte talks to it; the customer supplies it |
| 9 | The HSM is FIPS 140-2 Level 3 or higher, logically separate per entity, and supports key generation, secure key storage, multi-factor multi-role access control and audit logging | The customer's HSM. FoxByte generates keys in it and reads back that they cannot leave it (section 4); the certificate is declared by the customer | Customer |
| 10 | Authentication applications are hosted on premises or on GCC only | Not the vault's | Customer |

**Still to read:** the circular points to a 2025 FAQ on the vault, but its
link is unreadable in the PDF, and the 2017 FAQ the plan cites now returns
404. Both are to be found and read before Gate 1. If either changes a row
above, the table changes with it.

---

## 4. Checked on a throwaway token

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
  what migration and lookups cost at 1 ms a call (section 18).
- **SoftHSM2's error codes on a failed tag.** It answers `CKR_GENERAL_ERROR`,
  not `CKR_ENCRYPTED_DATA_INVALID`. The service treats any decrypt failure as
  a record that does not verify, and logs it as one.
- **SoftHSM2's limit as a key store.** Its token is files on disk, encrypted
  under the PIN. Whoever has both the files and the PIN has the key. That is
  why it is labelled for trials only.

---

## 5. The shape: one vault per install

```
 applications, console, `fox vault`
            │  HTTPS, FoxByte sign-in or API key
            ▼
 ┌──────── fox (the engine) ────────┐
 │ vault API: kinds and their       │
 │ checks, who may do what, rate    │
 │ limits, the security log         │
 └──────────────┬───────────────────┘
                │ a socket only the engine can reach, a per-install secret
                ▼
 ┌──── vault service (container) ───┐      ┌──── the HSM ─────┐
 │ PKCS#11 session, encrypt,        │─────▶│ each kind's data │
 │ decrypt, index, reference keys   │      │ and index keys:  │
 └──────────────┬───────────────────┘      │ never out        │
                │ vault network            └──────────────────┘
                │ (internal: no route out)
                ▼
 ┌──── vault database (container) ──┐
 │ kind, reference key, nonce,      │
 │ ciphertext, index, access log    │
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
- **The engine** knows the kinds: it checks and normalises a value before the
  service sees it, decides who may do what (section 9), applies the rate
  limits, and writes the security log. It never sees a key. It sees a value
  only while passing it between a caller and the vault service.

**Why a separate service, and not in `fox` itself.** PKCS#11 libraries are C
libraries that HSM vendors ship for Linux. `fox` is built without cgo, so that
one binary runs on every platform (the reason it uses a pure-Go SQLite). The
vault service is the one piece built with cgo, for Linux only, inside an image
beside the database image. A customer's HSM client library is mounted into it
read-only.

**Why not a schema in each branch** (decided 13 November). UIDAI's circular
asks for a separate system and a single logical instance (para 2 and 7(d)).
A schema inside the business database is neither. Every branch would also
copy it, multiplying the vault. And a branch's database can open network
connections through dblink, so the vault's network is kept apart from the
branches' network as well.

---

## 6. The keys

- **Each kind has two keys, both made inside the HSM, neither able to leave
  it** (`sensitive`, not `extractable`):
  - the **data key**, AES-256, which encrypts each value and its connected
    data;
  - the **index key**, a 256-bit HMAC key, which finds a value again
    (section 7).

  Separate keys per kind mean one kind can be rotated, or shredded, without
  touching another, and the same text stored as two kinds is never matched.
- **Every encrypt and decrypt is one call to the HSM** (decision 4). The
  value goes in, the ciphertext comes out. The data key is never unwrapped
  into the service's memory. For Aadhaar this is the plainest reading of
  para 8, "encryption/decryption of ADV data" in the HSM, and section 4 shows
  a token keeps up. Every kind works the same way, so there is one path to
  test.
  - *The alternative*, a data key wrapped by the HSM and unwrapped into
    memory, is faster on a slow network HSM, but the key then lives in a
    process the HSM cannot see. It is not proposed.
- **AES-256-GCM, with the kind and the reference key as associated data.** A
  ciphertext only decrypts under its own kind and reference key (section 4),
  so copying a ciphertext to another record gets nothing.
- **Nonces** are 96 bits from the HSM's random generator, one per encryption,
  kept beside the ciphertext. A data key is retired well before 2³² uses, the
  limit for random GCM nonces **(prototype: count uses per key)**.
- **One token per vault.** Every kind's keys are in the same token, so the
  vault has one HSM to configure, back up and audit. A kind whose rules
  require an HSM (Aadhaar) is shown as **not compliant** while that token is
  the software one. A kind whose rules do not (text) is shown as using a
  software token, with no verdict.
- **The PIN.** The service logs in to the HSM with the token's user PIN, kept
  in a file in the state directory, readable by the service's user only, and
  mounted read-only. Multi-factor, multi-role control of the HSM itself
  (para 9(c)) is the HSM's. FoxByte never has the security officer's PIN.
- **FoxByte's own key custody** (decided 13 November) is a SoftHSM2 token in
  the state directory, made by `fox vault setup` when no HSM is named. It
  uses the same code, so a trial becomes a real deployment by pointing the
  service at another library, then moving the keys (below). Wherever Aadhaar
  appears (the status line, the console, the evidence) it reads
  **"Software token: not UIDAI-compliant (trials and testing only)"**.
- **Rotation**, per kind. A new data key, or a new index key, is made in the
  HSM. Every record of the kind is read and written again, in batches, while
  the vault keeps answering **(prototype)**. Then the old key is destroyed in
  the HSM, which is also what shreds deleted values left in old backups
  (section 12).
- **Moving from the software token to an HSM** is a rotation of every kind
  across two tokens. The service holds both sessions, decrypts with the old
  one and encrypts with the new one, then the software token is deleted.

---

## 7. Reference keys

**Random, from the HSM's generator, with no relation to the value** (para
7(k)). Knowing any number of reference keys tells nothing about any value.

**Formats** (decision 6):
- **Opaque, for every kind (the default):** the kind's two-letter prefix and
  26 characters of Crockford base32, 130 random bits. `AR7Q2M…` is an
  Aadhaar reference key, `TX…` a text one. The prefix lets a person, the
  exposure report and the vault itself tell the kind apart without a lookup.
- **Legacy, per kind, for columns that cannot hold anything else**: a value
  shaped like the kind's own values that **can never pass the kind's check**,
  so it is never mistaken for a real one, by a person or by the PII scanner.
  A kind without a check (text) has no legacy format.
  - **Aadhaar's:** 12 digits starting with **1**, for columns typed
    `char(12)`, `numeric(12)` or `bigint`. An Aadhaar number never starts
    with 0 or 1, so the scanner's check (12 digits, the first 2 to 9, passing
    Verhoeff) never flags it. Starting with 1 rather than 0 keeps all 12
    digits in a `bigint`. 11 random digits: 10¹¹ keys.
  - Other kinds' legacy formats are designed with the kind, and shown to fail
    its check by a test.
- A collision is refused by the vault's unique index and a new key drawn.
- The smaller space of a legacy format matters only for guessing a key and
  then detokenising it, which needs the detokenise permission and is
  rate-limited (section 9). The evidence states it.

**One reference key per value, within a kind** (decision 5). Tokenising a
value already in the vault returns its existing reference key. Applications
need that: "is this customer already here?" is asked of the value.
- The vault finds a value through an **index**: HMAC-SHA-256 of the kind's
  normal form of the value, under the kind's index key, computed in the HSM.
- **The index is not a reference key.** It never leaves the vault database.
  No API returns it, and no business table holds it. UIDAI forbids a hash
  used *as a reference key* (para 7(k)). A keyed index inside the vault is how
  a vault finds its own records.
- An auditor may still ask about it, so the evidence states it plainly: what
  it is, that its key is in the HSM, and that it never leaves the vault.
- *The alternative* is no index: every tokenise makes a new reference key,
  and nobody can ask whether a value is already there. It is not proposed,
  because applications then keep their own copy of the value to answer that
  question, which is the exposure the vault exists to end.
- **Per-application reference keys**, so two applications cannot match their
  customers through the vault's keys, are left for later: named domains, as
  masking has (point 7). The default is one domain per install.

---

## 8. What the vault stores

The vault database has two tables, in a schema only the vault service's role
can use.

- **`records`**: the kind; the reference key; the index; the nonce; the
  ciphertext of the value; the nonce and ciphertext of the connected data, if
  any; which data key and index key were used; when it was made and by whom;
  and when it was last changed.
- **`access_log`**: one row per call (section 10).

**Connected data** is stored only if the kind allows it and the caller sends
it, encrypted the same way, up to a size limit **(prototype: pick the
limit)**. For Aadhaar it is the eKYC XML (para 2). A caller asks for it back
with the same detokenise permission.

**What stays outside**, as UIDAI's para 3 allows for Aadhaar: names,
addresses, photos and UIDAI's own UID tokens may stay in business tables,
encrypted by the customer as they choose. Masking (point 7) is how FoxByte
hides them from people who should not see them.

---

## 9. Who may do what

Every permission is **per kind**: being allowed to detokenise text says
nothing about Aadhaar.

| Action | What it does | Who |
|---|---|---|
| Tokenise | a value in, its reference key out (made if new); a value failing the kind's check is refused | an account or application given *vault use* for the kind by an admin; admins |
| Find | a value in, its reference key out, or "not in the vault"; never makes one | the same |
| Detokenise | a reference key in, the value out (and its connected data if asked) | only an account or application given *detokenise* for the kind by an admin, **with a stated purpose on every call** |
| Update, delete | replace or remove a record by its reference key | admins |
| Setup, rotate, evidence | the vault itself | admins; rotation and setup also the operator |

- **Admins grant both permissions** (decision 7), the way they grant unmask
  (point 7). Each grant is recorded, shown in the access review (4.8), and
  can carry an expiry.
- **Admins do not detokenise by being admins.** An admin who needs a value
  grants themselves detokenise, which is itself recorded and reviewed.
- **Agents and MCP never detokenise.** An agent key may be given vault use,
  to tokenise what it writes.
- **Masked accounts** (point 7) are never given detokenise. Granting it to one
  is refused.
- **Rate limits.** Each detokenise grant has a limit per hour (default 100,
  set per grant). Past it, calls are refused and a finding is raised.
  Tokenise and find have a much higher default limit, for applications.
- **Monitoring** (UIDAI para 7(i), and good practice for every kind):
  `fox check` raises findings for refused calls, limits reached, records that
  do not verify, a software token holding a kind that requires an HSM, and a
  grant unused for 90 days.
- **The console**:
  - a Vault page for admins: the HSM, each kind's keys and their ages,
    counts per kind, grants, and the access log;
  - a detokenise box for holders, which asks the purpose, and shows the value
    in the kind's display form (Aadhaar: the last four digits) until the
    holder chooses to reveal it.

---

## 10. The access log

- **Every call is a row:** when, who (account, application key or operator),
  which action, which kind, which reference key, the purpose, and the result
  (done, refused, not found, did not verify). **No value, ever:** a find or
  tokenise logs the reference key it returned, or none.
- **Hash-chained**, as the Blackbox is. Each row carries a hash of itself and
  of the row before it, so a deleted or changed row breaks the chain, and
  `fox vault evidence` checks it.
- **Its head anchored outside the vault** *(changed by the prototype, section
  20)*. A chain shows a row changed or removed from the middle, but not rows
  cut off the end. The running service remembers how long the log is; across
  a restart, Gate 1 records the head (sequence and hash) in the install's
  security log at every call, which FoxByte's anchors already cover, so a cut
  is seen afterwards too.
- **Copied to the security log**, one line per call, so the install's log of
  who did what has it too. Detokenise lines say whose reference key was read,
  never the value.
- **Kept** as long as the customer's retention policy says, at least a year
  by default **(for Aadhaar, to confirm against the 2025 FAQ)**.

---

## 11. The network, inside the machine

- The vault network is a Docker network created `--internal`: its containers
  have no route out, and nothing outside reaches them.
- On it are only the vault database and the vault service. The branches'
  network (where dblink could reach) and the object store are not.
- **The vault database also admits only the service's address and role**
  *(changed by the prototype, section 20)*. An internal network has no route
  out and no route from other networks, but the machine itself still reaches
  it through the network's bridge. So `pg_hba.conf` lets in the service's
  role from the service's fixed address only, and rejects everything else,
  the superuser included: the superuser works only from inside the database's
  container.
- The vault service is also on a second network, to which only the engine
  connects. It refuses any caller without the per-install secret.
- A network HSM is reached from the vault service through the HSM vendor's
  client, so the service needs a route to that one address. This is set at
  `fox vault setup --hsm …`, and is the only route the vault has out
  **(prototype: an internal network plus one route; else a third network)**.
- What surrounds the machine (UIDAI's restricted zone of para 7(g),
  firewalls, the dual links of 7(f)) is the customer's, and the evidence says
  so.

---

## 12. Deleting a value

- **Delete** removes the record and logs it. The reference key then answers
  "not in the vault" to everyone.
- **What lingers:** the ciphertext stays in the vault database's WAL and its
  backups until they expire. It is unreadable without the kind's data key,
  but that key still exists.
- **Shredding:** rotating a kind's data key, then destroying the old one in
  the HSM, makes every ciphertext under it unreadable, in backups too. The
  evidence shows when each key was destroyed. The customer's retention policy
  sets how often this happens, kind by kind.
- **Update** replaces the value under the same reference key, logged as
  such. The new value must pass the kind's check.

---

## 13. Backups, HA and DR

- **Backups:** the vault database is backed up with wal-g to the object
  store, like main. A backup holds ciphertext, nonces and the index only.
- **Restoring** a backup is useless without the HSM keys it was made under.
  This is the point, and the evidence says it.
- **DR:** the DR site needs the same keys in its own HSM. HSM vendors copy
  keys between their own devices; FoxByte cannot, and does not try. For the
  software token, the token's files are backed up with the state directory.
- **A standby** of the vault database, on a second node, uses the standbys
  FoxByte already makes for main (`fox node`). It comes after the four steps
  **(later)**.

---

## 14. What stays the customer's

The evidence (13.4) lists these as declared by the customer, never as checked
by FoxByte. For Aadhaar:

- where the vault is hosted (para 5), and the SOC 2 Type II report if on GCC
  (para 6);
- the HSM's FIPS 140-2 Level 3 certificate, by its CMVP number (para 9(a));
- the HSM's own access control and audit log (para 9(c));
- the network zone around the machine (para 7(g));
- the DR site and the dual links to the ASAs (para 7(f)).

Other kinds list their own when their rules are mapped.

---

## 15. Branches, finding values, and migration

- **Branches** hold reference keys only, so branching, masking and the
  Blackbox need nothing new. A reference key is not the value.
- **Finding values outside the vault:**
  - **Aadhaar:** the exposure report (4.5) already reads every table and log.
    With a vault, it also counts the reference keys it recognises (the `AR`
    prefix, and 12-digit values the vault confirms), so "exposed numbers: 0,
    reference keys: 12,408" is one line in the evidence.
  - **Other kinds:** the PII scanner's confirmed marks (4.1, 4.6) say which
    columns hold which category, and so which kind. A per-kind exposure
    report like Aadhaar's is a later step, if customers ask.
- **Migration** (13.3), on a branch first:
  1. the columns to move come from the exposure report's places (Aadhaar) or
     the confirmed marks (other kinds);
  2. each distinct value is checked against the kind and tokenised (one HSM
     call for the index, one to encrypt if new); a value that fails the check
     is listed and left alone;
  3. each row's value is replaced by its reference key, in batches;
  4. the columns are read again, and must hold no value of the kind;
  5. the branch is promoted (`fox promote`) once the owner has checked it.
- **What migration does not do:** values in query history, the audit log and
  the Blackbox stay where they are. For Aadhaar the exposure report keeps
  listing them. The Blackbox is hash-chained and is not rewritten. History
  and audit text follow their own retention.
- **A discarded migration branch** leaves records in the vault that no table
  points to. `fox vault orphans` lists reference keys made by a migration
  whose branch is gone, and an admin can delete them.

---

## 16. Edition

Enterprise, as the plan proposes. The vault service image is published beside
the engine image, and the engine starts it only with an Enterprise licence.
Reference keys already in a Standard install's tables stay where they are.
Without the vault they are only values.

---

## 17. Decisions

| # | Decision | Recommended | Status |
|---|---|---|---|
| 1 | Keys | PKCS#11 HSM from the first build; SoftHSM2 as FoxByte's own key custody, labelled not compliant for kinds that require an HSM | **Agreed 13 Nov** |
| 2 | Where the vault lives | One vault per install: its own database, container and internal network, reached only through the vault service | **Agreed 13 Nov** |
| 3 | What the vault holds | A general vault with kinds; Aadhaar first, under UIDAI's rules | **Agreed 13 Nov** |
| 4 | How values are encrypted | One HSM call per record (AES-256-GCM, the kind and reference key as associated data), never a data key in memory; each kind its own keys, one token per vault | Taken as recommended (merged, 13 Nov) |
| 5 | One reference key per value | Yes, within a kind, through a keyed index computed in the HSM that never leaves the vault | Taken as recommended (merged, 13 Nov) |
| 6 | Reference-key formats | Opaque with the kind's prefix (`AR…`, `TX…`) by default; a legacy format per kind that can never pass its check (Aadhaar: 12 digits starting with 1) | Taken as recommended (merged, 13 Nov) |
| 7 | Detokenise | Its own permission per kind, granted by admins only (admins included), a purpose on every call, every call logged, a rate limit per grant (default 100 an hour); never agents or masked accounts | Taken as recommended (merged, 13 Nov) |
| 8 | The first kinds | Aadhaar and text in 13.1; PAN and card numbers next; the rest as customers ask; kinds are code, not configuration | Taken as recommended (merged, 13 Nov) |

---

## 18. Gate 0: the prototype

Built after agreement, in the test VM, with SoftHSM2:

- the vault service in Go with cgo (`github.com/miekg/pkcs11`, BSD-3), in an
  image from the same Debian base as the database image;
- the vault database and the two networks; the engine reaching the service
  with its secret, and nothing else reaching either;
- the Aadhaar and text kinds, each with its own keys;
- tokenise, find, detokenise and delete, through a test-only API.

**What it measures:**
1. **Calls a second**, one service, with SoftHSM2 and with a simulated 1 ms
   HSM round trip: tokenise, find, detokenise.
2. **Migrating 1,000,000 rows** with 200,000 distinct numbers: time, and how
   long a table's writes wait.
3. **Rotation** of one kind's 1,000,000 records while the vault keeps
   answering, and the other kind untouched.

The results are in section 20.
4. **The network:** from a branch's container, from the object store and
   from the host, the vault database cannot be reached; the service cannot
   be reached without the secret.
5. **Uses per data key**, against GCM's nonce limit.

---

## 19. Gate 1: the steps

| Step | What | CLI | Console |
|---|---|---|---|
| 13.1 | The vault and its kinds (Aadhaar, text): setup with the software token or a named HSM, the vault database and service, tokenise, find, detokenise, the access log | `fox vault setup [--hsm lib --slot s]`, `fox vault status`, `fox vault tokenise --kind k`, `find`, `detokenise --purpose`, `fox vault kinds` | Vault page: status, kinds, keys, counts |
| 13.2 | Permissions and limits, per kind: vault use and detokenise grants, rate limits, findings, the access review | `fox vault grant --kind k`, `revoke`, `grants` | grants, the detokenise box, the access log |
| 13.3 | Migration on a branch, from the exposure report (Aadhaar) or the confirmed marks (other kinds); orphans | `fox vault migrate --branch b --column c --kind k`, `fox vault orphans` | Migrate from the exposure page and the PII page |
| 13.4 | Evidence per kind, against its rules (UIDAI's for Aadhaar); rotation; delete and update | `fox vault evidence [--kind k]`, `fox vault rotate --kind k`, `delete`, `update` | Evidence page and download |
| after | Further kinds: PAN and card numbers first, each with its check, legacy format, rules mapping and tests | `--kind pan`, `--kind card` | the same pages |

Each step comes with its CLI and console tests, an integration section in
the test VM, and the docs, as every point has.

---

## 20. What the prototype found (Gate 0)

Built in the test VM: the service (`enterprise/vault`, with the cgo part in
`enterprise/vault/hsm` and the command in `enterprise/vault/cmd/fox-vault`),
its image (`enterprise/vault/image`), and the suite
(`scripts/integration_p13.sh`, `make integration-p13`), which runs everything
in throwaway containers and networks and removes them. 75 checks pass. The
figures are from the test VM (4 Apple-silicon cores, 4 GB), with SoftHSM2, and
with a 1 ms delay added before every call to the token to stand for a network
HSM. The VM is shared and its speed varies, so each figure is the range over
two full runs.

**1. Calls a second**, one value a call, 8 calls at once, through the socket:

| Call | SoftHSM2 | 1 ms HSM | Calls to the token |
|---|---|---|---|
| Tokenise a new value | 1,477–2,696 (p99 6–20 ms) | 1,077–1,085 (p99 15 ms) | 4: index, random key, random nonce, encrypt |
| Find | 2,478–3,880 | 3,282–3,684 | 1: index |
| Detokenise | 2,966–3,949 | 3,363–3,921 | 1: decrypt |

- The token is not what limits these: from Python it did 30,000 encryptions a
  second (section 4). Each call's own costs are: the HTTP round trip; one row
  in the access log, written one at a time because each row chains to the
  one before; and the database. That is why find and detokenise are as fast
  with a 1 ms token. Gate 1 writes the log in small groups (each still
  chained) if a customer needs more.
- Big calls go much faster: migration tokenises 1,000 values a call (below).

**2. Migrating 1,000,000 rows holding 200,000 distinct numbers**, on a branch:

| | SoftHSM2 | 1 ms HSM |
|---|---|---|
| Tokenising the 200,000 distinct numbers, 1,000 a call | 19–39 s (5,157–10,337 a second) | 168–170 s (about 1,180 a second) |
| Rewriting the 1,000,000 rows, 10,000 a batch | 4.7–8.5 s | 4.7–7.4 s |
| Longest batch, so the longest a write to those rows waits | 0.11–0.63 s | 0.12–0.30 s |
| Numbers left in the column | 0 | 0 |

A value that fails the kind's check is listed and left alone. The map of
number to reference key is an unlogged table, so it never reaches the WAL,
and it is dropped at the end. At 1 ms an HSM call, 10,000,000 distinct numbers
would take about 2.4 hours with 8 sessions; more sessions shorten it, as far
as the HSM allows.

**3. Rotating about 1,005,000 records while the vault answers.** 3 min 3 s to
3 min 53 s with SoftHSM2. Readers detokenised all the while (316,540 to
355,019 reads, p99 12–29 ms) and none failed, through the switch to the new key and the old key's
destruction. Every record ended under the new key; the text kind was not
touched. With a 1 ms HSM each record costs three calls (decrypt, random,
encrypt), so expect roughly three to four times as long **(not measured)**.

**4. The network:**
- The service listens on no TCP port at all. Docker's own DNS on 127.0.0.11
  is the only listener in its container.
- Its socket is mode 600, owned by the service's user, in a directory of
  mode 700.
- A call without the secret is refused, and the refusal is logged.
- From a branch's database, the vault database cannot be reached.
- Neither the vault database nor the service has a route out.
- **But the machine itself reaches the vault database's port**, through the
  internal network's bridge. What refuses it is `pg_hba.conf`: only the
  service's role, from the service's fixed address. Even with the service's
  password, the host is refused, and so is a container put on the vault
  network at another address. Section 11 now says so.

**5. Uses per data key:** counted across restarts, and equal to the records
made under the key (421,003 when the suite counts, against GCM's limit of
2³²).

**Also found:**
- **The chain** held over 1,012,091 entries. One entry changed in the
  database was found at that entry. An entry cut off the end was found only
  because the running service remembered the log's length. Section 10 now
  anchors the head, so a cut made across a restart is found too.
- **Nothing in the clear:** neither a dump of the vault database nor its WAL
  (16 MB read) holds a number or a text value; the access log holds reference
  keys only. The secret, the PIN and the database password are files of mode
  400, the service's own.
- **Tampering:** a ciphertext with one bit changed, or copied onto another
  record, does not verify. Each case is logged as such, and the record opens
  again once it is put back.
- **A number's other spellings** (spaces, hyphens) find the same reference
  key. The same digits stored as text get a text reference key under the text
  kind's own index key, so the two never match.
- **The image links no PKCS#11 library.** The library is loaded at run time,
  so a customer's HSM library is mounted in and named; nothing is rebuilt.
- **Some HSMs choose their own GCM nonce.** The service stores the nonce the
  token reports back, not the one it offered.
- **cgo:** the service is the only cgo code, built for Linux in a Go image of
  the same Debian release. Every other build, macOS and Windows included,
  gets a stub. `fox` stays cgo-free.

**What Gate 1 changes because of this:** the `pg_hba.conf` pin (section 11);
the log's head in the security log (section 10); the log written in groups if
calls a second matter; a real HSM's figures, on the first design partner's
device.

---

## References

- UIDAI Circular No. 14 of 2025, 4 November 2025, "Revised guidelines for
  hosting Hardware Security Module (HSM), Aadhaar Data Vault (ADV) and
  authentication application on premises and cloud infrastructure":
  https://www.uidai.gov.in/images/Circular-No.14_of-2025.pdf
- PKCS#11 v2.40 (OASIS): the mechanisms and attributes in section 4.
- SoftHSM2: https://www.opendnssec.org/softhsm/ (BSD-2-Clause).
- `github.com/miekg/pkcs11` (BSD-3-Clause), for the prototype's service.
