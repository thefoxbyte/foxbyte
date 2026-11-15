# FoxByte Blackbox anchor format — version 1

This document specifies the checkpoint **anchor files** FoxByte writes for its
Blackbox (formerly the Schema Ledger), so that anyone — including a security team that does not trust
FoxByte — can verify a ledger independently. The reference verifier is
`cmd/fox-verify` (open source, standard-library hashing in
`internal/ledger/integrity.go`), but nothing here depends on it.

Blackbox is stored in the database as `bb.schema_ledger`, and the identifiers
below (`ledger-anchor/1`, `fox ledger export`) keep their original names so
existing anchors and tools keep working.

## Why anchors exist

Every ledger row is hash-chained inside the database (`bb.schema_ledger`:
`prev_hash`, `row_hash`). A chain proves rows weren't changed *unless* someone
with superuser access rewrites the rows **and** recomputes every hash after them.
A checkpoint closes that gap: it records a Merkle root over a range of rows in a
file **outside** the database. Changing, removing or wiping anchored rows makes
the rows stop matching the anchor, however the chain was rewritten.

Anchors are only as safe as where they are kept. By default FoxByte writes them
read-only (mode `0444`) to `~/.fox/anchors/<branch>/`, on the machine its
administrator controls, so against that person the default proves nothing.
Keep them somewhere that person cannot rewrite:

- **An anchor target** (`fox blackbox anchor-target set s3://bucket …`): a
  bucket of its own, created with Object Lock, ideally in an account the
  database administrators do not control. Every anchor is copied there under
  `anchors/<branch>/` and locked in **COMPLIANCE** mode for the target's
  retention (365 days unless `--retention-days` says otherwise). Until then
  nobody can delete or overwrite it, the bucket's owner included. GOVERNANCE
  mode is not enough: anyone allowed to bypass governance retention can delete.
  A bucket without Object Lock is refused. `fox check` reports the target and
  any anchor waiting more than a day to be copied.
- **The backup target**, if one is set, also receives a copy, under its
  default retention, with the backup keys.
- `FOX_ANCHOR_DIR` can point at a write-once mount, and `FOX_ANCHOR_IMMUTABLE=1`
  marks files immutable (`chattr +i`) where the filesystem supports it.

Rows written after the most recent checkpoint are protected only by the hash
chain until the next checkpoint (default: every 10 minutes, or every 500 new
entries).

## File name and encoding

One JSON object per file, UTF-8, named `<to_id>.json` with `to_id` zero-padded
to 20 digits (for example `00000000000000000120.json`), so lexical order is
checkpoint order. A directory holds the anchors of exactly one branch.

## Fields

| Field | Type | Meaning |
|---|---|---|
| `format` | string | Always `ledger-anchor/1`. Reject anything else. |
| `algorithm` | string | Always `sha256-merkle-v1` (defined below). |
| `branch` | string | Branch the ledger belongs to. |
| `checkpoint_id` | integer | Id of the checkpoint row in `bb.ledger_checkpoints`. Informational. |
| `from_id` | integer | First ledger id covered (inclusive). |
| `to_id` | integer | Last ledger id covered (inclusive). |
| `entry_count` | integer | Number of ledger rows that existed with `from_id ≤ id ≤ to_id`. |
| `last_row_hash` | hex string | Recomputed row hash (below) of the row with id `to_id`. |
| `merkle_root` | hex string | Merkle root over the covered rows. |
| `prev_root` | hex string | `merkle_root` of the previous checkpoint; `""` for the first. |
| `created_at` | RFC 3339 time | When the checkpoint was taken (UTC). |

Consecutive checkpoints are contiguous: `from_id` equals the previous `to_id + 1`,
and `prev_root` equals the previous `merkle_root`. Ledger ids can have gaps (for
example rows removed before any checkpoint existed); a checkpoint covers whatever
rows exist in its id range and records how many in `entry_count`.

## Row hash

A row's hash is SHA-256 over these 14 values joined with `|`, NULL written as the
empty string, hex-encoded (lowercase):

```
prev_hash | id | at | actor | actor_kind | tool | session | branch |
command_tag | object_type | object_identity | statement | status | risk
```

`id` is decimal. `at` is the row's timestamp converted to UTC and written as
`YYYY-MM-DD HH:MM:SS`, followed by `.` and the microseconds with trailing zeros
removed when the fractional part is non-zero (PostgreSQL's
`(at AT TIME ZONE 'UTC')::text`). This is the same value as `bb._ledger_hash`.

Anchors use the **recomputed** row hash, not the stored `row_hash` column, so they
commit to the row contents themselves (legacy rows without a stored hash included).

## Merkle root (`sha256-merkle-v1`)

1. Order the covered rows by id.
2. Leaf for each row: `SHA-256(0x00 ‖ row_hash ‖ "|" ‖ ext_hash)`, where
   `row_hash` is the recomputed row hash as ASCII hex and `ext_hash` is the row's
   capture hash from `bb.ledger_ext.ext_hash` as ASCII hex (empty if the row has
   no capture row).
3. Combine each level pairwise: `SHA-256(0x01 ‖ left ‖ right)` over the raw
   32-byte digests. If a level has an odd number of nodes, duplicate the last one.
4. The single remaining node, hex-encoded, is `merkle_root`.

## Verifying

Given every ledger row and a branch's anchor files:

1. **Hash chain.** For each row with a stored `row_hash`, in id order: the
   recomputed row hash must equal `row_hash`, and `prev_hash` must equal the
   `row_hash` of the previous row that has one (`""` for the first).
2. **Anchor sequence.** Sort anchors by `to_id`. Each must have
   `from_id = previous.to_id + 1` and `prev_root = previous.merkle_root`.
3. **Each anchor.** Take the rows with `from_id ≤ id ≤ to_id`. Their count must
   equal `entry_count`, their Merkle root must equal `merkle_root`, and the
   recomputed hash of the last one must equal `last_row_hash`.

Any failure means the ledger no longer matches what was recorded. Rows outside
every anchor's range are reported as not yet anchored.

## Signatures

Anchors written since 22 Sep 2026 carry two more fields:

| Field | Type | Meaning |
|---|---|---|
| `key_id` | hex string | First 16 bytes of SHA-256 of the Ed25519 public key that signed it. |
| `signature` | base64 | Ed25519 signature over the signing payload below. |

The **signing payload** is these values, each followed by a newline (`\n`):

```
ledger-anchor-signature/1
format
algorithm
branch
checkpoint_id        (decimal)
from_id              (decimal)
to_id                (decimal)
entry_count          (decimal)
last_row_hash
merkle_root
prev_root
created_at           (UTC, RFC 3339 with nanoseconds, trailing zeros removed)
key_id
```

The private key is `~/.fox/anchor-signing.key` (or `FOX_ANCHOR_KEY`), which no
database can read; its public key is beside it with `.pub` added, and
`fox blackbox anchor-key` prints it. Verifying with a public key, anchors written
before signing existed (unsigned) are accepted only **before** the first signed
one: an unsigned anchor after a signed one fails, as does any signature that
does not match or was made by another key.

A signature proves an anchor was written by whoever holds the private key. It
does not help against someone who holds that key too — on one machine, its
administrator — so keep a copy of the anchors, or the key, where they are not.

## Using fox-verify

```bash
# with the public key, so a forged anchor is caught too
fox blackbox anchor-key > anchor.pub

# against a live branch, through the FoxByte gateway with an admin's API key
fox-verify --dsn 'postgresql://dbadmin:<api-key>@localhost:6432/main?sslmode=require' \
           --anchors ~/.fox/anchors/main --pubkey anchor.pub

# offline, against an export
fox ledger export main > main-ledger.jsonl
fox-verify --export main-ledger.jsonl --anchors ./anchors/main
```

Every hash covers the entry's statement, and a client login may read only the
text of its own entries (`bb.ledger_statement`), so `--dsn` needs an admin's
login (`fox admin grant`) or the superuser; anyone else verifies an export, or
asks the database to check its own chain with `SELECT * FROM bb.ledger_verify()`.

Exit status is `0` when intact, `1` when tampering is detected, `2` on a usage or
connection error. `--json` prints the full report.

### Against the anchor bucket

Whoever audits should not need anything from the machine they are auditing but
the ledger rows. With `--anchors-s3`, fox-verify reads the anchors straight from
the bucket they are locked in (`fox blackbox anchor-target`), with read-only keys
of the auditor's own:

```bash
export FOX_VERIFY_S3_SECRET_KEY=…          # or AWS_SECRET_ACCESS_KEY
fox-verify --export main-ledger.jsonl \
           --anchors-s3 s3://acme-anchors/anchors/main \
           --s3-endpoint https://s3.eu-west-1.amazonaws.com --s3-region eu-west-1 \
           --s3-access-key AKIA… --pubkey anchor.pub
```

It reads **every version** of every anchor, not the bucket's current listing,
because Object Lock protects versions, not names: a plain delete only adds a
delete marker on top, and an overwrite adds a new version. Each anchor's first
version is its anchor of record. These are reported as problems:

- a **delete marker** over an anchor (the locked version underneath is still
  checked);
- a **later version** that differs from the first (an attempt to rewrite it);
- **no anchor at the start** of `main`'s sequence (the earliest one continues
  an anchor the bucket does not have, unless older ones expired with their
  retention). Any other branch is a clone whose first anchor continues its
  parent's: the rows before it are anchored under the parent, which is noted,
  and checked with `--anchors-s3 …/anchors/<parent>`;
- **anchoring that has stopped**: rows the bucket has no anchor for, written
  longer ago than `--max-anchor-age` (24 hours by default).

Anchors not locked in COMPLIANCE mode, or whose retention the keys cannot read
(`s3:GetObjectRetention`), are noted. Given `--anchors` as well, the local files
are compared with the locked copies: one that differs was rewritten, one the
bucket lacks was never copied, one only the bucket has was removed here.

The keys need `s3:ListBucketVersions`, `s3:GetObjectVersion` and, to see each
anchor's lock, `s3:GetObjectRetention`. Requests are signed with AWS Signature
Version 4, by fox-verify itself, with no SDK.
