# F4: erasure across every copy FoxByte manages — design

**Status:** agreed (24 November 2026, #268). Decisions 1 to 4 were taken by
the user, and decisions 5 to 12 agreed as recommended, the same day
(section 18). The Gate 0 prototype is built and its suite passes (99/99 on
PostgreSQL 18 and 16); what it found is in section 21, and it changes sections
7 and 9 where marked. This answers point 11.2 of the review plan
(`docs/FOX_Expert_Review_Plan.md`, foundation F4 and point 11, phase 2):
erasing one person's personal data from every copy FoxByte manages, saying
what each copy still holds and when it clears, and never claiming more. It was
written against `main` at `69541d3`, after the DPDP inventory (11.1, #267),
masking (point 7) and the vault (point 13) shipped.

Every claim here about what PostgreSQL and ZFS keep was checked on throwaway
PostgreSQL 18.6 and 16.15 servers on a ZFS dataset in the test VM (section 3),
not taken from documentation alone. The script is `docs/f4/probe-erasure.sh`.
Claims that still need the prototype are marked **(prototype)**.

**This is FoxByte's design, not legal advice.** Section 8(7) of the Act asks
for erasure; what counts as erased on a disk is a question for the privacy
lawyer and the storage engineer the review plan names (section 20).

**Decided on 24 November 2026** (section 18; 5 to 12 as recommended there):

1. **What erasure does to a row** is set per table in the DPDP inventory:
   clear its personal columns (the default) or delete the row. FoxByte shows
   the plan with counts, then runs it on `main` in one transaction.
2. **Branches:** the same erasure runs on every branch. Branches made before
   it are listed for an admin to remake from the erased parent or delete; the
   "clears on" date waits for them. A maximum branch age flags forgotten ones.
3. **The Blackbox:** recorded `UPDATE` and `DELETE` text keeps placeholders
   for its literals from now on. Existing entries holding the person's value
   are redacted in place with a seal, as the security log is pseudonymised
   today, so the chain and its anchors still verify. Schema changes keep their
   exact text, and one holding the value is flagged.
4. **Restores:** a restore to a point before an open erasure is refused unless
   an admin records a decision. If they go ahead, the erasures are applied
   again on the restored copy before anyone can open it.

---

## 1. What erasure will be, and what it will not

**It will be:** one request, for one person, that

- finds the person's rows on every branch, from the values given and the
  columns a reviewer confirmed as personal data;
- shows what it will do, table by table, with counts, before it does it;
- clears or deletes those rows on `main` and on every branch, except where a
  law requires them to be kept;
- removes the person's values from the copies FoxByte keeps beside the data:
  the Blackbox, query history, the audit log's forensic text, the Aadhaar
  exposure report's places, and the vault;
- reports each copy's state, with its date and evidence, and one "clears on"
  date, the latest of them;
- keeps the person from coming back through a restore or a branch made from
  an old copy;
- lists the copies FoxByte cannot reach.

**It will not be:**

- **"Deleted from disk".** PostgreSQL's `VACUUM` makes space reusable; it
  does not overwrite it (section 3, E3–E4), and ZFS frees blocks without
  overwriting them. The promise is **"erased from every copy FoxByte
  manages"**, with the steps that make the old bytes unreachable through
  FoxByte, and the outcome that says when they are.
- **A search for a person by name.** FoxByte recognises the categories its
  scanner does (email, mobile, PAN, Aadhaar, card, UPI and the rest; no name
  and no free text). A person is found by those values, and by the rows that
  reference those rows (section 4).
- **Proof that nothing else holds the person.** Places nobody confirmed as
  personal data, derived data without lineage, and copies outside FoxByte
  are stated as limits, never implied reached.
- **A rights-request register.** The request records FoxByte's part of an
  erasure. Receiving the person's request, verifying who they are, and
  answering them stay with the customer's DPO and their own systems, as the
  founders decided on 5 November.

---

## 2. Today

What already exists, and what it leaves behind. The references are to `main`
at `69541d3`.

| Where | What it holds | What exists to remove it |
|---|---|---|
| **Branches** | Each is a ZFS clone of `<parent>@for-<branch>` (`internal/branch/storage.go`, `clone`). The snapshot lives as long as the branch, and is destroyed with it (`destroy`) | `fox branch delete`; `fox branch reset` remakes a branch from its parent under one lock, keeping its keys and owner (CLI only) |
| **Branch age** | ZFS `creation`, read by `branchMadeAt` (`internal/branch/maskkey.go`); `branch_owners.created` for branches made through the API | — |
| **Backups** | wal-g base backups and the WAL archive on the backup target (`objstore` by default). `FOX_BACKUP_RETAIN` full backups kept (default 7), one every `FOX_BACKUP_INTERVAL` (default 24h); `Prune` runs after each scheduled backup | Pruning only. FoxByte sets no Object Lock retention on backups; a bucket default applies if the customer set one |
| **Restores** | `fox restore --to`, `fox ledger revert`, `fox blackbox branch-before`, `fox backup restore` (an export tar), `fox pg upgrade --rollback` | Nothing refuses a restore for a reason other than a technical one |
| **The Blackbox** | `bb.schema_ledger.statement` is `current_query()`: all schema changes, `TRUNCATE`, and agents' `UPDATE` and `DELETE`, with every literal in the client's message. Hash-chained, append-only, anchored as a Merkle root of row hashes | Hidden from masked accounts and from `db_client` (`bb.ledger_statement`); a masked branch's starts afresh. No placeholders, no redaction |
| **Change requests** | `change_requests.entries` keeps each statement's SQL | — |
| **Query history** | `query_history.sql` in the account store, 90 days by default | `fox history purge [--user]`, per actor; no search by value across actors |
| **Audit log** | Default mode holds no statement text. Forensic mode keeps text in `forensic/<day>.jsonl.gz`, 30 days by default; the chain holds only its hash | `fox audit-log purge --user`, by login only |
| **Aadhaar exposure report** | `bb.aadhaar_places` and `aadhaar_log_places`: row keys and last four digits | — |
| **The vault** | The person's Aadhaar, encrypted, under a reference key the branches hold | `fox vault delete`; rotation destroys old keys |
| **Masks** | Shadow tables follow the base table's writes | Automatic |
| **Security log** | No values; emails and addresses of deleted accounts pseudonymised with a seal (`internal/auth/seclogprivacy.go`) | The seal is the precedent decision 3 follows |
| **Finding a person** | `fox subject find` counts matches in confirmed findings on running branches, by whole normalised value (`enterprise/pii/subject.go`) | Read-only; it states that stopped branches, the ledgers, the audit log and backups are not searched |

`docs/data-subject-requests.md` says today, plainly, that FoxByte does not
erase a person across the databases. This design is what changes that
sentence.

---

## 3. Checked on a throwaway server

PostgreSQL 18.6 and 16.15 (`postgres:18-bookworm`, `postgres:16-bookworm`),
each on its own ZFS dataset in the test VM, as FoxByte lays branches out.
5,003 rows; one deleted, one with its email and phone cleared, one with a
value large enough for TOAST deleted. The files were then read as someone
holding the disk would: by searching them for the values. Both versions gave
the same results.

| # | Question | Found |
|---|---|---|
| E1 | Before: are the values in the table's file, its index and TOAST? | Yes, each. |
| E2 | After `DELETE` and `UPDATE … SET email = NULL`, before `VACUUM` | The old versions are still in the file (dead tuples). |
| E3 | **After a plain `VACUUM`** | The deleted row's bytes were gone from the table's file; **the cleared row's old version was still there**, and the deleted email was still in the unique index's file. TOAST was clean. |
| E4 | Is that a tuple PostgreSQL still keeps? (`pageinspect`: every item, live or dead) | **No.** No heap item and no index item holds either value. What remains is **bytes in a page's free space**, left when `VACUUM` compacts the page, until something overwrites them. `INDEX_CLEANUP ON` changed nothing. |
| E5 | Live queries and statistics | Neither value is found; `pg_stats` holds neither. |
| E6 | The WAL | Both values are in `pg_wal` after the erasure; after three switches and checkpoints the segments holding them were gone. The **archive** keeps its copy until it is pruned. |
| E7 | **After `VACUUM FULL`** | The table and index are rewritten into new files, the old ones removed. **The whole data directory, WAL included, holds neither value.** |
| E8 | A branch made before the erasure (a snapshot of the parent, cloned) | The parent's snapshot and the branch both still hold both values. The snapshot keeps the parent's freed blocks alive (3.9 MB here). |
| E9 | The branch erased and rewritten too | The branch's files are clean, but **the snapshot it was cloned from still holds both values**, and ZFS refuses to destroy it while the branch exists. |
| E10 | The branch remade: deleted with its snapshot, cut again from the erased parent | Clean; the snapshot keeps nothing alive. |

**What this means.**

- **Removed from live queries is not removed from the files.** After
  `DELETE` or `UPDATE` and `VACUUM`, the values are unreachable by any query,
  but their bytes can stay in the table's and the index's free space. They
  are readable by the host administrator, or by a superuser reading raw pages
  (`pageinspect`), and they are **copied into every branch and base backup
  made afterwards**, because both copy whole files.
- **A rewrite removes them** from the branch's files: `VACUUM FULL` writes
  new files and removes the old (E7). It takes an `ACCESS EXCLUSIVE` lock for
  as long as it runs, so it is a step of its own (section 7).
- **A branch made before the erasure keeps its parent's old blocks** in its
  origin snapshot, whatever is done inside the branch (E9). Only deleting or
  remaking the branch frees them (E10). That is why decision 2 lists those
  branches and the date waits for them.
- **Freed is not overwritten.** ZFS returns freed blocks to the pool and
  reuses them later; nothing FoxByte does overwrites them. That stays a
  stated limit (section 15).

Found on the way: `zfs destroy -R`, which deleting a branch runs, also
destroys every branch made from that branch (checked on a throwaway dataset).
That is a separate fix, raised apart from this design.

---

## 4. Finding the person

A request names the person by one or more values: an email, a mobile number,
a PAN, an Aadhaar number, and so on, each with its category or recognised
from its shape, as `fox subject find` does.

**Matched rows.** On each branch, a row is the person's when a column a
reviewer **confirmed** as personal data, in the value's category, holds the
value, compared whole and normalised (`subjectSQL`, so `+91 98765 43210`
matches `9876543210`). A JSON path is matched the same way inside the
document.

**Referencing rows** (decision 5). A person is rarely one row: orders,
addresses and tickets refer to the customer by its key. FoxByte follows
foreign keys from each matched row to the rows that reference it, and
includes those that have confirmed personal columns of their own, transitively,
with each step shown in the plan. Rows that reference the person but hold no
personal data (an order's amount and date) are left, with the reference
cleared or kept as each table's action says.

**What is not found, and said so:** a value in a column nobody confirmed
(suggested or never scanned), in free text, under a different spelling, or
in a table no foreign key leads to. The plan lists the findings still
undecided on the affected tables, so a reviewer can decide them first.

**Aadhaar.** When the vault holds the person's number, the request finds it
through the vault (`find`), and the branches by its reference key. Where the
number is still in a column in the clear, it is matched as any value is.

---

## 5. The plan: what happens to each table

Each table's DPDP entry (11.1) gains an **on erasure** action, set with the
rest of the entry (decision 1):

| Action | What it does | For |
|---|---|---|
| `clear` (the default) | Sets the row's confirmed personal columns to `NULL`, or to the column's default where it is `NOT NULL` and has one; the row stays | Rows other records depend on: customers with orders, accounts with transactions |
| `delete` | Deletes the row | Rows that are only the person: a newsletter signup, a contact form |

- A column's own entry (11.1's override) sets its own action and its own
  retention, so `aadhaar_no` can be kept under PMLA while the rest of the row
  is cleared.
- **A `NOT NULL` column with no default** cannot be cleared. The plan says
  so for that table, and offers `delete` or a placeholder value the entry
  names (`--clear-to`).
- **A foreign key that refuses a delete** (`RESTRICT`), or one that would
  cascade into rows the plan does not list, stops the plan for that table
  before anything runs. `ON DELETE CASCADE` into listed rows is shown as such.
- **A table with no entry** (an 11.1 gap) gets `clear`, and the plan says it
  is the default and not a decision.
- **A unique constraint on a cleared column** keeps working: `NULL` is
  distinct in PostgreSQL.

**The plan is shown first:** per branch, per table, the action, the rows,
the columns, the retention exceptions (section 13) and the copies of
section 9. Nothing changes until an admin applies it.

**On `main`** the plan runs in one transaction: every table's statements, or
none. The Blackbox records agents' `UPDATE` and `DELETE`, not the engine's,
so the erasure's own statements are recorded by the request (section 16) and
the security log, never as text holding the values.

---

## 6. Every branch

The same plan runs on each branch (decision 2), each branch in its own
transaction, matched again on that branch: a branch may hold rows `main` no
longer has, or none at all.

| Branch | What happens |
|---|---|
| Running | Erased |
| Suspended | Woken, erased, left to suspend again |
| Agent branch | Erased, as any branch; the agent's session is not interrupted beyond the transaction's locks |
| Masked branch | Erased by row key: its masks are pseudonyms of the person, still personal data |
| Closed masked branch (being made, or failed) | Listed. A branch being made is finished first and then erased; a failed one is listed for deletion |
| The restore copy (`pg-restore`, `fox restore`) | Listed, with its time; FoxByte removes it on the admin's word |
| An upgrade's stashed datasets (`fox pg upgrade`, before `--finalize`) | Listed: they are the pre-upgrade copy and cannot be changed |
| HA standby | Follows `main` by physical replication, so it is erased with `main`; listed for its own archive |

**No new copies while it runs.** While a request runs, branch creation from
an affected branch waits for that branch's erasure to finish, under the
branch's lock (**prototype**: the order of locks with `createBranch`).

**Branches made before the erasure** keep the old blocks in their origin
snapshot (E9), so after the erasure each is listed with its age, its owner
and the date it was made, for an admin to **remake** (`fox branch reset
--from <parent>`, after the parent's erasure) or **delete**. Its "dependent
branches cleared" outcome is met when no branch made before the erasure is
left. A branch of a branch is listed under its own parent. (Remaking a branch
discards its work; that is the admin's call, never FoxByte's.)

**A maximum age for branches holding personal data** (decision 6). A
setting, `FOX_BRANCH_MAX_AGE` (off by default, 90 days suggested in the
docs). A branch older than it, on a table with confirmed personal data, is
flagged by `fox check`, on the dashboard and in every open request, because
it turns "clears on" into "never". It is flagged, not remade.

---

## 7. What the files keep: vacuum, then rewrite

After the statements, each affected table on each branch is vacuumed:
`VACUUM (INDEX_CLEANUP ON)` on the table, its TOAST and its indexes. That
meets **removed from live queries** (E3–E5).

The rewrite then removes the bytes left in free space (E7): `VACUUM FULL` of
each affected table, on each branch (decision 7).

- It holds an `ACCESS EXCLUSIVE` lock for as long as it runs, so the plan
  shows each table's size and an estimate.
- **Tables under a size limit** (`FOX_ERASURE_REWRITE_MAX`, default 1 GB) are
  rewritten as part of applying the plan.
- **Larger tables** are listed, for an admin to rewrite at a quiet time
  (`fox dpdp erase rewrite <request> [--table …]`). Until they are, the
  request's "rewritten in the files" outcome is open, and the "clears on"
  date for backups (section 11) cannot start.
- A rewrite needs free space for a second copy of the table; the plan checks
  the branch's quota first.
- Statistics (`pg_statistic`) can hold a column's most common values.
  FoxByte runs `ANALYZE` on each affected table afterwards, so they are
  recomputed without the person (none held the values in E5, but a common
  value would be). **(From the prototype, section 21, and F5's.)** `ANALYZE`
  writes new statistics rows and leaves the old ones in `pg_statistic`'s
  file, so `pg_statistic` is rewritten too (`VACUUM FULL pg_statistic`), and
  the WAL holding the old pages is switched out and recycled, as masked
  branches already do.

Because new branches and base backups copy whole files, the rewrite is what
stops the old bytes reaching copies made after the erasure.

---

## 8. The vault

When the person's Aadhaar number is in the vault:

- the vault record is deleted (`/v1/delete`), so its reference key no longer
  detokenises anywhere;
- the reference key is cleared from the branches as any personal column is;
- the vault database's own WAL and backups keep the ciphertext until they
  age out, as the vault design says (`docs/FOX_P13_Vault_Design.md`,
  section 12). The vault database is not backed up today, so only its WAL
  directory is listed.

A reference key held under a retention exception (KYC under PMLA) keeps its
vault record, and the exception is recorded against it (section 13).

---

## 9. Statement text: the Blackbox, history, the audit log, requests

### The Blackbox (decision 3)

**From now on, placeholders.** The text recorded for `UPDATE` and `DELETE`
(agents' changes, and blocked attempts) replaces every
literal with a placeholder: `UPDATE people SET email = $1 WHERE id = $2`.
Placeholders are made with PostgreSQL's own lexer, in FoxByte's C extension,
so quoted strings, `E''` strings, dollar quotes, numbers, comments and
quoted identifiers are told apart as the server tells them apart. A regular
expression cannot do that (**prototype**: the C function, and the trigger
calling it, with its cost on the write path measured).

- **Schema changes keep their exact text**: branch comparison and promotion
  replay it. A schema change whose text holds a value the request searches
  for (a `DEFAULT`, a `CHECK`, a comment) is flagged in the plan, never
  changed.
- **Where.** **(From the prototype, section 21.)** `datachanges.sql` takes a
  data change's text in six places: an agent's applied `UPDATE` and
  `DELETE`, a blocked one (no `WHERE`, or over its limit), a flagged one, and
  `TRUNCATE`, applied or blocked. All six get placeholders. The seventh use,
  the refusal of a `bb_` trigger, is a schema change and keeps its text.
- **Every edition.** Placeholders are a privacy fix for every Blackbox, not
  an Enterprise feature; they need no findings to work. What is lost is the
  literal values of an agent's `UPDATE`; the row itself is recovered, if
  needed, from the entry's transaction id (`fox blackbox branch-before`),
  which is kept.
- **Existing installs:** entries recorded before the change keep their text
  until a request finds a value in them.

**Existing entries holding the value: redacted with a seal.** On each
branch, the entries whose statement holds one of the request's values are
rewritten in place, every literal replaced by its placeholder, as the
security log pseudonymises an account today:

- the entry's `row_hash` is left as it was, so the chain and every anchor
  already signed still hold;
- a **seal** is written: a hash over the entry's original `row_hash` and its
  fields as they now stand;
- a chained Blackbox entry of its own (`ERASURE REDACT`) records the request,
  how many entries were redacted, and a digest of every seal, so a seal
  cannot be added, changed or removed afterwards without breaking an entry
  the anchors cover;
- `fox blackbox verify` checks an entry by its hash until it is redacted,
  and by its seal afterwards (**prototype**: the verifier, the anchors, and
  the export a masked account is refused).

A schema change's entry is never redacted (above). The append-only triggers
unlock only inside the redaction's own transaction, as the security log's do.

### Query history

Entries whose SQL holds one of the values are **deleted** for every actor,
not only the person's own, and the count recorded (decision 8). Parameters
are not stored, so there is nothing else to search. Saved queries holding a
value are listed for their owner, not deleted.

### The audit log

- **Default mode keeps no statement text**, so its records are kept under
  the logging exception until their retention ends (one year by default);
  their "clears on" is that date (`docs/FOX_F6_Audit_Design.md`, section 11).
- **Forensic text** holding a value is removed from its day file; the chain
  holds only the text's hash, so it still verifies.
- **Raw files** waiting to be collected (at most two days) are listed with
  the time they are removed.
- **Text forwarded to a SIEM** is outside FoxByte (section 14).

### Change requests

An applied, rejected or withdrawn request whose statement holds a value has
its SQL replaced by its placeholders. An **open** request is listed: changing
its statement would change what it applies. It is cleared once it is decided.

### Derived tables

The Aadhaar exposure report's places for the person's rows (`bb.aadhaar_places`,
`aadhaar_log_places`) are deleted, and so are the masking shadows' rows (they
follow the base table already).

---

## 10. Derived data

Embeddings, chunks, summaries and caches made from the person's data are
erased only where FoxByte can trace them. **It cannot yet:** point 4's
lineage is not built. Until it is, each request's "derived data" outcome
reads **not traced: FoxByte has no lineage for derived data**, never "done".
Columns of derived data that a reviewer confirmed as personal data (a
summary holding an email) are erased as any column is.

---

## 11. Backups and the WAL archive

Backups are never edited. They hold the person until they are pruned, and
the request says when that is.

- Data written before the erasure is in every base backup taken before the
  **rewrite** (section 7), and in the archived WAL before it. Base backups
  copy whole files, so one taken after the statements but before the rewrite
  still holds the bytes left in free space (E4).
- With `retain FULL N`, wal-g keeps WAL from the oldest kept backup on. So
  the last copy goes at the prune after the **N-th backup taken after the
  rewrite**: about *rewrite + interval × N*. With the defaults (daily, 7) that
  is 7 days.
- **Object Lock** on the backup bucket sets a floor: an object cannot be
  deleted until its retention ends, so the date is the later of the prune
  and *the last pre-rewrite object's write + the bucket's default retention*.
  FoxByte reads the bucket's default (`CheckTarget`) for this.
- **"Never", and why**, where no prune will come: backups switched off
  (`FOX_BACKUP_INTERVAL=off`), an earlier backup target left behind when the
  target changed, an upgrade's archive prefix, or a rewrite still open.
- **Export tars** (`fox backup export`, in `<state>/exports/`) and the HA
  standby's own archive are listed with their dates.

The outcome is **backup and WAL expiry pending** until that date, then met
once a prune after it has run (FoxByte checks the oldest kept backup's start).

---

## 12. Restores (decision 4)

A restore to a time before an open erasure would bring the person back. So
each of these is **refused** while a request it would undo is open (not yet
past its "clears on" date):

- `fox restore --to <time>` and `fox ledger revert --to`;
- `fox blackbox branch-before <entry>`, for an entry before the erasure;
- `fox backup restore` of an export tar made before it;
- `fox pg upgrade --rollback` to stashed datasets made before it.

An admin may go ahead with `--after-erasure reapply`, recording a reason.
The decision goes to the security log and to each request it touches. The
restored copy is then **erased again** before anyone can open it: each
request's plan runs on it by the **row keys** the request kept (section 16),
not by searching, then vacuum and rewrite. The restore copy is reachable
only on loopback until that has finished (**prototype**: holding
`pg-restore`'s port until the reapply has run).

The weekly restore check (`restore-check`) is exempt: it is removed as soon
as its probe row is read, and no one connects to it.

---

## 13. Retention exceptions

A table or column whose entry's retention reason is **`law`** (11.1) is not
erased: the law requiring it to be kept overrides s.8(7). The request records,
for that place, the entry's citation, and the date the period ends:

- when the period runs from an event FoxByte cannot see (the account closed,
  the contract ended), the requester gives that event's date, and the end is
  that date plus the period;
- without it, the request says "kept under *citation*; ends *N* years after
  *event*, date not given", and its "clears on" date cannot be given.

A `contract` reason is **not** an exception: a contract does not override
s.8(7). Such a place is erased, and the plan says why. At banks the exception
is the normal case: KYC records are kept at least five years after the
relationship ends (PML Rules, Rule 10). The exception is the inventory's
entry as it stood when the request was made, kept with the request, so a
later edit to the inventory does not change what was decided.

---

## 14. Copies outside FoxByte's reach

Listed in every request, never implied reached:

- **Exports**: every `data.export` from an affected branch, with who, when,
  the query's fingerprint and the row count; FoxByte cannot tell which held
  the person. Blackbox exports and whole-install tars are listed too (neither
  is recorded in the security log today; recording them is part of Gate 1).
- **Realtime subscribers**, who were sent the person's rows as they changed,
  and the realtime slots, whose retained WAL holds them until consumed.
- **Pipelines and continuous imports**, whose source holds the person and
  **will bring them back** on its next run; listed as a warning.
- **A SIEM** the audit log forwards text to.
- **Backups of the state directory**, which hold query history and the
  account store.
- **Freed disk blocks** (section 3).

---

## 15. The outcomes and the one date

Each request shows these, each with its date and its evidence:

| Outcome | Met when | Evidence |
|---|---|---|
| **Removed from live queries** | The plan ran on `main` and every branch, and each affected table was vacuumed | Per branch: rows cleared and deleted, by table; a search afterwards finding none |
| **Rewritten in the files** | Every affected table on every branch was rewritten (`VACUUM FULL`) | Per table: when, and its new file |
| **Logs and records cleared** | Blackbox entries redacted and sealed; history deleted; forensic text removed; change requests cleared | Counts; the seals' digest; the open requests and saved queries listed |
| **Vault record deleted** | The vault answered the delete | The vault's log entry |
| **Derived data** | Not traced (section 10) | The limit, stated |
| **Dependent branches cleared** | No branch made before the erasure is left | The branches, each remade or deleted, by whom |
| **Backup and WAL expiry pending** | A prune after the date of section 11 has run | The oldest kept backup's start |
| **Audit records aged out** | The default-mode records' retention passed | The retention and its date |
| **Retention exception** | Not erased: a law requires it | The citation, and the date it ends |
| **Outside FoxByte** | Never met by FoxByte | The list of section 14 |

**"Clears on"** is the latest date among the outcomes FoxByte meets, the
retention exceptions' end dates included. It is **"never"** while a branch
made before the erasure remains, or a backup will never be pruned, and it
says which.

**Re-checked, not assumed.** `fox dpdp erase status <request>` searches
again, on every branch, for the request's row keys, and reads the branches'
ages and the backups' dates, so an outcome can be lost again (a branch
restored, a backup target changed) and is shown as such.

---

## 16. What a request keeps

A request is evidence, so it must not become one more copy of the person
(decision 9):

- **No values.** The values are held in memory for the run and the searches
  of section 9, then dropped. The request keeps, per category, **the last
  four characters** of each value as the requester's reference, as the
  Aadhaar exposure report does.
- **Row keys**: for each branch and table, the primary key of each row
  cleared or deleted, so the erasure can be applied again after a restore,
  and re-checked, without the values. A table with no primary key uses its
  replica identity; one with neither is listed as erasable only by search.
- **The plan as applied**: actions, counts, exceptions with citations, and
  the inventory entries as they stood.
- **Who and when**: who made, previewed and applied it, each branch's time.

Requests live in the install's store, not in a branch: a branch can be
deleted or restored, and the request must outlive both.

---

## 17. Who, the edition, and the record

- **Admins only** make, preview and apply a request, and remake or delete
  the branches it lists (decision 10). A two-person rule (one admin
  prepares, another applies) is a setting for later, if a bank asks.
- **Enterprise**, under the `dpdp` licence feature, as the inventory is:
  making and applying requests. Reading requests and their evidence stays
  free, so an install whose licence lapses can still show what was done.
  Placeholders in the Blackbox, and the refusal of restores while a request
  is open, work in every edition (decision 11).
- **The security log** records each step without a value: `erasure.planned`,
  `erasure.applied`, `erasure.branch`, `erasure.rewritten`, `erasure.restore`
  (the admin's decision of section 12), `erasure.closed`.
- **The doors:** `fox dpdp erase new|plan|apply|status|list|rewrite`,
  `/api/dpdp/erasures`, and the console's **Erasure requests** page under
  Compliance. Not through MCP or the Agent API: erasure is a person's
  decision, not an agent's.

---

## 18. Decisions

| # | Decision | Decided (1–4 asked; 5–12 agreed as recommended, 24 November 2026) |
|---|---|---|
| 1 | What erasure does to a row | **Decided:** per table in the inventory, `clear` by default or `delete`; previewed, then one transaction on `main` (section 5) |
| 2 | Branches | **Decided:** erased on every branch; those made before it listed to remake or delete; "clears on" waits; a maximum age flags them (section 6) |
| 3 | The Blackbox | **Decided:** placeholders for `UPDATE`/`DELETE` from now on; existing entries redacted with a seal; schema changes kept and flagged (section 9) |
| 4 | Restores | **Decided:** refused while a request is open, unless an admin records a decision; then applied again before the copy opens (section 12) |
| 5 | Referencing rows | **Agreed:** Follow foreign keys to rows with confirmed personal columns of their own, transitively, each shown in the plan (section 4) |
| 6 | Maximum branch age | **Agreed:** A setting, off by default; flagged, never remade (section 6) |
| 7 | The rewrite | **Agreed:** `VACUUM FULL` for tables under 1 GB as part of applying; larger ones listed for an admin to run; the backups' date starts from it (section 7) |
| 8 | Query history | **Agreed:** Entries holding a value deleted for every actor; saved queries listed for their owners (section 9) |
| 9 | What a request keeps | **Agreed:** No values; the last four characters; row keys per branch and table (section 16) |
| 10 | Who | **Agreed:** Admins only; a two-person rule later, if asked (section 17) |
| 11 | Edition | **Agreed:** Requests Enterprise (`dpdp`), reading free; placeholders and the restore guard in every edition (section 17) |
| 12 | Sign-off | **Agreed:** The design and the build go ahead on the founders' agreement; the privacy lawyer's and the storage engineer's reviews recorded as open, as 11.1's lawyer's review is |

---

## 19. Gate 0: the prototype (built; section 21)

The claims marked **(prototype)**, proven in a suite like F5's
(`make integration-f4`, `scripts/integration_f4.sh`, with file checks in
`docker/postgres/f4_test.go`), on PostgreSQL 18 and 16, on ZFS:

- the placeholder function in C, with PostgreSQL's lexer, on a corpus of
  hard cases (quotes inside strings, `E''`, dollar quotes, comments holding
  quotes, quoted identifiers with digits, multi-statement messages), and its
  cost on the Blackbox's write path;
- redaction with a seal on a chain with anchors already written, then
  verified, and a tampered seal failing;
- a plan on a schema with `RESTRICT`, `CASCADE`, `NOT NULL` without default,
  and a table without a primary key (JSON paths moved to Gate 1 step 1,
  where the plan is built: they match as `fox subject find` already does);
- erasure on a branch made before it, then the remake, with the files
  searched as in section 3;
- a restore to before the erasure, re-applied by row keys before it opens.

## 20. Gate 1: the steps, once the prototype passes

| Step | What | CLI | Console |
|---|---|---|---|
| 1 | The request, the plan and `main`: matched and referencing rows, actions from the inventory, exceptions, vacuum, rewrite | `fox dpdp erase new`, `plan`, `apply`, `rewrite` | Erasure requests: new, plan, apply |
| 2 | Every branch; branches made before it; the maximum age | `fox dpdp erase status` | the branches list, remake and delete |
| 3 | Statement text: placeholders, the Blackbox's sealed redaction, history, forensic text, change requests, derived tables, the vault | | |
| 4 | Restores refused and re-applied | `--after-erasure reapply` | |
| 5 | The outcomes, "clears on", the copies outside reach, the evidence export; exports and tars recorded | `fox dpdp erase evidence` | evidence |

**Sign-off.** The review plan asks that a privacy lawyer and a storage-engine
engineer approve F4 together before erasure is built. Until they have, the
docs, the console and every request say that FoxByte's reading of erasure has
not been reviewed, as the inventory's mapping does (decision 12).

---

## 21. What the prototype found (Gate 0)

`make integration-f4`: **99 passed, 0 failed**, on PostgreSQL 18.6 and 16.15,
on throwaway containers and a ZFS pool of the suite's own. The prototype is
bb_identity 0.3's `bbid_placeholders` (C) and `docs/f4/redact.sql` (the
redaction, the seal and the verifier, on the real Blackbox SQL).

1. **Placeholders read as the server reads.** Ten hard cases come out with
   every literal replaced and nothing else changed: doubled quotes, `E''`
   strings with escapes, dollar quotes with tags, comments holding quotes and
   values, quoted identifiers with digits and quotes, numbers of every shape
   (`1.5e3`, `.5`, `0x1F`, `-7`), `B''`, `X''`, `U&''`, typed literals,
   arrays, strings joined across a newline, parameters already there (new
   ones are numbered after them), several statements in one message. With
   `standard_conforming_strings` off, a backslash-escaped quote is read
   correctly. A comment becomes a space, so a value an agent writes in one
   (`-- fix asha@…'s email`) goes with it. A text the lexer refuses raises the
   server's own error. An install at 0.2 updates to 0.3.
2. **The cost is negligible.** About 2.5 µs a call (100,000 calls in 250–290
   ms). 2,000 recorded agent `UPDATE`s took 973 ms as today and 863 ms with
   placeholders on PostgreSQL 18, and 2,654 and 2,792 ms on 16: within the
   noise of the run.
3. **Blocked attempts too.** The text is taken in six places in
   `datachanges.sql`, blocked and flagged attempts among them (section 9). The
   prototype puts placeholders in all six; an agent's `UPDATE` with no `WHERE`
   is recorded as `BLOCKED: UPDATE public.people SET email = $1`.
4. **Redaction with a seal holds.** Every data change holding the person's
   values was redacted, the comment the agent wrote one in included; the
   schema change holding one was kept and flagged; an entry holding no value
   was untouched. Every `row_hash` and every `ledger_ext` hash is unchanged,
   so the anchors' Merkle roots are too. The chain verifies, redacted entries
   by their seals. A second request finds nothing left to redact.
5. **Tampering after the redaction is caught**, each way: a redacted entry's
   text changed (its seal fails); a seal removed (the entry fails its hash,
   and the digest fails); the text changed and its seal rewritten (the
   digest fails); the digest rewritten too (the redaction's own entry fails
   its hash); a seal forged for another entry (no redaction wrote it). The
   ledger stays append-only outside a redaction; inside one, only the
   statement may change; `db_client` can neither unlock it nor run one.
6. **Found: the Blackbox refuses `DROP TABLE` of a temporary table**, for
   every role, a superuser's `SECURITY DEFINER` function included. The
   redaction keeps its seals in arrays instead. That an ordinary client
   cannot drop its own temporary table is an engine bug, raised apart.
7. **The plan's catalog facts.** The catalog gives every table referring to
   the person's, at each depth, with its `ON DELETE`; `RESTRICT` refuses the
   delete before anything else runs; a `NOT NULL` column without a default
   refuses clearing, and one with a default clears to it; the catalog says
   which; a table with neither a primary key nor a replica identity is known
   as one; a unique column clears on several rows; `CASCADE` reaches exactly
   the rows the catalog listed.
8. **The branch made before the erasure** (section 3's E8–E10 again, with the
   plan's steps): after the `UPDATE` and `VACUUM (INDEX_CLEANUP ON)`, four
   files under `base/` still held the values' bytes; after the rewrite,
   `ANALYZE`, `pg_statistic` rewritten and the WAL recycled, main's whole
   data directory held none. The branch erased the same way was clean, but
   main's snapshot it was made from still held the person, kept 8.3 MB alive,
   and could not be destroyed while the branch existed. The remade branch,
   its snapshot included, held no value and every other row.
9. **The restore to before the erasure.** A base backup and the WAL archive,
   recovered to just before the erasure, brought the person back. Started
   with no address to listen on, the copy refused every network connection
   while the erasure was applied again **by the row key alone**, the request
   having kept no value; then it opened, without the person, with another
   person restored alongside still there, and its table's files clean. The
   archive still held the person's WAL, as section 11 says, until backups
   are pruned.

**What changes for Gate 1:** the rewrite includes `pg_statistic` and the WAL
(section 7); placeholders go in all six recording places (section 9); no
Blackbox function the erasure runs may drop a table; a restored copy starts
with `listen_addresses` empty until the erasure is applied again (section 12).
