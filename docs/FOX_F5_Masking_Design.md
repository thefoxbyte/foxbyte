# F5: masking — design

**Status:** agreed (5 November 2026, #212), decisions 2 to 4 confirmed by the
founders. The Gate 0 prototype is built and its suite passes; what it found
is in section 17, and it changes sections 10, 12 and 13 where marked. This
answers point 7 of the review plan
(`docs/FOX_Expert_Review_Plan.md`, foundation F5 and point 7): masking personal
data for the people who should not see it, without the masks becoming a way to
recover what they hide. It was written against `main` at `9ddaa89`, after
point 4's marks (4.6), the access review (4.8), the audit log (F6) and the
hardening report (3.2) shipped.

Every claim here about PostgreSQL was checked on a throwaway PostgreSQL 18.6
server in the test VM (section 3), not taken from documentation alone. The
scripts are in `docs/f5/`. Claims that still need the prototype are marked
**(prototype)**.

**What a reader is asked to decide** (section 14 lists each with the
recommendation):

1. FoxByte's own masking, kept in shadow tables, rather than PostgreSQL
   Anonymizer (section 5).
2. A masked account is a **masked reader**: it reads ordinary tables directly
   and marked tables through their masks, and does not write marked tables
   (sections 6 and 9).
3. Who is masked: nobody until an admin masks an account; admins and branch
   owners always see real values (section 10).
4. One key domain per install by default, with named domains for tables that
   must never join (section 8).
5. Masked branches are masked in place before anyone opens them, and stay
   closed until masking is verified (section 12).

---

## 1. What masking will be, and what it will not

**It will be:** a person or agent who is not trusted with personal data reads
a marked column as a mask, everywhere they read it:
- the Gateway and the console;
- exports, the API and agent sessions;
- and on a branch made for them.

It will be shown not to leak through the side doors:
- statistics;
- error messages;
- functions they can call;
- the query planner.

A support person can still find a customer by an exact value, through an
audited lookup.

**It will not be:**
- **Protection from administrators.** Whoever can change the masks, or read
  the server's files, can see the data. Section 8 says where the key's
  protection ends.
- **Encryption at rest.** Backups and the WAL hold real values (F5). The vault
  (point 13) is the answer for Aadhaar at rest.
- **Format-preserving encryption.** A mask cannot be reversed, except by
  someone allowed to unmask.

---

## 2. Today

- **Point 4 marks personal data,** column by column and JSON path by path. A
  reviewer confirms each mark (4.6), and marks travel with branches. They are
  what masking will read.
- **Every account's role** is a member of `db_client`, with `INHERIT`. Tables
  made through the Gateway or the console are owned by `db_client`, so every
  account can read every table it made, or anyone made.
- **Agents** log in as `db_agent`, which is also in `db_client`.
- **There is no unmask right.** The access review's "unmask rights" column waits
  for this design (4.8), and so does the audit log's last item: reads audited
  for those who may unmask (3.1).

---

## 3. Checked on a throwaway server

PostgreSQL 18.6 (`postgres:18-bookworm`), in the test VM, as the superuser,
with roles made for the purpose. The scripts are `docs/f5/probe-views.sql` and
`docs/f5/probe-shadow.sql`.

| # | Question | Found |
|---|---|---|
| E1 | A view in a schema ahead of `public` in the masked role's `search_path`: does an unqualified name reach it? | Yes. `SELECT * FROM customers` reads the view. |
| E2 | And the real table, named in full? | `permission denied for table customers` when the role has no grant on it. |
| E3 | **A view whose expression calls a function the reader may not EXECUTE**: does the view still work? | **No:** `permission denied for function hmac_secret`. PostgreSQL checks a view's functions as the reader, not the view's owner. Plain `EXPLAIN` fails the same way. |
| E4 | Masked values kept in a **shadow table** by a trigger, and a view joining it, with no function at read time | Works. The reader sees the masks. `WHERE`, `GROUP BY`, `ORDER BY` and `EXPLAIN` work on the masked values; an indexed lookup is two index scans. The hash function stays out of reach. The application writes the real table as before, and the shadow keeps up. |
| E5 | `pg_stats` for the real table, with no grant on it | No rows. With `SELECT` on two columns, only those two columns' statistics. |
| E7 | A role that may `INSERT` but not read: what does a unique violation tell it? | `duplicate key value violates unique constraint "customers_email_key"`, with no `DETAIL`. **The value is hidden, its existence is not.** With `SELECT` on the column, the `DETAIL` names the value. |
| E8 | `COPY` | `COPY public.customers TO STDOUT` is refused. `COPY (SELECT … FROM customers)` reads the view, so it copies masks, or is refused with the view's function error (E3). |
| E11 | A `SECURITY DEFINER` lookup, owned by the masks' owner: does it return masked rows to a masked caller? | Yes, matching through the hash, which the caller cannot call itself. |
| E13 | A `security_invoker` view | The reader needs the table's own grant, so it is no use here. |
| — | PostgreSQL Anonymizer for PostgreSQL 18 | Not in apt.postgresql.org for bookworm, which FoxByte's image builds from. It would be a Rust extension built into the image, or a third-party repository. |

**What E3 means.** Masking computed in a view needs the reader to be able to
EXECUTE the masking function. That turns the function into an oracle: a
masked user hashes their guesses and compares the results with the masks. That
is the attack behind Anonymizer's CVE-2026-13455 (F5). Either the masks are
computed before the read, or the function can be called directly.

---

## 4. Two kinds of masking

| | Dynamic masking | Masked branch |
|---|---|---|
| Where | The real branch, read by masked accounts | A branch made for someone, whose data is replaced |
| Who sees real values | Everyone not masked | Nobody: the values are gone from the branch |
| For | Support staff, analysts, reviewers on production | Developers and AI agents who need production's shape |
| Point 7 phase | 1 to 4 | 5 |

Both use the same rules (section 7) and the same key (section 8).

---

## 5. The engine: FoxByte's own, not PostgreSQL Anonymizer

| | PostgreSQL Anonymizer | FoxByte's own (recommended) |
|---|---|---|
| Masks computed | In views, at read time | On write, into shadow tables (E4) |
| The hash function | Must be callable by masked readers (E3): an oracle, fixed by restricting it in 3.1.2 | Never callable by masked readers: nothing runs at read time |
| Where the salt or key is | In the database, readable by superusers | In a file the server reads, never in a table (section 8) |
| PostgreSQL 18 | Not packaged in apt.postgresql.org; a Rust build into the image | SQL plus a small C function in `bb_identity`, FoxByte's existing extension |
| Marks | Its own security labels | Point 4's marks, already confirmed and on branches |
| Cost | Every read computes | Every write to a marked table also writes its shadow row **(prototype: measure)**; reads are a join on the key |

The reasons are the oracle (E3), the key's place, and packaging. Anonymizer's
static masking is close to what masked branches need, but FoxByte would still
need its own gating around it (section 12).

---

## 6. How dynamic masking works

For each table with masked columns:

- **A shadow table, `bb_mask.<schema>__<table>`.** It holds the table's
  primary key and one masked value per masked column, and is owned by
  `bb_masker`, a role nobody logs in as.
- **A trigger on the real table.** It writes the shadow row after every
  insert and update, and deletes it with the row (`ON DELETE CASCADE`). It is
  `SECURITY DEFINER`, owned by `bb_masker`, and its `search_path` is fixed.
- **A view with the table's own name, in schema `bb_mask`.** It shows the
  table's columns: the unmarked ones as they are, the masked ones from the
  shadow, and partial masks computed on the spot, since they need no secret
  (section 7).
- **Masked readers have:**
  - `bb_mask` first in their `search_path`, so an unqualified name reaches the
    view (E1);
  - no grant on the real table (E2);
  - `SELECT` on the view;
  - no `EXECUTE` on anything that hashes (E3, E11).

Unmarked tables have no view, so the same `search_path` reaches them in
`public`.

**Requirements and consequences:**
- **A table needs a primary key to be masked.** The shadow is joined on it,
  and the data grid already needs one (12.2). A table without a key is refused,
  saying so.
- **The shadow is filled when masking starts,** in batches, holding no long
  lock **(prototype)**. Until it is full, masked readers are refused the table,
  never shown a half-masked one.
- **Everything is in the catalog:** the views, the shadow tables, the triggers
  and the grants. A branch made from a masked branch is masked the same way.
- **The Blackbox records** creating and changing the masks, under the person who
  asked.
- **Statistics:** masked readers see none for the real table (E5). The shadow
  table's statistics are of masks.
- **TRUNCATE** of a masked table empties its shadow too: a
  `TRUNCATE … CASCADE` through the foreign key, done by the engine
  **(prototype)**. TRUNCATE is refused by default anyway (the Blackbox).

---

## 7. The rules

A rule is set on a confirmed mark: a column, or a JSON path inside one.

| Rule | Shows | Computed | Joins | For |
|---|---|---|---|---|
| `partial` | the last few characters: `XXXX XXXX 1234` | in the view; no secret | no | Aadhaar, PAN, card numbers, phone numbers |
| `hash` | a keyed hash (HMAC-SHA-256, as hex) | on write, in the shadow | yes, within one key domain | emails, customer ids: anything joined or grouped on |
| `fake` | a realistic value chosen by the keyed hash, so the same input always gets the same fake | on write, in the shadow | yes, within one key domain | names, cities: what a screen or a demo needs to look real |
| `empty` | NULL | in the view | no | free text that should not be shown at all |

- **Aadhaar is never hashed** (F5): a keyed hash of Aadhaar that applications
  join on is a hash used as a reference key, which UIDAI forbids. Aadhaar's
  only rules are `partial` and `empty`. A rule asking to hash Aadhaar is
  refused, saying why. Joins on Aadhaar go through vault tokens (point 13).
- **JSON paths** are masked inside the document. The shadow keeps the whole
  document with the path's value replaced **(prototype: cost on large
  documents)**.
- **Default rules by category** (point 4's categories), changeable per mark:
  - Aadhaar, PAN, card, mobile: `partial`;
  - email: `hash`;
  - name: `fake`;
  - anything else: `empty`.

---

## 8. The key

- **One HMAC key per key domain,** 256 bits, made by the engine. It is kept in
  the state directory, mounted read-only into each database container at
  `/run/bb-mask/<domain>.key`, readable by the server's own user only.
- **Never in a table.** It is read by a C function in `bb_identity`, which only
  `bb_masker` may EXECUTE. The key never appears in SQL, a log or an error.
- **Domains.** By default the whole install is one domain, so a customer's
  email hashes the same in every table and joins work. A named domain keeps
  tables that must never be correlated apart, such as two tenants' data. Joins
  work only within one domain.
- **The boundary, stated:**
  - The key file holds against every role FoxByte gives a person or an agent.
  - It does not hold against a database superuser, or a role allowed to read
    the server's files: they can read any file the server can.
  - It does not hold against the host's administrator.
  - Against them, only a key held outside the machine (an HSM or a key service,
    as for the vault) is out of reach, and the threat model says so.
- **Rotation** writes every shadow again, in batches, while masked readers keep
  reading the old masks until a table is done **(prototype)**. Rotation changes
  every hash, so it breaks joins against masks copied out before it, which is
  the point of rotating.

---

## 9. What a masked reader can do

- **Read** every table: ordinary ones directly, marked ones through their
  masks.
- **Filter, sort, group and join on masks.** `WHERE email = <a mask>` works.
  `WHERE email LIKE '%@bank.in'` matches nothing, because the masks are hashes.
  Developers are told what this rules out (F5).
- **Count and aggregate.** `count(DISTINCT email)` counts the same people, since
  a hash is one-to-one.
- **Not write marked tables.** A masked writer learns that a value exists from
  a unique violation, even with the value hidden (E7). It could also probe
  through `ON CONFLICT`, through `RETURNING`, and by timing. Writes to marked
  tables are for accounts that can see them.
- **Write everything else,** as before, if the account is allowed to.
- **Not make objects that read marked tables** for others: views, functions or
  triggers made by a masked reader would run as that reader, so they can only
  read masks anyway.
- **Not read** the shadow tables' history, the Blackbox's statement text, query
  history of others, or the audit log. Each is already closed to non-admins,
  and the access-path suite (section 11) checks it.

---

## 10. Who is masked, and unmask

- **Nobody is masked until an admin masks an account**:
  `fox mask account <email>`, or the access page in the console. A masked
  account's role leaves `db_client` and joins `db_masked`, whose grants are
  section 6's.
- **Admins always see real values.** They can change the masks, so masking
  them would only pretend; the design says so rather than hiding it.
- **A branch's owner is masked too, if its account is (step 4).** Owners were
  exempt until the access-path suite found the way through it: a masked
  account made a branch of main, owned it, and read everything there. The
  branch carries the masks, and only unmask lifts them, on one branch.
- **Agents:**
  - An agent key can be made masked.
  - Agents are pointed at masked branches (section 12), which is where they
    belong.
  - Realtime refuses masked tables to masked keys: the change feed reads the
    log, under the masks.
- **Unmask** is a right on a branch, given by an admin only:
  - recorded in the security log;
  - listed in the access review (4.8's column);
  - every read by an unmask holder is audited through pgAudit's `bb_audit_read`
    role, which closes 3.1.
- **The lookup** finds a person by an exact value without unmasking:
  `bb_mask.find(table, column, value)`.
  - It is `SECURITY DEFINER`, hashes the value it is given, and returns the
    matching rows masked (E11).
  - It is rate-limited, by default 30 lookups a minute for each account.
  - Every call is recorded with who, when, which column and how many rows,
    never the value.
  - **A masked login's failing statements are never logged with their text**
    (section 17, item 1): `ALTER ROLE … SET log_min_error_statement = panic`
    on every masked login, which only a superuser can set or undo. Without
    it, a refused lookup put the value being looked up in the server log.
  - A lookup is itself an oracle, one value at a time, and its record is what
    makes using it as one visible.

---

## 11. Every access path, tested

The suite runs as a masked reader, and as a masked agent, on every path F5
names. A path that cannot keep the masks is refused for masked accounts, or
declared unsupported, never left open.

| Path | Expected |
|---|---|
| Gateway (psql) | masks; real table refused |
| Console: query, data grid, object browser | masks; the grid's edit refused on marked tables |
| Exports (1.2, 1.3) | masks |
| API and agent sessions (`execute_change`, MCP `run_sql`) | masks |
| Joins, views and functions a masked reader writes | masks only |
| `SECURITY DEFINER` functions owned by others | the hardening report's `roles.definer`, and F6's definer finding, name them; a definer function owned by a reader of real data can leak, and is listed |
| `RETURNING`, `ON CONFLICT`, errors | no write to marked tables (section 9) |
| `pg_stats`, `EXPLAIN` | no real values (E5) |
| `COPY` | masks or refused (E8) |
| Realtime | refused for masked tables |
| Logical replication, continuous import | not given to masked accounts |
| Branch create, restore, promote | masks travel; a promoted change request does not unmask |
| The lookup | masked rows, rate-limited, recorded |

**What the suite found (step 4).** Run as a masked account and as its agent
key: integration §11al and `web/tests/masking.spec.ts`. Eight paths gave real
values; each is closed and tested.

| Path | Found | Now |
|---|---|---|
| A branch it makes, of main or back in time; an agent branch | owners saw real values | masked on its own branches too; agent branches refused to it |
| Agent keys; MCP `run_sql`, `execute_change` | the agent role was in `db_client` | a masked agent role: `db_masked`, a member of `db_agent` with neither its rights nor `SET ROLE` (PostgreSQL 16+), so still an agent to the Blackbox; never a shared role |
| Realtime | the feed decoded every published table for anyone on the branch | refused to a masked account where there are masks |
| The Gateway's fallback | a role that could not be made, or not yet on a standby, fell back to the shared role | refused, to try again |
| The Blackbox's statements | `GET /ledger` and its export carried every statement's text | the entries without the text; the export, whose rows must verify, refused |
| Views and materialized views by others | the default privileges gave masked readers `SELECT` on a view reading a marked table as its owner | the guard (`bb.mask_close_paths`, an event trigger) takes it, and gives it back when the rule goes |
| `GRANT` on a marked table or such a view (a promoted change request included) | given | taken back; to `PUBLIC`, refused |
| A foreign key into a masked column | a write said whether a guessed value exists | `INSERT` and `UPDATE` on that table taken |
| A definer function owned by a reader of real values | could return them | listed by `fox mask` and the Masking page, never changed |

Kept, now tested: `COPY`, `RETURNING`, `ON CONFLICT`, `MERGE`, errors (a
cast quotes the mask), `pg_stats` and extended statistics (nothing),
`EXPLAIN` (no values), the console's query, grid, object browser and exports,
temporary views and functions (masks only). Left, and said: `CREATE TABLE AS`
copies real values into an ordinary table, which the scan finds on its next
run; the change requests list shows a request's SQL to anyone on its
branches.

---

## 12. Masked branches

`fox branch create <name> --masked [--from main]`:

1. The branch is made, as any branch is, and **left closed**. The Gateway, the
   console and the API refuse it; only the engine connects.
2. Every masked column is overwritten in place with its mask: the `partial`,
   `hash`, `fake` and `empty` rules, the same key.
3. Then the engine, each step a statement of its own (section 17, item 3):
   - runs `VACUUM FULL` on each masked table, so the real values' dead rows
     are gone from the branch's files;
   - runs `ANALYZE`, then `VACUUM FULL pg_statistic`: ANALYZE writes new
     statistics, and the old rows, with the real most-common values, stay in
     `pg_statistic`'s file until it is rewritten;
   - turns WAL recycling off, then switches and checkpoints three times, so
     the segments from before the masking (the parent's, which the clone came
     with, and the full-page images of pages as they were before) are
     deleted, not renamed for reuse with their old bytes in; then turns
     recycling back on;
   - removes the shadow tables and views, which the branch no longer needs.
4. **Verified:** a scan (point 4) finds none of the marked categories left in
   clear. Only then does the branch open.
5. **Gated:** a failed or cancelled run leaves the branch closed. A retry
   starts again from the source, and nobody can open a partly masked branch.
6. **Its access is never weaker than the source's:** owners, guardrails and
   policies carry over, and every change is in the Blackbox.

**What a masked branch cannot promise:**
- The parent's WAL and backups hold real values. They are the parent's.
- The blocks the clone shares with the parent's snapshot, and the blocks the
  branch freed, are still on the pool. Only someone with the host's ZFS can
  reach them, which is the host administrator, outside masking's reach
  (section 1).
- **The other way, if the clone ever proves not enough:** a fresh cluster
  loaded with only the masked rows holds nothing of the parent at all. It
  took 0.3 s for 20,000 rows (section 17), and it gives up copy-on-write
  sharing.

---

## 13. Measured before shipping (prototype; results in section 17)

1. **Write overhead** of the shadow trigger, on a 10,000-row update and on
   pgbench with one marked table, against no masking. Budget: 10%.
2. **Read cost** of the join, on an indexed lookup and on a full scan.
3. **Filling and rotation** on a 1,000,000-row table: time, locks held, WAL
   written.
4. **JSON paths** on 256 KB documents.
5. **The masked branch** on a ZFS clone:
   - no real value is readable afterwards, in pages (`pageinspect`), WAL or
     statistics;
   - its time on 1 GB.

---

## 14. Decisions

| # | Decision | Recommendation |
|---|---|---|
| 1 | Engine | FoxByte's own masks in shadow tables, computed on write (sections 3 and 5) |
| 2 | What a masked account is | A masked reader: reads ordinary tables, reads masks of marked ones, does not write marked tables (sections 6 and 9) |
| 3 | Who is masked by default | Nobody; an admin masks accounts and agent keys. Admins and branch owners always see real values (section 10) |
| 4 | Who grants unmask | Admins only, per branch, recorded, in the access review, reads audited (section 10) |
| 5 | Key domains | One per install by default; named domains for tables that must never join (section 8) |
| 6 | Aadhaar | `partial` or `empty` only, never hashed (section 7) |
| 7 | Masked branches | Masked in place, vacuumed, analysed, verified by a scan, closed until then (section 12) |
| 8 | Edition | Enterprise, as point 7 is: rules, masked readers, unmask, the lookup, masked branches. The masks already on a branch keep working in every edition, as anchors and findings do |
| 9 | The cost, over the 10% budget (section 17, item 4) | Accept it, as the audit log's was: masking is per table, on tables with marks only, and its cost is said before a rule is set. Keep the masks with a trigger a statement (bulk writes 3.6× rather than 5.6×). A C trigger is the way to cut it further, if a customer's write load needs it |

---

## 15. Gate 0: the prototype (built; section 17)

The design's claims above marked **(prototype)**, proven in a suite like
F6's (`docker/postgres/f5_test.go`), on PostgreSQL 18 and 16:

- the shadow tables, triggers, views and grants for one table with `partial`,
  `hash`, `fake` and `empty` columns, and a JSON path;
- the C `bb_mask_hmac` in `bb_identity`, reading the key file, with `EXECUTE`
  for `bb_masker` only;
- a masked reader on every path section 11 lists that the database itself
  serves;
- filling, rotation and the measurements of section 13;
- a masked branch on a ZFS clone, read afterwards with `pageinspect` as the
  superuser.

## 16. Gate 1: the steps, once the prototype passes

| Step | What | CLI | Console |
|---|---|---|---|
| 1 | Rules on confirmed marks; masked readers; dynamic masking on a branch | `fox mask rule …`, `fox mask account …`, `fox mask status` | rules on the Personal data page; masked accounts on the access page |
| 2 | The key, domains and rotation | `fox mask key …` | settings |
| 3 | Unmask, the lookup, the access review's column, reads audited (3.1) | `fox mask unmask …`, `fox mask find …` | unmask; find a person |
| 4 | The access-path suite (section 11), in the integration suite and the UI suite | | |
| 5 | Masked branches, gated | `fox branch create --masked` | Masked branch |

---

## 17. What the prototype found (Gate 0)

`make integration-f5` (`scripts/integration_f5.sh`) builds the engine image
with `bbid_mask_hmac` in `bb_identity` 0.2, and runs throwaway containers,
with a ZFS pool of its own made from a file for the masked branch. It passes
57 of 57 on PostgreSQL 18 and 16. On both:

- **Every rule shows its mask:**
  - a fake name, the same for the same input;
  - a 64-hex keyed hash;
  - partial phone and Aadhaar;
  - an empty column;
  - a JSON path partial, with the rest of the document as it was.
- **Out of a masked reader's reach:** the real table, the shadows, the hash
  function, the fake function and the key file.
- **Works on masks:** filtering, grouping and joining (a customer's orders by
  the hashed email), and `EXPLAIN` (two index scans). `pg_stats` shows
  nothing of the real table, and `COPY` of a query copies masks.
- **Writes:** a masked reader cannot write a marked table, through the view or
  around it. What a masked reader makes runs as them: a definer function of
  their own reading the real table is refused, and a view of their own shows
  masks.
- **The lookup** returns the masked row, allows 30 a minute, and records every
  call without the value.
- **The application** inserts, updates, changes a key, deletes and truncates
  as before, and the shadows keep up.
- **The key:**
  - domains hash apart;
  - a missing key, a name that is not a file name, and a key file others can
    read are each refused, with no key in the message;
  - the key is in no log;
  - a session that read the old key reads the new one once the file is
    replaced (the file's inode and modification time are checked on each
    call).

**What it changed:**

1. **A refused lookup put its value in the server log.** PostgreSQL logs a
   failing statement's text (`log_min_error_statement`, `error` by default),
   and the lookup's value was in it. Every masked login now has
   `log_min_error_statement = panic`, which only a superuser can set or undo.
   Afterwards no real value is in the log (section 10).
2. **Statements that `VACUUM` must run alone.** `VACUUM FULL pg_statistic`
   sent with another statement runs inside one transaction and is refused,
   which silently left the old statistics in place. Each step of a masked
   branch is a statement of its own (section 12).
3. **A masked branch, step by step, counted as files holding a real value:**

   | After | base/ | pg_wal/ |
   |---|---|---|
   | the clone | 2 (the table, and `pg_statistic`) | 2 |
   | masking in place | 2 | 2 |
   | `VACUUM FULL` of the table | 1 (`pg_statistic`) | |
   | `ANALYZE` | 1 | |
   | `VACUUM FULL pg_statistic` | **0** | 2 |
   | recycling off, three switches and checkpoints | | **0** |

   So masking in place on the clone leaves no real value in the branch's own
   files. A fresh cluster loaded with only the masked rows also holds none, in
   0.3 s for 20,000 rows.
4. **The cost is over the 10% budget.** PostgreSQL 18, the test VM's 4 CPUs,
   16 clients, medians of three:

   | | Without masks | With masks |
   |---|---|---|
   | One 10,000-row `UPDATE` | 55 ms | 307 ms a row each; **198 ms** a statement each |
   | Single-row writes | 34,566 tps | 27,297 tps (21% fewer; 30% in a first run) |
   | Indexed reads | 207,798 tps from the table | 155,810 tps through the view (25% fewer) |
   | A full scan of 10,000 rows | 2.3 ms | 4.8 ms |
   | Updating 100 documents of 250 KB, a JSON path masked | 1.4 ms | 544 ms |

   And, for 1,000,000 rows:
   - **Filling an existing table's masks** in batches of 10,000 takes 14 s. A
     writer meanwhile, with a 1-second lock timeout, was never held up.
   - **Rotating the key** takes 21 s.

   The cost falls only on tables with masked columns, and the read cost only
   on masked readers. Like the audit log's, it is said before a rule is set,
   not hidden in a default (decision 9). A JSON path in large documents costs
   most, because the shadow keeps a copy of the whole document. Masking a path
   in documents over 64 KB is warned about when the rule is set.
