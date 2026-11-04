# F6: audit coverage — design

**Status:** agreed as recommended (2 November 2026, #193). The Gate 0
prototype is built and its suite passes; what it found is in section 19, and
it changes sections 6, 7, 12 and 13 where marked. Gate 1's plan and its steps
are in section 20 and after. Written against `main` at `d80f6e9`. It answers Gate 0's
F6 item in the review plan (`docs/FOX_Expert_Review_Plan.md`, sections 4 and
5): "the audit design, shown to keep no personal data it doesn't need". Gate 1
then ships pgAudit in Standard, in the default mode this describes.

Every claim about pgAudit or PostgreSQL here was checked on a throwaway server
(section 3), not taken from documentation alone. Claims that still need the
prototype are marked **(prototype)**.

**What a reader is asked to decide** (section 18 lists them with the
recommendation for each):

1. Values are kept out of PostgreSQL's own error lines by a hook in FoxByte's
   extension, rather than by not logging errors at all (section 6).
2. Audit logs leave the database's directory for a dataset of their own, with
   a quota, and the engine collects them into a hash-chained store (section 9).
3. pgAudit is opt-in on existing installs, because turning it on restarts
   `main` (section 15).
4. Default retention: one year for the default mode, 30 days for forensic mode
   (section 11).
5. Until masking exists, reads are audited per table, for everyone (section 8).

---

## 1. What the audit log will be, and what it will not

The audit log answers: **who did which kind of operation, to which object,
when, and did it succeed.** It is evidence of configured classes of
operations. It is not a record of every query, and nothing FoxByte says will
imply that it is.

| It records | It does not record (default mode) |
|---|---|
| Role and schema changes, by everyone, superusers included | Statement text |
| Writes to tables marked for audit | Parameter values |
| Reads of tables marked for reads | Error messages, details or values |
| The login, and the application's user where one was asserted (F1) | Client addresses or application names |
| Each audited transaction's outcome | Anything on a table not marked |

Forensic mode (section 10) adds statement text, switched on deliberately,
with its own access and a shorter retention.

---

## 2. Today: where statement text and values already land

Checked against the code and on the probe server (section 3).

| Place | What it holds today | Kept for |
|---|---|---|
| **The containers' Docker logs** | Every failed statement's full text and its error detail, values included: the official image logs errors with `log_min_error_statement=error`, FoxByte sets no logging option, and Postgres writes to stderr, which Docker keeps | Until the container is removed. Docker's `json-file` driver, no rotation (no `daemon.json`, no `--log-opt`) |
| Console query history (point 8) | The SQL people ran in the console, by design | Retention setting, default 90 days; purgeable per person (8.3) |
| The Blackbox | DDL statement text, by design | The chain's life (F4 covers it) |
| The control plane's own log | No SQL: its `log.Printf` calls name actor, branch and error only | Daemon log |

The first row is a leak today, and this design closes it (section 6). Until
then it is worth knowing:

- a unique-key violation writes the key's value;
- a bad cast writes the literal;
- the statement line writes everything the statement held.

All three land in a log nobody rotates, reads or erases.

---

## 3. pgAudit, checked

A throwaway `postgres:18-bookworm` server in the test VM, with
`postgresql-18-pgaudit` from the PGDG repository the engine image already
trusts, and logs written as JSON.

- **Packages.** pgAudit 18.0 (`18.0-3.pgdg12+1`) for PostgreSQL 18, and 16.1
  (`16.1-2.pgdg12+1`) for 16. Both majors FoxByte supports have one.
- **Default mode works as the plan describes.** With `pgaudit.log_statement`
  and `pgaudit.log_parameter` off, a write to an audited table logs:

  ```
  AUDIT: OBJECT,1,1,WRITE,INSERT,TABLE,public.customers,<not logged>,<not logged>
  ```

  It carries the class, the command, the object and nothing the statement
  held.
- **Object auditing through a role works.** A table granted
  INSERT/UPDATE/DELETE to `bb_audit` (with `pgaudit.role = 'bb_audit'`) had
  its writes logged. A table not granted had none.
- **Reads per login work.** `ALTER ROLE carol SET pgaudit.role =
  'bb_audit_read'`, a role that also holds SELECT, logged carol's read. The
  same read by alice was not logged. This is how "reads by roles that hold
  unmask rights" will be done (section 8).
- **Passwords are redacted.** Even with statement text on, `ALTER ROLE dave
  PASSWORD '…'` was logged as `ALTER ROLE dave PASSWORD <REDACTED>`.
- **Role changes are logged for superusers too.** The engine's own `dbadmin`
  sessions were logged.
- **A failed statement still has its audit line.** pgAudit logs when the
  statement starts. The failure is a separate ERROR line after it, in the same
  session and virtual transaction. pgAudit itself records no outcome.
- **The audit line has no transaction id.** `txid` is 0 in the audit line,
  because the line is written before a transaction id is assigned. The error
  line in the same transaction had `txid` 766. Records join on the session
  (`session_id`) and the virtual transaction (`vxid`), which both lines carry.
- **Postgres's own error lines carry values:**

  | Setting | What the ERROR line held |
  |---|---|
  | Defaults | message, `detail` with the key's value, `statement` with every literal |
  | `log_min_error_statement=panic` | no `statement`; message and detail as before |
  | `log_error_verbosity=terse` | **detail still there** in JSON output; `terse` does not apply to it |
  | `log_min_messages=log` | no ERROR line at all, so no outcome either |

  Some messages hold the value themselves: `value "4111111111111111abc" is out
  of range for type integer`. No combination of settings removes values from
  error lines and keeps the outcome. Section 6 does.

---

## 4. Default mode: exactly what is logged

| pgAudit setting | Value | Why |
|---|---|---|
| `pgaudit.log` | `ddl, role` | Schema and role changes, for everyone |
| `pgaudit.role` | `bb_audit` | Writes on marked tables (object auditing) |
| `pgaudit.log_statement` | `off` | No statement text |
| `pgaudit.log_parameter` | `off` | No values. F1 already requires it, since tokens are bind parameters |
| `pgaudit.log_relation` | `on` | One line per table, so an object is always named |
| `pgaudit.log_catalog` | `off` | Catalog reads by tools are noise, not evidence |
| `pgaudit.log_client` | `off` | Clients are not shown audit lines |
| `pgaudit.log_rows` | `off` until measured | A row count is useful but costs a line format change (prototype) |

PostgreSQL's own settings that keep values out:

| Setting | Value |
|---|---|
| `log_min_error_statement` | `panic`: no statement text on errors |
| `log_statement`, `log_min_duration_statement` | off: their defaults, now stated so nothing turns them on by accident |
| `log_parameter_max_length`, `log_parameter_max_length_on_error` | `0` |

`TRUNCATE` is not covered by object auditing, which sees only
SELECT/INSERT/UPDATE/DELETE. It is blocked by FoxByte's guardrails by default
(`bb_guard_truncate`). When an admin overrides that, the Blackbox records it.
The coverage statement says so.

---

## 5. Each field, and why it is kept

What the default mode's record holds, after collection (section 9):

| Field | Personal data? | Needed for |
|---|---|---|
| Time | No | When |
| Branch | No | Where |
| Login (`user`) | **Yes**: a person's role is their email | Who. This is the purpose of the log |
| Application's user, its state and application (F1) | **Yes**: the application's user id | Whom it was for |
| Class, command, object type, object name | No (object names are schema) | What, and to what |
| Session and virtual transaction | No | Joining a statement to its outcome |
| Statement and sub-statement number | No | Gap detection within a session (section 13) |
| Outcome: commit, rollback, or the SQLSTATE | No (a code, not a message) | Did it succeed |

Dropped when collected, and never kept:

- the client address (`remote_host`): inside FoxByte it is the Gateway's or
  the control plane's address, not the person's;
- `application_name`, which the client sets to anything it likes;
- the process id;
- every message, detail, hint, context and statement.

So the only personal data in a default-mode record is **who**: the login and
the application's user. That is the record's purpose. It is kept under the
logging exception to erasure, until its retention date (section 11).

---

## 6. Errors: keeping values out of PostgreSQL's own lines

Section 3 shows settings cannot do it. FoxByte already preloads a C extension
in every engine image (`bb_identity`, F1). This adds a small **log hook** to it
(`emit_log_hook`), which runs before PostgreSQL writes any line to the server
log.

For an ERROR from a client session:

- The client still gets the full error. Only the **server log's copy** is
  changed.
- The server log gets a redacted line instead, holding the SQLSTATE, its
  class, and the same session and virtual transaction:

  ```
  AUDIT: OUTCOME,ERROR,23505
  ```

  No message, detail, hint, context or statement.

How: the hook copies the error, empties the copy's text fields, writes the
copy to the log, and marks the original as not for the server log
(`output_to_server = false`). PostgreSQL 15 and later export `write_jsonlog`
for that. **(prototype)** checks that it is safe from the hook, on 16 and 18.

Errors that are not from client sessions are left alone, because they hold no
user values and are what an operator needs. These are startup, checkpoints,
replication and the engine's own `dbadmin` maintenance.

**The fallback**, if the hook proves unsafe, is `log_min_messages=log`. Error
lines are then not logged at all, and the outcome comes only from section 7's
commit and rollback line. That is weaker (no SQLSTATE), but it still keeps no
values.

---

## 7. Outcome and whom-for: one line per audited transaction

pgAudit logs a statement when it starts. A write that later rolls back still
has its audit line. So the same extension adds a transaction callback:

- When a transaction that had an audit line ends, it logs one more line, in
  the same session and virtual transaction:

  ```
  AUDIT: TXN,COMMIT,asserted,shop,alice
  ```

  or `ROLLBACK`.
- The log hook notices audit lines as they pass, so nothing else has to
  track them.
- The application's user comes from F1's transaction-local settings, which the
  MAC guards. The callback reads them as `bb.app_actor()` does, with their
  state (`asserted`, `claimed`, or none).
- A transaction with no audit line logs nothing extra.

This is how F1's identity reaches the audit log. pgAudit's line format is
fixed and cannot carry it, and joining on the transaction id fails because
the audit line has none (section 3). The login itself is in every line.

---

## 8. Marking tables for audit

pgAudit's object auditing works through grants to an audit role. It does not
see FoxByte's personal-data marks. So:

| | Writes | Reads |
|---|---|---|
| **Role** | `bb_audit`, granted INSERT, UPDATE, DELETE | `bb_audit_read`, granted SELECT as well |
| **Standard** | `fox audit-log table <t>` grants it | `fox audit-log table <t> --reads` |
| **Enterprise** | a confirmed personal-data mark (point 4.6) grants it automatically | as Standard until point 7, then automatic for unmask holders |

Both roles are `NOLOGIN` and own nothing. Their names are brand-free, like
every stored name.

**Reads, before and after masking.** The plan asks for reads by roles that
hold unmask rights. Unmask rights do not exist until point 7. Until then, a
table marked `--reads` has every read logged, by everyone. After point 7, each
role granted unmask gets `ALTER ROLE … SET pgaudit.role = 'bb_audit_read'`, as
checked in section 3. Its reads of marked tables are then logged, and other
roles' are not.

Grants live in the catalog, so marks travel with a branch when it is cloned,
as point 4's marks do. Every grant or revoke goes in the security log.

---

## 9. Where the logs go

**Today** Postgres writes to stderr and Docker keeps it (section 2).

**With audit on:**

1. **Postgres writes JSON log files** (`logging_collector=on`,
   `log_destination=jsonlog`) to a directory **outside the data directory**.
   A branch is a clone of its parent's data directory. Logs inside it would be
   copied into every branch, and personal data with them.
2. **That directory is a ZFS dataset of its own**, `dbpool/audit`, with a
   quota, mounted into each container (`/var/log/bb-audit/<branch>`).
   - A full audit dataset stops audit writes. It cannot fill the VM's disk,
     and a full disk is what suspended the pool on 26 October (#189).
   - Rotation: hourly or at 64 MB.
3. **The engine collects them.** A collector in the control plane reads the
   JSON files and keeps the fields in section 5, dropping the rest. It writes
   records to a store in the same dataset: one gzip-compressed JSON-lines file
   per day.
   - **Each record is hash-chained**, as the security log is. Enterprise
     anchors the chain's head with the Blackbox's anchors (F3), so a host
     administrator's later edit is detectable.
   - A raw file is deleted once collected, and forwarded if forwarding is set.
     It is kept at most 2 days.
4. **Forwarding to the customer's SIEM**, as syslog (RFC 5424, TLS) or HTTPS
   JSON, from the collected records, not the raw files. So the SIEM receives
   no more than the store holds.

A record outlives its branch. Today a branch's log vanishes with its
container. With this, a deleted branch's audit records stay until their
retention date.

---

## 10. Forensic mode

`fox audit-log mode forensic` turns on `pgaudit.log_statement`. Statement text
then appears, with its literals. Parameters stay off in both modes, because
F1's tokens are parameters.

- **Who:** admins only, recorded in the security log, with the reason given.
- **Scope:** the whole install, or one branch.
- **Retention:** 30 days by default, shorter allowed.
- **Reading:** admins only, and every read is recorded.
- **Erasure:** forensic records are searched and purged for a person (F4),
  within their retention. Default-mode records have no text to search.
- **Visible everywhere:** `fox check` and the console say plainly when
  forensic mode is on, and since when.

Error lines stay redacted in forensic mode too. The statement text is in the
audit line, and the error's values add nothing an investigation needs.

---

## 11. Retention and erasure (F4)

| Record | Default retention | Erasure |
|---|---|---|
| Default mode | **1 year** | Kept under the logging exception until its date; "clears on" is that date |
| Forensic mode | **30 days** | Searched and purged for the person |
| Raw files | at most 2 days | Removed once collected |

**Why one year.** India's CERT-In directions (28 April 2022) require ICT logs
for a rolling 180 days, and the DPDP Rules' security safeguards ask for logs
to be kept one year. The rule number and text are to be confirmed against the
notified Rules before this ships. The longer period covers both.

Retention is a setting, so an install bound by a different rule can change
it. Records past their date are deleted by the collector. A SIEM's copy is
the customer's to expire, and FoxByte cannot erase it. The evidence export
and the docs say so, as F4 requires.

---

## 12. Coverage and limits, stated

What `fox audit-log status`, the console and the evidence export will say,
never implying more:

- **Logged:**
  - role and schema changes, by every login;
  - writes to marked tables;
  - reads of tables marked for reads;
  - each audited transaction's outcome;
  - who: the login, and whom it was for when an application asserted it.
- **Not logged:**
  - statements on unmarked tables;
  - statement text, unless forensic mode is on;
  - `TRUNCATE`, which is blocked by default and in the Blackbox when allowed;
  - changes applied by continuous import's replication, which run no
    statements;
  - anything a database superuser does after turning auditing off for their
    session.
- **Checked:** delivery and gaps, as section 13.
- **Found by the prototype (section 19):** the statements inside a `SECURITY
  DEFINER` function are not in pgAudit's object audit, whoever owns the
  function. A definer function that writes a marked table is a gap, and the
  status says so. Section 19 lists the options.

The superuser limit is the same as the Blackbox's. A superuser can `SET
pgaudit.log = 'none'` for their own session. FoxByte's own superuser is the
engine's. No client, user or agent role can change a `pgaudit` setting,
because they are superuser-only.

---

## 13. Delivery and gaps

- **Statement numbers.** pgAudit numbers statements within a session. The
  collector reports a gap within a session as a finding.
- **Heartbeat.** Every 5 minutes, on each running branch, the engine reads a
  one-row table marked for reads and checks that the record arrives.
  - A heartbeat that does not arrive is a finding in `fox check`.
  - Forwarded heartbeats let the SIEM alert on silence.
  - The heartbeat must not count as activity, so it does not keep an idle
    branch awake.
- **A full dataset** is the case that matters, and **(prototype)** measures
  it. A full dataset means PostgreSQL's log writes fail. We expect it to keep
  running and drop lines, so writes are not refused.
  - `fox check` warns at 80% of the quota.
  - The collector records the gap with its start and end.
  - Turning a full log into refused writes is a choice to offer later, not a
    default: it would turn a log problem into an outage.
- **Collector stopped.** Raw files wait in the dataset, up to its quota. A
  restart catches up.

---

## 14. Threat model

| Who | Can they avoid the record? | What holds |
|---|---|---|
| A client, user or agent role | No: `pgaudit.*` is superuser-only, and roles are given no superuser | The record |
| An application asserting for a user | It can assert for anyone its key covers, as in F1 | The record says "asserted by", never "was" |
| A database superuser | Yes, for their session | Outside, as for the Blackbox, and stated |
| The host administrator | Can edit raw files and the store | The chain (Standard), anchors and the SIEM copy (Enterprise and forwarding) |
| Someone reading the log | Sees logins and whom-for only, in default mode | Admin-only access; reads recorded |

---

## 15. Turning it on

pgAudit has to be loaded at server start (`shared_preload_libraries`), and
the logging collector is a start-time setting too. So turning audit on
restarts `main`. That follows the change feed's precedent:

- **Existing installs:** `fox audit-log setup --yes` says that `main` will
  restart and connections drop for a few seconds, then does it. Branches pick
  it up when next started, as they do for realtime.
  - `postgresArgs` stays byte-identical while audit is off, and a test keeps
    it so.
  - Upgrading the binary never restarts anyone's database.
- **New installs:** on by default once section 17's measurements are within
  budget. Otherwise opt-in like existing ones.
- **Settings split:**
  - Start-time settings go on the container's command line: the preload,
    collector, destination and directory.
  - The policy goes in `ALTER SYSTEM`, so mode changes need only a reload:
    `pgaudit.*`, `log_min_error_statement`.
  - The policy is applied to each running branch at once, and on resume and on
    create. That is how F1's registrations reach branches.
- **The image:** `postgresql-<major>-pgaudit` is version-pinned, as pgvector
  is, and `image-revision` goes to 3.
- **HA:** the standby gets the same arguments, and its own collector writes to
  its own dataset.

---

## 16. CLI and console

`fox audit` already names the security log, so pgAudit's log is
`fox audit-log`:

| Command | Does |
|---|---|
| `fox audit-log status` | On or off, mode, marked tables, coverage, dataset use, last heartbeat, findings |
| `fox audit-log setup --yes` / `off --yes` | Turns it on or off (restarts `main`) |
| `fox audit-log table <t> [--reads] [--off] [--branch b]` | Marks or unmarks a table |
| `fox audit-log show [--branch] [--table] [--user] [--since] [--json]` | Reads records (admins) |
| `fox audit-log mode default\|forensic [--branch b] --reason "…"` | Switches mode |
| `fox audit-log retention <days> [--forensic]` | Sets retention |
| `fox audit-log forward syslog://…\|https://…` | Sets forwarding |
| `fox audit-log verify` | Checks the chain, and with Enterprise the anchors |

The console gets an **Audit log** page with the same status, a filterable
record list, and a mark on each table in the schema rail.

**Editions:**

- **Standard:** everything above except anchoring.
- **Enterprise:**
  - automatic marks from point 4;
  - reads by unmask holders, with point 7;
  - anchors;
  - the evidence export, which states coverage and limits as section 12 does.

---

## 17. Measured before shipping

| What | How | Budget to agree |
|---|---|---|
| Write latency | `pgbench` (TPC-B-like) on a marked table, audit off / default / forensic, PG 16 and 18 | Default mode ≤ 5% |
| Read latency | `pgbench -S` on a table marked for reads | Default mode ≤ 5% |
| Storage | Bytes per record: raw (the probe's lines were about 430 bytes) and collected and compressed | Per million audited statements |
| Rotation | Files rotate at 64 MB or hourly under load, and the collector keeps up | No backlog after 1 hour at full load |
| Full dataset | Fill the quota, keep writing | Writes continue; the gap is reported with start and end; nothing else on the VM is affected |
| The hook | Every error class from client sessions, on 16 and 18 | Client gets the full error; the log holds none of the values |

---

## 18. Prototype and its tests (Gate 0 exit)

The prototype has the image with pgAudit, the hook and the transaction line
in `bb_identity`, the dataset, the collector and `fox audit-log status/show`.
Its suite will contain:

1. **No values kept: the Gate 0 exit test.**
   - Run a workload with distinctive synthetic values (Verhoeff-valid
     Aadhaar numbers, PANs, emails, card numbers that pass Luhn) through the
     Gateway, the console, the REST API, MCP, and `fox import`.
   - Include errors of every common class: unique violation, bad cast,
     check, foreign key, not-null.
   - Then scan the raw files, the store, the forwarded output and the
     containers' Docker logs with point 4.1's recognisers.
   - **Zero hits in default mode.** In forensic mode, hits only in statement
     text.
2. Writes to a marked table are logged, and to an unmarked table are not.
   Reads are logged only with `--reads`.
3. The audit role's grants travel to a new branch.
4. Coverage through a view, a `SECURITY DEFINER` function, a CTE, a trigger,
   and `COPY` into a marked table. Each is logged or listed in section 12.
5. Each transaction line says COMMIT or ROLLBACK correctly, including a
   rollback to a savepoint. It carries F1's application user and state.
6. No client role can change a `pgaudit` setting.
7. Gap detection: a removed record is reported. A stopped collector catches
   up. A full dataset is reported with start and end.
8. Section 17's measurements, written up as F2's benchmark was.

---

## Decisions

| # | Decision | Recommendation |
|---|---|---|
| 1 | How values are kept out of error lines | The log hook in `bb_identity` (section 6); `log_min_messages=log` only if the hook proves unsafe |
| 2 | Where logs live | A dataset of their own, with a quota; collected, chained, forwarded (section 9) |
| 3 | Existing installs | Opt-in with `fox audit-log setup --yes` (restarts `main`) |
| 4 | New installs | On by default if section 17 is within budget. **It is not** (section 19, item 5), so opt-in, as for existing installs |
| 5 | Retention | 1 year default mode, 30 days forensic, 2 days raw |
| 6 | Reads before masking | Per table, for everyone, with `--reads` |
| 7 | Command name | `fox audit-log` (`fox audit` stays the security log) |
| 8 | Editions | pgAudit, marking, the store, the chain and forwarding in Standard. Automatic marks, anchors and the evidence export in Enterprise |

---

## 19. What the prototype found (Gate 0)

The prototype adds three things:

- pgAudit in the engine image, pinned per major;
- the log hook and the transaction line in `bb_identity`, installed only when
  the library is preloaded;
- `scripts/integration_f6.sh` (`make integration-f6`).

The suite builds the image for PostgreSQL 18 and 16 and runs throwaway
servers with audit on. It touches no install.

**The Gate 0 exit holds.** A workload as an application's role sent
synthetic values (Verhoeff-valid Aadhaar numbers, Luhn-valid card numbers, a
PAN, an email, a phone number) through simple and extended queries, `COPY`
and PL/pgSQL. It raised ten kinds of error, and `RAISE` at every level. The
whole server log held none of the values, and neither did the containers' own
output, on both majors. Neither held the F1 token. No line carried a detail,
a context, a hint or a statement. The client still got every error whole.

What it changed or added:

1. **The hook redacts more than errors** (section 6). Anything a client
   session, background worker or autovacuum worker sends to the server log is
   redacted to its severity and SQLSTATE: errors, warnings, and `RAISE LOG`.
   A function can `RAISE LOG` any value it likes, at a level the server logs.
   Only pgAudit's own lines pass, recognised by the file that raised them
   (`pgaudit.c`). `RAISE LOG 'AUDIT: OBJECT,…'` with a value in it is
   redacted like anything else, so a forged audit line cannot carry data.
2. **The transaction line carries its own virtual transaction** (section 7).
   By the time a commit's callback runs, the process has cleared it, and the
   log's `vxid` field reads `n/0`. The line therefore says which transaction
   it closes: `AUDIT: TXN,5/2,COMMIT,asserted,shop,alice`.
   - A virtual transaction id is reused by a later session in the same slot,
     so records join on `session_id` and the virtual transaction together.
   - A rolled-back savepoint adds `AUDIT: TXN,5/2,SUBROLLBACK,2`: the last
     two audit lines did not take effect.
   - Whom-for is decided at pre-commit, so an assertion undone with its
     savepoint is none, as F1's design section 5.3 has it.
3. **Coverage, measured** (section 12):

   | Path | Logged |
   |---|---|
   | Through a view | yes, writes and reads |
   | A CTE | yes |
   | A trigger (invoker's rights) | yes |
   | `COPY … FROM` | yes |
   | `TRUNCATE` | no. Refused by the Blackbox by default |
   | **Inside a `SECURITY DEFINER` function** | **no**, whether the owner is a superuser or not |

   **The last row is new, and a real gap.** Options for Gate 1, to decide
   there:
   - log `FUNCTION` calls for definer functions only, by marking them;
   - refuse to mark a table that a definer function writes, until the
     function is reviewed;
   - state it, and have `fox audit-log status` list the definer functions
     that touch marked tables.

   The last costs nothing and is honest either way.
4. **A full log is silent** (section 13). With the log's space full, every
   write still succeeded (4,000 of 4,000) and the server kept answering.
   - Only 1,301 of the 4,000 audit lines reached the log.
   - Nothing said so: not the server's own output, and not its stderr file.
   - Once space was freed, lines were logged again.

   So the gap is found only by the collector's own checks: free space,
   statement numbers and the heartbeat. This is now required, not optional.
5. **Cost: over budget, so audit stays opt-in.** pgbench on PostgreSQL 18,
   16 clients on the test VM's 4 CPUs, so the CPUs are full, logs on disk.
   Three rounds per mode, medians:

   | Mode | Write capacity (TPC-B) | Read capacity (`-S`) | Log per write transaction |
   |---|---|---|---|
   | pgAudit alone, every statement audited | −16% to −32% | −23% to −49% | 2,204 bytes |
   | Default mode (pgAudit, hook, transaction line), every statement audited | −13% to −48% | −36% to −65% | 2,577 bytes |
   | Default mode, one write in five audited | −13% to −29% | not audited: +12% to −22% | 820 bytes |
   | Forensic mode, every statement audited | −13% to −37% | −35% to −58% | 2,869 bytes |

   - **Measured:** each figure is the median of three rounds against audit
     off, and the range is over five such runs.
   - **The VM is noisy.** The read column for one write in five audits no
     reads at all, yet it moved from 12% faster to 22% slower than audit off.
   - **Log sizes were counted line by line**, not estimated. In 128,451
     transactions of default mode and 83,834 of forensic mode:
     - every audited statement had its line;
     - every transaction had its transaction line;
     - no line was cut off.

     Under load, PostgreSQL's logging process slows the server rather than
     drop a line. The suite now checks this every run.

   - **The cost is the log's volume.** Each audited statement is one line of
     about 430 bytes. Every line goes through PostgreSQL's single logging
     process, which slows the server rather than lose one.
   - **The hook's own share could not be separated from the noise.** Across the
     five runs it ranged from nothing to 16 points on writes. On single-statement
     reads it adds a second line per transaction, the transaction line,
     which shows in both.
   - **The 5% budget is not met** with every statement audited, nor with one
     write in five. A precise figure needs a quiet machine, not the shared
     test VM, and that is a Gate 1 item. The answer does not depend on the
     precision: the cost is far above 5%.
   - **How it was measured matters.** With 4 clients the runs were bound by
     round trips, not CPU, and audited reads came out *faster* than
     unaudited. A busy logging process keeps the virtual CPUs awake. The
     figures above are capacity with the CPUs full: the fair measure, and the
     worst.

   **What follows:**

   - Section 15 put audit on by default for new installs only within budget.
     It is not, so **audit is opt-in everywhere**, and the console says what
     it costs before turning it on.
   - For Gate 1:
     - a shorter line format: `stderr` with a compact prefix, against
       `jsonlog`'s ~500 bytes;
     - a transaction line only for transactions that wrote, or that read for
       an asserted user;
     - reads audited only for tables marked for reads, which section 8
       already makes the rule.

6. **Two values a client controls stay in the raw log.** `application_name`
   and the client address are written by PostgreSQL itself, beside every
   line, and no hook can change them. The collector drops them (section 5),
   and raw files live at most 2 days.
7. **Passwords:** pgAudit redacts them even in forensic mode
   (`PASSWORD <REDACTED>`). Parameters stay out in both modes: a read with a
   bound card number logged the read and not the number.

Everything else in sections 1 to 18 held as written.

---

## 20. Gate 1: the plan, and step 1

Gate 1 puts pgAudit in the product (the review plan's Gate 1 item 2). Each
step is its own branch from `main` and its own PR, with the full regression
before it opens.

| Step | Adds | CLI | Console |
|---|---|---|---|
| 1 | Turning it on and off: the image (revision 3), start-time settings and the policy on main, branches and the standby, the log in its own dataset with a quota | `fox audit-log status / setup / off`, a `fox check` line | the Audit log page (status) |
| 2 | Marking tables, for writes and for reads (section 8) | `fox audit-log table <t> [--reads] [--off]` | a mark in the schema rail, the marked tables |
| 3 | The collector: raw files into a hash-chained store, kept by retention, and read (sections 5 and 9) | `fox audit-log show`, `verify` | the records, filtered |
| 4 | Gaps and delivery: free space, statement numbers, the heartbeat (section 13, required by section 19) | `fox check` lines | findings |
| 5 | Forensic mode, retention settings, forwarding (sections 10, 11, 9) | `mode`, `retention`, `forward` | settings |
| 6 | Enterprise: automatic marks from point 4, anchors for the chain, the evidence export; the `SECURITY DEFINER` decision (section 19) | | |

### Step 1, as built

- **The way in.** `fox audit-log setup` says what it will do and what it
  costs. Run with `--yes`, it:
  - makes sure the image is revision 3, fetching or building it;
  - makes main's log directory;
  - records the choice and restarts main;
  - applies the policy and restarts the standby.

  `off` undoes it the same way. Both are refused while the standby serves
  main, as the change feed's are, and both go in the security log.
- **The command line** gains the start-time settings: the two libraries, and
  the logging process writing JSON to the log directory. They come after
  everything else, so with audit off every database's command line is
  unchanged to the byte, and a test holds it.
- **The policy** is applied by `ALTER SYSTEM`, so step 5's mode change is a
  reload. It is applied:
  - to main after setup and on every `fox up`;
  - to a branch when it is made, woken or recreated.

  A database not started with pgAudit is skipped, because `ALTER SYSTEM`
  would refuse settings that do not exist there. `off` resets exactly what
  the policy set, and keeps the two roles, so a table's mark survives being
  turned off and on.
- **The log** is `/dbpool/audit/<branch>`, a ZFS dataset beside
  `dbpool/branches`, never inside it.
  - The quota is `FOX_AUDIT_QUOTA` (2G), set on each start.
  - Each directory is owned by the container's postgres user, mode 0700.
  - Until the collector exists, PostgreSQL keeps it to a week by itself: one
    file per weekday and hour, each overwritten a week later.
  - On btrfs it is a directory without a quota, and `fox check` watches it.
- **Branches made before** keep their command line through a suspend, which
  stops the container rather than removing it. `Resume` therefore makes the
  container again, from the same data, when its setting does not match the
  install's. A branch picks the change up the next time it wakes. Until
  then `status` and the API name it.
- **`fox check`** warns at 80% of the quota and fails at 95%. A full log loses
  lines without a word (section 19), so this is the only warning there is
  until step 4.
- **The console's Audit log page** shows the state, where the log is, its
  space and the branches waiting. Turning it on stays the CLI's, which says
  what it will do first, as `fox realtime setup` does. The page names the
  command.

---

## 21. Gate 1, step 2: marking tables, as built

- **A mark is a grant.** pgAudit's object audit logs a statement when the
  audit role holds the privilege it uses, so:
  - `bb_audit` gets INSERT, UPDATE and DELETE on a marked table, and SELECT
    too when its reads are marked;
  - `bb_audit_read` gets all four, ready for the logins that will have their
    reads audited once masking exists (section 8).

  Marking a table again without reads takes SELECT back from `bb_audit`.
- **Only a table can be marked** (`relkind` r or p). A view is refused,
  naming the tables under it as what to mark: pgAudit logs a statement on a
  view against those tables, as the coverage table in section 19 shows.
- **The two roles are made if missing**, so a table can be marked before
  audit was ever turned on. The mark waits for audit, and turning audit off
  keeps it.
- **Marks are in the catalog.** A branch made after a mark carries it, as
  point 4's marks travel.
- **Who:** reading the marks is Use, since the grants are in the catalog for
  anyone to read. Changing them is Manage: the branch's owner, or an admin
  on main.
  - Each change is in the security log.
  - It is also in the Blackbox, as the GRANT or REVOKE it is, under the
    person who asked.
- **The surfaces:**
  - `fox audit-log table <t> [--reads] [--off] [--branch b]` and
    `fox audit-log tables`;
  - `/api/branches/{name}/audit/tables`;
  - **Audit…** on a table's view in the console, beside **Track changes…**;
  - the Audit log page's marked tables, for any branch.

**Found: a table's owner can take its mark off.** A superuser's GRANT on a
table is recorded as granted by the table's owner, so the owner can REVOKE
it, as with any grant on what they own. This is not silent: pgAudit logs the
REVOKE in the ROLE class, for every login, under the owner's name.
Integration §11z shows it. A stronger guard would need marks that no table
owner can touch, which pgAudit's grant-based design does not offer.

**Found by the UI suite: marks and promotion.** A mark is a GRANT, recorded
in the source branch's Blackbox like any schema change. Promoting that branch
replays it on the target. A target that never had the audit roles refused
it, and with it the whole request. Applying a request now makes the two roles
on the target first. They carry no privileges, so this changes nothing else
about the target.

Step 4 will compare each branch's marks with the ones set through FoxByte,
which the security log holds, and report a mark that has gone.

---

## 22. Gate 1, step 3: the collector and the store, as built

- **Who reads the raw logs.** PostgreSQL writes them as the container's
  postgres user, mode 0600, so the collector reads them through sudo, as the
  engine reaches everything else it does not own. It lists the files and
  reads only what is new past its offset, and only complete lines. The store
  it writes belongs to the install's user, so the CLI and the console read
  records without sudo.
- **When.** The control plane collects every minute, and `show`, `verify` and
  the console's Records collect first, so a read is never a minute stale. A
  file lock lets one collector run at a time.
- **What a record keeps** is section 5's list:
  - when, branch and login;
  - the kind (a statement; how a transaction ended, with whom it was for; or
    an error, as its SQLSTATE);
  - pgAudit's class, command and object;
  - the statement numbers, session and virtual transaction;
  - forensic mode's text, and nothing else.

  The server's own lines are not records. They stay in the raw files for
  two days, for an operator.
- **The store** is `AuditRoot/.store`, mode 0700, never mistakable for a
  branch, since a branch's name cannot start with a dot.
  - It holds one gzip file per day, appended to as one more member per
    batch.
  - A state file records how far each raw file was read, how long each day's
    file is, and the chain's head.
  - The batch is written before the state. After a crash between the two,
    the next run cuts the day file back to what the state says and reads the
    batch again, so nothing is lost or written twice.
  - **Only a crash's leftover is cut, found by integration §11aa.** A batch
    is one gzip member, so a crash leaves bytes that begin, at exactly the
    recorded size, with gzip's magic number. The first version cut any day
    file longer than the state said. An edited and recompressed file is
    usually longer, so the collector, running every minute, would have cut
    it into a file that cannot be read. `verify` then failed with a read
    error rather than reporting the edit. Now an edit is left as it is, and
    `verify` reports it, carrying on through the other days.
- **Records are filed by the day they are collected, found by §11aa.** The
  first version filed each record by its own time. A raw file collected late
  put records with the newest numbers into an older day's file, and `verify`,
  reading the days in order, found the chain going backwards. Filed by
  collection, the files in date order are the chain in order. A read from a
  day on still finds every record of that day on, because a record is
  collected on or after the day it happened.
- **The chain.** Each record holds the previous one's hash and its own:
  SHA-256 over the record as JSON, with its fields in their declared order.
  `verify` checks every link, and that the store ends where the collector
  wrote, so records cut from the end are found too.
  - The store belongs to the install's user, so that user, or the host's
    administrator, could rewrite the whole chain consistently.
  - Anchoring its head outside the machine (step 6, Enterprise) is what
    closes that, as for the Blackbox and the security log.
- **Raw files** are removed once read to their end and two days old.
  - A database's current file is never two days old: PostgreSQL starts a new
    one every hour.
  - A file PostgreSQL replaces under its name a week later is recognised by
    its first line, which does not change as a file grows, and is read from
    its start.
- **Retention** removes whole days older than `FOX_AUDIT_RETENTION_DAYS`
  (365). The state keeps the last record removed, and the chain verifies from
  it. Step 5 makes retention a setting, and adds forensic mode's own.
- **Reading.**
  - `fox audit-log show` shows each statement with how its transaction ended,
    the SQLSTATE that ended it, and whom it was for, joining the
    transaction's record by session and virtual transaction (section 19,
    item 2). Errors outside an audited statement are lines of their own,
    with `--errors` for those alone.
  - The API and the console's Records do the same, for admins only.
  - Every read is in the security log: the records name logins, and whom
    changes were for.

---

## 23. Gate 1, step 4: gaps and delivery, as built

A full log drops lines without a word (section 19), so nothing PostgreSQL
says can be waited for. Each finding below is checked from outside.

- **Gaps.** Measured first: pgAudit numbers only the statements it logs, one
  after another in a session. Two audited inserts with unaudited statements
  between them were numbered 1 and 2.
  - So a session whose numbers jump has lost lines, and the collector writes
    a gap record into the chain, before the statement that showed it,
    naming the session's login and the missing numbers.
  - The last number of each session is kept between collections, and
    forgotten two days after it was last seen.
  - What it cannot see: lines lost at the end of a session, which nothing
    after them numbers. The heartbeat covers that.
- **The heartbeat.** Every five minutes the control plane has each running,
  audited database run `SET pgaudit.log = 'misc_set'` as the engine's
  superuser, in a session of its own. pgAudit logs that SET as MISC, which
  was also measured first.
  - It touches no table, so the Blackbox records nothing.
  - No client logs in as that superuser, and the policy logs MISC for no one
    else, so the collector knows the line as a heartbeat.
  - A database started more than 15 minutes ago with no heartbeat in the
    last 15 minutes is a finding. It goes through docker, never the Gateway,
    so it keeps no branch awake. `fox audit-log heartbeat` sends one now.
- **The collector** not having finished a run for five minutes is a finding:
  the control plane is down, or the collector is failing every minute.
- **Marks taken off** (step 2's finding). The marks set through FoxByte are
  read back from the security log, the last word on each table.
  - A table that should be marked and still exists, whose grant has gone, is
    a finding naming who marked it. The same goes for reads that should be
    audited and are not.
  - A table dropped since is not a finding: the drop is its own change, in
    the Blackbox.
  - Only running branches are checked; none is woken to be.
- **Space**, as step 1 had it.

Each finding is a warning in `fox check` with what to do. Findings appear in
`fox audit-log status`, in `GET /api/audit-log`'s `findings`, and on the
console's Audit log page. `show` lists gap records with the statements, and
leaves heartbeats out.

---

## 24. Gate 1, step 5a: forensic mode and retention, as built

Step 5 became two PRs: this one, and forwarding (5b).

- **Forensic mode** turns on `pgaudit.log_statement` for every branch or one
  branch, by `ALTER SYSTEM` and a reload.
  - It needs an admin, a reason, and `--yes` after it says what it keeps.
  - Every running database it covers takes it at once. A branch started
    later takes it from the policy, which now sets the mode per database.
  - `pgaudit.log_parameter` stays off in both modes, because F1's tokens are
    parameters.
  - The settings live in the state directory (`audit-settings.json`), beside
    the audit marker.
- **The text is not in the chain.** This is a change from sections 9 and 10,
  which put forensic records in the store like any other.
  - A record holds `text_sha`, the SHA-256 of its statement's text.
  - The text goes to `.store/forensic/<day>.jsonl.gz`, written just before
    its records.
  - Removing the text, at its retention or for a person, therefore breaks
    nothing, because the chain never held it.
  - `verify` checks every text still kept against the hash its record
    holds. A text changed after it was kept is reported.
  - A read shows the text while it is kept and matches. Otherwise it says
    the text was removed.
- **Purge** (`fox audit-log purge --user <login>`, F4) removes every text that
  login's statements left. The records stay: what was done stays, and what it
  held goes. It is in the security log, with how many texts went.
- **Retention** is a setting (`fox audit-log retention`): records 365 days and
  text 30 by default. Text is never kept longer than its records: shortening
  the records' retention shortens the text's with it. The setting comes
  before `FOX_AUDIT_RETENTION_DAYS`, which comes before the default.
- **Seen everywhere.**
  - `fox check` warns while forensic mode is on: where, by whom, why, since
    when.
  - `status` says it.
  - The console's Audit log page has the mode, retention and a purge, each
    behind a confirmation, and shows the text under its record.

## 25. Gate 1, step 5b: forwarding to a SIEM, as built

`fox audit-log forward <url>` sends a copy of every record to a SIEM, as
section 9 says: from the collected records, never the raw files, so the SIEM
receives no more than the store holds.

- **Two ways, both over TLS.** Every record names a login, so plain `http://`
  and unencrypted syslog are refused.
  - `https://…`: records as JSON lines (`application/x-ndjson`), one POST per
    batch of up to 500. A 2xx answer means delivered. A redirect is a
    failure, not followed, since it would take the records and the token
    somewhere nobody set.
  - `syslog://host[:6514]`: RFC 5424 messages over TLS, framed with octet
    counting as RFC 5425 says. Facility 13 (log audit). Severity is
    informational, a notice for an error's outcome, and a warning for a
    gap. The APP-NAME is `bb-audit`, not the product's name, so a rename does
    not break the SIEM's rules. The record's JSON is the message.
- **Each record goes with its place in the chain** (`seq`, `prev`, `hash`).
  The SIEM's copy links record to record, so a record changed or removed here
  afterwards shows against it. For Standard this is the anchor section 14
  names for the host administrator.
- **Statement text goes only with `--text`.** By default a forensic record
  goes with its `text_sha` and not the text. Once the text is in the SIEM,
  FoxByte's retention and purge (section 24) no longer reach it, and the
  CLI and the console say so before it is set.
- **Secrets.**
  - A token is for HTTPS only, and is sent as `Authorization: Bearer`.
  - A URL holding a user or password is refused, with where a token goes
    instead.
  - The token and a CA bundle are copied, when forwarding is set, into files
    of the engine's own in the state directory (0600). They come from the
    CLI's `--token-file` (or `-` for stdin) and `--ca`, or from the console's
    form.
  - Nothing later makes the engine read a path someone named. A console
    admin, who need not be the host's administrator, therefore cannot send
    a host file somewhere as a "token". Neither is ever sent back.
  - With `--ca`, only that bundle is trusted; otherwise the system's CAs.
- **Delivery is at least once.**
  - A position beside the store (`.store/forward.json`) says how far the SIEM
    has got. It moves only once a batch is delivered, so a failed batch is
    sent again.
  - The control plane collects and then forwards every minute, up to 10,000
    records a run. `forward --now` (or the console's Send now) runs it at
    once.
  - Forwarding has a lock of its own, so a slow SIEM never holds up
    collection.
  - Forwarding starts from the next record, or with `--from-start` from every
    record the store still holds.
  - Syslog has no acknowledgement: a batch the TLS connection took counts as
    delivered, and the session ends with close_notify.
- **Found when it goes wrong** (section 13).
  - Forwarding that fails for more than five minutes is a finding: in
    `fox check`, `status`, the API and the console, with the error and how
    many records wait. The records wait in the store until their retention.
  - Records retention removes before they are sent are counted, and are a
    finding for a week.
  - The control plane's log says a failure once, and again when it works.
- **Changes are in the security log** (`audit-log.forward`): where to,
  whether text goes, from where. Never the token.
- **Setting forwarding before the audit log was ever on** makes the log's
  dataset first, with its quota, as setup does. It never leaves a plain
  directory where the dataset would be mounted.
- **Not in this step:** client certificates for syslog (mutual TLS), and
  several destinations at once.

---

## 26. Gate 1, step 6a: anchors, automatic marks and SECURITY DEFINER, as built

Step 6 is two PRs, as step 5 was. This one is anchors, automatic marks and
the SECURITY DEFINER decision. The evidence export (6b) reports all three, so
it comes after.

### Anchors (Enterprise)

The chain shows a record changed, or one taken from the middle. It cannot
show the newest records taken away with `state.json` edited to match, or the
whole store rewritten with every hash recomputed. Whoever can write the store
can do both.

- **An anchor is the chain's head at one moment.** It holds the last record's
  number and hash, and follows the anchor before it.
  - It is signed with the install's anchor key, as the Blackbox's and the
    security log's anchors are.
  - It is written read-only to `anchors/_audit-log/`, beside theirs.
  - It is copied with them to the backup bucket, and to the anchor target
    under Object Lock when one is set.
- **The engine anchors every 10 minutes** (`FOX_CHECKPOINT_INTERVAL`), on the
  checkpointer that anchors the branches. `fox audit-log anchor` anchors now.
- **It refuses to anchor what does not verify:** an anchor over a broken
  chain would bless it.
  - The first anchor checks the whole store.
  - Later ones check the record the last anchor holds is unchanged, and the
    records since chain from it. A year of records is not read every ten
    minutes.
- **`verify` checks the store against every anchor:**
  - each follows the one before;
  - the record each holds is there and unchanged;
  - none holds a record past the store's end;
  - an anchor copied off the machine is still here;
  - the signatures hold.
  An anchor whose record retention removed is noted, not failed.
- **Writing anchors is Enterprise; checking them is free,** as for the
  Blackbox. An install that anchored before changing edition still verifies.
  `status` and the console say how far anchoring has got.

### Automatic marks (Enterprise)

Section 8 said a confirmed personal-data mark (point 4.6) grants the audit
role automatically. Now it does.

- **Confirming a finding marks its table's writes,** if they are not audited
  already. This holds in the CLI and the console, and the decision says so.
  The mark is recorded in the security log like any other, so taking it off
  outside FoxByte is a finding (step 4).
- **It only adds.** Reads are left as they were. Rejecting or reopening a
  finding takes nothing off, because a mark that disappears on its own is a
  gap nobody chose. `fox audit-log table <t> --off` takes it off, on the
  record.
- **Tables confirmed before this, or unmarked since,** are named:
  - by `fox audit-log tables` and `status` (main), in every edition;
  - by `GET …/personal-data/unaudited`, for the branch's owner or an admin,
    as where personal data sits is.
  `fox audit-log table --personal-data` (Enterprise), or the console's
  button, marks them all.
- **The licence:** this uses the personal-data feature, and anchors the
  anchors feature. No licence gains a new name.

### SECURITY DEFINER: said, not refused

Section 19 found that pgAudit does not see the statements inside a SECURITY
DEFINER function. It gave three options: log such functions' calls, refuse
to mark tables they write, or state it. This is the third, which costs
nothing and is honest either way. The other two can still come.

- **Each definer function whose body names a marked table** is a finding
  (`definer`):
  - in `fox check`, as a warning with the fix;
  - in `status` and the console, beside the marked tables;
  - with whom it runs as, and which tables.
- **Function sources are matched by word**, so the check can say too much (a
  comment, a column of the same name) or too little (a name built for
  EXECUTE). It says which function, so a person can look.
- **Left out:** functions in the Blackbox's own schemas (`bb`, and F1's
  `bb_f1`), and functions an extension installed.
- **The fix it names:** if the function need not run as its owner, make it
  `SECURITY INVOKER`, whose statements are audited. The suite shows both
  cases: a write through the definer function is not in the log, and once
  the function is made invoker, the same write is.
