# F6: audit coverage — design

**Status:** for review. Written against `main` at `d80f6e9`. It answers Gate 0's
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
| 4 | New installs | On by default if section 17 is within budget |
| 5 | Retention | 1 year default mode, 30 days forensic, 2 days raw |
| 6 | Reads before masking | Per table, for everyone, with `--reads` |
| 7 | Command name | `fox audit-log` (`fox audit` stays the security log) |
| 8 | Editions | pgAudit, marking, the store, the chain and forwarding in Standard. Automatic marks, anchors and the evidence export in Enterprise |
