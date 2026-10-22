# What the Blackbox records, and what it does not

The Blackbox is FoxByte's record of changes to a database's schema. This page
says exactly what goes into it, how, and where it stops, so that nobody has to
take "every change is recorded" on trust.

There are two ways a change gets into the Blackbox:

- **As it happens.** Event triggers inside the database write an entry in the
  same transaction as the change, attributed to the login role that made it.
  These entries are `APPLIED`, `FLAGGED` or, for a change the guardrails
  refused, `BLOCKED`.
- **After the fact.** The engine's **catalog scan** reads the catalogue every
  five minutes (and whenever someone runs `fox blackbox scan`), compares it with
  what it read last time, and writes an entry for every difference no entry
  accounts for. These entries are `UNRECORDED` or `OBSERVED`, carry no actor,
  and say in their statement between which two scans the change was made.

## Recorded as it happens

In the database FoxByte serves on each branch:

| Change | Recorded |
|---|---|
| `CREATE` and `ALTER` of tables, partitioned and foreign tables, views, materialized views, indexes, functions, procedures, aggregates, types, domains, triggers and row-level security policies, including renames and changes of owner | yes |
| `DROP` of tables, views, materialized views, indexes, sequences, schemas, types, domains and functions | yes |
| `DROP` of triggers, policies, procedures, aggregates and foreign tables | no: the catalog scan records them, as `OBSERVED` |
| `GRANT` and `REVOKE` on objects, `ALTER DEFAULT PRIVILEGES` | yes, but the entry does not name the object a `GRANT` was on |
| `TRUNCATE`, by anyone | yes |
| `UPDATE` and `DELETE` by an agent | yes, one entry per statement |
| `UPDATE` and `DELETE` by a person, and every `INSERT` | no (row tracking keeps who changed each row of a tracked table) |
| Reads (`SELECT`) | never |
| A change the guardrails refused | yes, as `BLOCKED`, written through a separate connection so it survives the rollback |

Left out on purpose, as noise: `CREATE SCHEMA`, `CREATE EXTENSION`, `COMMENT`,
`ALTER DATABASE`, `CREATE` and `ALTER SEQUENCE` (a column's own sequence is part
of its table), the primary-key index created with a table, everything in the
Blackbox's own schema `bb`, and the triggers the Blackbox attaches to user
tables.

**Who** is the login role, which a client cannot change: the gateway logs each
person in as their own Postgres role and each agent as an agent role. **Which
tool** is `application_name`, which the client sets, so it describes a change
rather than proving where it came from. An application that shares one login
role between many people is recorded as that role, not as a person.

## Recorded after the fact, by the catalog scan

**`UNRECORDED`**: a change to any object in the first table that no entry
accounts for. The event triggers did not run for it. A superuser can stop them:

- for one session, with `SET event_triggers = off` (PostgreSQL 17 and later) or
  `SET session_replication_role = replica` (every version);
- for everyone, with `ALTER EVENT TRIGGER … DISABLE`, `DROP EVENT TRIGGER`, or
  by replacing the Blackbox's own functions.

Each start of the engine also re-creates the Blackbox's event triggers, and a
change made in that moment is unrecorded too. The scan finds the change
whichever way the record was stopped, because it compares the catalogue itself.

**`OBSERVED`**: a change event triggers never see, because it is not inside one
database:

- roles: created, dropped, renamed, or given `SUPERUSER`, `LOGIN`,
  `CREATEROLE`, `BYPASSRLS` and the like;
- role memberships (`GRANT role TO role`), including membership of the
  predefined roles such as `pg_read_all_data`;
- settings attached to a role or a database (`ALTER ROLE … SET`, `ALTER
  DATABASE … SET`), and the server's `event_triggers` and
  `session_replication_role`;
- event triggers, databases and tablespaces;
- the drops in the first table that the event triggers leave out.

An `OBSERVED` entry whose risk is **`kill-switch`** is a change that stops the
record: a setting that turns event triggers off or replica mode on for a role,
a database or the server, the Blackbox 2.0 capture's own switch (`bb.v2 =
off`), or one of the Blackbox's event triggers disabled or dropped. A disabled
event trigger is reported when two scans in a row see it, because each start
drops and re-creates them.

The scan keeps what it saw in the engine's state directory, not in the
database, so a superuser who stops the event triggers cannot also edit the
scan's memory to hide the change. Its entries are hash-chained, verified by
`fox blackbox verify` and anchored like every other entry. It runs in every
edition.

## What the scan cannot tell you

- **Who** made an `UNRECORDED` or `OBSERVED` change, or **exactly when**: only
  that it happened between two scans.
- **A change undone before the next scan.** A table created and dropped within
  five minutes, with the event triggers stopped, leaves nothing to find.
- **Anything before the first scan of a branch.** The first scan is a baseline.
  After a PostgreSQL major upgrade, or when a database's history is not the one
  the scan last read (it was restored, replaced or rewritten), the scan starts
  again from what is there and writes an entry saying so.
- **Which privilege change a GRANT covered.** Because a `GRANT`'s entry does
  not name its object, any recorded `GRANT` or `REVOKE` accounts for every
  change of privileges between the same two scans; likewise any `DROP …
  CASCADE` accounts for every object that disappeared. An unrecorded change of
  that kind made in the same five minutes as a recorded one is not reported.
- **Commands event triggers do not support**, such as `REASSIGN OWNED`, show up
  as `UNRECORDED` even though nothing was stopped.

## Not watched at all

- Sequences, schemas themselves, extensions, comments, statistics,
  publications and subscriptions, foreign servers and user mappings, casts,
  operators, collations, text search objects and large objects.
- Passwords. The scan never reads them, so a password change is not recorded.
- **Other databases in the same Postgres.** The Blackbox is installed in the
  database FoxByte serves. If someone creates a second database, the scan
  records that it was created; nothing inside it is recorded.
- The Blackbox's own schema, `bb`. Its integrity is what `fox blackbox verify`
  (the hash chain) and `fox blackbox integrity` (signed anchors) check.

## Who can get round it

The record is built against people and agents who log in through FoxByte,
none of whom is a superuser: they cannot stop the event triggers, write to the
Blackbox or change what the scan saw. A database **superuser** can stop the
event triggers, and the scan then records what they changed without knowing it
was them. Someone with **root on the machine** can also edit the scan's state
and the anchors kept there; for them, anchors kept elsewhere
(`fox blackbox anchor-target`) are the proof that history was not rewritten,
and nothing on the machine itself can be.

The scan detects; it prevents nothing.

### Why the event triggers are not set to fire always

Postgres can make an event trigger fire even in replica mode (`ALTER EVENT
TRIGGER … ENABLE ALWAYS`). FoxByte does not, for two reasons. The Blackbox's own
install scripts use replica mode on purpose, so that their own statements are
not recorded on every start, and with the triggers firing always they would be.
And it would close only one of the ways a superuser can stop the triggers:
`event_triggers = off`, disabling or dropping them still work. The scan is the
answer to all of them at once.
