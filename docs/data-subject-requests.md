# Data-subject requests

How to answer a person who asks what FoxByte holds about them, asks for a copy,
or asks for it to be erased, under the DPDP Act (India) or the GDPR. This page
says what FoxByte does for you, and what it leaves to you on purpose.

FoxByte holds personal data in two places, and they are handled differently:

1. **Its own accounts** — the people who sign in to the console or use API keys.
   Their accounts, keys, sessions and the security log are in FoxByte's account
   store.
2. **Your databases** — `main` and its branches, which hold whatever your
   applications put in them. FoxByte does not know who the people in your
   tables are; you do.

## Accounts

### Access and portability

A signed-in account holder can download their own data, without an admin:

```
GET /api/account/export
```

It returns JSON: the profile, linked GitHub or Google sign-ins, API keys
(described — name, prefix, scope, when made and last used — never the secret),
the branches the account owns, its open sessions (when each began and ends, never
a token), and the security-log events where the account acted or was acted on.
An IP address is shown on an event only when it was the account's own; the
address an admin acted from is the admin's. Query history and saved queries are
in `GET /api/history` and `GET /api/saved-queries`.

The console does not have a button for this yet; call the endpoint with a
session or an API key.

### Erasure

An account holder can delete their own account:

```
DELETE /api/account        {"password": "…"}
```

It needs the current password, or a console sign-in made in the last ten
minutes (for accounts that only sign in with a provider). An API key alone is
not enough. The only admin of an install cannot delete themselves; make someone
else an admin first. On an HA standby it is refused, because the accounts there
are a copy of the primary's.

An admin can delete any other account from the console (`DELETE /api/users/{id}`)
or the machine (`fox user delete <email>`). Every route does the same thing:

- the account, its sessions, API keys, provider sign-ins, pipelines, query
  history and saved queries are deleted, and its admin grant on `main` revoked;
- the branches it owned stay, reachable by admins only — nothing in a database
  is deleted (see below for what to do about them);
- in the security log, its email, and the IP addresses it signed in from, are
  replaced by a keyed pseudonym (`person:…`, `address:…`).

### The security log after a deletion

The security log is a hash chain anchored outside the store, so its events
cannot simply be edited. Pseudonymising leaves each event's hash, and so the
chain and every anchor, as they were. Each changed event gets a seal instead: a
hash over its original hash and what it now says, written by a
`security-log.pseudonymised` event that is itself chained and anchored and that
records a digest of every seal it wrote. `fox audit verify` checks events by
their hash until they are pseudonymised and by their seal afterwards, so it
keeps passing on existing installs, and an event changed after it was sealed
still fails it.

The pseudonym is an HMAC of the email with a key kept beside the store
(`security-log-pseudonym.key`), so the same person always gets the same token
and an investigation can still follow them through the log. Someone who already
knows an email can find that person's events with `fox audit pseudonym <email>`
(which is itself recorded). Keep that key out of the copies of the store you
hand to anyone; without it the token says nothing about the email. Each HA node
has its own log and its own key.

Copies of the account store taken before the deletion — backups of the state
directory, an HA standby's own log — still hold the old values until they are
replaced or age out.

### Retention

The security log keeps everything until you set a retention:

```
FOX_SECURITY_LOG_RETENTION=400d
```

**There is no default.** How long you keep sign-in records is part of your own
policy, and it is yours to set. With it set, each checkpoint (every ten minutes
by default) removes events older than that which are already anchored, records a
`security-log.pruned` event saying where the log now starts and the hash the
first kept event chains from, and anchors that record straight away.
`fox audit verify` then checks the log from there. `fox audit prune` runs it by
hand. Values are days (`400d`) or Go durations (`9600h`); less than a day is
refused, because it is almost always a missing unit.

## People in your databases

### Finding them

```
fox subject find asha@example.com
fox subject find "+91 98765 43210"
fox subject find 2345 6789 0124 --category aadhaar
```

(Enterprise, from the machine FoxByte runs on.) It says which tables and columns
on `main` and on each running branch hold that value, and in how many rows. It
never prints a row or a value, it changes nothing, and running it is recorded in
the security log without the value searched for.

It looks only in columns a reviewer has **confirmed** as personal data
(`fox pii scan`, then `fox pii mark <id> confirm`; see the personal-data pages of
the guide). Scan and review first, or it has nowhere to look. It compares whole
values after normalising case and separators, so a value buried inside free text,
or in a column no scan found, is not found. Its output lists what it could not
cover.

### Erasing them

FoxByte does **not** erase a person across your databases for you. An erasure
touches your application's data, its foreign keys and its business rules, and
only you can decide what "deleted" means for each table — a row removed, a
column blanked, a record kept because the law requires it. So:

- **On `main`:** delete or update the rows with ordinary SQL, through the
  console, the Gateway or your application. The Blackbox ledger records the
  statements, as it records every change.
- **On branches:** a branch is a copy of `main` at some moment, so it still has
  the rows. Delete branches you no longer need (`fox branch delete <name>`), or reset
  them from `main` after the erasure (`fox branch reset <name>`). `fox subject find` again afterwards to
  confirm nothing is left.
- **The ledger:** the Blackbox keeps the text of the statements it records, and
  a statement can contain the very values you erased (an `INSERT` with the
  person's email in it). Removing those from a tamper-evident ledger is a
  separate design and is not done yet. Note it in your response to the request
  if it applies.
- **The databases' audit log (pgAudit):** `fox audit-log purge --user <login>` removes
  the statement text a database login left; the records stay.
- **Backups and snapshots:** they are not edited. They age out under their
  retention; restoring one brings the data back, so re-apply the erasure after a
  restore.

Record what you did, and when, in your own register of requests: FoxByte's logs
say who ran which statement, not why.
