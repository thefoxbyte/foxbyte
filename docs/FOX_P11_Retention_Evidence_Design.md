# Retention acted on, and the safeguards evidence (points 11.3 and 11.4)

Status: built (`feat/dpdp-retention-evidence`, 28 November 2026). User guide:
`docs/dpdp-inventory.md`, sections "Retention acted on" and "The safeguards
evidence". The Rules are read from G.S.R. 846(E), 13 November 2025; Rules 6
and 8 and the Third and Seventh Schedules were read again on 28 November
2026. FoxByte's reading has not been reviewed by a privacy lawyer.

## 1. What the Rules ask

- **Rule 8(1)**, with the Third Schedule: three classes of business erase a
  person's data three years after they last approached it or exercised a
  right (or after the Rules began), unless a law keeps it.
- **Rule 8(2)**: at least 48 hours before that erasure, the person is told it
  is coming, unless they log in or make contact.
- **Rule 8(3)**: personal data, its traffic data and the logs of its
  processing are kept at least a year from the processing, for the Seventh
  Schedule's purposes, then erased unless a law asks for more.
- **Rule 6(1)(a)–(g)**: reasonable security safeguards "at the minimum":
  encryption, obfuscation, masking or virtual tokens; access control; logs,
  monitoring and review; continued processing, such as backups; logs and
  personal data kept a year; processor contracts; technical and
  organisational measures.
- Rules 6 and 8 apply from 13 May 2027 (Rule 1(4)).

## 2. Decisions (28 November 2026)

1. 11.3 and 11.4 are built together, on one branch, as one PR.
2. Retention runs on a scheduler of its own in the control plane, as backups
   do (Option A). Point 10's general job scheduler stays parked, and can take
   it over later.
3. **A year at least.** A row is erased no sooner than a year from its date,
   whatever its entry says (Rule 8(3)); the status and the inventory say so.
4. **Armed tables only.** The scheduler erases only from a table an admin
   armed, after a preview of what would go now, with a reason. Every other
   table with a period is listed as due, never erased.

Taken as defaults, within those:

5. A table's period is its inventory entry's on `main`; a column's own entry
   is not acted on. Its rows are dated by a column the admin names, which must
   be a `date` or a timestamp.
6. The notice goes before **every** retention erasure, not only the Third
   Schedule's: telling the person costs little, and FoxByte cannot tell which
   class a business is.
7. A row is erased only after a notice the customer's address accepted (2xx),
   and the notice period later (48 hours; `FOX_RETENTION_NOTICE` shortens it
   for a test, and the run says so). An address that refuses means nothing new
   is erased.
8. When the period is up, a row whose date moved (the person came back) is not
   erased: its notice is closed as renewed.
9. A row erased by retention is never noticed again, though a cleared row
   keeps its date.
10. Rule 6(1)(f) and (g), and what FoxByte cannot see in (a)–(d), are the
    customer's declarations, kept like the vault's (with who and when), under
    their own kind.

## 3. How it works

**Retention.** The settings (on, the notice address, the signing key) are in
`<state>/retention.json` (0600); each table's date column and arming, and each
notice, are in the install's store (`retention_tables`, `retention_notices`).
A run, for each armed table:

1. finds the rows dated before the cutoff (the entry's period back from now,
   or a year, whichever is earlier), leaving out those it erased already, up
   to `FOX_RETENTION_BATCH` (500);
2. posts one notice for the rows not yet told, signed with HMAC-SHA256 in
   `X-FoxByte-Signature`, and records a notice for each row if the address
   accepted it;
3. for the notices whose time is up: erases the rows still past the period,
   and closes the others as renewed.

The erasure is an erasure request made by the run (`retention of
public.customers: …`), so 11.2 applies to it: restores past it are refused or
re-apply it, and its outcomes and evidence read as any request's. The engine
finds the rows by key alone (no value), with two options added to its plan:
**only** that table (another table's rows are left to their own retention,
except what a foreign key takes with a delete), and **retention** (the
table's own law reason no longer keeps rows whose period has ended). Main is
erased first, then every branch, by the same keys. The Blackbox, query history
and the audit log are logs, and follow their own retention.

The control plane runs it a day after retention was turned on, then a day
after each run (`FOX_RETENTION_INTERVAL`); `fox dpdp retention run` runs it at
once. One run at a time.

**The safeguards evidence.** `fox dpdp evidence` reads, on this machine now:
the backup target and its encryption, the vault's exposure reports, masking
against masked accounts, the access review's counts, the audit log, main's
Blackbox and the security log's chains, the backups and the last restore
check, the logs' retention, and main's hardening report; and the
declarations. Each clause has a verdict (met, not met, open) and its threat
model. Like the vault's, the document is `safeguards-evidence/1`, a JSON
download from the console.

## 4. What it cannot claim

- The periods and the classes are the customer's. FoxByte does not check an
  entry against the Third Schedule, or the notices given.
- A row with no date in its column is never acted on.
- The person is told by the customer: FoxByte posts the notice, nothing more.
- A large table erased in batches takes a run per batch.
- A safeguard is reasonable or not on the facts; the evidence shows what is
  in place, not that it is enough.
- Rule 7 (breach intimation) and the Seventh Schedule's purposes are not part
  of this. Point 16's breach register is where the 72-hour clock goes.
