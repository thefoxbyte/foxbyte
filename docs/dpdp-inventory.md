# The DPDP inventory: where each word comes from

`fox dpdp inventory` and the console's **DPDP inventory** page record, for each
table holding personal data a reviewer confirmed, why it is held, whose data it
is and how long it is kept. This page says where each word the inventory uses
comes from in the law, so that a privacy lawyer can check the mapping before
anyone relies on it.

**This is FoxByte's reading of the law, not legal advice.** It has not yet been
reviewed by a lawyer. Until it has, treat every label as a suggestion to check.

## Sources

| Source | Reference | Read from | Read on |
|---|---|---|---|
| The Digital Personal Data Protection Act, 2023 (No. 22 of 2023) | Gazette of India, Extraordinary, Part II, Section 1, No. 25, 11 August 2023 | The Gazette copy published on TRAI's website | 24 November 2026 |
| The Digital Personal Data Protection Rules, 2025 | G.S.R. 846(E), Gazette of India, Extraordinary, Part II, Section 3(i), 13 November 2025 | A reproduction of the Gazette pages (dpdpa.com); India Code and MeitY's copies could not be fetched | 24 November 2026 |
| Corrigendum to the Rules | G.S.R. 892(E), 10 December 2025, as other sources report it | **Not read yet.** Check it before relying on this page | — |

**When the Rules apply** (Rule 1). Rules 1, 2 and 17 to 21 applied on
publication (13 November 2025); Rule 4 one year later (13 November 2026); Rules
3, 5 to 16, 22 and 23 eighteen months later (13 May 2027). The Rules the
inventory points to (3, 8, 10 and 11) are in the last group.

## What the law requires, and what you decide

The inventory keeps the two apart.

- **What the law requires**: the list of bases, the meaning of a child, and the
  periods the Third Schedule sets for some classes of business. These are fixed
  in FoxByte and change only with the law.
- **What you decide**: the basis for each table, the purpose, whose data it is,
  and the retention. FoxByte records these and does not check them against the
  notices you gave people or the consents they gave.

## The words

### Basis (`--basis`)

Section 4(1): personal data may be processed for a lawful purpose, either with
consent or for one of the "certain legitimate uses" of section 7.

| Value | Label | Source |
|---|---|---|
| `consent` | Consent | s.4(1)(a), s.6 (consent must be free, specific, informed, unconditional and unambiguous, and limited to the specified purpose); notice, s.5 and Rule 3 |
| `7a` | Given voluntarily for a specified purpose, not objected to | s.7(a) |
| `7b` | A State subsidy, benefit, service, certificate, licence or permit | s.7(b); Rule 5 and the Second Schedule |
| `7c` | A State function under law, or sovereignty, integrity and security | s.7(c) |
| `7d` | A legal duty to disclose information to the State | s.7(d) |
| `7e` | Complying with a judgment, decree or order | s.7(e) |
| `7f` | A medical emergency | s.7(f) |
| `7g` | Health services during an epidemic or other threat to public health | s.7(g) |
| `7h` | Safety or assistance during a disaster or a breakdown of public order | s.7(h) |
| `7i` | Employment, or safeguarding the employer from loss or liability | s.7(i) |

Section 17's exemptions are not a basis. They take processing out of parts of
the Act, and the inventory does not record them.

### Purpose (`--purpose`)

The "specified purpose" is the purpose named in the notice given to the person
(s.2(za)). Rule 3(b) asks the notice to itemise the personal data and give its
specified purposes. Write the purpose as your notice states it.

### Whose data (`--principals`)

The Data Principal is the person the data is about (s.2(j)). These categories
are FoxByte's grouping, not the Act's, with two exceptions:

- **`child`**: a person under eighteen (s.2(f)). Before processing a child's
  data, the parent's verifiable consent is needed (s.9(1); Rule 10). Tracking,
  behavioural monitoring and targeted advertising directed at children are
  barred (s.9(3)), subject to the exemptions in s.9(4)–(5), Rule 12 and the
  Fourth Schedule.
- **`disability`**: a person with a disability who has a lawful guardian. The
  guardian's verifiable consent is needed (s.9(1); Rule 11).

**The notice about children.** When the scanner has found a child's date of
birth in a column (category `child`), and the entry covering that column does
not list children, the inventory shows a notice. The scanner's finding is only
evidence, not proof: it reads a date of birth less than eighteen years ago.

### Retention (`--keep`, `--from`, `--reason`, `--citation`)

Section 8(7): personal data is erased when consent is withdrawn, or as soon as
it is reasonable to assume the specified purpose is no longer served, whichever
is earlier, unless a law requires it to be kept.

| Value | Meaning | Source |
|---|---|---|
| `--from purpose-served` | When the purpose is served; `--keep 0` is "until the purpose is served" | s.8(7)(a) |
| `--from last-contact` | The person's last contact for the purpose, or last exercise of a right | s.8(8) and s.8(11), Rule 8(1) |
| `--from collection`, `account-closed`, `contract-end` | Events you choose; not terms of the Act | — |
| `--reason law` | A law requires the data to be kept; `--citation` names it | s.8(7), opening words |
| `--reason contract` | A contract sets the period; `--citation` names it | Your decision. A contract does not override s.8(7) |
| `--reason purpose` | The purpose needs it for that long | s.8(7)(a) |

**What the Rules set, which 11.3 (retention) will act on.**

- **Rule 8(1) and the Third Schedule.** Three classes of business must erase a
  person's data three years after the person last approached them for the
  purpose or exercised a right, or three years after the Rules began, whichever
  is latest. The classes are:
  - e-commerce entities with at least two crore registered users in India;
  - online gaming intermediaries with at least fifty lakh;
  - social media intermediaries with at least two crore.

  Two things are excepted: access to the user account, and to virtual tokens
  that can be used for money, goods or services. A law that requires the data to
  be kept also overrides the period.
- **Rule 8(2).** At least forty-eight hours before that erasure, the person must
  be told it is coming, unless they log in or make contact.
- **Rule 8(3).** Personal data, the traffic data that goes with it and the logs
  of its processing are kept for at least one year from the processing, for the
  purposes in the Seventh Schedule, and then erased unless a law requires more.

The inventory records your retention. It does not yet check it against the
Third Schedule or against Rule 8(3)'s one-year minimum; that is point 11.3.

## On erasure

Each table's entry also says what an erasure request does to a person's rows
there (point 11.2, F4):

- `--on-erasure clear`, the default: the row stays, and its confirmed personal
  columns are emptied: set to `NULL`, or to the column's default when it is
  `NOT NULL` and has one. For rows other records depend on, such as customers
  with orders.
- `--on-erasure delete`: the row is deleted. For rows that are only the person,
  such as a newsletter sign-up.

A column's own entry can only clear. When the column is `NOT NULL` with no
default, it cannot be emptied, and a request's plan stops there until you give
it a placeholder on that entry (`fox dpdp set public.customers.phone … --clear-to
'0000000000'`) or set the table to delete. A table or column whose retention's
reason is `law` is not erased at all: the law requiring it kept overrides
s.8(7), and the request records the citation and, when you give the event's
date, when the period ends. A `contract` is not such a reason, and its places
are erased. A table with no entry is cleared, and the plan says that is the
default, not a decision.

## Erasure requests

One request erases one person on `main` and every branch (Enterprise; admins only). The values
the person is known by are read one a line from the terminal or standard
input, never the command line, so the shell's history and the process list do
not keep them:

```bash
fox dpdp erase new --note "DPO ticket 1234" --event account_closed=2025-03-31
#   > email:asha@example.com
#   > mobile:98765 43210
fox dpdp erase show 7              # the plan again, without the values
fox dpdp erase apply 7             # asks for the values again, then for the number
fox dpdp erase rewrite 7           # the tables left for a quiet time
fox dpdp erase status 7            # every branch, and those made before the erasure
fox dpdp erase apply 7 --branch qa # a branch the apply skipped, on its own
fox dpdp erase list
```

- **Found:** a row is the person's when a confirmed column (or JSON path) in
  the value's category holds it, compared whole after normalising case and
  separators, as `fox subject find` counts. From those rows the plan follows
  foreign keys to the rows that refer to them, up to ten deep. A referring
  table with confirmed personal columns takes its own entry's action; one with
  none is left as it is, unless its key deletes it (`ON DELETE CASCADE`) or
  clears its reference with a row the request deletes. A key that refuses the
  delete (`RESTRICT`, `NO ACTION`) stops the plan, as a column that cannot be
  cleared does. Rows of the same table that refer to the person's row are
  someone else's, and are left.
- **Shown first:** each table, why its rows are the person's, how many, what
  happens to them and to which columns, the entry as it stood, the exceptions,
  and anything that stops the plan. Nothing changes until it is applied.
- **Applied:** the values are given again and checked against the request, the
  rows are found again in one transaction, and the plan is applied only if it
  is the one shown; otherwise the new plan is kept, to review and apply again.
  A search afterwards in the same transaction must find none of the values
  outside a law's exception, or nothing is applied.
- **Vacuumed and rewritten:** `VACUUM (INDEX_CLEANUP ON)` removes the old
  versions from live queries; `VACUUM FULL` rewrites each table into new
  files, so a backup or branch made afterwards does not copy the old bytes left
  in free space. It locks the table while it runs, so tables over
  `FOX_ERASURE_REWRITE_MAX` (1 GB by default), or with too little free space
  for a second copy, are listed for `fox dpdp erase rewrite` at a quiet time.
  The statistics are rewritten and the WAL switched out after.
- **Kept:** no value. The request keeps each value's category and last four
  characters, the plan, and the row keys of what it changed.
- **Every branch:** the plan covers every branch too, each matched on its own
  rows (a branch can hold rows `main` no longer has); a suspended branch is
  woken to be searched, and suspends again when idle. Applying erases `main`,
  then each branch in its own transaction. A branch whose plan has changed
  since it was shown, or that has a problem, is skipped and says why; apply it
  on its own with `--branch` once you have looked. A masked branch is found by
  `main`'s row keys as well as by value, since its masks are not the person's
  values; one still being made, or that failed, is listed and not erased. No
  branch is copied from one while it is being erased.
- **Branches made before the erasure:** however a branch was erased, one made
  before its parent's erasure finished keeps the person's old blocks in the
  snapshot it was copied from. `fox dpdp erase status` lists each, with its
  owner and the commands, for you to remake from its parent (`fox branch
  reset <b> --from <parent>`, which discards its work) or delete; the console
  does either from the request and records it there. The erasure is not done
  in the files until none is left.
- **The maximum age:** set `FOX_BRANCH_MAX_AGE` (off by default; `90d` is a
  reasonable start) and `fox check`, the dashboard (for admins) and every
  request flag the branches older than it. They are never remade or deleted
  for you: an old branch holding the person is why an erasure would never
  finish.

- **The Blackbox:** on each branch, the entries whose recorded text still
  holds one of the values (data changes recorded before placeholders) are
  redacted in place with a seal, in the same transaction, and the original
  texts kept beside the chain that hold one are deleted. Schema changes
  holding a value are kept as they are and listed. The chain and its anchors
  still verify (`fox blackbox integrity`, `fox-verify`). A value is found as it
  was given and in its normalised form, case-blind; written another way in a
  statement, it is not.

What a request does not reach yet: query history, the audit log's forensic
text, change requests, the vault, restores of an earlier copy, and backups. Those are the next steps of F4 (`docs/FOX_F4_Erasure_Design.md`,
section 20); until they are built, the person can remain in them, and every
plan says so. FoxByte's reading of erasure has not yet been reviewed by a
privacy lawyer or a storage engineer.

## What the inventory cannot claim

- It lists only places a reviewer confirmed as personal data (`fox pii mark`).
  Personal data that no scan found, and findings that are still undecided, are
  not in it.
- The entries are yours. FoxByte does not check them against your notices or
  the consents you hold.
- It covers the databases FoxByte manages. Copies elsewhere, such as exports,
  application logs, backups taken outside FoxByte and processors' systems, are
  not in it.
