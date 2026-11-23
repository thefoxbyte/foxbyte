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

## What the inventory cannot claim

- It lists only places a reviewer confirmed as personal data (`fox pii mark`).
  Personal data that no scan found, and findings that are still undecided, are
  not in it.
- The entries are yours. FoxByte does not check them against your notices or
  the consents you hold.
- It covers the databases FoxByte manages. Copies elsewhere, such as exports,
  application logs, backups taken outside FoxByte and processors' systems, are
  not in it.
