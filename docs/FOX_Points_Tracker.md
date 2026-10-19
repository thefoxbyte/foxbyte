# FoxByte: the 13 points, tracked

What is done and what is left of the 13 points (the expert's 12, plus the
Aadhaar vault mode), sub-point by sub-point. The sub-points are the phases in
`docs/FOX_Expert_Review_Plan.md`, section 6. Updated with every PR.

**Last updated:** 19 October 2026: 8.2 done (the history panel and saved queries). Point 8 is complete.

## How a sub-point counts as done

A sub-point is ✅ only when all of these hold:

1. **CLI:** a `fox` command does it, with integration tests in the test VM.
   Where a sub-point has no sensible CLI form (autocomplete as you type, say),
   the table says so.
2. **UI:** the console does it, with Playwright tests (`make integration-ui`).
   Likewise marked where there is no UI form.
3. **Nothing old breaks:** the full regression run passes before the PR opens:
   `go test` in both editions, `integration`, `integration-v2`,
   `integration-ui`, and the suites the change touches (`integration-sdks`,
   `integration-realtime`, `integration-update`, `integration-pg-upgrade`).
4. **Docs:** the feature doc and checklist are updated, and so is this file.

**Key:** ✅ done · 🟡 in progress · ⬜ not started · ⏸ waiting on a decision ·
➖ not applicable

## Summary

| # | Point | Edition | Sub-points | Done |
|---|---|---|---|---|
| 1 | Console: export and copy query results | Standard | 3 | 3 ✅ |
| 2 | ETL: full and incremental load; Lakeflow | Enterprise | 5 | 1 (full load, existing) |
| 3 | CIS benchmark, hardening, pgAudit | pgAudit Standard; CIS ⏸ | 4 | 0 |
| 4 | PII scanner and access review | Enterprise | 9 | 0 |
| 5 | "Last modified": who changed each row | Standard | 2 | 0 |
| 6 | "Updated at": when each row changed | Standard | 2 | 0 |
| 7 | Masking | Enterprise | 5 | 0 |
| 8 | Query history | Standard | 3 | 3 ✅ |
| 9 | Query suggestions | Standard | 4 | 0 |
| 10 | Job scheduling ("DB agent") | Enterprise | 4 | 0 |
| 11 | DPDP compliance manager | Enterprise | 4 | 0 |
| 12 | pgAdmin features in the console | Standard | 6 | 0 |
| 13 | Aadhaar vault mode | Enterprise | 4 | 0 |
| | **Total** | | **55** | **7** |

## The points

### 1. Console: export and copy query results (Standard)

| Sub-point | CLI | UI | Status | PR |
|---|---|---|---|---|
| 1.1 Copy cells, rows or a whole result as CSV, TSV, Markdown, JSON or `INSERT`s | ✅ `fox sql --format csv\|tsv\|markdown\|json\|insert` (§11j) | ✅ Copy menu, ticked rows, ⌘C on a cell (Playwright) | ✅ | #149 |
| 1.2 Export what is on screen to CSV, JSON or Excel | ✅ `fox sql --format csv\|json\|xlsx > file` (§11j) | ✅ Export menu: CSV, JSON, Excel workbook (Playwright) | ✅ | #151 |
| 1.3 Export the full result, streamed, as the user's own role; formula injection escaped in text cells; every export in the security log | ✅ `fox export [--format csv\|tsv\|json\|xlsx] "<sql>" > file`: every row, read only, one statement (§11k) | ✅ Export menu → "Everything the query returns" (Playwright) | ✅ | #153 |

### 2. ETL: full and incremental load; Lakeflow (Enterprise)

| Sub-point | CLI | UI | Status | PR |
|---|---|---|---|---|
| 2.1 Full load | `fox pipeline run` | Pipelines page | ✅ (existing) | |
| 2.2 Incremental by the source's own watermark column, merged by primary key | `fox pipeline … --mode incremental` | Load mode per table | ⬜ | |
| 2.3 Change data capture from Postgres sources, reusing continuous import | `fox pipeline … --mode cdc` | Load mode per table | ⬜ | |
| 2.4 Incremental transformations; per-run inserted, updated and deleted counts | `fox pipeline runs` | Run history | ⬜ | |
| 2.5 Lakeflow: the Gateway replication test, then the sovereignty decision | ➖ | ➖ | ⏸ customer demand, and a founders' decision | |

### 3. CIS benchmark, hardening, pgAudit (pgAudit Standard; CIS edition ⏸ founders)

| Sub-point | CLI | UI | Status | PR |
|---|---|---|---|---|
| 3.1 pgAudit in every edition: default mode without statement text, audit-role marking, reads by unmask holders, SIEM forwarding (needs F6) | `fox audit-log …` | Audit log settings and view | ⬜ | |
| 3.2 CIS self-assessment (PostgreSQL 17 Benchmark): Pass, Fail, Manual, N/A, with evidence; PDF/JSON | `fox check --cis` | CIS page | ⏸ which edition | |
| 3.3 Fixes for each failing item, where safe | `fox check --cis --fix <item>` | Fix button per item | ⏸ | |
| 3.4 Hardening profiles ("baseline", "strict") with a preview | `fox harden --profile strict --preview` | Profiles page | ⏸ | |

### 4. PII scanner and access review (Enterprise)

| Sub-point | CLI | UI | Status | PR |
|---|---|---|---|---|
| 4.1 Scan columns: names and sampled values; Aadhaar (Verhoeff), PAN, GSTIN, mobile, card (Luhn), email, UPI, IFSC and others | `fox pii scan [--branch]` | Personal data page | ⬜ | |
| 4.2 Scan JSONB path by path | same | same | ⬜ | |
| 4.3 Free text as risk scoring (a local recogniser, nothing leaves the machine) | same | same | ⬜ | |
| 4.4 Embeddings by lineage | same | same | ⬜ | |
| 4.5 Aadhaar exposure report: outside the vault, including pgAudit logs and query history | `fox pii aadhaar` | Exposure report | ⏸ first customers to confirm | |
| 4.6 Verify and mark: suggested, then confirmed or rejected from masked samples, recorded; marks travel with branches | `fox pii mark …` | Review queue | ⬜ | |
| 4.7 Keep it current: re-scans; new columns and paths unclassified until reviewed | `fox pii scan --since` | "Unclassified" list | ⬜ | |
| 4.8 Access review report: accounts, roles, admin grants, keys (age, last use, kind), unmask rights, dormant accounts; PDF/CSV | `fox access review` | Access review page | ⬜ | |
| 4.9 Review campaigns: periodic approve or revoke, signed off | `fox access campaign …` | Campaigns page | ⬜ | |

### 5. "Last modified": who changed each row (Standard)

| Sub-point | CLI | UI | Status | PR |
|---|---|---|---|---|
| 5.1 Tracked tables, opt-in per table, or every new table | `fox track <table>` | Tracking toggle per table | ⬜ | |
| 5.2 Two identities per row: `last_modified_by` (the login) and `last_modified_for` (the application's user, asserted or claimed; needs F1's token protocol) | same | shown in the data grid | ⬜ | |

### 6. "Updated at": when each row changed (Standard)

| Sub-point | CLI | UI | Status | PR |
|---|---|---|---|---|
| 6.1 `created_at` and `updated_at`, names configurable, by the same trigger as 5 | `fox track <table> --timestamps` | Tracking toggle | ⬜ | |
| 6.2 Optional `deleted_at` record of deletions | same | same | ⏸ the expert to confirm it is wanted | |

### 7. Masking (Enterprise; needs point 4's marks and F5)

| Sub-point | CLI | UI | Status | PR |
|---|---|---|---|---|
| 7.1 Masking rules on marked columns and JSON paths: partial, keyed hash (not for Aadhaar), empty, fake | `fox mask set …` | Masking rules | ⬜ | |
| 7.2 Unmask permission per account, recorded and in access reviews; audited exact-match lookup | `fox mask grant …` | Unmask grants | ⬜ | |
| 7.3 Engine: PostgreSQL Anonymizer (3.1.2+) or FoxByte's own views | ➖ | ➖ | ⬜ | |
| 7.4 Every access path tested (the F5 suite, inference included); realtime refuses or masks | ➖ (tests) | ➖ (tests) | ⬜ | |
| 7.5 Masked branches, gated until masking is verified | `fox branch create --masked` | Masked branch option | ⬜ | |

### 8. Query history (Standard)

| Sub-point | CLI | UI | Status | PR |
|---|---|---|---|---|
| 8.1 Record console and API queries per user: SQL, branch, time, duration, rows, outcome | ✅ `fox history [--branch] [--limit] [--json]`; console, API, `fox sql`, `fox export` recorded (§11l) | ➖ (recorded from the console; seen on the account page) | ✅ | #155 |
| 8.2 History panel: search, re-run, copy, saved queries | ✅ `fox history --search\|--failed`, `show`, `run`, `save`, `saved`, `unsave` (§11m) | ✅ History panel in the console: search, open, run again, copy, save; Saved tab (Playwright) | ✅ | #PR |
| 8.3 Privacy: no results kept, 90-day retention, can be off, own history only, searchable and purgeable for a person | ✅ `fox history purge [--user]`, `--user`, `--people`, `on\|off`, `retention <days>` (§11l) | ✅ Account page: count, my switch, delete mine; install switch and retention for admins (Playwright) | ✅ | #155 |

### 9. Query suggestions (Standard)

| Sub-point | CLI | UI | Status | PR |
|---|---|---|---|---|
| 9.1 Autocomplete as you type: tables after FROM/JOIN, columns after a table or alias, keywords | ➖ (typing) | SQL editor | ⬜ | |
| 9.2 Corrections: "did you mean `customers`?" with a one-click fix | `fox sql` prints the suggestion on an error | SQL editor | ⬜ | |
| 9.3 Snippets for the selected table | ➖ | SQL editor | ⬜ | |
| 9.4 AI assistance, admin-enabled, schema only (optional) | ➖ | SQL editor | ⏸ optional | |

### 10. Job scheduling ("DB agent") (Enterprise)

| Sub-point | CLI | UI | Status | PR |
|---|---|---|---|---|
| 10.1 Scheduler: cron with timezone, one run at a time, retries, timeouts, pause, history; runs as its owner | `fox job …` | Jobs page | ⏸ the expert to define "DB agent" | |
| 10.2 Job types: compliance jobs first (re-scans, retention, access reviews, scheduled fox-verify), then pipelines and SQL | same | same | ⏸ | |
| 10.3 Notifications by webhook or email | same | same | ⏸ | |
| 10.4 AI agents manage jobs through MCP, each with its own credential | MCP | ➖ | ⏸ | |

### 11. DPDP compliance manager (Enterprise; scope ⏸ founders)

| Sub-point | CLI | UI | Status | PR |
|---|---|---|---|---|
| 11.1 Personal data inventory from verified marks: purpose, category, retention | `fox dpdp inventory` | Inventory | ⏸ scope | |
| 11.2 Erasure across every copy FoxByte manages, with outcomes and one "clears on" date (needs F4) | `fox dpdp erase …` | Erasure requests | ⏸ scope | |
| 11.3 Retention: scheduled erasure or anonymisation, 48-hour notice hook | `fox dpdp retention …` | Retention | ⏸ scope | |
| 11.4 Safeguards evidence (Rule 6): masking, access reviews, pgAudit, CIS, with each one's threat model | `fox dpdp evidence` | Evidence export | ⏸ scope | |

### 12. pgAdmin features in the console (Standard)

| Sub-point | CLI | UI | Status | PR |
|---|---|---|---|---|
| 12.1 Object browser (read-only): schemas, tables with columns, constraints, indexes, triggers; views; functions, procedures, sequences, types, extensions; each object's `CREATE` script; search | `fox schema [object]` | Object browser | ⬜ | |
| 12.2 Data grid: sort, filter, page; add, edit and delete rows on tables with a primary key, in one transaction; honours masking | ➖ (`fox sql`) | Data grid | ⬜ | |
| 12.3 Create and edit dialogs for tables, functions, procedures, triggers | ➖ | Dialogs | ⏸ customer demand | |
| 12.4 Run, toggle and plan views | ➖ | ➖ | ⏸ customer demand | |
| 12.5 Maintenance and sessions | `fox sessions` | Sessions page | ⏸ customer demand | |
| 12.6 A diagram (ERD) | ➖ | Diagram | ⏸ customer demand | |

### 13. Aadhaar vault mode (Enterprise)

| Sub-point | CLI | UI | Status | PR |
|---|---|---|---|---|
| 13.1 Vault table: Aadhaar encrypted, keys in the customer's HSM or KMS | `fox vault …` | Vault page | ⏸ which HSMs customers use | |
| 13.2 Reference tokens: random, never hashes; detokenising a separate, audited permission | same | same | ⏸ | |
| 13.3 Migration: move exposed Aadhaar into the vault, tokens left behind, on a branch first | same | same | ⏸ | |
| 13.4 Evidence for UIDAI audits | same | same | ⏸ | |

## Groundwork already done

These came from the reviewers' comments, not from the 13 points, and come before
them: they are the foundations the points build on.

| Foundation | What was done | PR | Points it serves |
|---|---|---|---|
| F1 identity | Agents identified by how they log in (`db_agent`, agent keys) | #144 | 4.8, 5.2, 10.1 |
| F2 policy by impact | Guard triggers cannot be made replica-only | #144 | 7.4 |
| F2 policy by impact | Agents' changes limited by rows changed, not by `WHERE` | #145 | (guardrails) |
| F2 policy by impact | A budget per agent per table across statements | #148 | (guardrails) |
| F3 Blackbox evidence | Anchors locked in COMPLIANCE mode in a separate bucket | #146 | 3.1, 11.4 |
| F3 Blackbox evidence | `fox-verify` reads the locked bucket itself | #147 | 3.1, 11.4 |

**Still to do before the points that need them:**
- F1's signed per-transaction identity, before 5.2.
- F2's approval grants.
- F4 erasure, before 11.2.
- F5 masking assurance, before point 7.
- F6 audit design, before 3.1.
- Two lines of public wording: README "non-forgeable", and the landing page's "does not reach your data".
