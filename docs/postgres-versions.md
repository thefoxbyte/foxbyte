# PostgreSQL versions

FoxByte runs stock PostgreSQL, plus `wal-g`, in one container per branch. This
page is for two readers: someone running FoxByte who wants to know which
PostgreSQL they have and how to move to a newer one, and someone maintaining
FoxByte who has to move the product itself to the next major.

## Which PostgreSQL you run

| | Major |
|---|---|
| A fresh install | **18** |
| An install created before 21 Sep 2026 | **16**, until you move it |

**Your data decides, not the `fox` binary.** A data directory belongs to one
major (initdb writes it into `PG_VERSION`), and a server of any other major
refuses to start on it. So the engine reads `PG_VERSION` from main's data
directory and runs the image for that major (`ghcr.io/thefoxbyte/postgres-walg:<major>`).
`fox update` therefore never moves your data between majors: an install on 16
keeps running 16 after it, and keeps getting fixes to everything around
Postgres. Moving a cluster between majors is a migration, and it stays your
decision.

If a branch ever holds data from a different major than the image about to run
it, `fox` refuses before starting the container, names both versions and says
what to do — rather than leaving Postgres to fail inside the container with
"database files are incompatible with server".

To see it directly:

```
fox psql            # then: SHOW server_version;
```

`FOX_PG_IMAGE=<image>` overrides the choice, for a registry mirror. Point it at
an image of the same major as your data.

## Backups and majors

| | Survives a major change? |
|---|---|
| `fox backup create` (a `wal-g` base backup) and the WAL archive | **No.** Physical backups belong to one major and one cluster. After an upgrade they stay in object storage and come back with `fox pg upgrade --rollback`. |
| `fox backup export` | **Yes.** A `pg_dump` of every branch, with its roles and its Blackbox, restorable into the same or any newer major. |

```
fox backup export                          # every branch except agents' -> ~/.fox/exports/
fox backup export --out ~/before.tar --branch main
fox backup restore ~/before.tar --as restored          # main, into a new branch
fox backup restore ~/before.tar --branch qa --as qa-copy
```

An export is one `.tar`: a manifest, and for each branch its `pg_dump` (custom
format, owners and privileges kept), its roles — each branch is its own
cluster, and a per-user login role lives only on the branch that user reached —
and a `SHA256SUMS` over everything. On macOS and Windows it is written inside
the VM, copied to your disk, and checked against those sums there; a copy that
does not verify is deleted rather than kept. A restore checks them again,
refuses an export from a newer major than the install runs, and afterwards
checks that the Blackbox came across exactly: every entry, ending in the same
hash.

## Moving an install to a newer major

```
fox pg status              # which major the install and each branch run
fox pg upgrade --dry-run   # everything that would change; nothing is done
fox pg upgrade             # asks, exports, upgrades
```

`fox pg upgrade` does four things, in this order, and stops at the first that
fails:

1. **Shows the plan.** Every branch and whether it is carried; what changes for
   you; and every PostgreSQL change between your major and the new one, taken
   from each release's own migration notes, with the ones found in *your*
   databases first (an expression index, an MD5 password, an inheritance tree,
   an unlogged partitioned table…). It refuses, saying what to do instead, when
   high availability is on (`fox ha disable` first), when main is served by the
   standby after a failover, when a Blackbox does not verify, or when an
   earlier upgrade's databases are still kept.
2. **Asks.** Type `fox` to go on. `--yes` skips the question.
3. **Takes an export** of every carried branch, onto your disk
   (`--export <file>` chooses where). `--i-have-a-backup` skips it — only if
   you have one.
4. **Upgrades.** Every database is offline while it runs. Each branch is dumped
   with the new major's `pg_dump` and reloaded into a new cluster — a reload,
   not `pg_upgrade`, so every index is rebuilt — and its Blackbox must come
   across exactly. The new main archives WAL under a prefix of its own and
   takes its first base backup.

What it keeps, and what it does not:

- **The old databases are kept, untouched**, outside the branch namespace,
  until `fox pg upgrade --finalize` deletes them. Until then
  `fox pg upgrade --rollback` returns to them — deleting any branch made after
  the upgrade, and saying so before it asks. Any failure during the upgrade is
  rolled back the same way before the command returns.
- **Point-in-time restore starts again.** The new cluster cannot use the old
  one's base backups or WAL. They stay in object storage, and a rollback brings
  them back.
- **Agent branches are not carried**; they are disposable by design. They stay
  in the kept copy until `--finalize`.
- **Carried branches become full copies** of their data, no longer sharing
  blocks with main, until you re-create them from it.
- **Accounts, API keys and roles come across.** Keys live in the state
  directory, and each branch's roles travel in its export.

## Moving FoxByte itself to the next major

For maintainers. Last done: 16 → 18, on 21 Sep 2026.

1. **Wait for the two things you do not control.** An official
   `postgres:<N>-bookworm` image (check `docker-library/postgres`), and a `wal-g`
   release that supports `<N>` — its integration suite runs one job per
   PostgreSQL major, so the matrix says. `wal-g` is the whole durability story:
   archiving, base backups, point-in-time restore.
2. **Change one constant.** In `internal/branch/images.go`, set `PGMajor` to the
   new major and add it to `SupportedPGMajors`. Keep the older majors there for
   as long as installs may still be on them: each one is an image the release
   has to keep publishing.
3. **Let the test list the rest.** `go test ./internal/branch/` —
   `TestPostgresMajorIsInStepEverywhere` fails for each file that still names
   the old major: the Dockerfile's `ARG PG_MAJOR` default, the release
   workflow's image matrix, and the Windows distro's preload.
4. **Read the release notes' "Migration" section** against what the engine
   assumes about Postgres behaviour. These are the places no compiler checks,
   and each has suite coverage:

   | Assumption | Where |
   |---|---|
   | `wal-g` `wal-push`, `backup-push`, `backup-list`, `backup-fetch` | `internal/branch/branch.go`, `restore_*.sh` |
   | The PITR protocol: `recovery.signal`, `recovery_target_*` | `internal/branch/restore_pitr.sh`, `restore_before.sh` |
   | The recovery GUCs reset by name after branch-before | `internal/branch/branch_before.go` |
   | `pg_basebackup -R`, `pg_promote()`, and `pg_controldata` output parsed by its English labels | `internal/branch/ha.go` |
   | Blackbox attribution through `GET DIAGNOSTICS PG_CONTEXT` text | `internal/ledger/ledger.sql` |
   | Event-trigger command tags and dropped-object types the Blackbox records | `internal/ledger/ledger.sql` |
   | Advisory-lock decoding from `pg_locks` (fails as a hung client) | `internal/ledger/ledger.sql` |
   | `dblink` over local trust auth, for recording BLOCKED attempts | `internal/ledger/ledger.sql` |
   | The hash chain's `timestamptz` text rendering, recomputed in Go | `internal/ledger/ledger.sql`, `internal/ledger/integrity.go` |
   | `pg_subscription_rel.srsubstate` for import cutover | `internal/branch/replication.go` |

5. **Run the three suites on the new major** in the throwaway VM:
   `make integration`, `make integration-v2`, `make integration-update`.
   Nothing ships on a major these have not passed on.
6. **Write down what changes for users.** Add the new release's notes to
   `pgNotes` in `internal/branch/pgnotes.go`, from its "Migration" section,
   with a probe where a database can show whether it is affected.
   `TestEveryUpgradeHopHasNotes` fails until every hop from a supported major
   to the new one has them — this is the list `fox pg upgrade` prints before
   it moves anything.
7. **Update the living documents** — M6 and its neighbours in
   `docs/FOX_Feature_Implemented.html`, `docs/FOX_Checklist.html`,
   `docs/FOX_Storage_Engine.html`, this page, the README's version table — and
   run `make feature-doc`.
8. **Release.** The image job publishes one image per entry in
   `SupportedPGMajors`. The GHCR package must be public, or every install fails
   to pull with `unauthorized`.

Dropping an old major from `SupportedPGMajors` strands every install still on
it: they can no longer pull their image, and `fox pg upgrade` needs the old
cluster running to dump it. Only drop a major after a release has shipped the
upgrade to its users, and say so in that release's notes.

Things that deliberately stay put: `internal/host/host_windows.go` re-tags a
legacy `foxbyte/postgres-walg:16` preload from Windows distro images built
before 16 Sep 2026. That name is history, not the current major.
