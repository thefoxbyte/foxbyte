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
| `fox backup create` (a `wal-g` base backup) and the WAL archive | **No.** Physical backups belong to one major and one cluster. After a move they can only be read by running the old major's image. |
| A `pg_dump` of your database | **Yes.** SQL is portable across majors. Take one before any move. |

## Moving an install to a newer major

**There is no command for this yet.** One is planned: `fox backup export`, a
portable dump of every branch with the roles it needs, and `fox pg upgrade`,
which moves an install in place — inventory, a warning listing what changes
between your major and the new one, a refusal to proceed without a fresh
export, a rollback point, and a Blackbox verification at the end. Until it
exists, staying on 16 is fully supported, and the manual route is below.

The manual route replaces the install. Accounts, API keys, the Blackbox history
and base backups do **not** come across — only your database contents. It is
not covered by the test suites; check the result before relying on it.

1. Export main (repeat with `pg-<branch>` for each branch you want to keep).
   macOS:

   ```
   limactl shell fox -- sudo docker exec pg-main \
     pg_dump -U dbadmin --no-owner --no-acl --exclude-schema=bb appdb > appdb.sql
   ```

   Windows: `wsl -d fox -- docker exec pg-main pg_dump -U dbadmin --no-owner --no-acl --exclude-schema=bb appdb > appdb.sql`.
   `--exclude-schema=bb` leaves out FoxByte's own bookkeeping, which the new
   install creates for itself.
2. Check the file: `tail appdb.sql` should end with `PostgreSQL database dump complete`.
3. Remove the old install completely: `fox uninstall`.
4. Install again (see the README). The new install runs PostgreSQL 18.
5. Create your account at https://localhost:8080 and make a new API key.
6. Load the dump into main. macOS:

   ```
   limactl shell fox -- sudo docker exec -i pg-main psql -U dbadmin -d appdb -v ON_ERROR_STOP=1 < appdb.sql
   ```

   Every table it creates is recorded in the new install's Blackbox as a new
   change: the history starts again from the load.

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
6. **Write down what changes for users** between each supported major and the
   new one — the list `fox pg upgrade` will print before it moves anything.
7. **Update the living documents** — M6 and its neighbours in
   `docs/FOX_Feature_Implemented.html`, `docs/FOX_Checklist.html`,
   `docs/FOX_Storage_Engine.html`, this page, the README's version table — and
   run `make feature-doc`.
8. **Release.** The image job publishes one image per entry in
   `SupportedPGMajors`. The GHCR package must be public, or every install fails
   to pull with `unauthorized`.

Dropping an old major from `SupportedPGMajors` strands every install still on
it: they can no longer pull their image. Only do it once there is a supported
way to move off it, and say so in the release notes.

Things that deliberately stay put: `internal/host/host_windows.go` re-tags a
legacy `foxbyte/postgres-walg:16` preload from Windows distro images built
before 16 Sep 2026. That name is history, not the current major.
