<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/foxbyte-logo-dark.png" />
    <img src="docs/brand/foxbyte-logo.png" alt="FoxByte" width="420" />
  </picture>
</p>

<p align="center">
  <b>Self-hosted PostgreSQL 18 with copy-on-write branches, point-in-time recovery, and a hash-chained record of every schema change.</b>
</p>

<p align="center">
  <a href="https://github.com/thefoxbyte/foxbyte/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/thefoxbyte/foxbyte/actions/workflows/ci.yml/badge.svg" /></a>
  <a href="#license"><img alt="License: AGPL-3.0 for the core" src="https://img.shields.io/badge/license-AGPL--3.0-blue" /></a>
  <a href="https://github.com/thefoxbyte/foxbyte/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/thefoxbyte/foxbyte" /></a>
  <a href="https://github.com/thefoxbyte/foxbyte/stargazers"><img alt="GitHub stars" src="https://img.shields.io/github/stars/thefoxbyte/foxbyte?style=social" /></a>
</p>

<!--
  DEMO GIF PLACEHOLDER
  Record docs/assets/demo.gif (a branch being created) and replace this
  comment with the image. How to record it: docs/assets/README.md.
  The tape is docs/assets/demo.tape.

  <p align="center">
    <img src="docs/assets/demo.gif" alt="Creating a FoxByte branch" width="720" />
  </p>
-->

> **Demo GIF goes here** (`docs/assets/demo.gif`). It is not recorded yet. The
> tape that records a branch being created is [`docs/assets/demo.tape`](docs/assets/demo.tape);
> [how to run it](docs/assets/README.md) (vhs, or asciinema plus agg).

FoxByte gives you a Postgres you can branch like a working copy, on a machine
you run, and a record of who changed the schema. The command is **`fox`**.

---

## Why FoxByte

An agent, a migration, or a pull request needs a database of its own. Copying
one is slow. FoxByte makes a branch with a **ZFS snapshot and clone** (a
**btrfs subvolume snapshot** on Windows), then starts a stock Postgres on that
clone. The clone itself is O(1) in the size of the data. `fox branch create`
prints how long the whole operation took on your machine. The docs say
seconds, not a single published benchmark. `main` is not written.

That branch is still Postgres 18 (a fresh install; an older install stays on
the major it was created with). Your driver, ORM, and SQL do not change. The
gateway speaks the wire protocol. The database name **is** the branch.

The **Blackbox** is why you can hand a branch to something that writes SQL
without a person reading it first. Every `CREATE`, `ALTER`, `DROP`, and
`GRANT` is appended to a hash chain, attributed to the login that ran it. A
policy gate blocks `DROP TABLE`, `DROP SCHEMA`, and `TRUNCATE` unless an admin
overrides them. Agents' `UPDATE` and `DELETE` are recorded and limited. Checking the chain is free.
Writing signed checkpoints of it is an Enterprise feature.

**Who it is for.** Teams that want branching without sending the database to a
hosted product. People giving a coding agent a database they can throw away.
Anyone who wants the schema record on stock Postgres, on one machine.

It is one machine today. High availability in this tree is a single-VM
demonstration, not a multi-host deployment. Masking is Enterprise and off
until you turn it on: a branch is a real copy, and FoxByte says so.

| | |
| --- | --- |
| ![Ops dashboard](docs/screenshots/dashboard.png) | ![Blackbox](docs/screenshots/ledger.png) |

The console is served by the engine at **https://localhost:8080**. More
screenshots: [landing](docs/screenshots/landing.png),
[SQL console](docs/screenshots/console.png),
[realtime](docs/screenshots/realtime.png).

---

## Quickstart

One installer. On macOS, in a terminal, it installs `fox`, installs
[Lima](https://lima-vm.io) if it is missing, and runs `fox setup`. On Linux it
installs `fox` and stops; the script's next line is `sudo fox start`.

```bash
curl -fsSL https://get.thefoxbyte.com/install.sh | sh
```

```bash
sudo fox start   # Linux only: ZFS, Docker, the Postgres image, then the stack
```

Windows, in PowerShell (not Command Prompt):

```powershell
irm https://get.thefoxbyte.com/install.ps1 | iex
```

That command is the usage line in [`deploy/install.sh`](deploy/install.sh) and
the host described in [`deploy/get/README.md`](deploy/get/README.md). There is
**no Compose file**. The engine image is
[`docker/postgres/Dockerfile`](docker/postgres/Dockerfile) (`ARG PG_MAJOR=18`)
and is published as `ghcr.io/thefoxbyte/postgres-walg:18`
(`internal/branch/images.go`). `fox setup` and `fox start` are what pull it
and bring the stack up. Windows stores branches on btrfs inside a dedicated
WSL2 distro ([docs/windows-setup.md](docs/windows-setup.md)).

The first run opens **https://localhost:8080** with a one-time setup token in
the link. `fox setup-token` prints it again. The first account is the admin.
Nothing is hardcoded, and no API key is minted for you.

Longer install notes, release signatures, and every flag:
[docs/reference.md](docs/reference.md).

---

## Branch a database in seconds

`main` already has three small sample tables (`users`, `projects`, `events`)
unless you started with `FOX_NO_DEMO=1`.

```bash
fox branch create qa
```

Prints the elapsed time and a connection string. `qa` is its own Postgres on
a copy-on-write clone. `main` is unchanged.

```bash
fox sql --branch qa "CREATE TABLE notes (id int primary key, body text);"
```

`fox sql` runs through the same path as the console and records you as the
actor. Any other client uses the gateway. The password is an API key
(`fox apikey create <email> <name>`, shown once), not your account password:

```bash
psql "postgresql://dbadmin:<API_KEY>@localhost:6432/qa?sslmode=require"
```

```bash
fox blackbox qa
```

The `CREATE TABLE` is in the chain, with the login that ran it.

```bash
fox branch delete qa
```

`main` still has its sample tables. `fox branch reset qa` would have thrown
away `qa`'s changes and cloned again, instead of deleting it.

---

## Features

- **Branches** — `create`, `list`, `reset`, `diff`, `suspend`, `resume`, `delete`. An idle branch stops; the next connection to `:6432` wakes it. The database name is the branch.
- **Blackbox** — hash-chained DDL ledger, in the Standard edition. `fox blackbox verify` recomputes it. Agents' data changes are recorded; destructive DDL is refused unless an admin overrides it. Detail: [docs/blackbox-coverage.md](docs/blackbox-coverage.md).
- **Point-in-time recovery** — `wal-g` archives WAL. `fox restore --to '<timestamp>'`. Backups start in a store on the same disk; `fox backup target set` sends them to S3. A base backup does not survive a major upgrade; `fox backup export` does.
- **Gateway** — Postgres wire protocol on `127.0.0.1:6432`, TLS by default. Loopback unless you set `FOX_LISTEN`.
- **Agents** — `fox mcp` (Model Context Protocol) and an HTTP Agent Branch API. A branch per agent, a key scoped to that branch. [docs/mcp.md](docs/mcp.md).
- **Console** — React UI embedded in the `fox` binary: dashboard, SQL, Blackbox, import, API keys. No separate dev server.
- **SDKs** — dependency-free [Python and TypeScript](clients/) clients (Apache-2.0). OpenAPI at `/api/openapi.yaml`.
- **Import** — Postgres, MySQL/MariaDB, MongoDB, and `.sql` / `.csv` / `.json` / `.ndjson`, each into a new branch.
- **Enterprise** (a licence; without one the binary behaves as Standard) — column masking and PII scan, writing signed Blackbox anchors, policy authoring, change requests, realtime change feed, ETL pipelines. The Standard binary does not contain this code.

| | Standard | Enterprise |
| --- | --- | --- |
| Branching, gateway, PITR, Blackbox hash chain, agent guardrails | yes | yes |
| Checking anchors (`fox blackbox integrity`, `fox-verify`) | yes | yes |
| Writing signed anchors, masking, policy authoring, change requests, realtime, pipelines | — | yes |

A fresh install runs **PostgreSQL 18**. An install created before 21 Sep 2026
stays on **16** until you run `fox pg upgrade`.
[docs/postgres-versions.md](docs/postgres-versions.md).

```bash
curl -fsSL https://get.thefoxbyte.com/install.sh | FOX_EDITION=enterprise sh
```

---

## Compared with Neon, Xata, and Supabase

Checked against their public docs on **20 Nov 2026**. The other columns are
their claims and docs, not a benchmark we ran. FoxByte's own limits are in
the first column on purpose.

| | Self-hosted | How a branch copies data | Hash-chained DDL ledger | Masking |
| --- | --- | --- | --- | --- |
| **FoxByte** | Yes, on one machine you run. macOS uses a Lima VM. Windows uses a dedicated WSL2 distro. HA here is a single-VM demonstration. | ZFS snapshot + clone, or a btrfs subvolume snapshot on Windows, then a Postgres container. The clone is O(1) in data size. Documented as seconds. `fox branch create` prints the elapsed time for that run. | Yes, in Standard (the Blackbox). Writing signed anchors is Enterprise. Checking them is free. | Enterprise and opt-in (`fox pii scan`, `fox mask`). A branch is unmasked unless you mask it, and FoxByte warns. |
| **Neon** | The product people use is hosted. The storage engine is open source and can branch by creating a pageserver timeline. Neon does not publish a supported one-command self-hosted install. | Copy-on-write timeline: a new pageserver timeline from an ancestor timeline. | Not described in the docs checked. | Not described as a first-party column-masking feature in the docs checked. |
| **Xata** | Hosted. On 9 Nov 2026 Xata announced it is joining ClickHouse and is still accepting sign-ups. Instant branching was not yet part of ClickHouse Managed Postgres. | Their 9 Nov 2026 post: a copy-on-write branch in around 3 seconds, including for large databases. Their figure, not ours. | Not described in the docs checked. | They document anonymized production data on branches. |
| **Supabase branching** | Supabase itself can be self-hosted. Branching, as documented, is a cloud feature. | Schema comes from migrations, not from a storage clone. Data is absent by default. "Include data" (dashboard, requires their PITR add-on) copies production data. Their setup waits up to 2 minutes for the branch to be healthy. | Not described in the docs checked. | No documented dynamic column masking. Keeping production rows off the branch is the default. Row Level Security and Vault are different controls. |

Sources: [Neon pageserver timeline API](https://github.com/neondatabase/neon/discussions/3413),
[Xata joining ClickHouse](https://xata.io/blog/xata-is-joining-clickhouse),
[Supabase branching](https://supabase.com/docs/guides/deployment/branching).

FoxByte did not invent copy-on-write Postgres branches. That idea is
[postgres.ai / Database Lab](https://postgres.ai)'s, and the products above
ship branching of their own. What this repository adds on top of a branch is
the Blackbox, the attribution, and the policy gate, on a Postgres you run.

---

## Architecture

Plain-language picture, then the storage note, then the parts that are easy
to get wrong:

- [Architecture overview](docs/foxbyte-architecture.html) — apps, gateway, branches, backups.
- [Storage engine](docs/FOX_Storage_Engine.html) — ZFS and btrfs. FoxByte does not replace Postgres's heap.
- [Blackbox coverage](docs/blackbox-coverage.md) — what the ledger records, and what a superuser can still do.
- [PostgreSQL versions](docs/postgres-versions.md) — 18 for a fresh install, 16 still supported for old data.
- [MCP](docs/mcp.md) — the agent tools.
- [Reference](docs/reference.md) — command list, security defaults, backups, HA, release signing.

A commit hits stock Postgres on local disk. Branching and WAL archival stay
off that path. The control plane, gateway, and Agent API are Go beside
Postgres, not inside the query.

---

## Contributing

The smallest useful change is welcome, including docs and tests.
[CONTRIBUTING.md](CONTRIBUTING.md) is the dev setup, how to run tests, and the
pull-request flow. **The [CLA](CLA.md) has to be signed** before a first
contribution is merged. You keep the copyright. The licence you grant covers
the paid edition as well as the AGPL core. Read that before you open a pull
request.

Candidate issues, not yet filed: [docs/good-first-issues.md](docs/good-first-issues.md).
Behaviour in the community: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
Vulnerabilities: [SECURITY.md](SECURITY.md), not a public issue.

```bash
make build     # ./bin/fox
make vet test  # no VM required
```

---

## Star the repo

If a self-hosted Postgres you can branch is what you wanted, [star the
repository](https://github.com/thefoxbyte/foxbyte). Stars are how the next
person finds it on GitHub, Show HN, and the READMEs that link here.

A star is the one-click version. A fork and a pull request are the useful
version. The [good first issues](docs/good-first-issues.md) list is the short
path in.

---

## License

- **Core and server** (this repo, except `clients/` and `enterprise/`): **AGPL-3.0-or-later** — [LICENSE](LICENSE).
- **Clients** (`clients/`): **Apache-2.0** — [clients/LICENSE](clients/LICENSE).
- **Enterprise** (`enterprise/`): commercial, source-available — [enterprise/LICENSE](enterprise/LICENSE). Not in the Standard binary.

Connecting with a Postgres driver does not make your application AGPL. The
copyleft applies if you modify FoxByte and offer that modification to others
as a service.
