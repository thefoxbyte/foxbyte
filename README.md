# FoxByte

**Postgres for AI agents — instant branches, and a tamper-evident record of every schema change.**

FoxByte is a **serverless PostgreSQL** platform. It keeps the hot transaction
path on stock Postgres on local NVMe (native commit latency) and moves
durability, branching, and time-travel *off* the commit path — **ZFS
copy-on-write** clones for instant branches and **asynchronous WAL archival**
(`wal-g`) for point-in-time recovery. It speaks the native Postgres wire
protocol, so your existing driver, ORM, and SQL work unchanged. It is the
postgres.ai / Database Lab model, implemented in Go.

The command-line tool is **`fox`**. Everything below is a `fox …` command.

> **New here?** Jump to [Install](#install) · [Quickstart](#quickstart) · [Blackbox](#blackbox)

---

## Screenshots

The web console is served by the engine itself at **https://localhost:8080** — no
separate dev server to run.

| Ops dashboard | Blackbox | SQL console |
| --- | --- | --- |
| ![Dashboard](docs/screenshots/dashboard.png) | ![Blackbox](docs/screenshots/ledger.png) | ![Console](docs/screenshots/console.png) |

---

## What you get

- **[Blackbox](#blackbox)** — every `CREATE`/`ALTER`/`DROP`/`GRANT`
  recorded with the actor (human or agent), tool, and branch; **tamper-evident**
  (hash-chained, append-only, `fox blackbox verify`) and **non-forgeable** (clients
  connect as a per-user role, so the recorded actor is the login identity). No
  other Postgres branching tool has this.
- **Instant branching** — `fox branch create qa` clones the whole database in
  seconds (copy-on-write), fully isolated; `main` is untouched. Plus
  `fox branch reset` (start over) and `fox branch diff` (what changed, from Blackbox).
- **Time travel / PITR** — continuous WAL archival; restore to any point.
- **One serverless endpoint** — connect to `:6432`; the database name *is* the
  branch. Idle branches scale to zero and wake on connect. TLS on by default, so
  `sslmode=require` clients connect out of the box.
- **A database per AI agent** — the Agent Branch API over HTTP, or the
  **Model Context Protocol** (`fox mcp`): an agent gets a database, runs SQL, sees
  what it changed (from Blackbox), and throws it away — one standard interface.
- **Migrate from anything** — import from PostgreSQL, MySQL/MariaDB, MongoDB, and
  `.sql`/`.csv`/`.json`/`.ndjson` files, each landing in a fresh branch.
- **ETL pipelines** *(experimental)* — dbt-style SQL models with data-quality
  tests, each run against a throwaway branch.
- **High availability** — a hot standby with transparent `ha failover`
  (single-VM demonstration).
- **Accounts, API keys, RLS** — email/password or GitHub/Google OAuth; keys are
  the gateway password; Postgres row-level security and GRANTs apply to clients.
- **Web console** — a React UI served by the engine: dashboard, SQL console,
  Blackbox viewer, import, pipelines, API keys.
- **Client SDKs** — an OpenAPI spec (served at `/api/openapi.yaml`) plus
  dependency-free [Python and TypeScript clients](clients/).

Per-install credentials are generated on first run — **nothing is hardcoded**.

---

## Blackbox

The differentiator: **Blackbox**, the database's own flight recorder for schema
changes (formerly called the Schema Ledger — `fox ledger …`, the `/ledger` API
routes and the original MCP tool names all still work). Three Postgres event triggers, installed into `main` and
inherited by every branch, capture **every** schema change and attribute it:

- **who** — the actor (a human email, or `agent-alice`) and whether it was a
  human or an agent;
- **what** — the command, the object, and the full statement;
- **context** — the tool (`application_name`, e.g. `cursor/opus`), the branch,
  and the session;
- **a guardrail** — destructive DDL (e.g. `DROP TABLE`) is blocked by policy
  unless explicitly overridden, and blocked attempts are recorded too.

```bash
fox blackbox            # every schema change on this branch, most recent first
fox blackbox verify     # prove the record has not been tampered with
```

**It cannot be quietly rewritten.** Each row is hash-chained to the one before
it, so a deleted or edited entry breaks the chain and `fox blackbox verify` catches
it — even if a superuser disabled the triggers. The table is append-only. And
because the gateway logs each client in as a **per-user Postgres role**, the
recorded actor is the login identity: a client cannot forge who made a change,
even by `SET`-ting a session variable. There is a **Blackbox** page in the web
console too.

---

## Install

One command installs the `fox` CLI; a second brings everything up. On macOS and
Windows the Linux engine (ZFS/btrfs + Docker + Postgres) runs transparently
inside a managed VM, so day-to-day you only ever type `fox …`.

Every install pulls the **latest** engine build and (re)installs it, so re-running
setup always updates you to the newest version rather than reusing an old one.

### macOS

Needs [Lima](https://lima-vm.io) for the local Linux VM.

```bash
brew install lima
curl -fsSL https://raw.githubusercontent.com/thefoxbyte/foxbyte/main/deploy/install.sh | sh
fox setup
```

`fox setup` creates a dedicated Lima VM, installs Docker + ZFS in it, and brings
the stack up. Your first `fox setup` downloads Ubuntu (a few minutes); after that
it's fast.

### Linux

The engine runs directly (no VM). ZFS + Docker are provisioned on first start.

```bash
curl -fsSL https://raw.githubusercontent.com/thefoxbyte/foxbyte/main/deploy/install.sh | sh
sudo fox start
```

### Windows

Run **in PowerShell** (not Command Prompt — `irm`/`iex` are PowerShell commands).
Needs Windows 10 21H2+/11 with virtualization enabled; everything else is handled
for you. The engine runs in a dedicated **WSL2** distro that stores branches on
**btrfs**, so it works on any WSL kernel — nothing kernel-specific to build.

```powershell
irm https://raw.githubusercontent.com/thefoxbyte/foxbyte/main/deploy/install.ps1 | iex
```

That installs WSL if absent (no Linux distribution of your own needed —
FoxByte brings its own dedicated distro), downloads FoxByte, puts it on your
PATH, and runs `fox setup`. If Windows needs a reboot to finish enabling WSL, it
says so and resumes automatically afterwards. Your other WSL distros and Docker
Desktop are untouched. Full prerequisites and troubleshooting:
**[docs/windows-setup.md](docs/windows-setup.md)**.

### From source (contributors)

```bash
make build       # host binary -> ./bin/fox
make vm-build    # build the Linux engine into the Lima VM (macOS)
```

Set `FOX_NO_REFRESH=1` when running `fox setup` from a source build, so it
keeps your locally-built engine instead of downloading a release.

---

## Quickstart

After `fox setup` (macOS/Windows) or `fox start` (Linux), open
<https://localhost:8080> and create your account — the first one on an install
can override the destructive-change guardrail. Then make an API key on the API
keys page (or `fox apikey create <email> <name>`; it is shown once) and use it
as the password in the connection string below. Then:

```bash
fox status                       # servers, primary readiness, branches
fox branch create qa             # instant copy-on-write branch of main
```

Connect any Postgres client through the gateway — the **database name is the
branch**, and the **password is your API key**:

```bash
psql "postgresql://dbadmin:<API_KEY>@localhost:6432/qa?sslmode=require"
```

```sql
CREATE TABLE notes (id serial PRIMARY KEY, body text, created_at timestamptz DEFAULT now());
INSERT INTO notes(body) VALUES ('hello');
```

```bash
fox blackbox qa                  # see that CREATE TABLE, attributed to you
fox branch delete qa             # throw it away; main is untouched
```

Mint more keys with `fox apikey create <email>` (or on the web *API keys* page).

---

## The web console

`fox start` serves the console at **https://localhost:8080** (a self-signed cert,
so your browser shows a one-time "not private" warning to accept; point
`FOX_TLS_CERT`/`_KEY` at a real pair to avoid it). It has:

- a **dashboard** (live status + branch create/suspend/resume/delete),
- a **SQL console** (run queries against any branch, expand rows as JSON),
- a **Blackbox** viewer (filter by actor, table, risk, kind),
- **import** and **pipelines** pages, and **API keys**.

> The web app is embedded in the engine binary and served same-origin — there is
> no separate dev server to run.

---

## Usage

```bash
fox start        # bring EVERYTHING up in the background: stack + gateway + APIs
fox status       # servers, main readiness, backups, HA, branches
fox logs gateway # tail a background server's log
fox stop         # stop servers and containers (data preserved)
```

**Branching**

```bash
fox branch create qa            # instant copy-on-write branch of main
fox branch list                 # branches and their containers
fox branch reset qa             # re-clone from parent, discarding changes
fox branch diff main qa         # schema changes distinguishing two branches (from Blackbox)
fox branch suspend qa           # stop a branch (data preserved); wakes on connect
fox branch resume qa
fox branch delete qa
```

**Blackbox** (`fox ledger …` works too)

```bash
fox blackbox [branch] [--limit N] # captured DDL — attributed and policy-checked
fox blackbox verify [branch]    # verify the tamper-evident hash chain
fox blackbox revert --to <ts>   # point-in-time restore of main on :5433 (like fox restore)
```

**Durability / time travel**

```bash
fox backup create               # base backup -> object storage
fox backup list
fox restore --to latest         # PITR into a disposable container on port 5433
fox restore --to '2026-08-24 15:07:00+00'
```

**High availability**

```bash
fox ha enable                   # hot standby streaming from main
fox ha status
fox ha failover                 # promote the standby; 'main' reroutes to it
fox ha disable
fox ha failback                 # after a failover: back to main's own container, keeping every write
```

**Accounts & keys**

```bash
fox apikey create <email> [name]   # mint an API key (shown once)
fox apikey list <email>
fox apikey revoke <email> <id>
fox user create <email>            # create an account (prompts for a password)
```

---

## Connect your app

FoxByte **is** PostgreSQL, so every driver and ORM connects unchanged — set one
env var to the gateway address (database = branch, password = API key):

```bash
DATABASE_URL="postgresql://dbadmin:<API_KEY>@localhost:6432/main?sslmode=require"
```

Point Prisma, Drizzle, SQLAlchemy, Django, GORM, ActiveRecord, etc. at that URL.

For the REST API there is an **OpenAPI spec** (served at
`https://localhost:8080/api/openapi.yaml`) and thin, dependency-free SDKs under
[`clients/`](clients/):

```python
from foxbyte import FoxByte
db = FoxByte(api_key="key_…", verify_tls=False)   # local self-signed cert
db.create_branch("qa")
print(db.query("qa", "select 1"))
print(db.verify_blackbox("qa"))
```

Generate a client for any other language from the spec (see [`clients/README.md`](clients/README.md)).

---

## A database per AI agent

Give each agent its own instant, disposable database — over HTTP:

```bash
fox serve --addr :8088          # the Agent Branch API
curl -k -H "Authorization: Bearer $FOX_KEY" -X POST https://localhost:8088/agents/alice/branch
# -> { "dsn": "postgresql://agent-alice:key_…@localhost:6432/agent-alice?sslmode=require", … }
curl -k -H "Authorization: Bearer $FOX_KEY" -X DELETE https://localhost:8088/agents/alice/branch
```

The agent connects with that DSN — through the gateway, so it works from your
machine as well as inside the VM. Its password is an API key **scoped to that
one branch**: it opens no other branch, and the control plane and this API both
refuse it. Deleting the branch revokes the key.

…or over the **Model Context Protocol**, so an agent framework drives it through
one standard interface:

```bash
FOX_API_KEY=key_… fox mcp   # MCP server on stdio (needs a key)
```

Client setup and the full tool reference: [docs/mcp.md](docs/mcp.md).

MCP tools: `create_branch`, `run_sql`, `changes` (what did I change, from
Blackbox), `verify_blackbox`, `list_branches`, `delete_branch`. DDL an agent runs is
attributed to that agent automatically.

---

## Import & migration

Every import lands in a **fresh branch**, so migration is safe and reversible.

```bash
fox import --from postgres://user:pw@host/db  --as prod-copy
fox import --from mysql://user:pw@host/db     --as legacy
fox import --from mongodb://host/db           --as events     # collections -> JSONB
fox import --from ./dump.sql                  --as fromfile    # .sql/.csv/.json/.ndjson

fox import --from postgres://… --continuous --as live          # logical replication
fox import-cutover live                                         # finish the cutover
```

---

## What FoxByte is not

- **Not distributed / not multi-host (yet).** Compute and storage are separated
  *logically* (stateless containers over persistent storage, scale-to-zero) but
  still run on one host. Networked storage disaggregation is on the roadmap.
- **HA is a single-VM demonstration**, not a production multi-host deployment.
- **Not a vector database**, despite the name — it is PostgreSQL (use `pgvector`
  on it if you like).
- **Single-tenant** — authenticated users share one instance; there is no project
  isolation yet.

---

## Development

```bash
make build        # host binary -> ./bin/fox
make vm-build     # Linux engine binary into the Lima VM (macOS)
make vet test     # go vet + unit tests (also run in CI on Linux and Windows)
make integration  # full end-to-end test, in a throwaway test VM
```

The integration suites (`make integration`, `integration-v2`, `integration-update`)
are destructive — they wipe Blackbox history, restore `main` to an earlier point and
fail HA over — so they run in a VM of their own (`fox-test`, created on first use by
`make test-vm`), never in the VM that holds your install, and refuse to start
anywhere else. `make test-vm-stop` frees its memory; `make test-vm-delete` removes it.

The web app lives in `web/` (Vite + React + TypeScript) and is embedded into the
engine binary via the `embedui` build tag, then served same-origin by `fox start`.

Releases are automated: pushing a `v*` tag builds every binary + the install
assets and publishes the multi-arch Postgres image to GHCR.

---

## License

- **Core / server** (this repo, except `clients/`): **AGPL-3.0-or-later** — see
  [`LICENSE`](LICENSE).
- **Clients & SDKs** (`clients/`): **Apache-2.0** — see [`clients/LICENSE`](clients/LICENSE).

> **Using FoxByte does not make your application AGPL.** Connecting over the
> Postgres wire protocol is not a derivative work, and the client libraries are
> Apache-2.0. The copyleft applies only if you modify FoxByte itself and offer
> it to others as a service.
