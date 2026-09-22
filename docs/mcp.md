<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# FoxByte over MCP

`fox mcp` speaks the [Model Context Protocol](https://modelcontextprotocol.io) on
stdio, so an agent framework can get its own disposable Postgres database, run
SQL, see exactly what it changed, and throw the database away — through one
standard interface, with no HTTP client to write.

It is newline-delimited JSON-RPC 2.0 on stdin/stdout. **stdout carries the
protocol**, so every log line goes to stderr; a tool that prints to stdout will
corrupt the session.

## Point a client at it

Most clients take a command and arguments. The command is `fox`, the argument is
`mcp`:

```json
{
  "mcpServers": {
    "foxbyte": {
      "command": "fox",
      "args": ["mcp"],
      "env": { "FOX_API_KEY": "key_…" }
    }
  }
}
```

`fox` must be on the client's `PATH` (the installer puts it there) and
FoxByte must be running — `fox start` — because the tools talk to the same
engine the CLI does.

The key is required: these tools create databases, run SQL and branch `main`,
and every change is recorded against the account the key belongs to. Make one
with

```
fox apikey create you@example.com mcp
```

and put it in the `env` block above (`--key <key_…>` also works, but a key on
the command line is visible in the process list). Started without one, the
server prints these instructions and exits rather than serving unauthenticated.

A key **scoped to one branch** — the kind the Agent Branch API issues — limits
the server to that branch: every tool call is pinned to it, naming another
branch is refused, and `create_branch`, `delete_branch`, `list_branches`,
`blackbox_diff` and `branch_before_change` are refused outright, since each
reaches past a single branch. An account key behaves as it always did.

On macOS and Windows the engine runs inside a VM or WSL distro, and `fox mcp`
forwards into it automatically, so the config above is identical on every
platform.

Check it by hand before wiring up a client:

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | fox mcp
```

You should get two JSON lines back: the server's capabilities, then the tools.

## The tools

Branches — a branch is a copy-on-write clone of `main`, created in seconds:

| Tool | What it does | Arguments |
|---|---|---|
| `create_branch` | Creates an isolated database for an agent and returns a DSN it can connect to | `agent_id` (required) |
| `list_branches` | Lists the active agent branches and their DSNs | — |
| `delete_branch` | Deletes an agent's branch and all its data | `agent_id` (required) |
| `run_sql` | Runs SQL on a branch and returns the result | `sql` (required), `branch` |

The DSN from `create_branch` goes through the gateway, so it works from the
machine the agent runs on, not only inside the VM. Its password is an API key
scoped to that one branch: it opens no other branch, and the control plane and
the Agent Branch API both refuse it. The key is shown once, at creation —
`list_branches` returns the DSN without it — and deleting the branch revokes it.

Blackbox — the tamper-evident record of every schema change:

| Tool | What it does | Arguments |
|---|---|---|
| `changes` | Recent schema changes: who changed what, when, with which tool | `branch`, `limit` |
| `verify_ledger` | Recomputes the hash chain to check nothing was altered | `branch` |
| `ledger_integrity` | Checks the record against anchors stored outside the database — catches edited, deleted or wiped history | `branch` |
| `ledger_entries` | Newest entries with their ids (feed one to `branch_before_change`) | `branch`, `limit` |
| `branch_before_change` | New branch holding `main` as it was just before a given entry | `entry_id` (required), `branch`, `name` |
| `blackbox_diff` | Where two branches' histories split, what each changed since, and objects both changed | `a`, `b` (both required) |

`verify_blackbox`, `blackbox_integrity` and `blackbox_entries` are listed too and
do exactly the same as `verify_ledger`, `ledger_integrity` and `ledger_entries` —
Blackbox is the product name, and both spellings work everywhere.

Changing schema safely:

| Tool | What it does | Arguments |
|---|---|---|
| `impact` | Before you change something: what depends on it, which other branches have it, the policy verdict, and a risk score | `sql` or `object` (+ `column`), `branch` |
| `policy_check` | Which policy rules a statement would trigger — warn or block — without running it | `sql` (required), `branch` |
| `execute_change` | Runs a change with provenance attached (session, task, parent session), after a policy preview; returns what happened and the Blackbox entries it wrote | `sql` (required), `branch`, `task_id`, `parent_session_id`, `dry_run` |

`execute_change` is the one to reach for when an agent alters a schema:
`run_sql` records the change too, but without the task and session provenance,
and it does not return the policy verdict.

## What it does not do

- **The key is the only credential.** The server verifies an API key and acts
  as that account for the life of the process; there is no per-call
  authorization beyond a scoped key's one branch, and no rate limiting. It is
  still meant for a local agent runtime: anyone who can read the client config
  can read the key, and the process itself runs with the privileges of the user
  who started it.
- **No superuser by default.** `run_sql` connects as the non-superuser
  `db_client` role, so an agent cannot disable triggers or override the
  destructive-DDL guardrail. `FOX_MCP_SUPERUSER=1` restores the old
  superuser behaviour (and `FOX_AGENT_SUPERUSER=1` does the same for agent
  branches created over the HTTP API) — only in a build made with
  `-tags insecure`. Release builds ignore both.
- **`branch_before_change` takes minutes, not seconds.** It restores a base
  backup and replays WAL, and it needs a base backup taken before the change
  (`fox backup create`).

## See also

- `docs/policy-errors.md` — the machine-readable contract behind `policy_check`
  and blocked changes (`BBX01`, `BBX02`).
- `docs/ledger-anchor-format.md` — the anchor format `ledger_integrity` checks
  against, and what `fox-verify` reads.
- The REST API (`GET /api/openapi.yaml` from a running engine) for the same
  operations over HTTP.
