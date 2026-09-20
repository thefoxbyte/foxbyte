# Naming: how to rename this product

The product has been renamed twice — VectoraDB, then OxynDB, now FoxByte. Each
rename before this one meant a fresh install, because the name was written into
the data. This document is how that was fixed, and what to do next time.

## The split

**Names people read** come from [`brand.json`](../brand.json): the product name,
the command, the environment variables, the state directory, the repository, the
documents, the web UI.

**Names written into a database or onto disk carry no product name**, and are
frozen. They are what an install *is* — renaming them means migrating or
reinstalling, which is the trap this avoids:

| What | Name | Where it is defined |
|---|---|---|
| SQL schema and session settings | `bb`, `bb.actor`, `bb.allow_destructive`, … | `internal/ledger/ledger.sql` |
| Roles | `db_client`, `db_admin` | `ledger.sql`, `internal/branch/security.go` |
| Postgres superuser, database | `dbadmin`, `appdb` | `internal/branch/branch.go` |
| Policy SQLSTATEs | `BBX01` (block), `BBX02` (warn) | `internal/ledger/policy.go`, `docs/policy-errors.md` |
| API-key prefix | `key_` | `internal/auth/auth.go` |
| Session cookies | `dbengine_session`, `dbengine_oauth_state` | `internal/auth/http.go` |
| Storage pool, datasets | `dbpool`, `dbpool/branches` | `internal/branch/provision.go`, `branch.go` |
| Docker network, containers | `dbnet`, `pg-<branch>` | `internal/branch/branch.go` |
| Object store, its volume and bucket | `objstore`, `objstore-data`, `wal-archive` | `internal/branch/branch.go` |
| Container label | `dev.dbengine.managed` | `internal/branch/branch.go` |
| Anchor format | `ledger-anchor/1` | `internal/ledger/integrity.go` |

Two tests hold the line, both in `cmd/fox/oldnames_test.go`:
`TestNoRetiredProductNames` fails on any retired name in the repository, and
`TestStoredNamesAreBrandFree` fails if the product's name appears in the SQL the
engine installs.

## Renaming

```
scripts/rebrand.sh --product Acme --cli acme --repo acme/acme
go test ./...        # the guard test fails on anything left behind
make feature-doc     # re-render the living documents
make integration     # and the rest of the suites
```

That script edits `brand.json` (moving the old name onto its `previous` list),
regenerates what is derived from it, sweeps the prose and file names, and
renames the module path. Then rename the GitHub repository to match and update
your remote.

**Existing installs keep working.** Nothing in the data changes, and the engine
reads a retired name where it still matters:

- an environment variable set under a retired prefix (`OXYNDB_API_KEY`) is still
  read — `internal/brand.Getenv`;
- a state directory from a retired name (`~/.oxyndb`) is moved to the new one
  rather than abandoned, which keeps accounts, keys, secrets and anchors —
  `internal/brand.StateDir`;
- a VM or WSL distro from a retired name is still found — `internal/host`;
- `fox uninstall` removes binaries and installs left by retired names.

## Generated files

`make brand` writes these from `brand.json`, and
`TestGeneratedFilesAreInStep` fails the build if any of them drifts:

| File | Why it cannot read brand.json at runtime |
|---|---|
| `internal/brand/brand_gen.go` | Go constants |
| `scripts/lib/brand.sh` | sourced by the integration suites |
| `web/src/brand.ts` | the web UI is built, not run from the repository |
| the marked block in `deploy/install.sh` and `install.ps1` | both are fetched standalone from GitHub |

## Things worth knowing

- **The module path is case-sensitive**, unlike GitHub's URLs. `brand.json`'s
  `module` must be `github.com/` + `repo`, and a test checks it.
- **Registry names must be lowercase**: the engine image stays
  `ghcr.io/<owner>/postgres-walg` in lowercase even when the owner is not.
- **Do not put the product's name in a message the database raises.** One used
  to read `OxynDB guardrail: … is blocked by policy`; the SQL console matched
  that text with a regular expression, and a unit test asserted it. A rename
  would have silently stopped the console recognising a blocked change.
- **A self-update cannot cross a rename**: release assets are named for the
  command (`fox-darwin-arm64`), so a binary of the old name looks for assets
  that no longer exist. Reinstall, or `fox uninstall` then install.
