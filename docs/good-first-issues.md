<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Good first issues

These are candidates, not GitHub issues. A maintainer should read each one
and file the ones that are still true. Please do not open all of them at
once from this list, and do not start one without saying so, or two people
will write the same patch.

Each item is a small gap that was in the tree when this file was written.
The difficulty is the size of the patch, not how important the gap is.
"Easy" is a doc or a single test. "Medium" crosses a client and its tests,
or a page that needs a mocked API.

---

### 1. The feature reference still says a fresh database is Postgres 16

**Difficulty:** easy

`docs/foxbyte-feature-reference.html` (the "How it works" paragraph under
Feature 01) says each database is a `postgres:16` process. A fresh install
runs PostgreSQL 18. The major lives in `internal/branch/images.go` (`PGMajor`)
and `docker/postgres/Dockerfile` (`ARG PG_MAJOR=18`). PostgreSQL 16 is only
for an install created before 21 Sep 2026, which `docs/postgres-versions.md`
already says.

Change that sentence so a reader of the feature reference does not think a
new install is 16. Do not delete the fact that 16 is still supported.

### 2. The developer guide names the wrong database user, and a deprecated console

**Difficulty:** easy

`docs/foxbyte-developer-guide.html` disagrees with itself and with the
engine:

- The connection recap says the user is `foxbyte`. The examples on the same
  page, and `internal/branch/branch.go`, use `dbadmin`.
- The endpoint table says the web console is `make web-dev` at
  `http://localhost:5173`. `make web-dev` is marked deprecated in the
  Makefile. `fox start` serves the console at `https://localhost:8080`.
- The sample URLs omit `sslmode=require`. The gateway expects TLS. The
  README's connection string includes it.

Bring those three in line with `cmd/fox/main.go`'s `fox start` banner and
with the README quickstart. Leave the rest of the guide alone.

### 3. SECURITY.md still describes transport encryption as unfinished

**Difficulty:** easy

`SECURITY.md`, "Known posture", says to treat a deployment as a trusted
network and that transport encryption is still in progress. A current
install listens on `127.0.0.1` and serves TLS, and refuses to fall back to
plain HTTP off loopback. That is described under "Security defaults" in
`docs/reference.md`.

Rewrite the paragraph so it matches those defaults. Do not claim a finished
security audit, and do not delete the request to report vulnerabilities
privately.

### 4. The Python client README says `fox setup` prints an API key

**Difficulty:** easy

`clients/python/README.md` says mint a key with `fox apikey create`, "or"
that `fox setup` also prints one you can use. `cmd/fox/main.go` (`start`)
says the opposite in a comment and in the text it prints: no account and no
key are created, and the person makes a key with `fox apikey create` after
they have signed in.

Delete the claim. Point at `fox apikey create` and the API keys page only.

### 5. (Closed) The landing page states a branch time nobody measured

The console no longer has a landing page (22 Nov 2026): its address opens the
sign-in page, so the fake terminal and its number are gone.

### 6. The architecture overview says backups go to the cloud, and that the product is simply open source

**Difficulty:** easy

`docs/foxbyte-architecture.html`:

- The caption says history is "safely copied to the cloud". By default the
  WAL archive and base backups sit in the object store beside `main`, on the
  same disk. `fox backup target set` is what sends them to a bucket
  (`docs/reference.md`, durability).
- A pill says "Open source". The core is AGPL-3.0-or-later. `enterprise/` is
  a commercial licence and is not in the Standard binary
  (`scripts/test_editions.sh`).
- The page never says Windows branches are btrfs subvolume snapshots.
  `docs/FOX_Storage_Engine.html` does.

Correct those three without turning the page into the reference.

### 7. A Makefile comment is cut off on the wrong target

**Difficulty:** easy

In the `Makefile`, the comment that introduces the feature document stops
mid-sentence ("set CHROME to a") and the next line is the `brand` target.
The rest of that sentence ("browser binary if it isn't found automatically.")
sits later, immediately above the `screenshots` target. `feature-doc` is the
target that actually reads `CHROME`.

Put the comment back together above `feature-doc`. No behaviour change.

### 8. Test that the Blackbox page does not offer "branch before" for a catalog scan

**Difficulty:** medium

`web/src/pages/Ledger.tsx` defines `canRewind`: only on `main`, only with an
entry id, not for `BLOCKED`, and not for `UNRECORDED` or `OBSERVED`
(`fromScan`). There is no `Ledger.test.tsx`. The other console pages under
`web/src/pages/` mostly have one.

Add a vitest that mocks `getLedger` and checks the "Branch from before this
change" control is absent for those three statuses and present for an
`APPLIED` row on `main`. Follow `web/src/pages/Requests.test.tsx` for how the
suite renders a page.

### 9. Test that Standard cannot author a policy rule

**Difficulty:** medium

`web/src/pages/Policies.tsx` uses `can('policy')`. When that is false the
"Add rule" button stays on screen, labelled "Add rule (Enterprise)", and is
disabled. There is no `Policies.test.tsx`.

Add a vitest for both states: Enterprise can open the draft, Standard sees
the disabled label and does not get a writable draft. `web/src/features.ts`
is where `can` comes from.

### 10. Test that continuous import is only offered for a Postgres URL

**Difficulty:** easy

`web/src/pages/Import.tsx` sets `isPg` with `/^postgres(ql)?:\/\//` and only
then renders the continuous-replication checkbox (around the `isPg && (`
block). There is no `Import.test.tsx`.

Render the page, type a `mysql://` source, and assert the checkbox is
absent. Type a `postgres://` source and assert it is present. Mock
`listReplication` so the page can mount.

### 11. Wrap change requests and Blackbox diff in the two SDKs

**Difficulty:** medium

The OpenAPI spec (`internal/controlplane/openapi.yaml`) has
`POST /api/branches/{name}/request`, `GET /api/requests`,
`POST /api/requests/{id}/approve`, `POST /api/requests/{id}/reject`, and
`GET /api/blackbox/diff`. `clients/python/foxbyte/__init__.py` and
`clients/typescript/src/index.ts` stop at branch lifecycle, `query`, and
`verify_blackbox`.

Add thin methods and unit tests that the path and the JSON body match the
spec. Do not call a live engine. Keep the clients dependency-free.

### 12. Let the TypeScript client skip TLS verification on purpose

**Difficulty:** medium

`clients/python/foxbyte/__init__.py` takes `verify_tls=False` for the local
self-signed certificate. `clients/typescript/README.md` tells Node users to
set `NODE_TLS_REJECT_UNAUTHORIZED=0`, which turns verification off for every
connection in the process, not just FoxByte.

Add an explicit option on the `FoxByte` constructor in
`clients/typescript/src/index.ts`, document that it is for a local install,
and test that the option is what the client passes to `fetch`. Do not make
insecure the default.

### 13. The console has no hint for a self-signed certificate

**Difficulty:** easy

`internal/errhint/errhint.go` matches `x509` / "certificate signed by unknown
authority" and says to use `sslmode=require`, not `verify-full`.
`web/src/errhint.ts` has no such pattern, and it has no test file. The
header says the console list is the half of those failures a person meets
while running SQL in the console.

Add the TLS hint to `hintFor`, and add `web/src/errhint.test.ts` that locks
the patterns already in the file plus this one. Do not copy the CLI-only
hints (Lima, WSL, Docker) into the console.

### 14. A unit test for the forgotten-password line on the login page

**Difficulty:** easy

`web/src/pages/Login.tsx` tells a person who cannot sign in to run
`fox user passwd` (the command is built from `BRAND.cli`). The only test is
Playwright in `web/tests/console.spec.ts`, which needs a live stack and does
not run in the pull-request CI job that runs `npm test`.

Add `web/src/pages/Login.test.tsx` that renders the logged-out form and
expects that command. Mock `providers()` so the page is not waiting on the
network. Look at `web/src/pages/License.test.tsx` for the render setup.

### 15. Do not drop the branch-create warning in the SDKs

**Difficulty:** easy

`internal/controlplane/server.go` attaches a `warnings` field to the
branch-create response when the new branch would show personal data in the
clear. The CLI prints those warnings (`printPersonalDataWarnings` in
`cmd/fox/piiwarn.go`, called from `fox branch create` in `cmd/fox/main.go`). `create_branch` in the Python client and `createBranch`
in the TypeScript client return the JSON and neither README mentions
`warnings`, so a caller who only reads the branch name never sees them.

Document the field in both client READMEs, and add a test that a body
containing `warnings` is still present on the value the method returns.
Do not swallow the field inside the client.
