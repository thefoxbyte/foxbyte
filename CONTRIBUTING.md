# Contributing to FoxByte

Thanks for your interest. FoxByte is a PostgreSQL branching platform written in
Go, with a React/TypeScript web app. This guide covers how to build, test, and
propose changes.

**The [CLA](CLA.md) must be signed** before your first contribution is merged.
Once, ever — not once per pull request. Read it before you open the pull
request. You keep the copyright. The licence you grant includes commercial
terms, because there is a paid edition. If that is not something you want, say
so and do not open the pull request.

## Development setup

You need **Go 1.26** and, for anything touching the web app, **Node 22.22.2 or
newer**. The Node floor is not advisory: `web/.npmrc` sets `engine-strict`, so
`npm ci` refuses on an older one rather than installing and failing later — the
console's tests run in jsdom, which needs it. CI builds on the same two.

The engine (ZFS + Docker + Postgres) is Linux-only and runs inside a local VM —
Lima on macOS, WSL2 on Windows. The `fox` binary is a launcher that forwards
engine commands into that VM.

```bash
make build        # host binary -> ./bin/fox
make vm-build     # Linux engine binary -> /tmp/fox inside the Lima VM (macOS)
make web-build    # build the web UI to web/dist (embedded into the engine binary)
```

Set `FOX_NO_REFRESH=1` when running `fox setup` from a source build, so it
keeps your locally built engine instead of downloading a release.

The engine serves the web UI itself: run `fox start` and open
https://localhost:8080. Only if you are working on the UI and want hot reload,
`make web-dev` (deprecated) starts a dev server at http://localhost:5173.

There is no Compose file to bring the stack up by hand. `fox start` (Linux) and
`fox setup` (macOS and Windows) provision Docker and run the image built from
`docker/postgres/Dockerfile`.

## Running tests

```bash
make vet          # go vet ./...
make test         # Go unit tests (host, no VM needed)
gofmt -l cmd internal   # must print nothing
```

The paid code is behind the `enterprise` build tag. CI vets and tests both
editions (`go test -tags enterprise ./...`) and runs `scripts/test_editions.sh`,
which checks the Standard binary contains none of `enterprise/`.

For a web change, from `web/` (the same commands CI runs):

```bash
npm ci
npm test                 # vitest
npx tsc --noEmit -p .
```

CI runs the same Go checks on Linux (`.github/workflows/ci.yml`) and Windows,
and the web type-check and component tests on Linux. For changes to the engine
lifecycle, run the end-to-end suites:

```bash
make integration integration-v2 integration-update
```

They run in a throwaway Lima VM (`fox-test`), created on first use — never in the
VM that holds your own install. The suites are destructive by design (they wipe
Blackbox history, restore `main` to an earlier point, fail HA over and create
accounts), so each refuses to start anywhere `scripts/test_vm.sh` has not marked.

## Pull requests

1. Fork the repository and create a branch from `main`. One logical change per
   branch.
2. Match the surrounding style. Comments explain why, not what.
3. Add or update tests for behaviour you change. Update docs and the README
   when you add or change a user-facing feature. Public wording should say what
   is true and no more: a number, a default, or a promise that the code does
   not back up will be sent back.
4. Run `make vet`, `make test`, and `gofmt -l cmd internal` (empty output). If
   you touched `web/`, run the vitest suite above.
5. Open the pull request against `main`. Fill in the template: what changed,
   how you tested it, and what you did not test.
6. **Sign the CLA** if this is your first contribution. The text is
   [CLA.md](CLA.md). When the repository variable `CLA_ENABLED` is `true`, the
   workflow in `.github/workflows/cla.yml` comments on the pull request and
   waits for a new comment that is exactly the sentence in CLA.md's "How to
   sign" section. The whole comment has to be that line. GitHub's Quote reply
   copies the bot's message in, and that is not recognised. The workflow is
   off until that variable is set, because the agreement was written to be
   reviewed first. Maintainers still require the agreement. Do not sign on
   someone else's behalf.

A pull request from a fork is welcome. Do not push to `main`, and do not open
a pull request that tags a release.

Please keep changes focused.

## Good first issues

[docs/good-first-issues.md](docs/good-first-issues.md) is a list of small gaps
a maintainer can file as issues. They are not GitHub issues until someone with
access creates them. If you start one, say so in the pull request so two people
do not write the same patch.

## Reporting bugs and security issues

- **Bugs and feature requests:** open a GitHub issue. The templates ask for
  the version (`fox version`), the OS, and what you expected.
- **Security vulnerabilities:** do **not** open a public issue. See
  [SECURITY.md](SECURITY.md).

## Code of Conduct

Participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).
