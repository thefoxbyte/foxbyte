# Contributing to FoxByte

Thanks for your interest. FoxByte is a serverless-Postgres platform written in
Go, with a React/TypeScript web app. This guide covers how to build, test, and
propose changes.

## Development setup

The engine (ZFS + Docker + Postgres) is Linux-only and runs inside a local VM —
Lima on macOS, WSL2 on Windows. The `fox` binary is a launcher that forwards
engine commands into that VM.

```bash
make build        # host binary -> ./bin/fox
make vm-build     # Linux engine binary -> /tmp/fox inside the Lima VM (macOS)
make web-build    # build the web UI to web/dist (embedded into the engine binary)
```

The engine serves the web UI itself: run `fox start` and open
https://localhost:8080. Only if you are working on the UI and want hot reload,
`make web-dev` (deprecated) starts a dev server at http://localhost:5173.

## Before you open a pull request

```bash
make vet          # go vet ./...
make test         # Go unit tests (host, no VM needed)
gofmt -l cmd internal   # must print nothing
```

CI runs the same checks on Linux (`.github/workflows/ci.yml`) and Windows. For
changes to the engine lifecycle, run the end-to-end suites:

```bash
make integration integration-v2 integration-update
```

They run in a throwaway Lima VM (`fox-test`), created on first use — never in the
VM that holds your own install. The suites are destructive by design (they wipe
Blackbox history, restore `main` to an earlier point, fail HA over and create
accounts), so each refuses to start anywhere `scripts/test_vm.sh` has not marked.

Please:

- keep changes focused; one logical change per PR;
- match the surrounding style — comments explain *why*, not *what*;
- add or update tests for behaviour you change;
- update docs and the README when you add or change a user-facing feature.

## Contributor License Agreement (CLA)

Before your first contribution is merged, we ask you to sign a one-page CLA:
**[CLA.md](CLA.md)**. Once, ever — not once per pull request.

**You keep the copyright to your code.** It stays yours, and you can use it
anywhere else for anything. What the CLA gives us is a licence to it, including
the right to release it under different terms later.

**Those terms include commercial ones.** FoxByte's core is AGPL-3.0-or-later and
there is a paid edition under a commercial licence (`enterprise/`), so a
contribution may end up in a product people pay for. We would rather say that
plainly here than have you find out afterwards. If it is not something you want,
say so before you open a pull request — we would rather lose a contribution than
take one on terms its author did not want.

**Why we need it:** keeping an open core and a paid edition side by side only
works if we hold the rights across the whole tree. Without a CLA, every past
contributor would have to be found and asked individually before any licensing
decision — and people change jobs and email addresses. One signature at the start
avoids a search later that may not succeed.

Contributing on an employer's time or equipment? They may own the rights to your
work, in which case we need a Corporate CLA instead. Get in touch before opening
a pull request.

## Reporting bugs and security issues

- **Bugs / features:** open a GitHub issue with steps to reproduce.
- **Security vulnerabilities:** do **not** open a public issue — see
  [SECURITY.md](SECURITY.md).

## Code of Conduct

Participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).
