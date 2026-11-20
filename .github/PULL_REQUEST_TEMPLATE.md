<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

## What changed

<!-- One or two sentences a reviewer can check against the diff. -->

## Why

<!-- The behaviour that was wrong, missing, or unclear. Link an issue if one exists. -->

## How to test

<!-- Commands you ran, and what you saw. Say if you did not run the engine. -->

- [ ] `make vet` and `make test`
- [ ] `gofmt -l cmd internal` prints nothing
- [ ] Web change: `npm --prefix web test` (and `tsc --noEmit` if types moved)

## Checklist

- [ ] One logical change
- [ ] Docs updated if a user-facing command, default, or promise changed
- [ ] I have read [CLA.md](https://github.com/thefoxbyte/foxbyte/blob/main/CLA.md). I understand the CLA must be signed before this is merged, and that a signature is a new pull-request comment when the CLA check is enabled — not a tick on this list, and not something to paste into this description

## Not tested

<!-- Suites you did not run, platforms you do not have, anything a reviewer should not assume. -->
