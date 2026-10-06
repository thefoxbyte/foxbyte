# Evaluation licences

How to mint a batch of licences for collaborators to try the Enterprise edition
against the Standard one, and what they do with them.

Everything here needs the private signing key, so **only the maintainer can do
the first part**. The key is deliberately not in CI and not in this repository:
a leaked licence key mints Enterprise silently, and rotating it invalidates
every licence already in the field, because the public half is compiled into
every binary.

## Once, ever: the signing key

```sh
make license-key
```

That writes the private key to `license-signing.key` (mode 0600, gitignored) and
the public half into `internal/license/license.go`. **Put the private key in your
password manager and keep it off CI.** Commit the public half: it is what every
binary checks licences against, so a licence is only valid for builds made after
this commit.

Running it twice is refused, by two separate checks — one for the key the build
trusts, one for the key file itself. There is no recovering a lost private key:
every licence it signed becomes unverifiable.

## Minting a batch

```sh
FOX_LICENSE_SIGNING_KEY=$(cat license-signing.key) \
  go run ./cmd/licensesign issue \
    --customer "FoxByte evaluation" \
    --features all \
    --months 3 \
    --id FB-EVAL \
    --count 50 \
    --out ./eval-licences
```

Or `make license-samples`, which is the same thing.

- `--features all` is every feature this build knows about, so the list cannot
  fall out of step with `internal/edition` by hand.
- `--count 50` with `--id FB-EVAL` gives `FB-EVAL-001` … `FB-EVAL-050`, each in
  its own file. They have **separate ids on purpose**: one shared reference
  across fifty licences makes the record useless the first time one has to be
  found.
- **No `--fingerprint`**, so these are site licences that run on any machine.
  That is right for evaluation and wrong for a sale: a real licence names the
  machine it was issued for.
- `--months 3`, so an evaluation licence cannot quietly become a production one.

`issue` refuses to sign with a key the build would not accept, so a mismatch is
caught here rather than by the first collaborator whose licence is rejected.

## What a collaborator does

They need an **Enterprise build** — the Standard binary does not contain the
paid code at all, so a licence does nothing to it. That is the point, and it is
also the comparison worth making:

```sh
curl -fsSL https://raw.githubusercontent.com/thefoxbyte/foxbyte/main/deploy/install.sh \
  | FOX_EDITION=enterprise sh

fox license activate FB-EVAL-007.json
fox version          # enterprise edition, 7 features licensed
fox check            # the licence line, and blackbox anchors: on
```

Against the Standard binary, the same file activates and changes nothing:

```sh
fox version          # fox 1.0.0 — no edition suffix, no features
fox blackbox checkpoint main
# error: FoxByte Enterprise is needed for writing signed Blackbox anchors, …
```

An engine already running keeps the entitlement it read at start-up, so
`fox stop && fox start` is what applies a newly activated licence. The licence
commands say so.

## What to tell them

- The lock is **soft**: a licence bound to another machine warns and keeps
  working, and an expired one stops *new* paid work without stopping a database
  or making anything already recorded unreadable.
- **Reading stays free in every edition.** Verifying the record, checking
  anchors already written, reading policy rules and the evaluations log,
  listing change requests and `fox import` all work without a licence. What a
  licence buys is *doing*: writing anchors, authoring rules, impact analysis,
  applying a promotion, exporting a bundle, running a pipeline.
- Activation, rebinding and expiry are recorded in the security log, by the
  engine, when it next starts.

## Revoking

There is nothing to revoke against offline: a signed licence is valid until it
expires. That is why these are three months and site-wide rather than
open-ended. Per-machine revocation arrives with the portal, which issues a
short-lived lease instead of a long licence.
