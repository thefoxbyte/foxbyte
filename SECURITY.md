# Security Policy

FoxByte is pre-1.0. We take security seriously and would rather hear about a
problem privately than read about it publicly.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Use GitHub's private vulnerability reporting: on this repository, go to the
**Security** tab → **Report a vulnerability**. That opens a private advisory only
the maintainers can see.

Please include:

- what you found and where (file, endpoint, or command),
- how to reproduce it, and
- the impact you think it has.

## What to expect

- **Acknowledgement** within 3 business days.
- **An initial assessment** (severity + whether we can reproduce it) within 7
  days.
- We will keep you updated as we work on a fix, and credit you in the release
  notes unless you prefer to stay anonymous.

## Scope

The most sensitive areas today are the wire-protocol gateway
(`internal/proxy`), authentication and API keys (`internal/auth`), the Schema
Ledger (`internal/ledger`), and the install scripts (`deploy/`). Findings
anywhere in the repository are welcome.

## Known posture

FoxByte is designed to run on infrastructure you control. Until the pre-1.0
hardening is complete, treat a deployment as trusted-network. Progress on
transport encryption, per-install credentials, and ledger tamper-evidence is
tracked in the roadmap.
