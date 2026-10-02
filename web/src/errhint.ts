// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The console's half of internal/errhint: the failures a person meets while
// running SQL here, each with the one thing to do next.
//
// Postgres messages are precise and say nothing about FoxByte. "cannot insert
// multiple commands into a prepared statement" is technically exact and tells a
// user nothing about why their script of three statements was refused. The raw
// message is still shown — this adds a line under it, never replaces it.
//
// Keep this list in step with internal/errhint/errhint.go; the guardrail and
// policy cases are deliberately absent, because Console.tsx already handles those
// with an override panel of its own.

type Hint = { re: RegExp; says: string }

const hints: Hint[] = [
  {
    re: /cannot insert multiple commands into a prepared statement/i,
    says: 'A prepared statement holds one command. The console runs scripts by falling back to the simple protocol, so seeing this means something sent the query another way.',
  },
  {
    re: /canceling statement due to statement timeout|context deadline exceeded/i,
    says: 'The statement hit its time limit and was cancelled, so nothing was left half-applied. For a long migration use `fox connect <branch>` instead.',
  },
  {
    re: /relation "([^"]+)" does not exist/i,
    says: 'That table is not on this branch. Check the branch picker above, and the table list on the left.',
  },
  {
    re: /column "([^"]+)" does not exist/i,
    says: 'No such column. Open the table on the left and look at its Structure tab for the real names — identifiers keep their case here.',
  },
  {
    re: /syntax error at or near/i,
    says: 'Postgres could not parse this. The position it names is where it gave up, so the mistake is usually just before it.',
  },
  {
    re: /violates foreign key constraint/i,
    says: 'A row this one points at is missing, or something still points at the row being removed. Insert the parent first, or delete the children first.',
  },
  {
    re: /violates unique constraint|duplicate key value/i,
    says: 'A row with that key is already there. Use ON CONFLICT to say what should happen when it is.',
  },
  {
    re: /violates not-null constraint/i,
    says: 'That column has no default and cannot be empty, so the insert has to give it a value.',
  },
  {
    re: /permission denied for/i,
    says: 'Your database role may not do this on this branch. An admin can grant it, or use a branch you own.',
  },
  {
    re: /password authentication failed/i,
    says: 'Through the gateway on :6432 the password is an API key, not your account password. Mint one on the API keys page.',
  },
  {
    re: /deadlock detected/i,
    says: 'Two transactions waited on each other and Postgres broke the tie by cancelling this one. Run it again.',
  },
  {
    re: /could not reach branch|connection refused/i,
    says: 'Nothing answered on that branch. It may be suspended — the dashboard will resume it — or the stack may be down (`fox check`).',
  },
]

// hintFor returns one sentence explaining msg, or null when nothing here does.
export function hintFor(msg: string | undefined | null): string | null {
  if (!msg) return null
  for (const h of hints) {
    if (h.re.test(msg)) return h.says
  }
  return null
}
