# Replication and HA: review of Prasoon's document, and a plan

Review of *Foxbyte: Replication and High Availability* (@Prasoon, 6 Oct 2026,
based on commit `fea97cd` of 4 Oct), checked against `main` at `8aae026`
(10 Oct 2026) and re-checked at `f0a1650` (11 Oct). Nothing in the review
changed between the two; one sentence in §3.1 did, and says so there.

---

## 1. Is the document correct?

**Yes — materially accurate, with one item that has gone stale since it was
written.** Every claim I checked against the code held up, including the ones I
expected to be loose.

| Claim | Verdict | Evidence |
|---|---|---|
| Active-passive is "a single-VM demonstration" | correct, verbatim | [internal/branch/ha.go:48](../internal/branch/ha.go) says exactly that, and names the same three gaps: multi-host, automatic failure detection, fencing |
| Standby is on the same machine and disk pool | correct | `dbpool/standby`, a container on the same docker network, no host port |
| All replication is asynchronous | correct | no `synchronous_standby_names` or `synchronous_commit` anywhere in the tree |
| No automatic failure detection, no fencing | correct | nothing in `internal/` does leader election or fencing |
| Read replicas not built | correct | `internal/proxy` never references the standby |
| Failback built, keeps every write | correct | `fox ha failback` |
| WAL archive ships "at least once a minute" | correct, exactly | `archive_timeout=60` ([branch.go:319](../internal/branch/branch.go)) |
| Default backup target is on the same disk as main | correct | [target.go:18](../internal/branch/target.go): "on the same disk, so one disk or host failure takes main and every backup of it" |
| Accounts and keys are a SQLite file on one machine | correct | `~/.fox/auth.db` |
| Inbound logical replication built | correct | `fox import --continuous` |
| Branches never replicated | correct | ZFS clones, local by design |

### The one stale item

The document says the **outbound change feed is not built** — in three places:
section 2's table ("Change feed out: Not possible"), section 4 ("the paid
realtime feed is planned, not built"), and "this also unlocks the planned
realtime feed".

It shipped on 9–10 Oct, in PRs #96–#102: readiness verdicts, a `/realtime/v1`
front door with stream-only `rtk_` keys, the console, activity and cost
metering with a subscriber cap, transaction framing, and subscribers in both
published clients. `wal_level=logical` is reachable today, opt-in, via
`fox realtime setup`.

That is not a criticism of the document — it is four days older than the work.
But it changes two things in the plan: `wal_level=logical` costs nothing to
reach now, and **a realtime subscriber interacts with failover**, which section
5 does not consider. See gap 3 below.

### Smaller corrections

- **"Create agent branches from a standby" needs more than validation.** A
  branch is a ZFS clone of a dataset. Cloning the standby's dataset gives a
  copy of a database in recovery, so the clone has to be brought out of
  recovery before it can be used — not impossible, but not the small
  experiment the phrasing implies.
- **Patroni "adds Python"** is worth stating more sharply: it adds a *runtime*
  dependency on every database node, which is a different proposition from a
  build-time tool. For an on-prem appliance that ships as one Go binary, that
  is the main argument against it.
- The RPO estimate "up to about a minute" for machine loss is right for the
  reason the document gives, and matches `archive_timeout=60` precisely.

---

## 2. Is this relevant to an on-prem product?

**More relevant, not less.** The instinct that HA is a cloud concern has it
backwards.

On a managed cloud database the provider supplies HA — RDS Multi-AZ, Cloud SQL
HA — and the product does not have to. **On-prem there is no provider.** If
FoxByte does not fail over, a DBA does it by hand at 3am, or the customer buys
something that does.

And the buyers who insist on on-prem are exactly the ones who ask for this:
banks, insurers, health providers, government. They are on-prem *because* they
are regulated, and the same review that forces on-prem also asks for a stated
RPO and RTO, a DR site, and evidence from a failover drill. Today the honest
answer to all three is "single machine, manual promotion, backups default to
the same disk".

So this is not a cloud feature to defer. It is the price of entry to the market
the product is already aimed at.

### What changes for on-prem

The document is lightly cloud-flavoured. The translations are easy and none of
them is a blocker:

| Document says | On-prem means |
|---|---|
| DR site "in another region" | a second room, building or site — many buyers already have one and will tell you where it is |
| "S3 bucket with Object Lock in that region" | MinIO or a NAS with retention, or the customer's existing object store. Already supported: the target speaks S3 with a custom endpoint and path-style addressing, and the engine already pins MinIO images |
| "a separate etcd cluster" | three machines the customer has to run and patch. For a two-server shop that is a real ask, and it is the strongest argument for `pg_auto_failover`'s single monitor despite the monitor being one more thing to protect |
| "several gateways behind one address" | the customer supplies the address: keepalived with a virtual IP, or HAProxy. Worth naming explicitly, because on-prem there is no load balancer to assume |

---

## 3. Four gaps the document misses

These are ours rather than general PostgreSQL practice, which is why a document
written from the outside would not catch them.

### 3.1 The licence is bound to a machine; failover changes machine

An enterprise licence carries a **host fingerprint** and a rebind allowance,
with a 14-day grace on mismatch. `fox license` is a host-local command, so each
node activates for itself. Since #105 a licence can also be activated from the
console, which changes the ergonomics and not the problem: that path runs in
the control-plane process, so on macOS or Windows it writes only the VM's copy
and the host still needs its own. Either way each node is activated
separately, and each has its own fingerprint.

A standby on a second machine therefore has a different fingerprint. After a
failover the new primary is running paid features on a licence activated for
the old one — grace for 14 days, then refusal. The feature most likely to lapse
is the one the customer is in the middle of needing.

#### Measured once HA pairs worked, and both halves of that were wrong

**A fingerprint mismatch never lapses.** The 14-day `Grace` applies to *expiry*
alone. The mismatch branch of `internal/license/state.go` returns `Warning`,
`Warning.Unlocks()` is true, and there is no deadline on it — the code says so
in as many words: "A fingerprint that does not match warns and no more. A
rebuilt VM, a replaced disk and a new laptop all land here, and none of them is
a licence problem." So a licence copied from the old primary to the new one
keeps working indefinitely.

**But a joined standby has no licence at all, and that is worse.** A licence is
per-install state — `~/.fox/license.json` — and `node join` copies the primary's
*database*, not its state directory. A fresh standby node was never activated,
so its status is the zero value `Invalid`, which does not unlock. Measured
against a real enterprise build with the licence removed:

```
fox version            → enterprise edition, no licence active
fox realtime enable …  → error: … no licence covers "realtime"
```

No grace, no warning period, immediate refusal.

So the real failure is not "the licence lapses 14 days after a failover". It is:

| After a cross-host failover | What actually happens |
|---|---|
| the standby was never activated — the default | paid features refuse **at once** |
| `license.json` was copied across | works **indefinitely**, warning about the fingerprint |

Which inverts the question. It is not "how do we stop the licence lapsing"; it
is "how does the second machine come to have a licence at all" — and until now
nothing told an operator that it did not. `fox node join` says so now, naming
what promotion would cost and that a site licence covers both nodes.

And `fox check`'s **licence** line says it on every run, because the join says
it once. Somebody who joined a month ago and has since let a licence lapse is
the person in the state that matters, and a one-time message at join is no use
to them. The clause adds the consequence and never changes the severity: an
absent licence warns on any install and warns here, a lapsed one fails on any
install and fails here. Being a standby does not make a licence problem milder
or worse — it makes it mean something extra.

The same line also corrects the misreading this section used to encourage. On a
standby with a licence activated elsewhere it says the licence "still unlocks
the paid features, here and after a promotion", because the obvious reading of
"activated on a different machine" is that a promotion will cost them, and it
will not.

That part was engineering rather than policy. The policy below is still a
decision.

There is already an escape hatch: an empty fingerprint is a **site licence**
([license.go:59](../internal/license/license.go)). So this is a licensing
*policy* decision HA forces, not new engineering:

- issue site licences to anyone buying HA (simplest, and probably right), or
- allow a fingerprint set — a licence valid for N named machines, or
- require one licence per node and say so in the pricing.

Decide this before the first HA customer, not during their first failover.

**The recommendation, now that the measurements are in: site licences for
anyone buying HA.** The other two options cost engineering that the first does
not, and buy nothing a buyer asked for:

- A *fingerprint set* means a new licence format, a new signing payload, and a
  verifier that understands N machines. The format is signed, so extending it
  touches `SigningPayload`, `cmd/licensesign`, and every licence already issued.
- *One licence per node* is the only option with no engineering at all, but it
  bills a customer twice for one database and makes the standby's licence an
  operational step somebody can forget — which is exactly the failure the
  warning above now has to exist for.
- A *site licence* needs no code: an empty fingerprint already means this, the
  50 evaluation licences already issued are site licences, and both nodes of a
  pair are covered by the same file. The rebind allowance becomes moot, which
  removes a support path rather than adding one.

The argument against it is that a site licence is harder to meter — it does not
pin the software to a machine. That is a real commercial consideration and it is
the thing to weigh, but note that the rebind counter lives in `~/.fox` and
`fox uninstall` removes it, which `internal/license` already documents as "a
deterrent, not a proof". The node lock is not load-bearing today, so HA is not
the thing that loosens it.

### 3.2 The shared-state move now carries the meter as well

The document's step 1.4 — move accounts and API keys out of the single SQLite
file — is still right. But that file now holds more than accounts: stage 4
added `realtime_activity`, the readings behind `fox realtime activity`, and
change requests and pipelines were already there.

Moving the store to "main itself", as the document suggests, means metering
writes land inside the replicated database and are then replicated. That is
probably acceptable, but it is a decision rather than a detail: it puts a
write-on-a-timer into the primary's WAL, and the WAL is what replication and
the archive carry.

#### Measured before phase 2, and it changes the recommendation

The paragraph above worried about the WAL. The larger problem is availability,
and it inverts the purpose of the phase.

**Authentication does not depend on the database engine today, and the package
boundary enforces it.** `internal/auth` imports exactly one package of ours:
`internal/brand`. Not `internal/branch`. So signing in, verifying an API key
and appending to the security log all work while `main` is down — by
construction, not by luck.

**The gateway reads that store on every client connection, before any branch is
touched** ([proxy.go:300](../internal/proxy/proxy.go)). What each kind of
credential needs today:

| Credential | The auth store | `main` |
|---|---|---|
| a branch-scoped key — an agent on its own branch | yes | **no**: the ACL is skipped entirely for scoped keys |
| an account key | yes | yes, to resolve admin (`branch.IsAdmin("main")`, cached 30s) |
| the console sign-in | yes | **no** |

So putting the store in `main` would mean:

- **nobody can sign in while `main` is unavailable** — which is exactly the
  window this phase exists to protect. Phase 2's own stated unlock is "logins
  and credentials survive a failover"; storing them in the thing that fails over
  is the one arrangement guaranteeing they do not;
- **an agent could not reach its own healthy branch** because `main` was down.
  A branch-scoped key needs no `main` today, and this would add that dependency
  to the product's headline use case;
- and the security log — append-only and hash-chained — would be unwritable in
  the same window, so the refusals happening *during* an incident are the ones
  that would not be recorded.

**Recommendation: not `main`.** A store of its own, which keeps the property the
package boundary already gives us. Where it lives is still open — a small
Postgres that is itself replicated, the monitor node phase 3 introduces, or a
consensus store with the operational cost §2 of this review already named — but
"main itself" should be struck from the options rather than carried forward as
the default because the original document suggested it.

**And the move is worth nothing until phase 1 exists.** "A store every node can
reach" has no content on one node: a single-VM failover keeps the same `~/.fox`
and the same SQLite file, so logins already survive it. Unlike phases 4, 5 and
6, none of this phase pays off before there is a second machine — which is why
it should follow phase 1 rather than precede it, and why the work was not
started here.

What the move will involve, measured rather than guessed: ten tables
(`users`, `sessions`, `api_keys`, `oauth_identities`, `branch_owners`,
`change_requests`, `pipelines`, `pipeline_targets`, `pipeline_runs`,
`realtime_activity`, and the hash-chained `security_events`), 3,861 lines in
`internal/auth`, and 31 places holding a `*auth.Store`. The SQL itself is nearly
portable — three `AUTOINCREMENT` declarations are the only SQLite-specific
constructs — so the cost is in the seam and the migration, not in rewriting
queries.

### 3.3 Replication slots do not survive promotion — but on PG 18 they can

This is the gap worth acting on, and it only exists because the change feed now
does.

A realtime subscriber's position lives in a **replication slot** on the
primary. Slots are not copied to a standby by default, so on promotion every
subscriber's slot is gone. The feed degrades correctly rather than silently —
subscribers receive `resync`, which both published clients handle by dropping
their position and refetching — but every subscriber re-reads everything after
a failover, which for a large table is exactly the wrong moment for that load.

PostgreSQL 17 added failover-aware slots, and **a fresh install ships
PostgreSQL 18** ([images.go:41](../internal/branch/images.go)). Creating slots
with `failover = true` and enabling `sync_replication_slots` on the standby
makes a subscriber's position survive promotion. We create slots without it
today.

That turns "every subscriber refetches after a failover" into "subscribers
carry on", for roughly a day of work. It is the cheapest high-value item on
this whole list and it did not exist as an option when the document was
written.

*Corrected while building Phase 4:* "we ship 18" is true of a fresh install and
not of every install — `pgImage` follows the data, so an install created under
PostgreSQL 16 keeps running 16, and none of these settings exist there. See
Phase 4 below.

### 3.4 The gateway is a single point of failure for *connections*

The document lists "redundant gateway and control plane — not built", which is
correct, but understates it: on-prem, if the gateway process stops, every
client connection fails even though the database is healthy. There is no cloud
load balancer to route around it. Two gateways plus a virtual IP is the minimum
credible on-prem answer, and the VIP is the customer's infrastructure.

---

## 4. The plan

Ordered by value for effort, not by the document's order. My sizing, as the
document asks for.

### Phase 0 — move the backup target off the box — **done**

The default sends the WAL archive and every base backup to the object store
beside main, on the same disk. One disk failure takes the database and every
backup of it.

`fox backup target set` already exists and already supports Object Lock, so
this needed no new machinery: a **backup target** line in `fox check` that
warns while the archive is still local, and the advice to match in the README.
**Largest RPO improvement available for the least work.**

The warning is deliberately not a failure — needing no bucket is the right
default for a fresh install — and it does not probe the bucket, because
`check` is run often and reaching a bucket means a container and a network
call under a ten-minute deadline. `fox backup target show` does that.

**What is still a decision, not a task:** nothing in the product can choose a
bucket for an operator. The check now tells every install that its backups are
one disk failure from gone; acting on it is theirs.

### Phase 1 — a standby on another machine (large) — **done**

| | |
|---|---|
| A dedicated replication role rather than widening `allowReplication` | **done** |
| TLS on replication traffic | **done** — `fox node expose`, with a per-install CA |
| Publishing Postgres off the machine at all | **done** — opt-in, TLS-required, one address, one role, one peer |
| `fox node join <primary>` — a second install builds its standby over the network | **done** |
| Distribute the install secret and signing keys to each node | **decided and narrowed** — see the join token below |
| `standbyRunArgs` grows a remote primary address | **done** |

Unlocks: survives losing a machine. Everything after this depends on it.

#### The replication role, and why it was worth doing first

It is the one item that is worth having on a single machine, so it did not have
to wait for the rest.

`ha enable` used to append this to the primary's `pg_hba.conf`:

```
host replication all all scram-sha-256
```

Any role, from any address. And the standby then connected as the **bootstrap
superuser**, because that was the only role with `REPLICATION`. So the
credential that copies the database was the credential that owns it, and the
rule admitting it admitted everything. On one machine with no published port the
reach of that is small, which is why it lasted — but phase 1 ends with Postgres
reachable from another host, and that rule is what would be waiting there.

Now `db_replica`: `LOGIN REPLICATION NOSUPERUSER NOBYPASSRLS NOINHERIT`, no
table grants, a member of nothing, with a password derived from the install
secret like every other role's. And one rule that names it.

Measured against a live install rather than reasoned about:

| | |
|---|---|
| superuser, physical replication from the network | `FATAL: no pg_hba.conf entry for replication connection … user "dbadmin"` |
| superuser, ordinary connection | unaffected |
| `db_replica` reading a user table | `ERROR: permission denied for table …` |
| `db_replica` running `IDENTIFY_SYSTEM` | answers |

That third row is the point, and the first is the one that had to be checked
rather than assumed: `host all all all` is in the image's default `pg_hba.conf`,
and it is only because `all` in the database column does **not** match a
physical replication request that removing the wide rule actually closes the
door. Asserted in the suite against a live server, not inferred from the
documentation.

**The address stays `samenet`,** which is the subnets the server is directly
attached to — inside a container, the docker network this engine made. Narrower
than `all`; as narrow as it can be until a standby on another machine has an
address worth naming, which is the rest of this phase.

**The wide rule is deleted, not outranked.** `pg_hba` is first-match-wins, so
leaving it below the narrow one would look like a narrowing and be none.

**And `fox check` grew a `replication` line,** because of the upgrade path: that
rule lives in the data directory, a routine `fox update` has no reason to
rewrite it, and the only thing that does is another `ha enable`. An install
whose HA was enabled by an older version keeps the wide rule, and nothing would
have said so.

#### `fox node expose` — TLS, and putting Postgres on a network at all

Everything else in the engine keeps Postgres off every network: `startContainer`
publishes no host port, and the comment there says why — a direct connection
would bypass the gateway, its API key, TLS and ledger attribution. This is the
one command that reverses it, and it reverses it narrowly: only when asked,
only on the address given, only over TLS with a certificate the standby
verifies, only for `db_replica`, and only from the one peer address named.

`internal/tlsutil` already exists and is deliberately **not** reused. That
package says of itself that the point "is not a trusted chain — it is encryption
on the wire", which is right for a browser accepting a self-signed certificate
once. It is wrong for replication: a standby that encrypts without verifying has
an encrypted channel to whoever answered, and what it sends down that channel is
a credential that can copy the database. So there is a small CA per install,
kept on the primary, issuing a certificate that names the address a standby
dials.

Measured between two machines (two VMs on a shared network) before any of it
was written, and again after:

| From the other machine | |
|---|---|
| `db_replica`, TLS, with the CA | `IDENTIFY_SYSTEM` answers |
| `db_replica`, **no TLS** | `no pg_hba.conf entry` |
| the **superuser**, TLS, from the permitted address | `no pg_hba.conf entry` |
| `verify-full` without the CA | the client refuses to trust the server |
| a real `pg_basebackup` over TLS | 47 MB copied, rc=0 |

Three things that environment caught which reading could not.

**A silent TLS bypass that nearly existed.** A published install carries two
rules: `host … samenet` for a standby on this machine and `hostssl … peer/32`
for the remote one. `host` matches plaintext. If docker's port publishing had
made a remote connection appear to come from the docker gateway, it would have
matched the *samenet* rule and TLS would have been optional while looking
mandatory. Docker preserves the source address, so it is genuinely refused —
but that was luck rather than design, and it is a test now.

**The private key must not live in `PGDATA`.** The first instinct was to put it
there: already bind-mounted, no new mount, and `ssl_cert_file` is a sighup
setting so TLS would need no restart at all. `pg_basebackup` copies `PGDATA`, so
every standby that joined would have been handed the primary's private key. The
certificates live in a read-only mount instead.

**Only the port needs a restart.** `ssl`, `ssl_cert_file` and `ssl_key_file` are
all sighup — checked against a live server — so the restart the command performs
is for the published port alone, and it says "connections drop for a few
seconds" rather than pretending otherwise.

**The rest of `pg_hba.conf` had to change too, found in a later audit.** Only
the replication rule had been narrowed. The image's own last rule, `host all all
all scram-sha-256`, stayed in place, so the published port admitted every role
from every network, which goes around the gateway's API keys, ACL and
attribution. While main is published, `node expose` now replaces the whole file
(the original is kept beside it as `pg_hba.conf.fox-unexposed`) with:

```
local   all          all                          trust
host    all          all          127.0.0.1/32    trust
host    all          all          ::1/128         trust
local   replication  all                          trust
host    replication  all          127.0.0.1/32    trust
host    replication  all          ::1/128         trust
host    all          all          samenet         scram-sha-256
host replication db_replica samenet scram-sha-256
hostssl replication db_replica <peer> scram-sha-256
host    all          all          all             reject
host    replication  all          all             reject
```

The socket and loopback rules are how the engine's own `docker exec psql` gets
in; `samenet` is the docker network the gateway and the engine's helper
containers use, and Docker keeps a remote client's source address, so nothing
arriving on the published port matches it. The rules are written into the
running main *before* the port is published, and `node unexpose` puts the
original back only *after* the port is gone, so the published port never carries
the stock rules. Both are a `pg_reload_conf()`, not a restart, and running
either twice changes nothing. An `--address` that is not an IP is now refused
rather than published on `0.0.0.0`, and a `--peer` of `/0` is refused.

**After upgrading,** an install that is already published keeps its old rules
until something rewrites them: run `fox node expose` again with the same
`--address` and `--peer`. An install published with a hostname as `--address`
will fail to start main with that address until it is exposed again with an IP.

#### The join token, which settles the third bullet

The plan asked to "distribute the install secret and signing keys to each node,
since every role password is derived from the secret". That is exactly what it
should **not** do. Deriving every role password from one secret means a node
holding that secret can derive the *superuser's*, so a standby would arrive
holding the credential that owns the database — which is the thing the previous
commit took away from replication in the first place.

So the token carries the CA certificate, the address and port, and
`db_replica`'s password. Nothing else. A test asserts the install secret does
not appear in it.

The cost, written down rather than discovered later: the other machine cannot
derive that password if it is ever rotated, so a rotation means re-issuing the
token. That is the right side of the trade — a rotation is rare, and a superuser
credential on a second machine is forever.

#### `fox node join` — and the promise, demonstrated

On the other machine: take the token, copy the primary over TLS, run the copy as
a standby. What it reuses is the point. The promotion, the failover refusals,
slot synchronisation, zero-data-loss mode and the drill all work on a standby
whose primary is across a network exactly as they do on one whose primary is
the container beside it. Two things differ: where the base backup comes from,
and that the walreceiver has a certificate to verify.

Confirmed in `pg_stat_wal_receiver` on the second machine: `sslmode=verify-full`,
`sslrootcert=/fox-tls/ca.crt`, `status=streaming`. And on the first,
`pg_stat_replication` showing `fox_standby | 192.168.105.3 | streaming`.

**The promise, measured rather than claimed.** Rows 1, 42 and 99 written on the
primary — 99 seconds before the end. The primary's database killed with SIGKILL.
`fox ha failover` on the surviving machine. It took a write, and held
`1 42 99 100`: nothing acknowledged was lost, and `pg_is_in_recovery()` was
false. That is "survives losing a machine", on two machines.

**This install's own `main` is idle afterwards**, which is honest rather than
elegant: a node hosting a standby of another install is a standby node. It is
also what makes the change additive — no existing path changes meaning.

#### Three sharp edges the live testing found

**A promoted standby still claimed to follow its old primary.** After the
failover the surviving machine held the only copy of the data while its state
said it was a copy of something else — and the guards built on that state then
refused the *right* operations, `ha enable` among them. A promotion clears the
join now and says so: "it is the primary now, holding every write that reached
it."

**`ha enable` would have rebuilt a remote standby from the local main.** Same
container, same storage — so a machine following another primary would quietly
stop being a copy of anything that mattered. It refuses, and names `node leave`.

**The CA path has to be one constant.** `pg_basebackup -R` records `sslrootcert`
as the path it saw during the copy, and the walreceiver reads that path from
inside the standby container later. Give the backup a host path and the standby
verifies nothing. One constant, and a test.

#### What two VMs still do not prove

They share a kernel, a disk and a power supply. This establishes the networking,
the credentials, the TLS path and the promotion — not survival of a power cut,
and the drill report's "what this did not test" section goes on saying so until
there is hardware to say otherwise.

**Cross-host failback is not built.** After a failover the surviving machine is
the primary; giving the role back to the original means that machine joining
this one and failing over again. `node join` and `ha failover` support that in
principle and it is not verified, so it is not claimed. `ha failback` on a
joined machine means something different — rebuilding its *own* main — which is
why a promotion clears the join rather than leaving the two to disagree.

### Phase 2 — shared state (medium) — **done, the way 3.2 recommended**

Accounts, API keys, change requests, pipelines and the realtime meter move out
of per-node SQLite into a store every node can reach. Decide 3.2 here.

Unlocks: logins and credentials survive a failover — without this, a failover
leaves nobody able to sign in.

**The investigation this phase asked for is done and is written up in 3.2
above.** Two findings:

1. **"main itself" should be struck from the options.** Authentication has no
   dependency on the database engine today — `internal/auth` imports only
   `internal/brand` — and the gateway reads the store on every connection
   before any branch is touched. Storing accounts in `main` would make signing
   in impossible while `main` is unavailable, which is the window this phase
   exists to protect, and would stop an agent reaching its own healthy branch.
2. **Nothing here pays off before phase 1.** On one node a failover keeps the
   same `~/.fox` and the same SQLite file, so logins already survive it. This
   phase is the only one in the plan with no single-host value, so it follows
   phase 1 rather than preceding it.

*Decided, and done:* **none of the three.** Each of them is a second thing to
run, promote, back up and upgrade, and a two-server shop pays that cost
forever. What the three options have in common is the assumption that the state
has to move somewhere both nodes can *reach*. It does not. It has to **be** on
both nodes — and there is already a channel that puts bytes on both nodes,
authenticated, encrypted and watched: the WAL the standby is streaming.

So: every node keeps its own SQLite, and the rows are carried. The node that
follows nobody writes a document of the carried tables into `statedb`, a
database of its own inside the replicated cluster; the other machine reads it
from its own copy and applies it into its own store. Auth reads never leave the
local file, so §3.2's property — logins work while `main` is down — is kept
rather than traded away, which none of the three options manage.

Seven tables travel (`users`, `api_keys`, `oauth_identities`, `branch_owners`,
`pipelines`, `pipeline_targets`, `change_requests`). Three do not, each for a
reason worth stating: `sessions`, because a bearer token is minutes old and
carrying it between machines widens what a stolen document is worth;
`pipeline_runs` and `realtime_activity`, because both are append-only logs that
grow without bound and this mechanism rewrites a whole document when it
changes; and `security_events`, because a hash chain is a per-writer structure
— two chains cannot be merged, and overwriting one node's with another's would
destroy the evidence the chain exists to keep. Each node keeps its own, which is
the honest reading: the log records what *that* node did.

One writer, enforced by the thing that already decides it: a node ships if and
only if it follows nobody, and `ha failover` clears the join record, so a
promotion makes a node the writer by the same act that makes it the primary. An
account change on a follower is refused rather than silently overwritten —
firmest for `apikey revoke`, since a key revoked on a copy comes back with the
next one.

**And the half this phase did not know it owned.** Phase 7 measured that a
joined node cannot serve clients at all, because every role password is derived
from the install secret and the copy carries the *other* install's roles. The
accounts arriving is useless if the gateway cannot then log into Postgres. The
decision taken was that the secret still never leaves the primary: a promoted
node rewrites the role passwords to its own, over the container socket that
needs no password. Clients are unaffected — they hold API keys, and the gateway
derives the role password locally. `fox ha repair-roles` is the hand crank.

**What is still not true.** The document is carried asynchronously, so a
failover can lose the last seconds of account changes exactly as it can lose the
last seconds of writes. And a standby that has *not* been promoted still cannot
serve reads across machines: a copy in recovery cannot have its passwords
rewritten, so that case needs a role created on the primary instead — which is
the follow-up phase 7 named.

### Phase 3 — automatic failover with fencing (large) — **done; the virtual IP is still a decision**

Wrap `pg_auto_failover` or Patroni; do not write one. The document's reasoning
is right and the recommendation stands. For an on-prem appliance I lean
`pg_auto_failover`: one monitor to protect is a smaller operational ask than a
three-node etcd cluster, and it does not put Python on every database node.

The gateway stops asking "which container on this host is primary"
(`PrimaryContainer`) and starts asking the manager. Run two gateways behind a
virtual IP the customer provides.

Unlocks: recovery in about a minute with nobody awake.

*Done, and not by wrapping either of them.* `fox ha watch` runs on the standby
and promotes only when it and a **witness** on a third host both fail to reach
the primary. The refusal to run without a witness is the feature: this section
already said that no amount of local probing can tell a dead primary from an
unreachable one, and an automatic failover configured without a third opinion is
a scheduled split brain.

Why not `pg_auto_failover` or Patroni, having leaned towards the first. Both
want to own the cluster — they create the data directory, write the recovery
configuration and perform the promotion — and this engine owns all three, since
every branch is a ZFS clone of a data directory it made and `node join` writes
`primary_conninfo` itself. Marrying either would mean handing over the parts
branching is built on. The measurement in §6.3 is the second reason:
`postgresql-18-auto-failover` installs from pgdg, but its last tagged release is
April 2025 and the PG 17/18/19 work is untagged. What those projects are
actually for is the quorum, and that is the part reproduced here — a witness,
and a refusal without one.

The promotion is the ordinary fenced `HAFailover`. Nothing in the watcher
reimplements promotion, nothing skips the fence, and `--force` is not reachable
from it at all: the one thing an unattended process must never do is decide that
a primary it cannot see has definitely gone. Four decisions, one of which
promotes, and the two refusals are separate — "the witness reaches it" means
*this* machine is the cut-off one, while "the witness could not be asked" is no
opinion at all. Both go in the hash-chained security log, because a refusal is a
split brain that did not happen and that is worth being able to prove.

**Still a decision, and the only thing left of this phase:** the gateway half.
Two gateways behind a virtual IP is what makes a failover invisible to clients,
and §6.4 — whether the customer supplies the IP — decides what we build. With
one gateway per site the surviving machine serves on its own address, which is
correct and is not transparent.

**The witness's answer is authenticated, found in a later audit.** It used to
answer over plain HTTP, with an optional token compared in the ordinary way, so
anything on the network path could have supplied the "primary unreachable" an
unattended promotion waits for. Now:

- the token is required on both sides (`--token` or `FOX_HA_WITNESS_TOKEN`, at
  least 16 characters). `ha witness` will not start without one and `ha watch`
  will not run without one; each says how to set it and suggests a fresh value;
- the token never travels. A request carries an HMAC-SHA256 of a fresh nonce,
  which the witness checks in constant time; an answer carries an HMAC-SHA256
  over the verdict, the witness's name, its time and that nonce. The watcher
  rejects an answer whose MAC, nonce or time (more than two minutes from its
  own clock) does not check out, so an altered, made-up or replayed answer is
  refused;
- the witness serves HTTPS with the engine's self-signed certificate
  (`internal/tlsutil`) and prints its SHA-256 fingerprint, which `ha watch
  --witness-fingerprint` can pin. The MAC is what makes an answer authentic; the
  pin is a second check;
- an answer that fails any check is no answer. The round is `blind`, and blind
  never promotes.

**After upgrading,** a witness or watcher set up without a token stops with an
error saying how to set one. Pick one token, give it to both, restart the
witness, and change the watcher's `--witness` URL from `http://` to `https://`.

**What no drill and no witness can fix:** the witness has to be where the
clients are. A witness partitioned from the primary alongside the standby will
agree with it about a primary that is still serving somebody else. That is a
placement an operator chooses, which is why `ha watch` prints it rather than
assuming it.

#### Fencing came first, because phase 1 shipped a split brain

On one machine `HAFailover` stops the old primary before promoting the standby,
and "stop the old primary" is the whole of fencing when both are containers
here. Across machines it stopped the wrong thing: `PrimaryContainer()` is *this*
host's `pg-main`, which on a joined node is an idle database nobody uses, while
the real primary went on serving writes somewhere else.

Measured, with the primary deliberately left healthy:

```
node 1 main container:   running
node 1 accepts a write:  yes
node 2 accepts a write:  yes      ← pg_is_in_recovery() = f
```

Two primaries, diverging, with nothing to say so. That shipped in the `node
join` change and is fixed here: `ha failover` on a machine that follows a
remote primary probes it first and refuses while it answers. Verified both
ways — refused with the primary alive and the standby left in recovery,
promoted when the primary was genuinely stopped.

`--force` exists for a primary an operator has already isolated by other means,
and warns in the words that matter: "both machines are about to accept writes
and the two copies will diverge with no way to merge them."

A promotion also now says what must happen to the old primary: it **must not**
be started as a primary again, because it would accept writes the survivor
never sees. `node join` against the survivor is the way back, and it replaces
that copy.

**What the fence does not do, said plainly rather than implied.** It cannot tell
a dead primary from one this machine merely cannot reach. If the network is
partitioned and clients can still reach the primary, forcing a promotion
produces exactly the split brain above, and no amount of local probing can
distinguish the two cases. That needs a third opinion — which is the rest of
this phase.

#### The manager: the evidence has moved since this plan was written

The plan leans `pg_auto_failover` over Patroni, for reasons that still hold: one
monitor to protect is a smaller operational ask than a three-node etcd cluster,
and it does not put a Python runtime on every database node. What has changed is
the state of the project.

| | |
|---|---|
| Last tagged release | **v2.2, April 2025** — about eighteen months old |
| PostgreSQL 18 | the README claims 13–18, and PGDG packages `postgresql-18-auto-failover 2.2-4.pgdg12+1`, which **is installable in this engine's image** (checked) |
| PG 17/18/19 work | merged to `main`, not in any tagged release |

So it is installable, and the version that supports what we ship is partly
untagged. For an appliance that a bank runs on-premises, "the HA manager's last
release predates the database it manages" is a procurement question as much as a
technical one.

**And either choice collides with what phases 4 and 5 built.** A failover manager
wants to own the Postgres lifecycle: `pg_autoctl` starts and stops the server,
writes its own configuration, and — the direct conflict — manages
`synchronous_standby_names` itself. Phase 5 just made that setting ours, with
`fox ha sync on` asserting the standby is counted and rolling back if not. Two
things managing one GUC is not a configuration, it is a bug waiting for an
incident. The same goes for `postgresArgs`, `startContainer` as the supervisor,
and the primary pointer the gateway reads.

That is not an argument against the phase. It is an argument that it is a
rewrite of how this engine runs Postgres rather than a wrapper around it, and
that the decision deserves the measurement before the code — which is what the
remaining decisions in §6 are for.

### Phase 4 — failover-aware realtime slots — **done**

Subscribers carry on through a failover instead of refetching. The ratio was
the best on the list and it held. The description of the work above was not
accurate, though — it named one of four things that have to be true, and three
of the obvious ways to build it would have broken an existing install: one that
runs PostgreSQL 16, one that rebuilds its standby, and one that is simply
busy.

**Four things, not one.** "Create slots with `failover = true`; enable
`sync_replication_slots`" is what the feature is called, and on its own it does
nothing at all. Slot synchronisation runs only when every one of these is true,
and when one is missing it does not fail — the worker logs a line nobody reads
and the slots are simply never copied:

| | Where |
|---|---|
| the logical slot is marked `failover` | `ALTER_REPLICATION_SLOT` after the decoder creates it |
| `sync_replication_slots=on`, `hot_standby_feedback=on` | main and the standby's command line (`postgresArgs`) |
| the standby holds a physical slot on the primary (`primary_slot_name`) | `fox_standby`, on the standby's command line (`standbyRunArgs`) |
| `primary_conninfo` names a database | `pg_basebackup -d "host=… user=… dbname=…"` |

The last one is the trap. `pg_basebackup -R` copies the parameters it connected
with, and `-h host -U user` produce a conninfo with no database name — checked,
not assumed. The sync worker connects to a *database* on the primary to read
its slots, so with `-h`/`-U` the whole feature is inert and looks installed.

`synchronized_standby_slots` is deliberately **not** set. It makes logical WAL
senders *wait for* the slots it names, so a named standby that is not there
stops decoding altogether. A setting that turns a missing standby into a
stalled feed does not belong in a default.

**PostgreSQL 16 is still supported, and this would have broken it.** §3.3 above
reasoned from "we ship PostgreSQL 18", which is true of a fresh install and not
of every install: `pgImage` follows the data, not the binary, so an install
created under 16 keeps running 16. `sync_replication_slots` does not exist
there, and an unrecognised setting is fatal — `postgres -c
sync_replication_slots=on` on 16 exits with `FATAL: unrecognized configuration
parameter`, which inside docker is a database that never comes up. Every piece
of this is gated on the major (`SlotSyncMajor`), including the catalog query
behind `fox realtime slots`, which reads `failover` and `synced` through
`to_jsonb` because naming them as columns is an error on 16.

**And the backup must not go through that slot at all** — two independent
reasons, one found by reading and one by the suite.

The obvious way to make the physical slot is `pg_basebackup -C -S`, which
refuses a slot that already exists and then deletes the data directory it was
building. `fox ha enable` is the documented way to rebuild a standby, so the
second one would have failed.

Creating the slot separately and passing only `-S` fixes that and introduces
something worse, which the integration suite caught and no amount of reading
would have:

```
pg_basebackup: error: could not send replication command "START_REPLICATION":
  ERROR: can no longer access replication slot "fox_standby"
  DETAIL: This replication slot has been invalidated due to "wal_removed".
```

A slot created with `immediately_reserve` pins its position at creation, so it
is subject to `max_slot_wal_keep_size` from creation — and on a busy primary
with a small budget it can be invalidated in the seconds between being made and
the backup's WAL streamer connecting to it. `ha enable` then cannot build a
standby *at all*: a resilience feature taking out the thing it was meant to
protect. The suite reached that state honestly, because section 10 leaves the
budget at 32 MB after proving the budget invalidates slots.

So the backup streams through no slot, exactly as it always did. The standby is
told its slot on its own command line, where a setting also outranks the
`postgresql.auto.conf` that `-R` writes, and the slot reserves nothing until the
standby connects to it. Nothing is lost by waiting: the WAL the standby needs
next is already in its own `pg_wal`, put there by the backup's `-X stream`.

**A failback gets no slot.** `main` is rebuilt as a temporary standby of the
promoted standby by `startContainer`, which names no slot, so one made there
would reserve WAL that nothing reads. A failback is minutes long and ends with
`main` a primary again; the standby that `ha enable` then builds gets the slot.

**It is the same switch as the feed.** A physical slot holds WAL on the primary
for a standby that may be gone, and with the change feed off there is no
`max_slot_wal_keep_size` to bound it — so on an install that does not stream
changes, adding one would trade "a dead standby needs rebuilding" for "a dead
standby fills the primary's disk". So the slot exists only while the feed is on
and the major can synchronise it, and a base backup on every other install is
byte-for-byte the command it has always been. `fox ha disable` drops it.

**Degrades rather than refuses.** A slot that is not failover-aware still
streams every change correctly; all it loses is its position across a promotion
that may never happen. So a failed `ALTER_REPLICATION_SLOT` logs and carries
on, and `fox realtime slots` says of each slot whether it survives a failover —
a degradation nobody can see is the thing worth avoiding, not the degradation.

**The limit, which is PostgreSQL's and not ours.** A slot is copied to the
standby only while it is being consumed. PostgreSQL will not copy one whose
position is behind the standby's catalog horizon —

```
could not synchronize replication slot "fox_rt_main_stream"
DETAIL: Synchronization could lead to data loss, because the remote slot needs
WAL at LSN 0/72001F20 and catalog xmin 10115, but the standby has
LSN 0/72001F20 and catalog xmin 10116.
```

— and the horizon of an otherwise idle database sits exactly one transaction
ahead of a slot nobody is reading, so the position never catches up and the
copy is retried forever. Measured: the standby stayed at `catalog xmin N+1` and
the slot at `N` for fifty seconds without moving.

So **a subscriber that reads continuously keeps its place through a failover;
one that read once and went away is told to resync, exactly as it was before.**
`sync_replication_slots` is not a thing you switch on and forget. It is also
not something the product can fix — PostgreSQL is refusing in order not to lose
data — so `fox realtime slots` says "marked to survive a failover" rather than
"survives", and prints the reason once.

This cost three runs of the suite to find, because `pg_replication_slots.synced`
goes true long before the copy is usable: the copy is still `temporary` at that
point, and promotion drops a temporary copy. The condition that actually means
a position will survive is a copy that is **not temporary and has a position of
its own**, and that is what the suite now waits for.

`synchronized_standby_slots` was tried against this and does not help, which is
a second reason not to set it.

The assertion the plan asked for is in `integration_realtime.sh` section 12,
and it is discriminating rather than structural: a subscriber reads until the
standby's copy of its slot is usable, detaches, a row is written with nobody
attached, the standby is promoted, and a subscriber then attaches and receives
that row. It was written on a primary that no longer exists, so it can only
arrive from a position that crossed the promotion. Before this, the decoder
would have found no slot on the promoted standby, made a fresh one starting
from "now", and that row would never have reached anyone.

**Still a decision, not a task:** §3.1. Slots now survive a failover; the
*licence* still does not, and after Phase 1 the promoted node is a different
machine with a different fingerprint.

### Phase 5 — opt-in zero-data-loss mode — **done**

`fox ha sync on` makes the primary hold a commit until the standby has it on
disk; `fox ha sync off` releases it. RPO zero inside the data centre, which is
what a regulated buyer is usually asking for when they say "active-active".
Strictly opt-in and named for what it costs, as the plan asked.

**One correction to the sentence above, and it matters commercially.** The plan
described `ANY 1 (...)` as a quorum "so one slow standby cannot stall writes".
A quorum does that only when there is more than one standby to choose from.
With the single standby this engine builds today, `ANY 1 (fox_standby)` means
every commit waits for that one standby, and **if it stops, writes stop**. The
quorum form is still the right thing to write — it is what phase 1 extends by
adding names rather than by rewriting this code — but it buys nothing yet, and
a buyer told otherwise would be misled. So the CLI says it outright:

```
Zero-data-loss mode is on: a commit is not reported until the standby has it on disk.
  Writes now wait for a second machine, so they are slower by the round trip to it.
  There is one standby, so if it stops, writes stop. `fox ha sync off` releases them,
  and works while they are waiting.
```

**The escape hatch is the reason this is safe to offer at all.** `ALTER SYSTEM
RESET synchronous_standby_names` plus a reload works *while every commit is
waiting*, because neither needs a commit of its own. Verified against a primary
with two backends stalled in `SyncRep`: both were released and the next commit
succeeded. Without that property, switching this on would be a one-way door,
and `fox check` would have nothing useful to say.

**The standby has to have a name, and `pg_basebackup` does not give it one.**
`-R` writes no `application_name` into `primary_conninfo`, so the walreceiver
reports itself as `walreceiver` and `synchronous_standby_names = 'ANY 1
(fox_standby)'` would match nothing — the setting would be in place, no standby
would satisfy it, and every commit would wait for a server that can never
answer. The name comes from the standby's **`cluster_name`**, set on its own
command line, which also makes it the physical slot name from phase 4: one word
names this standby in `pg_replication_slots`, in `pg_stat_replication`, and in
`synchronous_standby_names`. `cluster_name` is postmaster-scoped, so `ha sync
on` restarts a standby that predates this rather than asking for a rebuild —
the same thing `realtime setup` already does for the same reason.

**Named rather than `*`.** `synchronous_standby_names = '*'` matches any
walsender, and `pg_basebackup -X stream` is a walsender — a backup in progress
would satisfy the quorum and a commit would be reported durable when only a
backup had it. Checked: with the standby stopped and a base backup running, a
commit still waits.

**Enabling proves itself and rolls back.** After applying the setting, `ha sync
on` asserts the standby is actually counted (`sync_state = 'quorum'`). If it is
not, the database is already refusing to finish a commit, so the setting is
undone and the command fails saying nothing was changed — rather than reporting
success and leaving somebody to discover it.

#### The trap: a failover would have made the database unwritable

`ALTER SYSTEM` writes `postgresql.auto.conf`, and `pg_basebackup` copies
`PGDATA` — so a standby built while this mode was on **carries the setting**.
Checked; it is in the copy. Promote that standby and it is a primary waiting for
a standby of its own that does not exist: every write stops at the moment of a
failover, which is the moment it must not.

So `ha failover` clears it on the promoted node and says the mode is off until a
new standby exists. `ha failback` and `ha disable` do the same for their own
reasons. The *intent* is kept in a marker file separate from the setting, so
`ha status` and `fox check` can tell "nobody asked for this" from "it was asked
for and cannot be honoured right now" — and `ha enable` puts it back once a
standby is streaming again.

#### What `fox check` says

A new **durability** line, because this is the one feature whose failure looks
like the database hanging:

| State | Line |
|---|---|
| on, standby counted | `ok` — zero data loss, a commit waits until `fox_standby` has it |
| on, nothing counted | **`FAIL`** — every commit is waiting and will not complete, with `ha sync off` on the next line |
| asked for, not in effect | `warn` — no standby to wait for, so a lost machine still costs up to 60s |
| not asked for | `ok` — commits never wait, and what that costs |

The failing case is the point. From outside, a stalled primary looks like a hung
database; `fox check` is where somebody looks, so the one command that releases
it has to be on the screen, along with the fact that it works *while* commits
are stalled.

**Not changed:** `synchronous_commit` stays at its default `on`, which already
means "wait for the standby to flush" once names are set. `remote_apply` would
additionally wait for replay — read-your-writes on the standby, at more latency
— and is a separate decision nobody has asked for.

Unlocks: RPO of zero inside the data centre. Phase 1 is what makes the quorum
form mean what the plan originally claimed.

### Phase 6 — DR site and drills — **done: the drill can be run at the second site**

The plan said it itself: "the drill is the deliverable, not the standby". The
drill is built. The second site is not, and cannot be — an asynchronous standby
*at another site* needs a standby on another machine, which is phase 1, of which
this plan says "everything after this depends on it". So this phase lands in the
order its own dependencies allow:

| | |
|---|---|
| A scripted drill that measures and reports real RPO and RTO | **done** |
| The WAL archive at a second site with retention | **already possible** — a remote S3 target with Object Lock, which `fox backup target set` has supported since before this plan, and `fox check` has warned about since phase 0. Configuration, not code |
| An asynchronous standby at the second site | **unblocked**: phase 1 landed `node expose` and `node join`, so a standby at another site is a `node join` from there |
| A drill that can be run *at* that site | **done** — `fox ha drill --takeover`, below |

*Done since.* Two things were wrong with the report rather than with the drill.

It disclaimed three things in every copy of it — losing a machine, noticing, and
a second site — and after phases 1, 3 and 7 all three can be false. A document
that goes on saying "there is only one site" when there were two is as
misleading as one claiming a site it did not have, and only the second kind of
mistake gets checked for. A result now carries the topology it ran in and who
noticed, and the limits section prints what is true of *that* drill: with two
machines and a watcher it says "nothing it set out to" and names the one thing
no drill can test, which is whether the witness is where the clients are.
Detection is read from the security log rather than passed as a flag, because
the watcher is a different process and the log is what an incident review would
use to answer the same question.

And the drill could only be run from the machine that dies, which at a second
site is the wrong machine. `fox ha drill --takeover` runs on the survivor. It
stops nothing and promotes nothing — both are what it is watching for — and a
*local* drill is now refused on a machine that follows a primary elsewhere,
naming this one, because there is no local primary there to end.

That changes what it measures, in both directions. **RTO now includes
noticing**, which a drill that kills the primary itself structurally cannot, so
it is the number a client experienced rather than the number the promotion took.
**RPO is reported as not measurable from that side** rather than as a zero: the
writer was on the machine that went away, so what it acknowledged in its last
moments is known only to it and, for whatever it shipped, to the archive. The
last WAL position the copy received is reported instead, as the one true thing a
survivor can say about what it might be missing. Measured in the test VM: 6.8s
from unreachable to serving, credited to `ha watch`, with the loss figure
refused.

**What is still the operator's to do:** run it between two real machines at two
real sites. Everything the run needs is built, and a WAN is not something a
single-host suite can stand in for.

#### `fox ha drill --yes`

It ends the primary without warning, recovers through the real failover path,
and writes a dated report. Three things make it a drill rather than a
demonstration, and each was a decision:

**It kills the primary rather than stopping it.** `docker stop` sends SIGTERM,
Postgres does a fast shutdown, and a fast shutdown flushes its remaining WAL to
the standby before exiting — so a stopped primary loses nothing and the number
would be a flattering fiction. A machine that dies does not say goodbye, so the
drill sends SIGKILL.

**It kills it with writes in flight**, half way through the run, from a single
session that reads back each commit the server acknowledged. A drill against an
idle database measures an idle database, and the only honest definition of data
loss is a write the client was *told* had happened which then had not.

**It recovers through `HAFailover`** — the same function `fox ha failover`
calls, not a promotion written for the test. What is measured is the thing that
ships.

Measured on the single-VM topology: **0 of 60 acknowledged writes lost, and
400ms from the kill to a write on the new primary.** Those are real numbers from
a real run, and the report spends more words on what they do not mean than on
what they are.

#### The number that would have been misquoted

The first real run lost **nothing** — with *asynchronous* replication. On one
host, with a standby microseconds behind, that is the usual outcome, and it is
exactly the figure somebody would put in a tender. Asynchronous replication
promises nothing of the sort.

So the report never prints a measurement without the configuration that produced
it, and says plainly which of the two may be quoted:

- **zero-data-loss mode on** → RPO zero is a property of the configuration, and
  the measurement is "a confirmation, not the evidence".
- **asynchronous, nothing lost** → "Nothing, on the strength of this." The
  standby was keeping up; a busier primary, a slower link, or a standby doing
  anything else would all lose writes, and nothing bounds how many.
- **asynchronous, writes lost** → the loss is what *this* workload cost at *this*
  rate on *this* machine. What may be promised is the archive: `archive_timeout`
  seconds, once the archive is somewhere the machine's failure cannot reach.

That last clause is why the report shouts when the archive is still local: with
backups on the same disk as the database, no figure in the report is a
disaster-recovery figure at all.

`archive_timeout` is now one constant rather than a literal in the primary's
arguments and another in the report, because a report that disagreed with the
setting would be worse than no report, and a test holds them equal.

#### What the report says it did not test

The section that stops it being misused, because the measured figures are the
part that gets quoted:

- **Losing a machine.** The standby is a container on the same host, sharing its
  disk and its power. The drill measures promotion and rerouting, not survival
  of the host. (Phase 1.)
- **Noticing.** Detection and the decision to fail over were manual, and the RTO
  clock starts at the kill. (Phase 3.)
- **A second site.** There is only one. (Phase 1.)

#### Smaller things it turned up

The drill's own `DROP TABLE` was refused by the Blackbox guardrail, which is the
guardrail working: it is one of the two that stay free in every edition. A drill
does not get an exemption from the product's own rules, so it creates its schema
and empties it with a qualified `DELETE` instead, and the one place that
overrides anything is the cleanup at the end, which says so.

A drill refused before it starts — no standby, already failed over — prints the
refusal and nothing else. The first version printed a report of zeroes, which
buried it.

Unlocks: a dated artifact in `~/.fox/drills/` that a procurement review can
read. The claim is no longer a claim, for the topology we have; phase 1 is what
makes it a claim about surviving a machine.

### Phase 7 — reads from standbys (small to medium) — **done, and smaller than it looks**

Route read-only sessions to a standby, through a separate database name. Lower
priority than it looks: it is a performance feature, and nothing above it is.

*Done.* `main:standby` instead of `main` — same gateway, same API key — and the
standby answers it. The suffix is resolved in the gateway before anything looks
at the name, so the ACL, a key's scope, the audit record and the per-user role
are all about the branch: a suffix chooses a backend, never a different thing to
be allowed. `:` because it is the one readable separator a branch name can never
contain, which reserves the namespace without reserving a name anybody might
want.

Four refusals, each naming the command that resolves it: no standby, a branch
(which has none), a standby that is not running, and a **promoted** standby —
the one that matters, because a read-only DSN silently becoming a connection to
the primary would keep working, keep looking right, and put every read back on
the machine the reader was trying to spare.

*What it buys, which is less than the phase name suggests.* On one machine the
gain is process isolation, not more hardware: a long sequential scan stops
evicting the primary's buffer cache and stops competing for its backends. Real,
and modest. **The cross-machine case — the one that is actually read scaling —
is refused, and the reason is not routing.** A joined node's copy carries the
*primary's* roles, whose passwords derive from the primary's install secret,
while the second machine's gateway has its own secret and its own accounts. The
login fails. So phase 7 across machines is blocked on §3.2's shared state, which
is phase 2, and the refusal says so rather than failing at the backend
handshake.

That is worth recording as a correction to this section's own estimate: phase 7
was sized as "small to medium" on the assumption that routing was the work. The
routing took an afternoon. The half that makes it a scaling feature is a
different phase.

Staleness is reported rather than capped — `ha status` says how far behind the
copy is, `fox connect` prints the read-only DSN with the caveat — because there
is no defensible default for a lag ceiling, and a connection that works or not
depending on how busy the primary was a second ago is worse than one slightly
behind.

### Active-active

The document's conclusion is right and I would not revisit it. Route C — each
database or tenant has one home site — falls out of Phases 1–3 almost for free
and fits the model, where a team or agent already gets its own branch. Route A
risks silently discarding a write, which is unacceptable for a product whose
pitch is a tamper-evident record. Route B is a different product.

---

## 5. What I would not do

- **Build our own failover.** The document is right, and the failure mode is
  data loss during an incident.
- **Phase 7 before Phase 3.** Read scaling is a nice-to-have; surviving a
  machine failure is the thing being bought.

  *Since Phase 7:* the order held — fencing landed first. And the phase turned
  out to be two features wearing one name: the routing, which is done, and read
  scaling, which needs a second machine able to authenticate against a copy of
  somebody else's roles. Only the first was ever "small to medium".
- **Promise RPO and RTO numbers before Phase 6's drill measures them.** The
  figures in the document are estimates from the code and say so; ours should
  come from a drill or not be quoted.

  *Since Phase 6:* `fox ha drill` measures them, and the report distinguishes a
  figure that may be quoted from one that may not — which turned out to be the
  harder half. A drill on one host with asynchronous replication loses nothing
  most of the time, and that number is worth less than it looks.

## 6. Decisions needed before Phase 1

1. **Licence policy for HA pairs** (3.1) — site licence, fingerprint set, or
   per-node. Blocks nothing technically; blocks the first sale. The 50
   evaluation licences already issued are site licences (empty fingerprint),
   so they would survive a failover; a customer licence issued the default way
   would not. *Measured since:* a mismatched fingerprint never lapses, but a
   joined standby has no licence at all and refuses paid features immediately —
   see 3.1. `node join` now warns. **Recommended: site licences for HA buyers**,
   the only option needing no new code.
2. **Where shared state lives** (3.2) — **decided and built.** Not main, for
   the availability reason measured in 3.2, and not a separate store either:
   each node keeps its own SQLite and the rows are carried between them through
   the WAL already being replicated. The three options this section listed were
   all a second thing to run; none of them kept the property that makes auth
   survive `main` being down. See phase 2.
3. **Failover manager** — **decided: neither.** Both want to own the data
   directory, the recovery configuration and the promotion, all of which this
   engine owns; and the measurement below is the second reason. What they are
   for is the quorum, and phase 3 reproduces that with a witness and a refusal
   without one. The original note, kept because the measurement stands:
   *Narrowed by
   measurement:* `pg_auto_failover` is installable for PostgreSQL 18 in this
   engine's image (`postgresql-18-auto-failover 2.2-4.pgdg12+1`), but its last
   tagged release is April 2025 and the PG 17/18/19 work is untagged on `main`.
   Either manager wants to own the Postgres lifecycle, including
   `synchronous_standby_names`, which phase 5 made ours — so this is a rewrite
   of how the engine runs Postgres, not a wrapper around it.
4. **Whether the customer supplies the virtual IP**, or we ship something.
   *Now the only thing standing between phase 3 and a failover clients do not
   notice.* Everything else in that phase is built: `ha watch` promotes
   unattended behind a witness, and the surviving machine serves on its own
   address. Two gateways behind an IP that moves is what makes the address stop
   changing, and whose IP it is decides whether we ship keepalived-style
   machinery or document a requirement.
