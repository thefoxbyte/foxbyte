# FoxByte — Python client

A thin, dependency-free client for the FoxByte control-plane REST API. Apache-2.0.

## Install

```bash
pip install ./clients/python        # from a checkout
```

Python 3.9 or newer, and nothing else — the client uses only the standard
library. Not on PyPI: install it from the repository.

## Get a branch in three lines

```python
from foxbyte import FoxByte

db = FoxByte(api_key="key_…", verify_tls=False)   # verify_tls=False for the local self-signed cert
db.create_branch("qa")
print(db.query("qa", "select 1"))
```

Mint an API key with `fox apikey create <email>` (or the web *API keys* page); `fox setup`
also prints one you can use.

## Reference

```python
db.status()
db.branches()
db.create_branch("qa"); db.delete_branch("qa")
db.suspend("qa"); db.resume("qa")
db.query("qa", "select now()")
db.blackbox("qa", kind="agent", limit=20) # who changed what (Blackbox)
db.verify_blackbox("qa")                   # tamper-evidence check (ledger()/verify_ledger() still work)
```

## The change feed (Enterprise)

Subscribe to a branch and be told when rows change. Give an application a
**realtime key** — `fox realtime key create <branch>` — which subscribes to that
one branch and can do nothing else: not the control plane, not SQL through the
gateway, not another branch.

```python
import os
from foxbyte import Notice, Transaction, subscribe

rows = {}
sub = subscribe(os.environ["FOX_REALTIME_URL"],
                transactions=True,          # whole commits
                since=load_position(),      # resume where this process left off
                verify_tls=False)           # a local self-signed certificate

for item in sub:
    if isinstance(item, Transaction):
        # One commit, whole. Two rows moved by one transaction arrive together,
        # so nothing you derive from the feed passes through a state where one
        # side moved and the other had not.
        for change in item.changes:
            key = change.identity["id"]
            after = change.apply(rows.get(key))
            rows[key] = after if after is not None else rows.pop(key, None)
        save_position(item.commit_lsn)       # only after the whole commit
    elif isinstance(item, Notice) and item.type == "resync":
        # The feed could not continue from where we were: everything held is of
        # unknown age, so refetch rather than carry on with a hole.
        rows.clear()
        refetch_everything()
```

Four things this handles so you do not have to:

- **A column missing from `new` is not null.** Postgres omits a large (TOASTed)
  value an update did not touch and names it in `unchanged`. Copying `new` over
  your row writes null across a value that never changed, and nothing reports
  it — which is why `Change.apply` exists. Use it.
- **Resume from a commit, not a change.** Every change in a transaction carries
  the same `commit_lsn`; `sub.position` moves only once a whole transaction has
  been yielded.
- **Reconnects.** The server ends a stream every hour by design; this comes back
  on its own, resuming from the last transaction delivered.
- **Values are strings.** A `bigint` or `numeric` does not survive a float, so
  every value is a `str` and `None` means SQL NULL — `""` and `None` are
  different.

Already holding an API key? `db.subscribe("main")` uses it. A realtime key is
the better choice for anything that should only ever read.

The full API is described by the OpenAPI spec, served at `GET /api/openapi.yaml`
(and at [`internal/controlplane/openapi.yaml`](../../internal/controlplane/openapi.yaml)).
