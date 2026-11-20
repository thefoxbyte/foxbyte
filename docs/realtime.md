# Realtime: the row-level change feed

Enterprise. `fox realtime enable` needs a licence. Summary and the commands
you need to start: [README](../README.md#realtime).

The change feed is logical decoding of a branch's own write-ahead log, on the
Postgres this install is already running. It is not a connector aimed at some
other server. `fox realtime setup` is what makes the databases ready for it,
and that command restarts `main`.

```bash
fox realtime setup
fox branch create qa
fox realtime enable orders --branch qa --columns id,status
fox realtime key create qa    # a stream-only key, shown once; it cannot run SQL
fox realtime url qa           # fox-realtime://…@127.0.0.1:8080/qa
```

`--branch` defaults to `main`. The same commands work on any branch. Enabling
a table on a suspended branch starts that branch. The HTTP route does it
first (`POST /api/branches/{name}/realtime/enable` is wrapped so
`EnsureRunning` runs before the publication change). The CLI's `docker exec`
retries once after the same wake when the container answers "is not running"
(`retryIfStopped`). Opening the stream wakes it too: the decoder calls
`branch.Wake` before it reads the log, and `main` is only resolved to the
current primary, never restarted by that call.

## The stream

The feed is server-sent events. A realtime key uses its own path, on the same
port as the console:

```text
GET /realtime/v1/branches/qa/stream?since=0/1A2B3C
Authorization: Bearer rtk_…
```

`0/1A2B3C` is the shape of a `commit_lsn` (`enterprise/realtime/dsn_test.go`
builds that exact query). It is the log position of a transaction the client
already applied, not a special value. Leave `since` off and the stream starts
from now, not from the beginning of the log. A position the slot can no longer
replay is refused; the client refetches. The Python client sends the same
parameter, on `GET /api/branches/qa/realtime`:

```python
from foxbyte.realtime import subscribe

for tx in subscribe(
    "fox-realtime://rtk_…@127.0.0.1:8080/qa",
    since="0/1A2B3C",
    transactions=True,
    verify_tls=False,  # the local certificate is self-signed
):
    save(tx.commit_lsn)
```

An account API key can open that `/api/branches/qa/realtime` URL directly.
A masked account is refused when the branch has masking rules: the feed is
decoded from the log, under the masks, so it would carry the real values.
`fox realtime disable orders --branch qa` stops the publication. A one-hour
cap ends a forgotten stream; reconnect with the same `since`.

## In the Standard edition

`fox realtime status`, `setup`, `teardown`, and `slots` stay in Standard, so
an install can see and undo a feed it turned on after a licence lapses.

## See also

- [Reference](reference.md) — every command, security defaults, backups.
- [Masking design](FOX_F5_Masking_Design.md) — why a masked account cannot subscribe.
