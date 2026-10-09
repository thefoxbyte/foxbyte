# SPDX-License-Identifier: Apache-2.0
"""Subscribing to a FoxByte branch's change feed.

    from foxbyte.realtime import subscribe

    for tx in subscribe("fox-realtime://rtk_...@127.0.0.1:8080/app",
                        transactions=True, verify_tls=False):
        for change in tx.changes:
            rows[change.identity["id"]] = change.apply(rows.get(change.identity["id"]))
        save_position(tx.commit_lsn)

The feed is server-sent events over HTTP, which is simple enough to read by
hand — and there are four things a hand-written subscriber tends to get wrong,
each of which costs real data:

1. **A column missing from ``new`` is not null.** Postgres omits a large
   (TOASTed) value an update did not touch, and names it in ``unchanged``. A
   client that copies ``new`` over its own row writes null across a value that
   never changed. ``Change.apply`` exists for this.
2. **Resume from a commit, not from a change.** Every change in a transaction
   carries the same ``commit_lsn``, which is the transaction's boundary;
   resuming from it cannot land halfway through a transaction already applied.
3. **``resync`` means start again.** The server says it when a bookmark went
   past the write-ahead-log budget. Carrying on from the last position would
   leave a silent hole.
4. **Values are strings.** A bigint or a numeric does not survive a float, so
   every value arrives as ``str``, and ``None`` means SQL NULL. ``""`` and
   ``None`` are different.

Dependency-free: urllib and the standard library only.
"""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator

SCHEME = "fox-realtime"

# Row values are Postgres text, or None for SQL NULL.
Row = dict[str, str | None]


class RealtimeError(Exception):
    """A subscription could not be opened or could not continue."""


@dataclass(frozen=True)
class RealtimeUrl:
    """A parsed ``fox-realtime://`` connection string."""

    host: str
    branch: str
    key: str
    # "require" (the default: encrypted, certificate not verified, which is what
    # a default install serves), "verify-full", or "disable".
    sslmode: str = "require"

    @property
    def base_url(self) -> str:
        scheme = "http" if self.sslmode == "disable" else "https"
        return f"{scheme}://{self.host}"


def parse_realtime_url(raw: str) -> RealtimeUrl:
    """Parse a connection string.

    The key is carried in userinfo, where a Postgres URL puts its password, and
    this client turns it into an ``Authorization`` header. It never goes in a
    path or a query string: a URL reaches access logs, browser history and
    ``Referer``, and a key that lands in any of those has to be treated as
    disclosed.
    """
    text = (raw or "").strip()
    if not text:
        raise RealtimeError("empty realtime URL")
    # Checked before urlsplit, which accepts almost anything and would leave a
    # confusing failure three fields later.
    if not text.startswith(SCHEME + "://"):
        raise RealtimeError(f"a realtime URL starts with {SCHEME}:// (got {raw!r})")
    # Re-schemed so urlsplit parses the authority the way it does for http.
    u = urllib.parse.urlsplit("http://" + text[len(SCHEME) + 3 :])
    if not u.hostname:
        raise RealtimeError(f"no host in {raw!r}: expected {SCHEME}://<key>@host:port/<branch>")
    if u.port is None:
        raise RealtimeError(
            f"no port in {u.hostname!r}: expected {SCHEME}://<key>@host:port/<branch>"
        )
    # The key may be the username (what `fox realtime key create` prints) or the
    # password (what somebody transcribing a Postgres URL is likely to type).
    key = urllib.parse.unquote(u.password or u.username or "")
    branch = urllib.parse.unquote(u.path.strip("/"))
    if not branch:
        raise RealtimeError(f"no branch in {raw!r}: expected {SCHEME}://<key>@host:port/<branch>")
    if "/" in branch:
        raise RealtimeError(
            f"{u.path!r} names more than one path segment; a realtime URL ends at the branch"
        )
    mode = dict(urllib.parse.parse_qsl(u.query)).get("sslmode", "require")
    if mode not in ("require", "verify-full", "disable"):
        raise RealtimeError(f"sslmode={mode!r} is not one of require, verify-full, disable")
    # netloc carries userinfo; host:port is what gets dialled.
    host = u.hostname if u.port is None else f"{u.hostname}:{u.port}"
    return RealtimeUrl(host=host, branch=branch, key=key, sslmode=mode)


@dataclass
class Change:
    """One row change."""

    table: str
    action: str  # insert | update | delete | truncate
    # The transaction's commit position: the same on every change in it, and
    # the only safe place to resume from.
    commit_lsn: str
    # The replica-identity columns — the only row locator promised under every
    # identity setting. Always present.
    identity: Row = field(default_factory=dict)
    # The row after the change, for insert and update. A column absent here may
    # be named in `unchanged` rather than being null.
    new: Row | None = None
    # The row before it, and only when Postgres sent one: an update or delete
    # under REPLICA IDENTITY FULL.
    old: Row | None = None
    # The columns whose value differs, and only under FULL where it can be
    # computed truthfully.
    changed: list[str] = field(default_factory=list)
    # Large columns the update did not touch, which are therefore absent from
    # `new`. Leave your own copy of these alone.
    unchanged: list[str] = field(default_factory=list)
    # This record's own position, for ordering within a transaction.
    lsn: str | None = None
    xid: int | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def apply(self, row: Row | None) -> Row | None:
        """Apply this change to a row being kept, correctly.

        This is the method the module exists for. Postgres omits a large column
        an update did not touch, so ``new`` has a hole in it and ``unchanged``
        names it. Copying ``new`` over a stored row writes null across a value
        that never changed — and nothing reports it, because the feed did
        exactly what it promised.

        Returns the row after the change, or None for a delete.
        """
        if self.action in ("delete", "truncate"):
            return None
        nxt: Row = dict(row or {})
        nxt.update(self.new or {})
        # The identity is always sent, and locates the row.
        nxt.update(self.identity)
        for col in self.unchanged:
            if row is not None and col in row:
                nxt[col] = row[col]
            else:
                nxt.pop(col, None)
        return nxt


@dataclass
class Transaction:
    """One transaction's changes, delivered together."""

    xid: int
    # Where to resume from once this transaction has been applied.
    commit_lsn: str
    changes: list[Change] = field(default_factory=list)
    at: str | None = None


@dataclass
class Notice:
    """A ``resync`` or ``error`` from the server."""

    type: str
    code: str | None = None
    detail: str | None = None


@dataclass
class Schema:
    """A table's shape, re-sent whenever it changes."""

    table: str
    columns: list[dict[str, Any]] = field(default_factory=list)


class Subscription:
    """A reconnecting subscription to one branch's change feed.

    Iterating yields :class:`Change` by default, or :class:`Transaction` when
    ``transactions=True`` — so related changes can be applied together or not
    at all. :class:`Schema` and :class:`Notice` are yielded too unless filtered
    out with ``events=``.

    Reconnects on its own, resuming from the last transaction it yielded, so a
    network blip does not lose changes.
    """

    def __init__(
        self,
        url: str | RealtimeUrl,
        *,
        since: str | None = None,
        transactions: bool = False,
        verify_tls: bool = True,
        max_retries: int = 0,
        on_error: Callable[[Exception], None] | None = None,
    ) -> None:
        self.dsn = parse_realtime_url(url) if isinstance(url, str) else url
        self.transactions = transactions
        self.max_retries = max_retries
        self.on_error = on_error
        self._position = since
        self._closed = False
        self._ctx = ssl.create_default_context()
        if not verify_tls:
            # A default install serves a self-signed certificate, which is what
            # sslmode=require describes: encrypted, identity not verifiable.
            # The choice is the caller's to make explicitly — this client will
            # not quietly disable certificate checking.
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    @property
    def position(self) -> str | None:
        """Where a reconnect would resume from: the last transaction delivered
        in full. Persist it to survive a restart of your own process."""
        return self._position

    def close(self) -> None:
        """Stop iterating at the next opportunity."""
        self._closed = True

    def __iter__(self) -> Iterator[Change | Transaction | Schema | Notice]:
        failures = 0
        while not self._closed:
            try:
                for item in self._read_once():
                    yield item
                failures = 0  # a stream that ended cleanly is not a failure
            except Exception as err:  # noqa: BLE001 — reported, then retried
                failures += 1
                if self.on_error:
                    self.on_error(err)
                if self.max_retries and failures >= self.max_retries:
                    raise
            if self._closed:
                return
            # Backoff, capped. A suspended branch wakes on the next connection,
            # so retrying is right — just not in a tight loop.
            time.sleep(min(2 ** min(failures, 5), 30))

    def _open(self):
        q: dict[str, str] = {}
        if self._position:
            q["since"] = self._position
        if self.transactions:
            q["transactions"] = "1"
        path = f"/api/branches/{urllib.parse.quote(self.dsn.branch)}/realtime"
        url = self.dsn.base_url + path + (f"?{urllib.parse.urlencode(q)}" if q else "")
        req = urllib.request.Request(url, method="GET")
        # The key goes here and nowhere else.
        req.add_header("Authorization", "Bearer " + self.dsn.key)
        req.add_header("Accept", "text/event-stream")
        try:
            return urllib.request.urlopen(req, context=self._ctx)
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")
            raise RealtimeError(f"{e.code}: {detail or e.reason}") from None

    def _read_once(self) -> Iterator[Change | Transaction | Schema | Notice]:
        open_tx: Transaction | None = None
        with self._open() as resp:
            for data in _frames(resp):
                try:
                    e = json.loads(data)
                except ValueError:
                    continue  # not ours, or truncated: skip rather than stop
                kind = e.get("type")

                if kind == "schema":
                    yield Schema(table=e.get("table", ""), columns=e.get("columns") or [])

                elif kind == "begin":
                    open_tx = Transaction(
                        xid=e.get("xid", 0), commit_lsn=e.get("commit_lsn", ""), at=e.get("at")
                    )

                elif kind == "change":
                    c = _change(e)
                    if open_tx is not None and c.xid == open_tx.xid:
                        open_tx.changes.append(c)
                        if not self.transactions:
                            yield c
                    else:
                        # Without frames there is no transaction to wait for, so
                        # the change's own boundary is the position — set before
                        # the yield, for the same reason as at a commit.
                        if not self.transactions:
                            self._position = c.commit_lsn
                        yield c

                elif kind == "commit":
                    # The position moves before the yield, not after.
                    #
                    # This is a generator: a consumer that handles one
                    # transaction and stops — persist the position, exit, which
                    # is the ordinary pattern — never resumes it, so anything
                    # after the yield simply does not run. The first version set
                    # the position afterwards and such a consumer read None.
                    #
                    # Still only at a commit, which is the rule that matters: a
                    # position taken mid-transaction would skip the rest of that
                    # transaction after a reconnect. By the time the caller holds
                    # the transaction, the position already covers it.
                    self._position = e.get("commit_lsn", self._position)
                    finished, open_tx = open_tx, None
                    if finished is not None and finished.xid == e.get("xid"):
                        finished.at = e.get("at") or finished.at
                        if self.transactions:
                            yield finished

                elif kind in ("resync", "error"):
                    if kind == "resync":
                        # Everything held locally is of unknown age. Carrying on
                        # from the old position would leave a hole nothing would
                        # ever report.
                        self._position = None
                        open_tx = None
                    yield Notice(type=kind, code=e.get("code"), detail=e.get("detail"))

                if self._closed:
                    return


def _change(e: dict[str, Any]) -> Change:
    return Change(
        table=e.get("table", ""),
        action=e.get("action", ""),
        commit_lsn=e.get("commit_lsn", ""),
        identity=e.get("identity") or {},
        new=e.get("new"),
        old=e.get("old"),
        changed=e.get("changed") or [],
        unchanged=e.get("unchanged") or [],
        lsn=e.get("lsn"),
        xid=e.get("xid"),
        raw=e,
    )


def _frames(resp) -> Iterator[str]:
    """Yield the ``data:`` payload of each server-sent event.

    Events are separated by a blank line, and a payload can span several reads —
    splitting on every newline would hand half a JSON object to the parser the
    moment a wide row crosses a packet boundary, which is routine.
    """
    # read1, not read. http.client.HTTPResponse.read(n) blocks until it has all
    # n bytes or the stream ends — which for a feed means waiting for a buffer
    # to fill with events that have not happened yet. read1 returns whatever one
    # underlying read gives, which is what streaming needs.
    #
    # This was found by the contract test against a live engine and could not
    # have been found without one: the unit tests feed a BytesIO, where
    # read(4096) returns immediately at end of file, so the blocking never
    # showed. The symptom was a subscriber that reported no error and delivered
    # nothing.
    read = getattr(resp, "read1", None) or resp.read
    buf = ""
    while True:
        chunk = read(4096)
        if not chunk:
            return
        buf += chunk.decode("utf-8", "replace")
        while "\n\n" in buf:
            frame, buf = buf.split("\n\n", 1)
            for line in frame.split("\n"):
                if line.startswith("data:"):
                    payload = line[5:].strip()
                    if payload:
                        yield payload


def subscribe(
    url: str | RealtimeUrl,
    *,
    since: str | None = None,
    transactions: bool = False,
    verify_tls: bool = True,
    max_retries: int = 0,
    on_error: Callable[[Exception], None] | None = None,
) -> Subscription:
    """Subscribe to a branch's change feed. See :class:`Subscription`."""
    return Subscription(
        url,
        since=since,
        transactions=transactions,
        verify_tls=verify_tls,
        max_retries=max_retries,
        on_error=on_error,
    )
