# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the Python client's change-feed subscriber.

Run with the standard library only:

    python3 -m unittest discover -s clients/python/tests

Two of these matter more than the rest, because they are the mistakes this
module exists to stop a user making:

* ``Change.apply`` must leave an unchanged TOASTed column alone. Postgres omits
  a large value an update did not touch, so ``new`` has a hole in it — and a
  client that copies ``new`` over its row writes null across a value that never
  changed, with nothing to report it.
* the resume position must move only at a transaction boundary, and must be
  dropped on ``resync``. Moving it mid-transaction skips the rest of that
  transaction after a reconnect; keeping it after a resync leaves a hole that
  nothing ever reports.
"""
from __future__ import annotations

import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from foxbyte.realtime import (  # noqa: E402
    Change,
    Notice,
    RealtimeError,
    Schema,
    Subscription,
    Transaction,
    _frames,
    parse_realtime_url,
)


class TestParseRealtimeUrl(unittest.TestCase):
    def test_what_the_cli_prints(self):
        u = parse_realtime_url("fox-realtime://rtk_abc@127.0.0.1:8080/app")
        self.assertEqual(u.host, "127.0.0.1:8080")
        self.assertEqual(u.branch, "app")
        self.assertEqual(u.key, "rtk_abc")
        self.assertEqual(u.sslmode, "require")
        self.assertEqual(u.base_url, "https://127.0.0.1:8080")

    def test_key_as_password(self):
        # What somebody transcribing a Postgres URL is likely to type.
        u = parse_realtime_url("fox-realtime://ignored:rtk_abc@127.0.0.1:8080/app")
        self.assertEqual(u.key, "rtk_abc")

    def test_sslmode_disable_is_plain_http(self):
        u = parse_realtime_url("fox-realtime://rtk_abc@127.0.0.1:8080/app?sslmode=disable")
        self.assertEqual(u.base_url, "http://127.0.0.1:8080")

    def test_verify_full_is_still_https(self):
        u = parse_realtime_url("fox-realtime://k@db.example.com:8443/app?sslmode=verify-full")
        self.assertEqual(u.base_url, "https://db.example.com:8443")

    def test_whitespace_as_a_copy_paste_leaves_it(self):
        u = parse_realtime_url("  fox-realtime://rtk_abc@127.0.0.1:8080/app\n")
        self.assertEqual(u.branch, "app")

    def test_refusals(self):
        for raw, expect in [
            ("", "empty"),
            ("postgres://u@h:5432/db", "starts with fox-realtime://"),
            ("127.0.0.1:8080/app", "starts with fox-realtime://"),
            # A port is required rather than defaulted: the control plane's port
            # is configurable, so a guess produces a connection refused
            # somewhere the user never asked to connect.
            ("fox-realtime://k@127.0.0.1/app", "no port"),
            ("fox-realtime://k@127.0.0.1:8080/", "no branch"),
            ("fox-realtime://k@127.0.0.1:8080", "no branch"),
            ("fox-realtime://k@127.0.0.1:8080/app/orders", "more than one path segment"),
            ("fox-realtime://k@127.0.0.1:8080/app?sslmode=prefer", "not one of"),
        ]:
            with self.subTest(raw=raw):
                with self.assertRaises(RealtimeError) as cm:
                    parse_realtime_url(raw)
                self.assertIn(expect, str(cm.exception))


class TestApply(unittest.TestCase):
    def test_insert_builds_the_row(self):
        c = Change(table="t", action="insert", commit_lsn="0/1",
                   identity={"id": "1"}, new={"id": "1", "note": "hello"})
        self.assertEqual(c.apply(None), {"id": "1", "note": "hello"})

    def test_update_merges_over_what_is_held(self):
        held = {"id": "1", "note": "old", "body": "big"}
        c = Change(table="t", action="update", commit_lsn="0/1",
                   identity={"id": "1"}, new={"id": "1", "note": "new", "body": "big"})
        self.assertEqual(c.apply(held), {"id": "1", "note": "new", "body": "big"})

    def test_an_unchanged_toasted_column_is_left_alone(self):
        # The trap. `body` is a large value the update did not touch, so the
        # server omitted it from `new` and named it in `unchanged`. Copying
        # `new` over the held row would write null across it.
        held = {"id": "1", "note": "old", "body": "a very large value"}
        c = Change(table="t", action="update", commit_lsn="0/1",
                   identity={"id": "1"}, new={"id": "1", "note": "new"},
                   unchanged=["body"])
        got = c.apply(held)
        self.assertEqual(got["body"], "a very large value",
                         "an untouched large column was overwritten")
        self.assertEqual(got["note"], "new")

    def test_an_unchanged_column_never_held_is_simply_absent(self):
        # Not invented as None: the client has never seen the value, and
        # claiming it is null would be a fact it does not have.
        c = Change(table="t", action="update", commit_lsn="0/1",
                   identity={"id": "1"}, new={"id": "1"}, unchanged=["body"])
        self.assertNotIn("body", c.apply(None) or {})

    def test_empty_string_and_null_stay_different(self):
        c = Change(table="t", action="update", commit_lsn="0/1",
                   identity={"id": "1"}, new={"id": "1", "a": "", "b": None})
        got = c.apply({"id": "1", "a": "x", "b": "y"})
        self.assertEqual(got["a"], "")
        self.assertIsNone(got["b"])

    def test_delete_removes_the_row(self):
        c = Change(table="t", action="delete", commit_lsn="0/1", identity={"id": "1"})
        self.assertIsNone(c.apply({"id": "1", "note": "x"}))

    def test_truncate_removes_the_row(self):
        c = Change(table="t", action="truncate", commit_lsn="0/1")
        self.assertIsNone(c.apply({"id": "1"}))


def sse(*events: dict) -> bytes:
    return b"".join(
        f"event: message\ndata: {json.dumps(e)}\n\n".encode() for e in events
    )


class fakeResponse(io.BytesIO):
    """Stands in for urlopen's result: read(n) and a context manager."""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestFrames(unittest.TestCase):
    def test_a_payload_split_across_reads_is_not_truncated(self):
        # A wide row crosses a packet boundary routinely. Splitting on every
        # newline would hand half a JSON object to the parser.
        payload = {"type": "change", "table": "t", "note": "x" * 9000}
        got = list(_frames(fakeResponse(sse(payload))))
        self.assertEqual(len(got), 1)
        self.assertEqual(json.loads(got[0])["note"], "x" * 9000)

    def test_several_events_in_one_read(self):
        got = list(_frames(fakeResponse(sse({"type": "a"}, {"type": "b"}, {"type": "c"}))))
        self.assertEqual([json.loads(g)["type"] for g in got], ["a", "b", "c"])

    def test_a_reader_that_returns_short_chunks_still_delivers(self):
        """The bug the contract test found, as a unit test.

        ``HTTPResponse.read(n)`` blocks until it has all n bytes or the stream
        ends, so reading a feed that way waits for a buffer to fill with events
        that have not happened yet. A BytesIO hides this — ``read(4096)``
        returns at once at end of file — so this stands in for a socket: a
        reader whose ``read1`` hands back one small piece at a time, and whose
        ``read`` would block for ever if it were used.
        """

        class socketLike:
            def __init__(self, data: bytes):
                self.pieces = [data[i : i + 7] for i in range(0, len(data), 7)]

            def read1(self, _n):
                return self.pieces.pop(0) if self.pieces else b""

            def read(self, _n):  # pragma: no cover - a failure if ever called
                raise AssertionError("read() would block on a live stream; read1 is required")

        got = list(_frames(socketLike(sse({"type": "change", "table": "t"}))))
        self.assertEqual(len(got), 1)
        self.assertEqual(json.loads(got[0])["table"], "t")

    def test_a_trailing_partial_frame_is_not_yielded(self):
        # Half an event at the end of a stream is not an event.
        data = sse({"type": "change"}) + b"event: message\ndata: {\"type\": \"ch"
        got = list(_frames(fakeResponse(data)))
        self.assertEqual(len(got), 1)


class subscriptionOver(Subscription):
    """A Subscription reading a canned stream instead of a socket."""

    def __init__(self, body: bytes, **kw):
        super().__init__("fox-realtime://k@127.0.0.1:8080/app", **kw)
        self._body = body

    def _open(self):
        return fakeResponse(self._body)


class TestSubscriptionDelivery(unittest.TestCase):
    def one_pass(self, sub):
        """Read a single stream rather than looping with reconnects."""
        return list(sub._read_once())

    def test_changes_are_yielded_with_their_fields(self):
        sub = subscriptionOver(sse(
            {"type": "schema", "table": "public.t", "columns": [{"name": "id", "type_oid": 20, "key": True}]},
            {"type": "change", "table": "public.t", "action": "insert",
             "commit_lsn": "0/AB", "lsn": "0/A1", "xid": 7, "identity": {"id": "1"},
             "new": {"id": "1"}},
        ))
        got = self.one_pass(sub)
        self.assertIsInstance(got[0], Schema)
        self.assertIsInstance(got[1], Change)
        self.assertEqual(got[1].xid, 7)
        self.assertEqual(got[1].lsn, "0/A1")
        self.assertEqual(got[1].commit_lsn, "0/AB")

    def test_unframed_position_follows_the_change(self):
        sub = subscriptionOver(sse(
            {"type": "change", "table": "t", "action": "insert",
             "commit_lsn": "0/AB", "identity": {"id": "1"}},
        ))
        self.one_pass(sub)
        self.assertEqual(sub.position, "0/AB")

    def test_a_transaction_is_delivered_whole(self):
        # The case framing exists for: two rows moved in one transaction.
        sub = subscriptionOver(sse(
            {"type": "begin", "xid": 42, "commit_lsn": "0/FF", "at": "2026-10-09T12:00:00Z"},
            {"type": "change", "table": "t", "action": "update", "xid": 42,
             "commit_lsn": "0/FF", "identity": {"id": "1"}, "new": {"id": "1", "bal": "90"}},
            {"type": "change", "table": "t", "action": "update", "xid": 42,
             "commit_lsn": "0/FF", "identity": {"id": "2"}, "new": {"id": "2", "bal": "110"}},
            {"type": "commit", "xid": 42, "commit_lsn": "0/FF", "changes": 2},
        ), transactions=True)
        got = self.one_pass(sub)
        self.assertEqual(len(got), 1, f"want one transaction, got {got}")
        tx = got[0]
        self.assertIsInstance(tx, Transaction)
        self.assertEqual(tx.xid, 42)
        self.assertEqual(len(tx.changes), 2)
        self.assertEqual(tx.commit_lsn, "0/FF")
        self.assertEqual(tx.at, "2026-10-09T12:00:00Z")

    def test_the_position_moves_only_at_the_commit(self):
        # Mid-transaction it must not move: a reconnect from there would skip
        # the rest of the transaction.
        sub = subscriptionOver(sse(
            {"type": "begin", "xid": 42, "commit_lsn": "0/FF"},
            {"type": "change", "table": "t", "action": "update", "xid": 42,
             "commit_lsn": "0/FF", "identity": {"id": "1"}},
        ), transactions=True)
        self.one_pass(sub)
        self.assertIsNone(sub.position, "the position moved before the commit arrived")

        sub2 = subscriptionOver(sse(
            {"type": "begin", "xid": 42, "commit_lsn": "0/FF"},
            {"type": "change", "table": "t", "action": "update", "xid": 42,
             "commit_lsn": "0/FF", "identity": {"id": "1"}},
            {"type": "commit", "xid": 42, "commit_lsn": "0/FF", "changes": 1},
        ), transactions=True)
        self.one_pass(sub2)
        self.assertEqual(sub2.position, "0/FF")

    def test_a_consumer_that_stops_after_one_transaction_still_has_a_position(self):
        """The ordinary pattern: handle one transaction, persist, stop.

        A generator only runs up to its yield, so anything after it never
        happens for a consumer that breaks out of the loop. The first version
        set the position after yielding and such a consumer read None — which
        the other tests missed because they drain with ``list()``, a consumer
        more cooperative than any real one.
        """
        sub = subscriptionOver(sse(
            {"type": "begin", "xid": 42, "commit_lsn": "0/FF"},
            {"type": "change", "table": "t", "action": "update", "xid": 42,
             "commit_lsn": "0/FF", "identity": {"id": "1"}},
            {"type": "commit", "xid": 42, "commit_lsn": "0/FF", "changes": 1},
            # More after it, which this consumer never reaches.
            {"type": "begin", "xid": 43, "commit_lsn": "0/11"},
        ), transactions=True)
        for item in sub._read_once():
            self.assertIsInstance(item, Transaction)
            break
        self.assertEqual(sub.position, "0/FF",
                         "a consumer that stopped after one transaction has no position to persist")

    def test_a_consumer_that_stops_after_one_change_still_has_a_position(self):
        sub = subscriptionOver(sse(
            {"type": "change", "table": "t", "action": "insert",
             "commit_lsn": "0/AB", "identity": {"id": "1"}},
            {"type": "change", "table": "t", "action": "insert",
             "commit_lsn": "0/AC", "identity": {"id": "2"}},
        ))
        for _ in sub._read_once():
            break
        self.assertEqual(sub.position, "0/AB")

    def test_resync_drops_the_position(self):
        # Everything held is of unknown age; resuming from the old position
        # would leave a hole nothing would ever report.
        sub = subscriptionOver(sse(
            {"type": "begin", "xid": 1, "commit_lsn": "0/AA"},
            {"type": "change", "table": "t", "action": "insert", "xid": 1,
             "commit_lsn": "0/AA", "identity": {"id": "1"}},
            {"type": "commit", "xid": 1, "commit_lsn": "0/AA", "changes": 1},
            {"type": "resync", "code": "slot_invalidated", "detail": "refetch"},
        ), transactions=True)
        got = self.one_pass(sub)
        self.assertIsInstance(got[-1], Notice)
        self.assertEqual(got[-1].type, "resync")
        self.assertIsNone(sub.position, "a resync left a stale resume position behind")

    def test_a_since_position_is_sent_and_kept(self):
        sub = subscriptionOver(b"", since="0/1234")
        self.assertEqual(sub.position, "0/1234")

    def test_unparseable_data_does_not_end_the_stream(self):
        body = (b"event: message\ndata: {not json}\n\n"
                + sse({"type": "change", "table": "t", "action": "insert",
                       "commit_lsn": "0/AB", "identity": {"id": "1"}}))
        got = self.one_pass(subscriptionOver(body))
        self.assertEqual(len(got), 1)
        self.assertIsInstance(got[0], Change)


if __name__ == "__main__":
    unittest.main()
