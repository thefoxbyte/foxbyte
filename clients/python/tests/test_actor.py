# SPDX-License-Identifier: Apache-2.0
"""Unit tests for application identity in the Python client: a query that acts
for a user, ``with_actor``, and ``with_actor_transaction``. Standard library
only, with a local HTTP server standing in for the engine.

The one that matters most: the token goes in the request body or as a bound
parameter, never in a URL or in SQL text, where logs would keep it.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from foxbyte import FoxByte, FoxByteError, with_actor_transaction  # noqa: E402


class _Engine:
    def __init__(self, reply):
        seen = self.seen = []

        class H(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"null")
                seen.append({"path": self.path, "auth": self.headers.get("Authorization"), "body": body})
                out = json.dumps(reply(body)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


class QueryActForTest(unittest.TestCase):
    def test_body_carries_act_for_only_when_asked(self):
        e = _Engine(lambda b: {"columns": ["n"], "rows": [[1]], "act_for": {"user": "alice"}})
        try:
            db = FoxByte("key_x", e.url)
            r = db.query("main", "SELECT 1", act_for="tok.en.sig")
            self.assertEqual(e.seen[0]["body"], {"sql": "SELECT 1", "act_for": "tok.en.sig"})
            self.assertNotIn("tok", e.seen[0]["path"])
            self.assertEqual(r["act_for"]["user"], "alice")
            db.query("main", "SELECT 2")
            self.assertEqual(e.seen[1]["body"], {"sql": "SELECT 2"})
        finally:
            e.close()

    def test_with_actor_requires_the_token_on_every_query(self):
        e = _Engine(lambda b: {"columns": [], "rows": []})
        try:
            db = FoxByte("key_x", e.url)
            with db.with_actor("tok.en.sig") as acting:
                acting.query("main", "UPDATE a SET x = 1")
                acting.query("qa", "UPDATE b SET y = 2")
            self.assertEqual(len(e.seen), 2)
            for s in e.seen:
                self.assertEqual(s["body"]["act_for"], "tok.en.sig")
                self.assertTrue(s["body"]["act_for_required"])
                self.assertEqual(s["auth"], "Bearer key_x")
            self.assertEqual(e.seen[1]["path"], "/api/branches/qa/query")
        finally:
            e.close()

    def test_with_actor_refuses_an_empty_token(self):
        with self.assertRaises(FoxByteError):
            with FoxByte("key_x", "http://127.0.0.1:9").with_actor(""):
                pass


class _Cursor:
    def __init__(self, conn):
        self.conn = conn

    def execute(self, sql, params=None):
        self.conn.calls.append((sql, params))
        if self.conn.fail_on and sql.startswith(self.conn.fail_on):
            raise RuntimeError("application identity refused: expired")

    def close(self):
        pass


class _Conn:
    def __init__(self, autocommit=False, fail_on=None):
        self.autocommit, self.fail_on, self.calls = autocommit, fail_on, []

    def cursor(self):
        return _Cursor(self)

    def commit(self):
        self.calls.append(("commit()", None))

    def rollback(self):
        self.calls.append(("rollback()", None))


class WithActorTransactionTest(unittest.TestCase):
    def test_asserts_with_a_parameter_then_commits(self):
        c = _Conn()
        with with_actor_transaction(c, "tok.en.sig") as cur:
            cur.execute("UPDATE orders SET paid = true WHERE id = %s", (7,))
        self.assertEqual(c.calls, [
            ("SELECT bb.act_for(%s)", ("tok.en.sig",)),
            ("UPDATE orders SET paid = true WHERE id = %s", (7,)),
            ("commit()", None),
        ])
        for sql, _ in c.calls:
            self.assertNotIn("tok.en.sig", sql)

    def test_autocommit_gets_its_transaction_by_hand(self):
        c = _Conn(autocommit=True)
        with with_actor_transaction(c, "tok", paramstyle="$1"):
            pass
        self.assertEqual([s for s, _ in c.calls], ["BEGIN", "SELECT bb.act_for($1)", "COMMIT"])

    def test_rolls_back_and_reraises(self):
        c = _Conn()
        with self.assertRaises(ValueError):
            with with_actor_transaction(c, "tok"):
                raise ValueError("boom")
        self.assertEqual(c.calls[-1], ("rollback()", None))

    def test_a_refused_token_rolls_back(self):
        c = _Conn(fail_on="SELECT bb.act_for")
        with self.assertRaises(RuntimeError):
            with with_actor_transaction(c, "tok"):
                self.fail("the block must not run")
        self.assertEqual(c.calls[-1], ("rollback()", None))

    def test_refuses_a_driver_that_puts_parameters_in_the_sql_text(self):
        Fake = type("connection", (), {"__module__": "psycopg2.extensions"})
        with self.assertRaises(FoxByteError) as cm:
            with with_actor_transaction(Fake(), "tok"):
                pass
        self.assertIn("psycopg 3", str(cm.exception))

    def test_refuses_an_unknown_paramstyle(self):
        with self.assertRaises(FoxByteError):
            with with_actor_transaction(_Conn(), "tok", paramstyle="{}"):
                pass


if __name__ == "__main__":
    unittest.main()
