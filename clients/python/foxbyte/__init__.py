# SPDX-License-Identifier: Apache-2.0
"""FoxByte Python client — a thin, dependency-free wrapper over the
control-plane REST API (see internal/controlplane/openapi.yaml).

    from foxbyte import FoxByte
    db = FoxByte(api_key="key_...", verify_tls=False)  # local self-signed cert
    db.create_branch("qa")
    print(db.query("qa", "select 1"))
"""
from __future__ import annotations

import contextlib
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request

# The one place this package's version is written. pyproject.toml reads it from
# here, so a release cannot ship a wheel whose metadata disagrees with what the
# package reports about itself.
__version__ = "0.8.0"


# The change feed. See foxbyte/realtime.py — a subscriber has several details
# to get right, and they are handled there rather than left to the caller.
from foxbyte.realtime import (  # noqa: E402,F401
    Change,
    Notice,
    RealtimeError,
    RealtimeUrl,
    Schema,
    Subscription,
    Transaction,
    parse_realtime_url,
    subscribe,
)


class FoxByteError(Exception):
    """An API request failed (non-2xx response)."""


class ActingClient:
    """What ``FoxByte.with_actor`` yields: queries that all act for one user."""

    def __init__(self, db: "FoxByte", token: str) -> None:
        self._db = db
        self._token = token

    def query(self, branch: str, sql: str):
        return self._db.query(branch, sql, act_for=self._token, act_for_required=True)


@contextlib.contextmanager
def with_actor_transaction(conn, token: str, paramstyle: str = "%s"):
    """One transaction on a Postgres connection of your own (through the
    Gateway, logged in with your application's account key), after saying
    which of your users it acts for: ``SELECT bb.act_for(...)`` with the token
    as a parameter. Commits when the block ends, rolls back when it raises.
    Every change made in it is recorded for that user::

        with with_actor_transaction(conn, token) as cur:
            cur.execute("UPDATE orders SET paid = true WHERE id = %s", (7,))

    ``conn`` is a DB-API connection whose driver binds parameters on the
    server (psycopg 3 does; use ``paramstyle="$1"`` for one that numbers
    them). psycopg2 is refused: it writes parameters into the SQL text it
    sends, which would put the token in ``current_query()``, the server's
    logs and ``pg_stat_statements``.
    """
    if not token:
        raise FoxByteError("with_actor_transaction needs a token")
    if type(conn).__module__.split(".")[0] in ("psycopg2", "pgdb", "pg8000"):
        raise FoxByteError(
            f"{type(conn).__module__} sends parameters inside the SQL text, so the token would be "
            "logged with it: use psycopg 3 (server-side binding), or FoxByte.with_actor over the API"
        )
    placeholder = {"%s": "%s", "$1": "$1", "?": "?", ":1": ":1"}.get(paramstyle)
    if placeholder is None:
        raise FoxByteError(f"paramstyle is %s, $1, ? or :1, not {paramstyle!r}")
    # A connection in autocommit mode is given its transaction by hand; one
    # that is not already opens one with its first statement (DB-API), and is
    # ended the driver's way.
    manual = bool(getattr(conn, "autocommit", False))
    cur = conn.cursor()
    try:
        if manual:
            cur.execute("BEGIN")
        cur.execute(f"SELECT bb.act_for({placeholder})", (token,))
        yield cur
        cur.execute("COMMIT") if manual else conn.commit()
    except BaseException:
        try:
            cur.execute("ROLLBACK") if manual else conn.rollback()
        finally:
            raise
    finally:
        try:
            cur.close()
        except Exception:  # noqa: BLE001 - the original outcome matters more
            pass


class FoxByte:
    def __init__(
        self,
        api_key: str,
        base_url: str = "https://localhost:8080",
        verify_tls: bool = True,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self._ctx = ssl.create_default_context()
        if not verify_tls:
            # The engine serves a self-signed cert by default; pass verify_tls=False
            # for a local install, or point base_url at a host with a real cert.
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    def _request(self, method: str, path: str, body: dict | None = None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base_url + path, data=data, method=method)
        req.add_header("Authorization", "Bearer " + self.api_key)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, context=self._ctx) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")
            raise FoxByteError(f"{e.code} {e.reason}: {detail}") from None

    # --- status & branches ---
    def status(self):
        return self._request("GET", "/api/status")

    def branches(self):
        return self._request("GET", "/api/branches")

    def create_branch(self, name: str):
        return self._request("POST", "/api/branches", {"name": name})

    def delete_branch(self, name: str):
        return self._request("DELETE", f"/api/branches/{name}")

    def suspend(self, name: str):
        return self._request("POST", f"/api/branches/{name}/suspend")

    def resume(self, name: str):
        return self._request("POST", f"/api/branches/{name}/resume")

    def query(self, branch: str, sql: str, act_for: str | None = None, act_for_required: bool = False):
        """Run SQL on a branch. Returns {"columns": [...], "rows": [...]} or {"error": ...}.

        ``act_for`` is an application identity token (``fox app``): the query
        then runs in one transaction that first says which of your users it
        acts for, so the Blackbox and row tracking record each change for them.
        The reply's ``act_for`` says whom it ran for, or why the token was not
        taken; ``act_for_required`` refuses the query instead, running nothing.
        """
        body: dict = {"sql": sql}
        if act_for:
            body["act_for"] = act_for
            if act_for_required:
                body["act_for_required"] = True
        return self._request("POST", f"/api/branches/{branch}/query", body)

    @contextlib.contextmanager
    def with_actor(self, token: str):
        """Queries that all act for the user a token names (register your
        application with ``fox app register``, and sign a short-lived token for
        each user with its key). Each query is its own transaction, asserted
        afresh; one the engine does not take is refused, with nothing run, so a
        change is never recorded for nobody by mistake::

            with db.with_actor(token) as acting:
                acting.query("main", "UPDATE orders SET status = 'paid' WHERE id = 7")
        """
        if not token:
            raise FoxByteError("with_actor needs a token")
        yield ActingClient(self, token)

    # --- Blackbox (the record of schema changes; ledger* names still work) ---
    def ledger(self, branch: str = "main", **filters):
        """The branch's DDL history. Filters: actor, table, risk, status, kind, limit, offset."""
        qs = urllib.parse.urlencode({k: v for k, v in filters.items() if v is not None})
        path = f"/api/branches/{branch}/ledger" + (f"?{qs}" if qs else "")
        return self._request("GET", path)

    def verify_ledger(self, branch: str = "main"):
        """Recompute the Blackbox hash chain; the result reports broken rows (0 = intact)."""
        return self._request("GET", f"/api/branches/{branch}/ledger/verify")

    def blackbox(self, branch: str = "main", **filters):
        """Blackbox: the branch's DDL history. Same as ledger()."""
        return self.ledger(branch, **filters)

    def verify_blackbox(self, branch: str = "main"):
        """Recompute the Blackbox hash chain. Same as verify_ledger()."""
        return self.verify_ledger(branch)

    # --- the change feed ---
    def subscribe(self, branch: str, **kw) -> Subscription:
        """Subscribe to a branch's change feed using this client's credentials.

        For a program that already holds an API key. An application that should
        only ever read the feed is better given a realtime key — ``fox realtime
        key create <branch>`` — which cannot reach the control plane and cannot
        run SQL; pass its connection string to ``subscribe()`` directly.
        """
        host = urllib.parse.urlsplit(self.base_url)
        kw.setdefault("verify_tls", self._ctx.verify_mode is not ssl.CERT_NONE)
        return subscribe(
            RealtimeUrl(
                host=host.netloc,
                branch=branch,
                key=self.api_key,
                sslmode="disable" if host.scheme == "http" else "require",
            ),
            **kw,
        )
