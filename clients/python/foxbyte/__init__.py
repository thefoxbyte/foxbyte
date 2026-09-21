# SPDX-License-Identifier: Apache-2.0
"""FoxByte Python client — a thin, dependency-free wrapper over the
control-plane REST API (see internal/controlplane/openapi.yaml).

    from foxbyte import FoxByte
    db = FoxByte(api_key="key_...", verify_tls=False)  # local self-signed cert
    db.create_branch("qa")
    print(db.query("qa", "select 1"))
"""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request

__version__ = "0.6.0"


class FoxByteError(Exception):
    """An API request failed (non-2xx response)."""


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

    def query(self, branch: str, sql: str):
        """Run SQL on a branch. Returns {"columns": [...], "rows": [...]} or {"error": ...}."""
        return self._request("POST", f"/api/branches/{branch}/query", {"sql": sql})

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
