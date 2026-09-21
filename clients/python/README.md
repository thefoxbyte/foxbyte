# FoxByte — Python client

A thin, dependency-free client for the FoxByte control-plane REST API. Apache-2.0.

## Install

```bash
pip install ./clients/python        # from a checkout (until published to PyPI)
```

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

The full API is described by the OpenAPI spec, served at `GET /api/openapi.yaml`
(and at [`internal/controlplane/openapi.yaml`](../../internal/controlplane/openapi.yaml)).
