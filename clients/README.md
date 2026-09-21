# FoxByte clients & SDKs

Everything in this directory is licensed **Apache-2.0** (see `clients/LICENSE`),
so applications can link and redistribute the client libraries freely. The
server/core of FoxByte is licensed AGPL-3.0-or-later (see the repository-root
`LICENSE`).

## SDKs

- **[python/](python/)** — dependency-free client (`pip install ./clients/python`).
- **[typescript/](typescript/)** — dependency-free client (uses `fetch`).

Both are thin wrappers over the control-plane REST API. The API's source of truth
is the **OpenAPI spec**, served at `GET /api/openapi.yaml` by a running engine and
committed at [`internal/controlplane/openapi.yaml`](../internal/controlplane/openapi.yaml).

## Generating a client for another language

Point any OpenAPI generator at the spec — for example a Go client:

```bash
curl -k https://localhost:8080/api/openapi.yaml -o openapi.yaml
openapi-generator-cli generate -i openapi.yaml -g go -o clients/go
```

## Get a branch in three lines (Python)

```python
from foxbyte import FoxByte
db = FoxByte(api_key="key_…", verify_tls=False)   # local self-signed cert
db.create_branch("qa")
print(db.query("qa", "select 1"))
```
