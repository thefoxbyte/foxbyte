# FoxByte Enterprise

Everything in this directory is the paid edition. It is **source-available, not
open source**: see [LICENSE](LICENSE). The rest of the repository is unaffected —
the core engine stays AGPL-3.0-or-later and the SDKs stay Apache-2.0.

## The rules this directory lives by

1. **Every file carries `LicenseRef-FoxByte-Enterprise-1.0`**, never the AGPL
   header. A test enforces this in both directions: nothing here may carry the
   AGPL header, and nothing outside may carry this one.

2. **Everything is behind `//go:build enterprise`**, except one untagged file per
   package so `go build ./...` and `go vet ./...` stay green without the tag —
   the same reason `web/embed_stub.go` exists. A Standard binary therefore
   contains none of this code, which is what keeps it purely AGPL and freely
   redistributable. A test checks the built binary, not just the source.

3. **The core never imports this directory.** The only files that may are the
   `_on.go` halves of build-tag pairs inside core packages. The core seam is
   `internal/edition`.

4. **Nothing here is ever published under the AGPL.** Once a version ships under
   that licence it is free forever, and moving the code afterwards does not take
   it back. Anything meant to be paid is born here.

## Before the first sale

`LICENSE` is a conservative source-available licence, not legal advice. Have a
lawyer review it — and decide whether you would rather use the Business Source
License 1.1, which is more widely recognised and converts to an open licence on a
date you choose.
