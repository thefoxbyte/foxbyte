# SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0
#
# The vault service's image (point 13, docs/FOX_P13_Vault_Design.md, section
# 5). Its context is minimal, made by enterprise/vault/image/context.sh (and
# the same way by the engine when it builds the image itself):
#
#   go.mod go.sum enterprise/idcheck/ enterprise/vault/
#
# so the binary carries the vault and the Aadhaar check, and nothing of the
# engine. The release workflow publishes it as ghcr.io/thefoxbyte/fox-vault.
#
# SoftHSM2 is FoxByte's own software token, for trials and tests, labelled as
# not compliant wherever a kind's rules require an HSM. A customer's HSM
# client library is mounted instead and named with --pkcs11-lib.
#
# Both bases are pinned by content, as the database image's are: a tag
# replaced upstream fails the build instead of shipping.
ARG GO_IMAGE=golang:1.26.9-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c
ARG BASE_IMAGE=debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY enterprise/ enterprise/
RUN CGO_ENABLED=1 GOFLAGS=-buildvcs=false GOTOOLCHAIN=local \
    go build -tags enterprise -trimpath -ldflags "-s -w" -o /out/fox-vault ./enterprise/vault/cmd/fox-vault

FROM ${BASE_IMAGE}
# The engine fetches or builds the image again when its revision is older than
# the one it needs (internal/branch/vault.go, VaultImageRevision).
LABEL dev.dbengine.image-revision="1" dev.dbengine.vault="1"
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends softhsm2; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --system --gid 10001 vault; \
    useradd --system --uid 10001 --gid 10001 --home-dir /var/lib/fox-vault --no-create-home vault; \
    mkdir -p /var/lib/fox-vault/tokens /run/fox-vault /etc/fox-vault; \
    chown -R vault:vault /var/lib/fox-vault /run/fox-vault; \
    chmod 700 /var/lib/fox-vault/tokens /run/fox-vault

COPY enterprise/vault/image/softhsm2.conf /etc/fox-vault/softhsm2.conf
COPY --from=build /out/fox-vault /usr/local/bin/fox-vault
ENV SOFTHSM2_CONF=/etc/fox-vault/softhsm2.conf
# The engine runs the service as its own user, so only the engine can open
# the socket; 10001 is for running the image by hand.
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/fox-vault"]
CMD ["serve"]
