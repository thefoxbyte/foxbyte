# syntax=docker/dockerfile:1
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Stock PostgreSQL + wal-g (object-storage WAL archival, base backups, PITR).
# wal-g is installed as a pinned prebuilt release binary matching the build arch,
# so this image builds natively on both amd64 and Apple Silicon (arm64).
#
# One Dockerfile serves every PostgreSQL major the engine supports: PG_MAJOR
# picks the base, and the release workflow publishes one image per major
# (postgres-walg:16, postgres-walg:18), because an install keeps running the
# major its data was created with. The default is the major a fresh install
# gets -- internal/branch/images.go's PGMajor, which a test keeps this in step
# with.
#
# The ubuntu-20.04 build is used deliberately: it links against an older glibc
# and therefore runs on the Debian bookworm base (glibc is forward-compatible).
# Bookworm is kept for every major for that reason, although 18 defaults to
# trixie.

#
# Both inputs are pinned by content (audit v2 G23): the base image by digest
# (PG_DIGEST, per major — internal/branch/images.go PostgresBaseDigests), and
# wal-g by the SHA-256 wal-g publishes for each asset, checked before it is
# unpacked. A tag or a release asset replaced upstream fails the build instead
# of shipping.

ARG PG_MAJOR=18
ARG PG_DIGEST=sha256:3725f4e2499eef5134592b3b4ab79a543ed7f8e533b05b5b637af926630f6650

# ── bb_identity: application identity (F1) ──────────────────────────────────
# Ed25519 verification, the transaction's identity and the MAC that F1's
# application identity tokens rest on (docs/FOX_F1_Identity_Design.md, sections
# 6 and 14). Built against the server headers of the image's own major, from
# the PGDG apt repository the official image already trusts, and linked to the
# OpenSSL that image already carries; only the .so, the control file and the
# SQL file reach the final image, never the compiler.
FROM postgres:${PG_MAJOR}-bookworm@${PG_DIGEST} AS f1-build
ARG PG_MAJOR
COPY bb_identity/ /src/bb_identity/
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends build-essential "postgresql-server-dev-${PG_MAJOR}" libssl-dev; \
    rm -rf /var/lib/apt/lists/*; \
    mkdir -p /out; \
    make -C /src/bb_identity; \
    make -C /src/bb_identity install DESTDIR=/out; \
    test -f "/out/usr/lib/postgresql/${PG_MAJOR}/lib/bb_identity.so"

FROM postgres:${PG_MAJOR}-bookworm@${PG_DIGEST}

# PG_MAJOR was consumed by FROM; re-declared so the layers below can use it.
ARG PG_MAJOR
ARG WALG_VERSION=v3.0.9
ARG WALG_SHA256_AMD64=51ec330530f98fc3eb4f008fa539d291a2cac51e7076b256472862e45ceff0bd
ARG WALG_SHA256_ARM64=891ba47b17fa8b58587f06668d4de4db9469e1034e23e32fa545dd4a6bb40f8e
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    arch="$(dpkg --print-architecture)"; \
    case "${arch}" in \
      amd64) WG_ARCH=amd64; WG_SHA256="${WALG_SHA256_AMD64}" ;; \
      arm64) WG_ARCH=aarch64; WG_SHA256="${WALG_SHA256_ARM64}" ;; \
      *) echo "unsupported arch: ${arch}" >&2; exit 1 ;; \
    esac; \
    asset="wal-g-pg-20.04-${WG_ARCH}.tar.gz"; \
    url="https://github.com/wal-g/wal-g/releases/download/${WALG_VERSION}/${asset}"; \
    echo "downloading ${url}"; \
    curl -fsSL "${url}" -o /tmp/wal-g.tar.gz; \
    echo "${WG_SHA256}  /tmp/wal-g.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/wal-g.tar.gz -C /usr/local/bin; \
    mv "/usr/local/bin/wal-g-pg-20.04-${WG_ARCH}" /usr/local/bin/wal-g; \
    chmod +x /usr/local/bin/wal-g; \
    rm -f /tmp/wal-g.tar.gz; \
    /usr/local/bin/wal-g --version

# pgvector, from the PGDG apt repository the official image already trusts (audit
# v2 G34). The product is aimed at agent workloads, and an agent that needs
# embeddings should not have to leave the database it was given to store them.
# Nothing is enabled by it: `CREATE EXTENSION vector` is the user's to run, per
# database, and an install that never asks pays only the image size.
#
# Version-pinned like everything else here, so a rebuilt image is the same image;
# apt verifies the package's signature against the repository's key.
ARG PGVECTOR_VERSION=0.8.6-1.pgdg12+2
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends "postgresql-${PG_MAJOR}-pgvector=${PGVECTOR_VERSION}"; \
    rm -rf /var/lib/apt/lists/*; \
    ls /usr/share/postgresql/"${PG_MAJOR}"/extension/vector.control

COPY --from=f1-build /out/ /

# What this image has, as a number the engine reads without starting a
# container (internal/branch/images.go, PGImageRevision). An install keeps the
# image it first fetched, so a fox that needs something newer has to be able to
# tell: 2 is the first with bb_identity. Raise it with anything a fox comes to
# depend on, and raise PGImageRevision with it.
LABEL dev.dbengine.image-revision="2"

# Disposable point-in-time restore entrypoint (used by scripts/pitr_restore.sh).
COPY restore-entrypoint.sh /usr/local/bin/restore-entrypoint.sh
RUN chmod +x /usr/local/bin/restore-entrypoint.sh
