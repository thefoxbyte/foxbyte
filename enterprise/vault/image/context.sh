#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0
#
# Makes the vault image's build context in OUT from the repository at REPO:
# only what the service is built from, so neither the engine's source nor a
# developer's node_modules is sent to the builder.
#
#   enterprise/vault/image/context.sh REPO OUT
#   docker build -f OUT/enterprise/vault/image/Dockerfile OUT
set -euo pipefail
repo="${1:?the repository}"
out="${2:?the directory to make the context in}"
mkdir -p "$out/enterprise"
cp "$repo/go.mod" "$repo/go.sum" "$out/"
cp -R "$repo/enterprise/idcheck" "$repo/enterprise/vault" "$out/enterprise/"
find "$out/enterprise" -name '*_test.go' -delete
