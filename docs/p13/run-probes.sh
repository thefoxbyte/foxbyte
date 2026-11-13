#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Runs the vault design's probes (docs/FOX_P13_Vault_Design.md, section 3) in a
# throwaway Debian container with SoftHSM2. Nothing touches an install.
# Usage, in the test VM, from the repository: sh docs/p13/run-probes.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
docker run --rm -v "$here:/p13:ro" debian:bookworm-slim sh -c '
  set -e
  apt-get update -qq >/dev/null
  apt-get install -y -qq softhsm2 python3-pykcs11 >/dev/null 2>&1
  dpkg -s softhsm2 | grep ^Version
  softhsm2-util --init-token --free --label vault --pin 1234 --so-pin 5678 >/dev/null
  python3 /p13/probe-token.py
  softhsm2-util --delete-token --token vault >/dev/null
  softhsm2-util --init-token --free --label vault --pin 1234 --so-pin 5678 >/dev/null
  python3 /p13/probe-attributes.py make
  echo "--- a new process, the token read from disk"
  python3 /p13/probe-attributes.py read'
