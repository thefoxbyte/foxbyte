#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Keeps the test suites from leaking Docker volumes into the test VM. The
# official postgres and MinIO images declare a VOLUME, so every container made
# from them gets an anonymous volume of its own, and `docker rm -f` without -v
# leaves it behind. On 2 Nov 2026 187 of them (22.5 GB) took the shared VM's
# disk to 100%, which is how the storage pool, a file on that disk, gets
# suspended. -v removes a container's anonymous volumes only: named ones, such
# as the object store's, are never touched. Runs anywhere:
#   bash scripts/test_suite_volumes.sh
set -uo pipefail

scripts="$(cd "$(dirname "$0")" && pwd)"

# A removal may leave its volume only when the line says why: integration §11
# makes one on purpose, for fox check to find, and removes it itself.
bad="$(grep -n 'docker rm -f\( \|$\)' "$scripts"/*.sh "$scripts"/lib/*.sh 2>/dev/null | grep -v 'volleak-old' | grep -v 'test_suite_volumes.sh')"
if [ -n "$bad" ]; then
  echo "FAIL: these remove a container without -v, leaving its anonymous volume in the test VM:"
  echo "$bad"
  echo "Use docker rm -fv."
  exit 1
fi
echo "suite volumes: every container a suite removes takes its anonymous volumes with it"
