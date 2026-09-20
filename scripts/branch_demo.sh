#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Phase 2 demo: instant copy-on-write branching + isolation.
# Run inside the Linux dev VM (ZFS + Docker), after `foxbyte branch init`.
set -euo pipefail

S="${FOX_BIN:-/tmp/fox}"

pmain() { sudo docker exec -e PGPASSWORD=foxbyte pg-main \
  psql -U dbadmin -d appdb "$@"; }
pbranch() { local b="$1"; shift; sudo docker exec -e PGPASSWORD=foxbyte "pg-$b" \
  psql -U dbadmin -d appdb "$@"; }

echo ">> main rows before branching:"
pmain -c "SELECT * FROM notes ORDER BY id;"

echo; echo ">> creating branch 'feature' (timed)..."
time "$S" branch create feature

echo; echo ">> feature instantly sees main's data (zero-copy clone):"
pbranch feature -c "SELECT * FROM notes ORDER BY id;"

echo ">> writing a row to feature ONLY:"
pbranch feature -c "INSERT INTO notes(msg) VALUES ('written-on-feature');"

echo; echo ">> feature now has both rows:"
pbranch feature -c "SELECT * FROM notes ORDER BY id;"
echo ">> main is UNCHANGED (branch isolation):"
pmain -c "SELECT * FROM notes ORDER BY id;"

echo; echo ">> branch list (USED = copy-on-write delta; feature should be tiny):"
"$S" branch list

echo; echo ">> cleanup: delete feature"
"$S" branch delete feature
echo ">> done."
