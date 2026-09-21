#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Narrated feature tour of FoxByte. Run inside the Linux dev VM:
#   lima bash "/Users/.../Distributed Database/scripts/demo.sh"
set -uo pipefail

S="${FOX_BIN:-/tmp/fox}"
GATEWAY="postgres://dbadmin@127.0.0.1:6432" # auth via an API key in PGPASSWORD
say() { echo; echo "──▶ $*"; echo; }
sql() { psql "$GATEWAY/$1" -c "$2"; }
pg()  { sudo docker exec -e PGPASSWORD=foxbyte "$1" psql -U dbadmin -d appdb "${@:2}"; }

say "Bringing FoxByte up (stack + gateway + control API + agent API)"
$S start >/dev/null 2>&1; sleep 4
$S status 2>&1 | sed -n '1,12p'

# The Gateway requires an API key as the password — mint one and use it for psql.
printf 'demo\n' | $S user create demo@foxbyte.dev >/dev/null 2>&1 || true
export PGPASSWORD="$($S apikey create demo@foxbyte.dev demo 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"

say "Create an instant copy-on-write branch 'demo' (note the time)"
$S branch delete demo >/dev/null 2>&1
time $S branch create demo

say "CRUD on the branch, through the single gateway endpoint (dbname=demo)"
sql demo "CREATE TABLE notes(id serial PRIMARY KEY, body text);"
sql demo "INSERT INTO notes(body) VALUES ('hello'),('world') RETURNING *;"
sql demo "UPDATE notes SET body='edited' WHERE id=1;"
sql demo "SELECT * FROM notes ORDER BY id;"

say "Isolation — 'main' does NOT have that table"
pg pg-main -c "SELECT to_regclass('public.notes') AS notes_on_main;"

say "Copy-on-write: the branch stores only its delta (USED column)"
$S branch list

say "A database per AI agent, over HTTP"
curl -s -X POST localhost:8088/agents/alice/branch; echo

say "High availability — provision a streaming standby"
pg pg-main -c "CREATE TABLE IF NOT EXISTS ledger(n int);"
$S ha enable >/dev/null 2>&1; sleep 2
pg pg-main -x -c "SELECT application_name, state, sync_state FROM pg_stat_replication;"

say "Fail over — the SAME endpoint keeps working (write lands on the promoted standby)"
$S ha failover >/dev/null 2>&1; sleep 3
sql main "INSERT INTO ledger VALUES (1) RETURNING 'write ok after failover' AS result;"

say "Cleanup"
curl -s -X DELETE localhost:8088/agents/alice/branch >/dev/null
$S ha disable >/dev/null 2>&1; $S up >/dev/null 2>&1
$S branch delete demo >/dev/null 2>&1
echo
echo "Done.  Control API: http://localhost:8080/api/status   ·   Web UI: make web-dev (http://localhost:5173)"
