#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Point-in-time restore into the disposable "restore" container (fox restore).
# Restore runs this inside the stock postgres-walg image with `bash -c`, the way
# BranchBeforeEntry runs restore_before.sh, so the fix reaches installs whose
# image was built before it — nothing new has to be baked into the image.
#
# It fetches the base backup the caller chose (BACKUP_NAME, or LATEST when the
# target is the end of the archive), replays archived WAL to the target, and
# promotes to a normal read/write server so it can be queried on port 5433.
#
# The image's own restore-entrypoint.sh did the same but always fetched LATEST,
# so a target time earlier than the newest base backup could not be reached:
# recovery would start after the point being asked for.
set -euo pipefail

: "${PGDATA:=/var/lib/postgresql/data/pgdata}"
: "${BACKUP_NAME:=LATEST}"
: "${RECOVERY_TARGET_TIME:?set RECOVERY_TARGET_TIME to a timestamp or the literal 'latest'}"

mkdir -p "$PGDATA"
chown -R postgres:postgres "$(dirname "$PGDATA")"

echo ">> fetching base backup $BACKUP_NAME from object storage..."
gosu postgres wal-g backup-fetch "$PGDATA" "$BACKUP_NAME"

# 'latest' = replay ALL archived WAL and promote (no target time). A specific
# timestamp must fall within the archived WAL window (i.e. at or before the last
# archived transaction), otherwise Postgres fatals with "recovery ended before
# target reached".
if [ "$RECOVERY_TARGET_TIME" = "latest" ]; then
	echo ">> configuring recovery to: latest (end of archived WAL)"
	target=""
else
	echo ">> configuring recovery to: $RECOVERY_TARGET_TIME"
	target="recovery_target_time = '$RECOVERY_TARGET_TIME'"
fi
cat >>"$PGDATA/postgresql.auto.conf" <<EOF
restore_command = 'wal-g wal-fetch %f %p'
$target
recovery_target_action = 'promote'
archive_mode = off
EOF
gosu postgres touch "$PGDATA/recovery.signal"
chmod 700 "$PGDATA"

echo ">> starting postgres to perform recovery..."
exec gosu postgres postgres -c listen_addresses='*'
