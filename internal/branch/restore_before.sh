#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Branch-before-entry restore (Blackbox 2.0). BranchBeforeEntry runs this
# inside the stock postgres-walg image with `bash -c`, so the published image
# needs no new file. It fetches the named base backup into the new branch's
# empty data directory, replays archived WAL, stops just BEFORE the target
# transaction (or time) commits, and promotes to a normal read/write server.
#
# The existing restore-entrypoint.sh (fox restore) is separate and unchanged.
set -euo pipefail

: "${PGDATA:=/var/lib/postgresql/data/pgdata}"
: "${BACKUP_NAME:?set BACKUP_NAME to a wal-g base backup name}"
: "${RECOVERY_TARGET_KIND:?set RECOVERY_TARGET_KIND to xid or time}"
: "${RECOVERY_TARGET:?set RECOVERY_TARGET}"

case "$RECOVERY_TARGET_KIND" in
  xid)  target="recovery_target_xid = '$RECOVERY_TARGET'" ;;
  time) target="recovery_target_time = '$RECOVERY_TARGET'" ;;
  *)    echo "unknown RECOVERY_TARGET_KIND: $RECOVERY_TARGET_KIND" >&2; exit 2 ;;
esac

mkdir -p "$PGDATA"
chown -R postgres:postgres "$(dirname "$PGDATA")"

echo ">> fetching base backup $BACKUP_NAME from object storage..."
gosu postgres wal-g backup-fetch "$PGDATA" "$BACKUP_NAME"

echo ">> recovering to just before: $RECOVERY_TARGET_KIND $RECOVERY_TARGET"
cat >> "$PGDATA/postgresql.auto.conf" <<EOF
restore_command = 'wal-g wal-fetch %f %p'
$target
recovery_target_inclusive = off
recovery_target_action = 'promote'
archive_mode = off
EOF
gosu postgres touch "$PGDATA/recovery.signal"
chmod 700 "$PGDATA"

echo ">> starting postgres to perform recovery..."
exec gosu postgres postgres -c listen_addresses='*'
