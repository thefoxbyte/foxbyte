#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# F4's checks on a throwaway server: what deleting or clearing a person's row
# leaves behind in PostgreSQL's files, its WAL and a ZFS snapshot.
#
# Run as root in the test VM, which has the ZFS pool `dbpool`:
#   sudo bash docs/f4/probe-erasure.sh [postgres:18-bookworm]
# It makes its own dataset (dbpool/f4probe) and container (f4probe), and
# removes both at the end. It reads the files the way someone holding the disk
# would: by grepping them for the person's values.
set -euo pipefail

IMAGE=${1:-postgres:18-bookworm}
DS=dbpool/f4probe
MNT=/dbpool/f4probe
C=f4probe

cleanup() {
  docker rm -f "$C" "$C-b" >/dev/null 2>&1 || true
  if zfs list "$DS" >/dev/null 2>&1; then zfs destroy -r "$DS"; fi
}
trap cleanup EXIT
cleanup

zfs create -o mountpoint="$MNT" "$DS"
zfs create "$DS/main"
chown 999:999 "$MNT/main"
docker run -d --name "$C" -e POSTGRES_PASSWORD=probe -e PGDATA=/data/pg \
  -v "$MNT/main:/data" "$IMAGE" -c full_page_writes=on >/dev/null
for _ in $(seq 60); do docker exec "$C" pg_isready -U postgres -q && break; sleep 1; done
sleep 2

sql() { docker exec -i "$C" psql -U postgres -qAtX -v ON_ERROR_STOP=1 "$@"; }
# How many files under a directory hold a string (grep -rl over raw bytes).
holds() { local n; n=$(grep -rla --exclude='*.pid' -- "$2" "$1" 2>/dev/null | wc -l); echo "$n"; }
relfile() { echo "$MNT/main/pg/$(sql -c "SELECT pg_relation_filepath('$1')")"; }
say() { printf '%-4s %-72s %s\n' "$1" "$2" "$3"; }

DEL=asha.erase.me@example.com      # the row that is deleted
CLR=ravi.clear.me@example.org      # the row whose personal columns are cleared
BIG=meena-toasted-note-marker      # inside a value large enough for TOAST

sql <<SQL
CREATE TABLE people (id int PRIMARY KEY, email text UNIQUE, phone text, note text);
INSERT INTO people SELECT g, 'person' || g || '@example.com', '98' || lpad(g::text, 8, '0'), 'n'
  FROM generate_series(1, 5000) g;
INSERT INTO people VALUES (900001, '$DEL', '9000000001', 'x'),
                          (900002, '$CLR', '9000000002', 'y'),
                          (900003, 'meena@example.net', '9000000003',
                           '$BIG ' || (SELECT string_agg(md5(g::text), '') FROM generate_series(1, 400) g));
CREATE INDEX people_phone ON people (phone);
CHECKPOINT;
SQL
HEAP=$(relfile people); IDX=$(relfile people_email_key); TOAST=$(sql -c "SELECT pg_relation_filepath(reltoastrelid) FROM pg_class WHERE relname = 'people'")
say E1 "before: the deleted row's email in the heap / its unique index" "$(holds "$HEAP" "$DEL") / $(holds "$IDX" "$DEL")"
say E1 "before: the large note in the TOAST table" "$(holds "$MNT/main/pg/$TOAST" "$BIG")"

# A branch, as FoxByte makes one: a snapshot of the parent, cloned.
sql -c CHECKPOINT
zfs snapshot "$DS/main@for-b"
zfs clone "$DS/main@for-b" "$DS/b"

# Erase: one row deleted, one row's personal columns cleared, the large one deleted.
sql <<SQL
DELETE FROM people WHERE id IN (900001, 900003);
UPDATE people SET email = NULL, phone = NULL WHERE id = 900002;
CHECKPOINT;
SQL
say E2 "after DELETE / UPDATE, before VACUUM: heap holds deleted / cleared" "$(holds "$HEAP" "$DEL") / $(holds "$HEAP" "$CLR")"

sql -c "VACUUM people" -c CHECKPOINT
say E3 "after plain VACUUM: heap deleted / cleared" "$(holds "$HEAP" "$DEL") / $(holds "$HEAP" "$CLR")"
say E3 "after plain VACUUM: unique index deleted / cleared; phone index" "$(holds "$IDX" "$DEL") / $(holds "$IDX" "$CLR"); $(holds "$(relfile people_phone)" 9000000001)"
say E3 "after plain VACUUM: TOAST holds the large note" "$(holds "$MNT/main/pg/$TOAST" "$BIG")"

sql -c "VACUUM (INDEX_CLEANUP ON) people" -c CHECKPOINT
say E4 "after VACUUM (INDEX_CLEANUP ON): unique index deleted / cleared; phone index" "$(holds "$IDX" "$DEL") / $(holds "$IDX" "$CLR"); $(holds "$(relfile people_phone)" 9000000001)"
say E4 "after VACUUM (INDEX_CLEANUP ON): heap deleted / cleared" "$(holds "$HEAP" "$DEL") / $(holds "$HEAP" "$CLR")"
# Is what grep finds a tuple PostgreSQL still keeps, or bytes left in a page's
# free space? pageinspect reads the items a page lists, live or dead.
sql <<'SQL'
CREATE EXTENSION IF NOT EXISTS pageinspect;
CREATE FUNCTION heap_items_holding(rel regclass, v text) RETURNS bigint LANGUAGE sql AS $$
  SELECT count(*) FROM generate_series(0, pg_relation_size(rel) / 8192 - 1) b,
    LATERAL heap_page_items(get_raw_page(rel::text, b::int)) i
  WHERE position(convert_to(v, 'UTF8') IN coalesce(i.t_data, ''::bytea)) > 0 $$;
CREATE FUNCTION index_items_holding(rel regclass, v text) RETURNS bigint LANGUAGE sql AS $$
  SELECT count(*) FROM generate_series(1, pg_relation_size(rel) / 8192 - 1) b,
    LATERAL bt_page_items(rel::text, b::int) i
  WHERE position(encode(convert_to(v, 'UTF8'), 'hex') IN replace(i.data, ' ', '')) > 0 $$;
SQL
say E4 "pageinspect: heap items (live or dead) holding deleted / cleared" "$(sql -c "SELECT heap_items_holding('people', '$DEL') || ' / ' || heap_items_holding('people', '$CLR')")"
say E4 "pageinspect: unique-index items holding deleted / cleared" "$(sql -c "SELECT index_items_holding('people_email_key', '$DEL') || ' / ' || index_items_holding('people_email_key', '$CLR')")"
say E5 "live queries see the deleted / cleared values" "$(sql -c "SELECT count(*) FROM people WHERE email IN ('$DEL', '$CLR')")"
say E5 "the statistics (pg_statistic, via pg_stats) hold the deleted email" "$(sql -c "SELECT count(*) FROM pg_stats WHERE tablename = 'people' AND (most_common_vals::text LIKE '%erase.me%' OR histogram_bounds::text LIKE '%erase.me%')")"

say E6 "the WAL directory: files holding the deleted / cleared email" "$(holds "$MNT/main/pg/pg_wal" "$DEL") / $(holds "$MNT/main/pg/pg_wal" "$CLR")"
for _ in 1 2 3; do sql -c "SELECT pg_switch_wal()" -c CHECKPOINT >/dev/null; done
say E6 "after three WAL switches and checkpoints (segments recycled)" "$(holds "$MNT/main/pg/pg_wal" "$DEL") / $(holds "$MNT/main/pg/pg_wal" "$CLR")"

sql -c "VACUUM FULL people" -c CHECKPOINT
HEAP2=$(relfile people); IDX2=$(relfile people_email_key)
say E7 "after VACUUM FULL: new heap / new index hold the deleted email" "$(holds "$HEAP2" "$DEL") / $(holds "$IDX2" "$DEL")"
say E7 "after VACUUM FULL: the old heap file is still there" "$( [ -e "$HEAP" ] && echo yes || echo no)"
say E7 "after VACUUM FULL: the whole data directory holds deleted / cleared (WAL included)" "$(holds "$MNT/main/pg" "$DEL") / $(holds "$MNT/main/pg" "$CLR")"

say E8 "the parent's snapshot (main@for-b) holds deleted / cleared" "$(holds "$MNT/main/.zfs/snapshot/for-b/pg/base" "$DEL") / $(holds "$MNT/main/.zfs/snapshot/for-b/pg/base" "$CLR")"
say E8 "the branch's own files (the clone) hold deleted / cleared" "$(holds "$MNT/b/pg/base" "$DEL") / $(holds "$MNT/b/pg/base" "$CLR")"
zpool sync dbpool; say E8 "space the snapshot keeps alive (usedbysnapshots of main)" "$(zfs get -Hpo value usedbysnapshots "$DS/main") bytes"

# The branch erased too, the same way, while its snapshot remains.
chown -R 999:999 "$MNT/b"
rm -f "$MNT/b/pg/postmaster.pid"
docker run -d --name "$C-b" -e PGDATA=/data/pg -v "$MNT/b:/data" "$IMAGE" >/dev/null
for _ in $(seq 60); do docker exec "$C-b" pg_isready -U postgres -q && break; sleep 1; done
sleep 2
docker exec -i "$C-b" psql -U postgres -qAtX -v ON_ERROR_STOP=1 <<SQL
DELETE FROM people WHERE id IN (900001, 900003);
UPDATE people SET email = NULL, phone = NULL WHERE id = 900002;
VACUUM FULL people;
CHECKPOINT;
SQL
docker rm -f "$C-b" >/dev/null
say E9 "branch erased and rewritten too: the clone holds deleted / cleared (base)" "$(holds "$MNT/b/pg/base" "$DEL") / $(holds "$MNT/b/pg/base" "$CLR")"
say E9 "but the snapshot it came from still holds deleted / cleared" "$(holds "$MNT/main/.zfs/snapshot/for-b/pg/base" "$DEL") / $(holds "$MNT/main/.zfs/snapshot/for-b/pg/base" "$CLR")"
say E9 "can the snapshot be destroyed while the branch exists?" "$(zfs destroy "$DS/main@for-b" 2>&1 | head -1 | cut -c1-60)"

# The branch remade: deleted with its snapshot, then cut again from the erased parent.
zfs destroy "$DS/b"
zfs destroy "$DS/main@for-b"
sql -c CHECKPOINT
zfs snapshot "$DS/main@for-b"
zfs clone "$DS/main@for-b" "$DS/b"
say E10 "branch remade from the erased parent: the new clone holds deleted / cleared (base)" "$(holds "$MNT/b/pg/base" "$DEL") / $(holds "$MNT/b/pg/base" "$CLR")"
zpool sync dbpool; say E10 "usedbysnapshots of main now" "$(zfs get -Hpo value usedbysnapshots "$DS/main") bytes"
say E11 "server: $(sql -c 'SHOW server_version')" ""
