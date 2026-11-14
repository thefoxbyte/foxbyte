#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The vault's prototype suite (point 13), Gate 0's exit
# (docs/FOX_P13_Vault_Design.md, section 18): the vault service talking
# PKCS#11 to a SoftHSM2 token, its own database on an internal network, the
# engine's side played by the service's own client commands over the Unix
# socket. It checks what the design claims and measures the five things
# section 18 lists: calls a second (also with a simulated 1 ms HSM), migrating
# 1,000,000 rows, rotating 1,000,000 records while the vault answers, the
# network, and uses per data key.
#
# Self-contained, and touches no install: it builds the service in a Go
# container, runs throwaway containers and networks of its own, and removes
# all of it at the end. The shared stack in the test VM is never stopped,
# started or written to.
#
#   make integration-p13
set -uo pipefail

. "$(cd "$(dirname "$0")" && pwd)/lib/test_guard.sh" || exit 2

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
IMG=fox-p13-vault:proto
# The engine image's own base, pinned as internal/branch/images.go pins it.
PG=postgres:18-bookworm@sha256:3725f4e2499eef5134592b3b4ab79a543ed7f8e533b05b5b637af926630f6650
NET_V=fox-p13-vault
NET_B=fox-p13-branches
VAULT_DB=fox-p13-vaultdb
SVC=fox-p13-svc
APP=fox-p13-appdb
VAULT_DB_IP=10.213.13.5
SVC_IP=10.213.13.10
APP_IP=10.213.14.5
PASS=0
FAIL=0

ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
assert_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }
assert_contains() { case "$2" in *"$3"*) ok "$1";; *) bad "$1 (got '$2', want something containing '$3')";; esac; }
assert_not_contains() { case "$2" in *"$3"*) bad "$1 (got '$2', which contains '$3')";; *) ok "$1";; esac; }
note() { echo "  NOTE: $1"; }
d() { sudo docker "$@"; }

cleanup() {
  for c in "$SVC" "$VAULT_DB" "$APP" fox-p13-intruder fox-p13-readers; do d rm -fv "$c" >/dev/null 2>&1; done
  d network rm "$NET_V" "$NET_B" >/dev/null 2>&1
  d rmi -f "$IMG" >/dev/null 2>&1
  sudo rm -rf "$WORK"
}
trap cleanup EXIT
cleanup_before() { for c in "$SVC" "$VAULT_DB" "$APP" fox-p13-intruder fox-p13-readers; do d rm -fv "$c" >/dev/null 2>&1; done; d network rm "$NET_V" "$NET_B" >/dev/null 2>&1; }
cleanup_before

# ---------------------------------------------------------------------------
echo "### 0. Build: the image, the service built with cgo inside it, from a minimal context"
# The image's own Dockerfile builds the service in a Go image of the same
# Debian release, from only go.mod, go.sum and the vault's packages
# (enterprise/vault/image/context.sh), as the engine and the release do.
mkdir -p "$WORK/ctx"
bash "$REPO/enterprise/vault/image/context.sh" "$REPO" "$WORK/ctx"
assert_eq "the context holds the vault and the Aadhaar check, and nothing of the engine" \
  "$(cd "$WORK/ctx" && find . -type d -name internal | wc -l | tr -d ' ')|$(ls "$WORK/ctx/enterprise" | tr '\n' ' ')" "0|idcheck vault "
if d build -q -t "$IMG" -f "$WORK/ctx/enterprise/vault/image/Dockerfile" "$WORK/ctx" >"$WORK/image.log" 2>&1; then
  ok "the vault image builds, and the service in it with cgo and the enterprise tag"
else
  bad "the vault image: $(tail -8 "$WORK/image.log")"
  echo "==== $PASS passed, $FAIL failed ===="; exit 1
fi
assert_eq "the binary links only the C library and libdl, no PKCS#11 library: that is loaded at run time" \
  "$(d run --rm --entrypoint sh "$IMG" -c 'ldd /usr/local/bin/fox-vault | grep -c -i -E "softhsm|pkcs"')" "0"

# ---------------------------------------------------------------------------
echo "### 1. The vault: its database on an internal network, the token, the service"
d network create --internal --subnet 10.213.13.0/24 "$NET_V" >/dev/null
d network create --subnet 10.213.14.0/24 "$NET_B" >/dev/null
rnd() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
SECRET="$(rnd 32)"; PIN="$(rnd 8)"; SOPIN="$(rnd 8)"; VPW="$(rnd 16)"; SUPW="$(rnd 16)"; APW="$(rnd 16)"

mkdir -p "$WORK/secret" "$WORK/wrong" "$WORK/tokens" "$WORK/sock" "$WORK/vaultdb"
printf '%s\n' "$SECRET" >"$WORK/secret/secret"
printf '%s\n' "$PIN" >"$WORK/secret/pin"
printf 'postgres://vault_svc:%s@%s:5432/vault?sslmode=disable\n' "$VPW" "$VAULT_DB_IP" >"$WORK/secret/dsn"
printf '%s\n' "$(rnd 32)" >"$WORK/wrong/secret"
sudo chown -R 10001:10001 "$WORK/secret" "$WORK/wrong" "$WORK/tokens" "$WORK/sock"
sudo chmod 700 "$WORK/secret" "$WORK/wrong" "$WORK/tokens" "$WORK/sock"
# Expanded by root: the directories are the service's own, mode 700.
sudo sh -c 'chmod 400 "$1"/secret/* "$1"/wrong/*' _ "$WORK"

# Only the service's address may log in, and only as the service's role; the
# superuser only from inside the container.
cat >"$WORK/vaultdb/pg_hba.conf" <<EOF
local all all trust
host vault vault_svc $SVC_IP/32 scram-sha-256
host all all all reject
EOF
cat >"$WORK/vaultdb/init.sql" <<EOF
CREATE ROLE vault_svc LOGIN PASSWORD '$VPW';
CREATE DATABASE vault OWNER vault_svc;
EOF
chmod 644 "$WORK/vaultdb/"*
d run -d --name "$VAULT_DB" --network "$NET_V" --ip "$VAULT_DB_IP" -e POSTGRES_PASSWORD="$SUPW" \
  -v "$WORK/vaultdb/pg_hba.conf:/etc/fox-vault-db/pg_hba.conf:ro" -v "$WORK/vaultdb/init.sql:/docker-entrypoint-initdb.d/init.sql:ro" \
  "$PG" -c hba_file=/etc/fox-vault-db/pg_hba.conf -c listen_addresses='*' >/dev/null
for i in $(seq 1 60); do
  d exec "$VAULT_DB" psql -X -tA -U postgres -d vault -c 'SELECT 1' >/dev/null 2>&1 && d exec "$VAULT_DB" pg_isready -q -h 127.0.0.1 2>/dev/null && break
  sleep 1
done
vsql() { d exec "$VAULT_DB" psql -X -tA -U postgres -d vault -c "$1"; }

d run --rm -u 10001:10001 -v "$WORK/tokens:/var/lib/fox-vault/tokens" --entrypoint softhsm2-util "$IMG" \
  --init-token --free --label fox-vault --pin "$PIN" --so-pin "$SOPIN" >/dev/null && ok "the software token is made" || bad "the software token"

start_svc() {
  d rm -f "$SVC" >/dev/null 2>&1
  d run -d --name "$SVC" --network "$NET_V" --ip "$SVC_IP" -v "$WORK/tokens:/var/lib/fox-vault/tokens" \
    -v "$WORK/secret:/etc/fox-vault/secret:ro" -v "$WORK/sock:/run/fox-vault" "$IMG" serve "$@" >/dev/null
  for i in $(seq 1 60); do sudo test -S "$WORK/sock/vault.sock" && d logs "$SVC" 2>&1 | grep -q 'serving on' && return 0; sleep 1; done
  echo "the service did not start:"; d logs "$SVC" 2>&1 | tail -5; return 1
}
stop_svc() { d stop -t 10 "$SVC" >/dev/null 2>&1; sudo rm -f "$WORK/sock/vault.sock"; }
start_svc && ok "the service starts and serves on its socket" || { bad "the service did not start"; exit 1; }

# The engine's side: the service's own client, over the socket, with the
# secret. --network none: the socket needs no network.
eng() { d run --rm -u 10001:10001 --network "${NETWORK:-none}" -v "$WORK/sock:/run/fox-vault" -v "$WORK/${SECRETS:-secret}:/etc/fox-vault/secret:ro" "$IMG" "$@"; }
# Flags before values: Go's flag parsing stops at the first value.
callj() { local c="$1"; shift; eng call "$c" --actor suite "$@" 2>&1; }
status() { eng status --actor suite 2>/dev/null; }

# ---------------------------------------------------------------------------
echo "### 2. The token and the keys"
ST="$(status)"
assert_eq "the token is the software one, and says so" "$(jq -r '.token.software' <<<"$ST")|$(jq -r '.token.maker' <<<"$ST")" "true|SoftHSM project"
assert_eq "two kinds: aadhaar and text" "$(jq -r '[.kinds[].name]|join(",")' <<<"$ST")" "aadhaar,text"
assert_eq "Aadhaar on a software token is not compliant, and says why" \
  "$(jq -r '.kinds[]|select(.name=="aadhaar")|.compliant' <<<"$ST")" "no: software token (trials and testing only)"
assert_eq "text claims no rules" "$(jq -r '.kinds[]|select(.name=="text")|.compliant' <<<"$ST")" "no rules mapped"
assert_eq "each kind has its own data and index key" "$(jq -r '[.kinds[].keys[].label]|join(",")' <<<"$ST")" \
  "vault-aadhaar-data-1,vault-aadhaar-index-1,vault-text-data-1,vault-text-index-1"
assert_eq "every key, read back from the token: sensitive, not extractable, always sensitive, never extractable, made inside" \
  "$(jq -r '[.kinds[].keys[]|[.sensitive,.extractable,.always_sensitive,.never_extractable,.local]|map(tostring)|join(" ")]|unique|join(";")' <<<"$ST")" \
  "true false true true true"
assert_eq "the vault database knows the keys only by their labels" "$(vsql "SELECT count(*) FROM information_schema.columns WHERE table_schema='vault' AND table_name='keys' AND data_type='bytea'")" "0"

# ---------------------------------------------------------------------------
echo "### 3. Tokenise, find, detokenise"
N1="$(eng gen --n 3 | sed -n 1p)"; N2="$(eng gen --n 3 | sed -n 2p)"
R="$(callj tokenise --kind aadhaar "$N1")"
REF1="$(jq -r '.refs[0]' <<<"$R")"
case "$REF1" in AR??????????????????????????) ok "a new number gets an opaque Aadhaar reference key (AR and 26 characters)";; *) bad "reference key '$REF1'";; esac
assert_eq "…and it is new" "$(jq -r '.new[0]' <<<"$R")" "true"
R="$(callj tokenise --kind aadhaar "${N1:0:4} ${N1:4:4} ${N1:8:4}")"
assert_eq "the same number, typed with spaces, gets the same reference key, not a new one" "$(jq -r '.refs[0]+" "+(.new[0]|tostring)' <<<"$R")" "$REF1 false"
assert_eq "find gives it too" "$(callj find --kind aadhaar "$N1" | jq -r '.refs[0]')" "$REF1"
assert_eq "find of a number not there: not found, and nothing made" "$(callj find --kind aadhaar "$N2" | jq -r '.results[0]')" "not found"
assert_eq "detokenise without a purpose is refused" "$(callj detokenise --kind aadhaar "$REF1" | jq -r '.code')" "400"
R="$(callj detokenise --kind aadhaar --purpose "suite: KYC re-check" "$REF1")"
assert_eq "detokenise with a purpose gives the number back" "$(jq -r '.values[0]' <<<"$R")" "$N1"
assert_eq "an Aadhaar reference key does not open as text" "$(callj detokenise --kind text --purpose suite "$REF1" | jq -r '.results[0]')" "not found"
BADN="${N1:0:11}$(( (${N1:11:1} + 1) % 10 ))"
R="$(callj tokenise --kind aadhaar "$BADN" 123412341234)"
assert_eq "numbers failing the Aadhaar check are refused, and nothing is made" "$(jq -r '.results|join(",")' <<<"$R")|$(vsql "SELECT count(*) FROM vault.records")" "refused,refused|1"
R="$(callj tokenise --kind aadhaar --format legacy "$N2")"
LREF="$(jq -r '.refs[0]' <<<"$R")"
case "$LREF" in 1[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ok "the legacy format: 12 digits starting with 1 ($LREF)";; *) bad "legacy reference key '$LREF'";; esac
assert_eq "…which the Aadhaar check refuses, so it is never taken for a number" "$(callj tokenise --kind aadhaar "$LREF" | jq -r '.results[0]')" "refused"
assert_eq "the text kind has no legacy format" "$(callj tokenise --kind text --format legacy "anything" | jq -r '.code')" "400"
R="$(callj tokenise --kind text "$N1")"
TREF="$(jq -r '.refs[0]' <<<"$R")"
case "$TREF" in TX*) ok "the same digits as text get a text reference key ($TREF), not the Aadhaar one";; *) bad "text reference key '$TREF'";; esac
assert_eq "…indexed under the text kind's own key, so the two never match" "$(vsql "SELECT count(DISTINCT idx) FROM vault.records WHERE ref IN ('$REF1', '$TREF')")" "2"
TV="Asha Rao, 12 MG Road, Bengaluru"
TREF2="$(callj tokenise --kind text "$TV" | jq -r '.refs[0]')"
assert_eq "any text round-trips" "$(callj detokenise --kind text --purpose suite "$TREF2" | jq -r '.values[0]')" "$TV"

echo "### 4. What the vault database holds"
assert_eq "the vault database holds no number: not in a dump" "$(d exec "$VAULT_DB" pg_dump -U postgres vault | grep -c -E "$N1|$N2")" "0"
# The server says where its data is (PostgreSQL 18's image moved it), and the
# check fails rather than passes when it finds no WAL to read.
PGDATA_DIR="$(vsql 'SHOW data_directory')"
WAL_BYTES="$(d exec "$VAULT_DB" sh -c "cat '$PGDATA_DIR'/pg_wal/0* | wc -c")"
assert_eq "…nor in its WAL ($WAL_BYTES bytes read)" "$([ "${WAL_BYTES:-0}" -gt 0 ] && d exec "$VAULT_DB" sh -c "cat '$PGDATA_DIR'/pg_wal/0* | grep -a -c -E '$N1|$N2|Asha Rao'")" "0"
assert_eq "the access log holds reference keys, never a value" "$(vsql "SELECT count(*) FROM vault.access_log WHERE array_to_string(refs, ' ') || purpose || result ~ '$N1|$N2|Asha'")" "0"
assert_eq "…and the detokenise is in it, with its purpose" "$(vsql "SELECT actor || '|' || purpose || '|' || result FROM vault.access_log WHERE action = 'detokenise' AND purpose <> '' ORDER BY seq LIMIT 1")" "suite|suite: KYC re-check|done 1"
assert_eq "the refused detokenise is in it too" "$(vsql "SELECT count(*) FROM vault.access_log WHERE action = 'detokenise' AND result = 'refused: no purpose'")" "1"
# A ciphertext moved onto another record does not open there.
OTHER="$(callj tokenise --kind aadhaar "$(eng gen --n 1)" | jq -r '.refs[0]')"
vsql "UPDATE vault.records SET (nonce, ct) = (SELECT nonce, ct FROM vault.records WHERE ref = '$REF1') WHERE ref = '$OTHER'" >/dev/null
assert_eq "a ciphertext copied to another record does not verify there" "$(callj detokenise --kind aadhaar --purpose suite "$OTHER" | jq -r '.results[0]')" "did not verify"
vsql "UPDATE vault.records SET ct = set_byte(ct, 0, get_byte(ct, 0) # 1) WHERE ref = '$REF1'" >/dev/null
assert_eq "a ciphertext with one bit changed does not verify" "$(callj detokenise --kind aadhaar --purpose suite "$REF1" | jq -r '.results[0]')" "did not verify"
vsql "UPDATE vault.records SET ct = set_byte(ct, 0, get_byte(ct, 0) # 1) WHERE ref = '$REF1'" >/dev/null
assert_eq "…and opens again once put back" "$(callj detokenise --kind aadhaar --purpose suite "$REF1" | jq -r '.values[0]')" "$N1"
assert_eq "both are logged as records that did not verify" "$(vsql "SELECT count(*) FROM vault.access_log WHERE result = 'did not verify 1'")" "2"
callj delete --kind aadhaar "$OTHER" >/dev/null

# ---------------------------------------------------------------------------
echo "### 5. The network (section 18, item 4)"
SOCK_MODE="$(sudo stat -c '%a %u' "$WORK/sock/vault.sock")"
assert_eq "the secret, the PIN and the database's password are mode 400, the service's own" \
  "$(sudo sh -c 'stat -c "%a %u" "$1"/secret/*' _ "$WORK" | sort -u)" "400 10001"
assert_eq "the socket is the service's own, mode 600, in a directory of mode 700" "$SOCK_MODE $(sudo stat -c '%a' "$WORK/sock")" "600 10001 700"
# Docker's own DNS listens on 127.0.0.11 in every container on a network of
# its own making; that one is Docker's, not the service's.
assert_eq "the service listens on no TCP port at all (Docker's DNS on 127.0.0.11 aside)" \
  "$(d exec "$SVC" sh -c "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk '\$4 == \"0A\" && \$2 !~ /^0B00007F:/' | wc -l")" "0"
R="$(SECRETS=wrong eng status --actor intruder 2>&1)"
assert_contains "a caller without the secret is refused" "$R" "401"
assert_eq "…and logged" "$(vsql "SELECT count(*) FROM vault.access_log WHERE actor = 'intruder' AND result = 'refused: not the engine'")" "1"
d run -d --name "$APP" --network "$NET_B" --ip "$APP_IP" -e POSTGRES_PASSWORD="$APW" -e POSTGRES_DB=app "$PG" >/dev/null
for i in $(seq 1 60); do d exec "$APP" pg_isready -q -h 127.0.0.1 2>/dev/null && d exec "$APP" psql -X -tA -U postgres -d app -c 'SELECT 1' >/dev/null 2>&1 && break; sleep 1; done
tcp_from() { d exec "$1" bash -c "timeout 3 bash -c '</dev/tcp/$2/$3' >/dev/null 2>&1 && echo open || echo closed"; }
assert_eq "a branch's database cannot reach the vault database" "$(tcp_from "$APP" "$VAULT_DB_IP" 5432)" "closed"
assert_eq "the vault database has no route out" "$(tcp_from "$VAULT_DB" 1.1.1.1 53)" "closed"
assert_eq "…nor has the service" "$(d exec "$SVC" bash -c "timeout 3 bash -c '</dev/tcp/1.1.1.1/53' >/dev/null 2>&1 && echo open || echo closed")" "closed"
HOSTREACH="$(timeout 3 bash -c "</dev/tcp/$VAULT_DB_IP/5432" >/dev/null 2>&1 && echo open || echo closed)"
note "from the VM's own host, the vault database's port is $HOSTREACH (an internal network still has a bridge on the host)"
R="$(d run --rm --network host -e PGPASSWORD="$VPW" -e PGCONNECT_TIMEOUT=3 "$PG" psql -X -h "$VAULT_DB_IP" -U vault_svc -d vault -tAc 'SELECT 1' 2>&1)"
if [ "$HOSTREACH" = open ]; then
  assert_contains "…but even with the service's password, the host is refused: only the service's address may log in" "$R" "pg_hba.conf"
else
  ok "…so the host cannot log in either"
fi
R="$(d run --rm --name fox-p13-intruder --network "$NET_V" --ip 10.213.13.66 -e PGPASSWORD="$VPW" -e PGCONNECT_TIMEOUT=3 "$PG" psql -X -h "$VAULT_DB_IP" -U vault_svc -d vault -tAc 'SELECT 1' 2>&1)"
assert_contains "a container put on the vault network, with the service's password, is refused: the address is pinned" "$R" "pg_hba.conf"

# ---------------------------------------------------------------------------
echo "### 6. Calls a second (section 18, item 1)"
bench() { eng bench --actor suite "$@" 2>&1 | grep '^BENCH'; }
for op in tokenise find detokenise; do
  L="$(bench --op "$op" --n 5000 --c 8)"
  note "SoftHSM2: $L"
  assert_contains "$op: 5,000 calls, none failed" "$L" "errors=0"
done
stop_svc
start_svc --hsm-delay 1ms || { bad "the service did not restart with the delay"; exit 1; }
for op in tokenise find detokenise; do
  L="$(bench --op "$op" --n 2000 --c 8)"
  note "1 ms HSM: $L"
  assert_contains "$op with a 1 ms HSM: 2,000 calls, none failed" "$L" "errors=0"
done

# ---------------------------------------------------------------------------
echo "### 7. Migrating 1,000,000 rows, 200,000 distinct numbers (section 18, item 2)"
asql() { d exec -i "$APP" psql -X -tA -U postgres -d app "$@"; }
load_table() { # table, numbers file
  asql -c "CREATE TABLE $1 (id bigint PRIMARY KEY, name text NOT NULL, aadhaar text); CREATE TABLE ${1}_nums (i serial, n text)" >/dev/null
  asql -c "\\copy ${1}_nums (n) FROM pstdin" <"$2" >/dev/null
  local nn; nn="$(asql -c "SELECT count(*) FROM ${1}_nums")"
  asql -c "INSERT INTO $1 SELECT g, 'customer ' || g, n.n FROM generate_series(0, $3 - 1) g JOIN ${1}_nums n ON n.i = (g % $nn) + 1; DROP TABLE ${1}_nums; ANALYZE $1" >/dev/null
}
migrate() { NETWORK="$NET_B" eng migrate --actor suite --dsn "postgres://postgres:$APW@$APP_IP:5432/app?sslmode=disable" --kind aadhaar --column aadhaar "$@" 2>&1 | grep '^MIGRATE'; }
kv() { sed -n "s/.* $2=\([^ ]*\).*/\1/p" <<<"$1"; }

eng gen --n 200000 >"$WORK/nums1"
load_table customers "$WORK/nums1" 1000000
asql -c "INSERT INTO customers VALUES (1000000, 'typo', '123412341234'), (1000001, 'typo', '123412341234')" >/dev/null
assert_eq "the table: 1,000,002 rows, 200,001 distinct values" "$(asql -c 'SELECT count(*), count(DISTINCT aadhaar) FROM customers')" "1000002|200001"
M="$(migrate --table customers)"
note "1 ms HSM: $M"
assert_eq "every distinct number tokenised; the value failing the check refused and left" "$(kv "$M" distinct)|$(kv "$M" refused)" "200001|1"
assert_eq "1,000,000 rows rewritten" "$(kv "$M" rows_updated)" "1000000"
assert_eq "no Aadhaar number left in the column" "$(kv "$M" left)" "0"
assert_eq "…only reference keys, and the two rows that never held a number" "$(asql -c "SELECT count(*) FILTER (WHERE aadhaar ~ '^AR[0-9A-Z]{26}\$'), count(*) FILTER (WHERE aadhaar = '123412341234') FROM customers")" "1000000|2"
assert_eq "the same number on five rows has one reference key" "$(asql -c "SELECT count(DISTINCT aadhaar) FROM customers WHERE id IN (0, 200000, 400000, 600000, 800000)")" "1"
assert_eq "the map of numbers to reference keys is gone from the branch" "$(asql -c "SELECT count(*) FROM pg_class WHERE relname = 'fox_vault_map'")" "0"
FIRST="$(head -1 "$WORK/nums1")"
assert_eq "row 0's reference key opens to its number" "$(callj detokenise --kind aadhaar --purpose "suite: migration check" "$(asql -c 'SELECT aadhaar FROM customers WHERE id = 0')" | jq -r '.values[0]')" "$FIRST"

stop_svc
start_svc || { bad "the service did not restart"; exit 1; }
eng gen --n 200000 >"$WORK/nums2"
load_table customers2 "$WORK/nums2" 1000000
M="$(migrate --table customers2)"
note "SoftHSM2: $M"
assert_eq "SoftHSM2: 1,000,000 rows, no number left" "$(kv "$M" rows_updated)|$(kv "$M" left)" "1000000|0"

# ---------------------------------------------------------------------------
echo "### 8. Uses per data key (section 18, item 5)"
ST="$(status)"
MADE="$(vsql "SELECT count(*) FROM vault.records WHERE kind = 'aadhaar'")"
DELETED=1
USES="$(jq -r '.kinds[]|select(.name=="aadhaar")|.keys[]|select(.label=="vault-aadhaar-data-1")|.uses' <<<"$ST")"
assert_eq "the data key's uses count every encryption, across restarts: records made, the deleted one included" "$USES" "$((MADE + DELETED))"
note "GCM's limit for random nonces is 2^32 uses a key; this key has $USES"

# ---------------------------------------------------------------------------
echo "### 9. Rotating 1,000,000 records while the vault answers (section 18, item 3)"
NEED=$((1000000 - MADE))
if [ "$NEED" -gt 0 ]; then
  eng gen --n "$NEED" >"$WORK/nums3"
  load_table fill "$WORK/nums3" "$NEED"
  migrate --table fill >/dev/null
fi
# Synthetic numbers are drawn at random, so across a million a few repeat
# (about n^2 / 2 * 8 * 10^10, so six or so), and a repeat is given its
# existing reference key, not a new record: the vault holds a few short of
# the rows loaded.
RECS="$(vsql "SELECT count(*) FROM vault.records WHERE kind = 'aadhaar'")"
note "Aadhaar records in the vault: $RECS"
assert_eq "about 1,000,000 Aadhaar records in the vault" "$([ "$RECS" -ge 999900 ] && echo yes || echo "no: $RECS")" "yes"
TEXT_BEFORE="$(vsql "SELECT string_agg(ref || ':' || data_key || ':' || encode(ct, 'hex'), ',' ORDER BY ref) FROM vault.records WHERE kind = 'text'")"
# Readers throughout: 5,000 numbers read back again and again while it runs.
# The readers run in a container with a name, so they can be told to stop.
d run --rm --name fox-p13-readers -u 10001:10001 --network none -v "$WORK/sock:/run/fox-vault" -v "$WORK/secret:/etc/fox-vault/secret:ro" "$IMG" \
  bench --actor suite --op detokenise --n 5000 --c 8 --seconds 900 >"$WORK/during.log" 2>&1 &
BG=$!
sleep 5
T0=$(date +%s)
R="$(callj rotate --kind aadhaar)"
T1=$(date +%s)
note "rotation: $(jq -r '.results[0] // .error' <<<"$R")"
assert_contains "the rotation moves every record to the new key and destroys the old one" "$(jq -r '.results[0] // .error' <<<"$R")" "destroyed vault-aadhaar-data-1"
d kill -s INT fox-p13-readers >/dev/null 2>&1; wait "$BG" 2>/dev/null
L="$(grep '^BENCH' "$WORK/during.log")"
note "readers during the rotation ($((T1 - T0)) s): ${L:-$(tail -3 "$WORK/during.log")}"
assert_contains "readers kept reading throughout, and none failed while records moved and the old key was destroyed" "$L" "errors=0"
ST="$(status)"
assert_eq "every Aadhaar record is under the new key" "$(vsql "SELECT count(*) FROM vault.records WHERE kind = 'aadhaar' AND data_key <> 'vault-aadhaar-data-2'")" "0"
assert_eq "the old key is gone from the token, and marked so" \
  "$(jq -r '.kinds[]|select(.name=="aadhaar")|.keys[]|select(.label=="vault-aadhaar-data-1")|.destroyed' <<<"$ST")|$(vsql "SELECT destroyed_at IS NOT NULL FROM vault.keys WHERE label = 'vault-aadhaar-data-1'")" "true|t"
assert_eq "the text kind was not touched" "$(vsql "SELECT string_agg(ref || ':' || data_key || ':' || encode(ct, 'hex'), ',' ORDER BY ref) FROM vault.records WHERE kind = 'text'")" "$TEXT_BEFORE"
assert_eq "an old number still opens, under the new key" "$(callj detokenise --kind aadhaar --purpose "suite: after rotation" "$REF1" | jq -r '.values[0]')" "$N1"
assert_eq "and text still opens" "$(callj detokenise --kind text --purpose suite "$TREF2" | jq -r '.values[0]')" "$TV"
NEWREF="$(callj tokenise --kind aadhaar "$(eng gen --n 1)" | jq -r '.refs[0]')"
assert_eq "a new number is written under the new key" "$(vsql "SELECT data_key FROM vault.records WHERE ref = '$NEWREF'")" "vault-aadhaar-data-2"

# ---------------------------------------------------------------------------
echo "### 10. The access log's chain"
ST="$(status)"
ENTRIES="$(jq -r '.log.entries' <<<"$ST")"
assert_eq "the chain holds over every call ($ENTRIES entries)" "$(jq -r '.log.broken_at' <<<"$ST")" "0"
WAS="$(vsql "SELECT purpose FROM vault.access_log WHERE seq = 5")"
vsql "UPDATE vault.access_log SET purpose = 'nothing to see' WHERE seq = 5" >/dev/null
assert_eq "an entry changed in the database breaks the chain at that entry" "$(status | jq -r '.log.broken_at')" "5"
vsql "UPDATE vault.access_log SET purpose = '$WAS' WHERE seq = 5" >/dev/null
assert_eq "…and holds again once it is put back" "$(status | jq -r '.log.broken_at')" "0"
LAST="$(vsql "SELECT max(seq) FROM vault.access_log")"
vsql "DELETE FROM vault.access_log WHERE seq = $LAST" >/dev/null
assert_eq "an entry cut off the end is noticed too: the service remembers how long the log was" "$(status | jq -r '.log.broken_at')" "$LAST"

echo
echo "==== $PASS passed, $FAIL failed ===="
[ "$FAIL" = 0 ]
