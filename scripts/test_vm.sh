#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Creates (or starts) the throwaway Lima VM the integration suites run in.
#
# The suites are destructive by design: they wipe Blackbox history to prove
# tampering is caught, restore main to an earlier point in time, fail HA over
# and back, stop and remove containers, and create accounts, keys and admin
# grants. Run against a real install they destroy real data, so they run here
# instead, in a VM with its own containers, storage, backups and accounts —
# and each suite refuses to start anywhere this script has not marked
# (scripts/lib/test_guard.sh).
#
#   make test-vm                 # create or start it
#   FOX_TEST_VM=name make test-vm
set -euo pipefail

NAME="${FOX_TEST_VM:-fox-test}"
GO_VERSION="${FOX_TEST_GO_VERSION:-1.26.0}"
MARKER=/etc/fox-test-instance
# Lima forwards a VM's ports to the Mac's localhost. The test stack uses the
# same ports as a real one (8080, 6432, 8088), so forwarding them could put the
# test stack behind the user's localhost:8080. The suites talk to the stack from
# inside the VM, so nothing is forwarded at all.
NO_FORWARDS='.portForwards=[{"guestIP":"127.0.0.1","guestPortRange":[1,65535],"ignore":true},{"guestIP":"0.0.0.0","guestPortRange":[1,65535],"ignore":true}]'

# fox picks the user's VM by these names (internal/host/host_darwin.go: the
# dedicated instance, then one named for a retired product, then "default"), so
# a test VM with any of them would quietly become the VM every `fox` command
# talks to.
case "$NAME" in
fox | foxbyte | default | oxyndb | odb | vectoradb | vdb) # legacy: retired instance names
	echo "refusing: '$NAME' is a name fox uses for a real install — choose another FOX_TEST_VM" >&2
	exit 2
	;;
esac

status="$(limactl list "$NAME" --format '{{.Status}}' 2>/dev/null || true)"
case "$status" in
"")
	echo "Creating test VM '$NAME' (4 CPUs, 4 GiB, 40 GiB disk)…"
	limactl start --name "$NAME" --tty=false --cpus 4 --memory 4 --disk 40 --set "$NO_FORWARDS" template:ubuntu
	;;
Running) ;;
*)
	echo "Starting test VM '$NAME'…"
	limactl start "$NAME" --tty=false
	;;
esac

if limactl shell "$NAME" test -f "$MARKER"; then
	echo "Test VM '$NAME' is ready."
	exit 0
fi

echo "Provisioning '$NAME': Docker, ZFS, test tools and Go $GO_VERSION…"
limactl shell "$NAME" bash -s -- "$GO_VERSION" "$MARKER" <<'GUEST'
set -euo pipefail
go_version="$1" marker="$2"
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
# nodejs and npm: the SDK contract tests run the TypeScript client, and the web
# UI's Playwright tests run here too (scripts/integration_sdks.sh, web/tests).
sudo apt-get install -y -qq zfsutils-linux docker.io postgresql-client python3 curl jq openssl git nodejs npm >/dev/null
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"

# Go, checked against the digest go.dev publishes for this exact file.
arch="$(dpkg --print-architecture)"
file="go${go_version}.linux-${arch}.tar.gz"
want="$(curl -fsSL 'https://go.dev/dl/?mode=json&include=all' | python3 -c '
import json, sys
name = sys.argv[1]
for rel in json.load(sys.stdin):
    for f in rel["files"]:
        if f["filename"] == name:
            print(f["sha256"]); sys.exit(0)
sys.exit("no published digest for " + name)' "$file")"
curl -fsSL -o "/tmp/$file" "https://go.dev/dl/$file"
echo "$want  /tmp/$file" | sha256sum -c --quiet -
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf "/tmp/$file"
sudo ln -sf /usr/local/go/bin/go /usr/local/bin/go
rm -f "/tmp/$file"

echo "FoxByte throwaway test instance — created $(date -u +%FT%TZ) by scripts/test_vm.sh. Integration suites may destroy anything here." | sudo tee "$marker" >/dev/null
GUEST

# The docker group applies to new login sessions only; restart so every later
# `limactl shell` has it.
limactl stop "$NAME" >/dev/null
limactl start "$NAME" --tty=false >/dev/null
echo "Test VM '$NAME' is ready."
