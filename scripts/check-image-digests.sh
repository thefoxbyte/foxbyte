#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Reports whether the image digests FoxByte pins still match their tags
# (audit v2 G23). A pin that has fallen behind is not broken — it is the image
# FoxByte was tested with — but the tag has moved on, usually for security
# fixes in the base image. Move a pin in internal/branch/images.go (the tests
# then list every other file that names it) and run the suites.
#   bash scripts/check-image-digests.sh     exit 1 when any pin is behind
set -uo pipefail
cd "$(dirname "$0")/.."

ACCEPT='Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json'
hub_digest() { # hub_digest <repo> <tag>
	local tok
	tok="$(curl -fsSL "https://auth.docker.io/token?service=registry.docker.io&scope=repository:$1:pull" | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')" || return 1
	curl -fsSI -H "$ACCEPT" -H "Authorization: Bearer $tok" "https://registry-1.docker.io/v2/$1/manifests/$2" | tr -d '\r' | awk 'tolower($1)=="docker-content-digest:"{print $2}'
}
quay_digest() { # quay_digest <repo> <tag>
	curl -fsSI -H "$ACCEPT" "https://quay.io/v2/$1/manifests/$2" | tr -d '\r' | awk 'tolower($1)=="docker-content-digest:"{print $2}'
}
pinned() { grep -o "\"$1\": \"sha256:[0-9a-f]*\"" internal/branch/images.go | grep -o 'sha256:[0-9a-f]*'; }

behind=0
report() { # report <what> <pinned> <current>
	if [ -z "$3" ]; then echo "?  $1: could not read the registry"; behind=1
	elif [ "$2" = "$3" ]; then echo "ok $1: $2"
	else echo "!! $1: pinned $2, the tag is now $3"; behind=1; fi
}
for m in 16 18; do
	report "postgres:$m-bookworm" "$(pinned "$m")" "$(hub_digest library/postgres "$m-bookworm")"
done
for img in minio mc; do
	ref="$(grep -o "quay.io/minio/$img:RELEASE[^\"]*" internal/branch/images.go | head -1)"
	pin="$(grep -o "\"@sha256:[0-9a-f]*\"" internal/branch/images.go | sed -n "$([ "$img" = minio ] && echo 1 || echo 2)p" | tr -d '"@')"
	report "$ref" "$pin" "$(quay_digest "minio/$img" "${ref##*:}")"
done
exit "$behind"
