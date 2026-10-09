#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The release notes, grouped, written here rather than by GitHub.
#
#   scripts/release_notes.sh <tag> [previous-tag]
#
# Why this exists: .github/release.yml is GitHub's way to group generated notes
# by label, and it did not work on this repository. The file was present at the
# tag, valid against the documented schema, and served correctly -- and every
# call came back with GitHub's default "What's Changed" heading and one flat
# list. That was tested down to a two-category config and a single category with
# no catch-all, on throwaway tags, with pull requests that had carried their
# labels since they were opened. No configuration made any difference.
#
# So the grouping happens here, where it can be read, run and fixed. The PR list
# still comes from GitHub's own generator -- it knows the compare range and
# formats the attribution -- and only the arrangement is ours.
set -euo pipefail

TAG="${1:?usage: release_notes.sh <tag> [previous-tag]}"
PREV="${2:-}"
REPO="${GITHUB_REPOSITORY:-thefoxbyte/foxbyte}"

# The greatest released tag strictly below this one. Taking "the newest other
# release" would pick a NEWER tag whenever an older one is re-released, and the
# notes would then cover a backwards range. $TAG is added to the list because
# --exclude-pre-releases drops it while it is still being held as one.
if [ -z "$PREV" ]; then
  PREV="$(
    { gh release list --repo "$REPO" --exclude-drafts --exclude-pre-releases --limit 50 --json tagName --jq ".[].tagName"
      echo "$TAG"
    } | sort -uV | awk -v cur="$TAG" '$0 == cur { print prev; exit } { prev = $0 }'
  )"
fi

args=(-f "tag_name=$TAG")
[ -n "$PREV" ] && args+=(-f "previous_tag_name=$PREV")
raw="$(gh api "repos/$REPO/releases/generate-notes" "${args[@]}" --jq '.body')"

# Every "* … in <url>/pull/N" line, and the compare link, which GitHub builds
# from the same range and is worth keeping exactly as it wrote it.
items="$(printf '%s\n' "$raw" | grep '^\* ' || true)"
full="$(printf '%s\n' "$raw" | grep '^\*\*Full Changelog\*\*' || true)"

if [ -z "$items" ]; then
  printf '%s\n' "$raw"
  exit 0
fi

# One call for every pull request's labels, rather than one call each.
nums="$(printf '%s\n' "$items" | sed -n 's#.*/pull/\([0-9][0-9]*\)$#\1#p' | sort -un)"
query='{repository(owner:"'"${REPO%%/*}"'",name:"'"${REPO##*/}"'"){'
for n in $nums; do
  query+="p$n: pullRequest(number:$n){number labels(first:30){nodes{name}}} "
done
query+='}}'
labels_json="$(gh api graphql -f query="$query" --jq '[.data.repository[] | select(. != null) | {key: (.number|tostring), value: [.labels.nodes[].name]}] | from_entries')"

label_of() { printf '%s' "$labels_json" | jq -r --arg n "$1" '(.[$n] // []) | join(" ")'; }
has() { case " $2 " in *" $1 "*) return 0;; *) return 1;; esac; }

# The sections, in the order they are printed. A pull request lands in the first
# one it matches, so the catch-all has to come last -- and unlike GitHub's '*',
# this one really does catch everything, including the unlabelled, which is what
# this repository's pull requests mostly are.
declare -a BREAKING FEATURES FIXES DOCS CHANGES DEPS
while IFS= read -r line; do
  [ -n "$line" ] || continue
  n="$(printf '%s' "$line" | sed -n 's#.*/pull/\([0-9][0-9]*\)$#\1#p')"
  l="$(label_of "${n:-0}")"
  if has duplicate "$l" || has invalid "$l" || has wontfix "$l"; then continue; fi
  if   has breaking "$l";      then BREAKING+=("$line")
  elif has enhancement "$l";   then FEATURES+=("$line")
  elif has bug "$l";           then FIXES+=("$line")
  elif has documentation "$l"; then DOCS+=("$line")
  elif has dependencies "$l";  then DEPS+=("$line")
  else                              CHANGES+=("$line")
  fi
done <<< "$items"

section() {
  local title="$1"; shift
  [ "$#" -gt 0 ] || return 0
  printf '## %s\n\n' "$title"
  printf '%s\n' "$@"
  printf '\n'
}

section "Breaking changes" ${BREAKING+"${BREAKING[@]}"}
section "Features"         ${FEATURES+"${FEATURES[@]}"}
section "Fixes"            ${FIXES+"${FIXES[@]}"}
section "Documentation"    ${DOCS+"${DOCS[@]}"}
section "Changes"          ${CHANGES+"${CHANGES[@]}"}
section "Dependencies"     ${DEPS+"${DEPS[@]}"}
[ -n "$full" ] && printf '%s\n' "$full"
