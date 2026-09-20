#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Keeps docs/FOX_Checklist.html in step with docs/FOX_Feature_Implemented.html:
# every feature id in the feature doc's index must have a checklist row, and
# every checklist row must be a real feature with a valid status. Runs anywhere:
#   bash scripts/test_feature_checklist.sh
set -uo pipefail

docs="$(cd "$(dirname "$0")/../docs" && pwd)"
feature="$docs/FOX_Feature_Implemented.html"
checklist="$docs/FOX_Checklist.html"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
FAIL=0

grep -o '<span class="n">[A-Z][0-9]*</span>' "$feature" | sed 's/<[^>]*>//g' | sort > "$tmp/feature"
grep -o 'data-id="[A-Z][0-9]*"' "$checklist" | sed 's/data-id="\(.*\)"/\1/' | sort > "$tmp/checklist"

missing="$(comm -23 "$tmp/feature" "$tmp/checklist")"
extra="$(comm -13 "$tmp/feature" "$tmp/checklist")"
dups="$(uniq -d "$tmp/checklist")"
[ -z "$missing" ] || { echo "FAIL: in FOX_Feature_Implemented but not in FOX_Checklist: $(echo $missing)"; FAIL=1; }
[ -z "$extra" ]   || { echo "FAIL: in FOX_Checklist but not in FOX_Feature_Implemented: $(echo $extra)"; FAIL=1; }
[ -z "$dups" ]    || { echo "FAIL: listed twice in FOX_Checklist: $(echo $dups)"; FAIL=1; }

bad_st="$(grep -o 'data-st="[^"]*"' "$checklist" | grep -v 'data-st="\(done\|man\|part\|bad\|todo\)"' | sort -u)"
[ -z "$bad_st" ] || { echo "FAIL: unknown status in FOX_Checklist: $bad_st"; FAIL=1; }

# A row's badge must match its status, or the PDF shows one thing and the summary counts another.
mismatch="$(grep -o 'data-st="[a-z]*"><td class="c"><i class="ck [a-z]*">' "$checklist" \
	| sed 's/data-st="\([a-z]*\)"><td class="c"><i class="ck \([a-z]*\)">/\1 \2/' | awk '$1 != $2' | sort -u)"
[ -z "$mismatch" ] || { echo "FAIL: status and badge disagree in FOX_Checklist: $mismatch"; FAIL=1; }

if [ "$FAIL" = 0 ]; then
	echo "feature checklist: $(wc -l < "$tmp/checklist" | tr -d ' ') features in step with FOX_Feature_Implemented"
fi
exit "$FAIL"
