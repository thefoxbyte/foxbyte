#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Rename the product.
#
#   scripts/rebrand.sh --product Acme --cli acme [--slug acme] [--repo owner/repo]
#
# What this does, in order:
#   1. rewrites brand.json with the new name, moving the old one onto the
#      "previous" list (which is what keeps old installs readable: retired
#      environment variables, state directories, VMs and binaries);
#   2. regenerates everything derived from it (`make brand`);
#   3. sweeps the names that live in prose, documents and file names, which no
#      generator can reach — the README, the living documents, the web pages,
#      the test suites, the Go module path;
#   4. renames the files whose names carry the brand.
#
# What it deliberately does NOT touch: the names written into a database or onto
# disk (schema bb, roles db_client/db_admin, pool dbpool, containers pg-*,
# bucket wal-archive, key prefix key_, SQLSTATE BBX01/BBX02, the anchor format).
# Those carry no product name, so a rename never touches an existing install.
# See docs/branding.md.
#
# Afterwards: go test ./... (the guard test fails on any name left behind),
# then the integration suites.
set -euo pipefail

cd "$(dirname "$0")/.."

product="" cli="" slug="" repo=""
while [ $# -gt 0 ]; do
	case "$1" in
	--product) product="$2"; shift 2 ;;
	--cli) cli="$2"; shift 2 ;;
	--slug) slug="$2"; shift 2 ;;
	--repo) repo="$2"; shift 2 ;;
	-h | --help) sed -n '3,25p' "$0"; exit 0 ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done
[ -n "$product" ] && [ -n "$cli" ] || { echo "--product and --cli are required" >&2; exit 2; }
slug="${slug:-$(printf '%s' "$product" | tr '[:upper:]' '[:lower:]')}"

command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 2; }
[ -z "$(git status --porcelain)" ] || { echo "working tree is not clean — commit or stash first" >&2; exit 2; }

python3 - "$product" "$cli" "$slug" "$repo" <<'PY'
import json, os, re, subprocess, sys

product, cli, slug, repo = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

b = json.load(open('brand.json'))
old = {k: b[k] for k in ('product', 'cli', 'slug', 'env_prefix', 'state_dir')}
if old['slug'] == slug and old['cli'] == cli:
    sys.exit(f"brand.json already says {product} / {cli}")

new = dict(b)
new.update({
    'product': product,
    'cli': cli,
    'slug': slug,
    'env_prefix': cli.upper() + '_',
    'state_dir': '.' + cli,
    'docs_prefix': cli.upper() + '_',
    'vm_instance': cli,
    'test_vm': cli + '-test',
})
if repo:
    new['repo'] = repo
    new['module'] = 'github.com/' + repo
    new['image_repo'] = 'ghcr.io/' + repo.split('/')[0].lower()
new['previous'] = [old] + [p for p in b.get('previous', []) if p['slug'] != slug]
json.dump(new, open('brand.json', 'w'), indent=2)
open('brand.json', 'a').write('\n')
print(f"brand.json: {old['product']} -> {product}")

# Ordered, most specific first. Only brand-facing names: anything stored is
# already free of them.
rules = [
    (re.escape(b['module']), new['module']),
    (re.escape(b['repo']), new['repo']),
    (re.escape(b['image_repo']), new['image_repo']),
    (r'\.' + re.escape(old['state_dir'][1:]) + r'\b', new['state_dir']),
    (re.escape(old['env_prefix']), new['env_prefix']),
    (re.escape(old['product']), product),
    (re.escape(old['slug']), slug),
    (re.escape(old['slug'].upper()), slug.upper()),
    (r'(?<![A-Za-z0-9])' + re.escape(old['cli']) + r'-', cli + '-'),
    (r'(?<![A-Za-z0-9])' + re.escape(old['cli']) + r'(?![A-Za-z0-9])', cli),
    (r'(?<![A-Za-z0-9])' + re.escape(old['cli'].upper()) + r'(?![A-Za-z0-9])', cli.upper()),
    (r'(?<![A-Za-z0-9])' + re.escape(old['cli'].capitalize()), cli.capitalize()),
]
skip = re.compile(r'\.(pdf|png|jpe?g|webp|ico|gif|woff2?|ttf)$|(^|/)(go\.sum|package-lock\.json|brand\.json)$')
files = subprocess.run(['git', 'ls-files'], capture_output=True, text=True, check=True).stdout.split()
changed = 0
for f in files:
    if skip.search(f):
        continue
    try:
        s = open(f, encoding='utf-8').read()
    except (UnicodeDecodeError, IsADirectoryError, FileNotFoundError):
        continue
    t = s
    for pat, rep in rules:
        t = re.sub(pat, rep, t)
    if t != s:
        open(f, 'w', encoding='utf-8').write(t)
        changed += 1
print(f"rewrote {changed} files")

# File names carrying the brand.
for f in files:
    base = os.path.basename(f)
    nb = base.replace(b['docs_prefix'], new['docs_prefix']).replace(old['slug'], slug).replace(old['cli'], cli)
    if nb != base:
        dst = os.path.join(os.path.dirname(f), nb)
        subprocess.run(['git', 'mv', f, dst], check=True)
        print(f"renamed {f} -> {dst}")
for d in ('cmd/' + old['cli'], 'cmd/' + old['cli'] + '-verify'):
    if os.path.isdir(d):
        subprocess.run(['git', 'mv', d, d.replace(old['cli'], cli, 1)], check=True)
        print(f"renamed {d}")
PY

echo "regenerating…"
go run ./cmd/brandgen -root .
gofmt -w ./cmd ./internal

cat <<'NEXT'

Done. Now:
  go test ./...            # the guard test fails on any name left behind
  make feature-doc         # re-render the living documents
  make integration         # and the rest of the suites
Then rename the GitHub repository to match brand.json, and update the remote.
NEXT
