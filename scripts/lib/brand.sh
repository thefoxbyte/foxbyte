# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Generated from brand.json by cmd/brandgen. DO NOT EDIT -- run `make brand`.
#
# Sourced by the integration suites so they name the product in one place:
#   . "$(dirname "$0")/lib/brand.sh"

BRAND_PRODUCT="FoxByte"
BRAND_CLI="fox"
BRAND_SLUG="foxbyte"
BRAND_ENV_PREFIX="FOX_"
BRAND_STATE_DIR=".fox"
BRAND_REPO="thefoxbyte/foxbyte"
BRAND_TEST_VM="fox-test"
BRAND_PREVIOUS_CLIS="odb vdb"

# Names that are deliberately brand-free, so a rename never touches an install.
# Taken from the packages that create them, not written out again.
DB_SCHEMA=bb
DB_CLIENT_ROLE=db_client
DB_ADMIN_ROLE=db_admin
DB_SUPERUSER=dbadmin
DB_DATABASE=appdb
DB_POOL=dbpool
DB_NETWORK=dbnet
DB_CONTAINER_PREFIX=pg-
DB_OBJECT_STORE=objstore
DB_OBJECT_STORE_VOLUME=objstore-data
DB_WAL_BUCKET=wal-archive
DB_MANAGED_LABEL=dev.dbengine.managed
DB_KEY_PREFIX=key_
