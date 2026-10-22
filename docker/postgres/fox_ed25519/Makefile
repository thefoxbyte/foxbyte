# SPDX-License-Identifier: AGPL-3.0-or-later
# Built by docker/postgres/Dockerfile's f1-build stage, against the server
# headers of the image's own PostgreSQL major.
MODULES = fox_ed25519
EXTENSION = fox_ed25519
DATA = fox_ed25519--0.1.sql
SHLIB_LINK = -lcrypto
PG_CONFIG ?= pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
