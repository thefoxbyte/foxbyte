# SPDX-License-Identifier: AGPL-3.0-or-later
# Built by docker/postgres/Dockerfile's f1-build stage, against the server
# headers of the image's own major.
#
# MODULE_big, not MODULES: PGXS applies SHLIB_LINK only to MODULE_big, and a
# library built with MODULES did not link libcrypto at all, working only
# because the postgres binary happens to.
MODULE_big = fox_ed25519
OBJS = fox_ed25519.o
EXTENSION = fox_ed25519
DATA = fox_ed25519--0.1.sql
SHLIB_LINK = -lcrypto
PG_CONFIG ?= pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
