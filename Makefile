# SPDX-License-Identifier: AGPL-3.0-or-later
#
# FoxByte runs inside the Linux dev VM (ZFS + Docker); day-to-day operation is
# via `lima /tmp/fox <command>`. This Makefile just builds/checks the CLI.

.PHONY: build vet fmt vm-build test integration web-dev web-build release release-linux wsl-zfs wsl-distro feature-doc integration-v2 integration-update integration-pg-upgrade test-vm test-vm-stop test-vm-delete

VERSION ?= 0.1.0
LDFLAGS := -s -w -X github.com/thefoxbyte/foxbyte/internal/version.Version=$(VERSION)

build:            ## Build the CLI into ./bin/fox (host)
	go build -o bin/fox ./cmd/fox

# The distro image bakes in one binary. Building the other four release
# targets to get it cost several minutes of cross-compilation per run, and
# release.yml already builds and publishes the full set separately.
release-linux: web-build   ## Cross-compile just the Linux engine binary (for the distro image)
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -trimpath -tags embedui -ldflags "$(LDFLAGS)" -o dist/fox-linux-amd64 ./cmd/fox

release: web-build   ## Cross-compile release binaries + the Windows image context into ./dist
	@mkdir -p dist
	@rm -f dist/fox-* dist/foxbyte-docker-context.tar.gz
	@for t in darwin/arm64 darwin/amd64 linux/arm64 linux/amd64 windows/amd64; do \
		os=$${t%/*}; arch=$${t#*/}; ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
		tags=""; [ "$$os" = "linux" ] && tags="-tags embedui"; \
		echo "  building fox-$$os-$$arch$$ext"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
			go build -trimpath $$tags -ldflags "$(LDFLAGS)" -o dist/fox-$$os-$$arch$$ext ./cmd/fox; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
			go build -trimpath -ldflags "$(LDFLAGS)" -o dist/fox-verify-$$os-$$arch$$ext ./cmd/fox-verify; \
	done
	@echo "  building foxbyte-docker-context.tar.gz"
	@tar -C docker/postgres -czf dist/foxbyte-docker-context.tar.gz .
	@echo "release binaries in ./dist (version $(VERSION))"
	@echo "note: the Windows installer also needs the ZFS module bundle (see make wsl-zfs / docs/windows-setup.md)"

vet:              ## go vet
	go vet ./...

fmt:              ## list files needing gofmt
	gofmt -l cmd internal

vm-build: web-build   ## Build the Linux binary (UI embedded) inside the Lima VM to /tmp/fox
	lima bash -c 'cd "$(CURDIR)" && go build -tags embedui -o /tmp/fox ./cmd/fox'

test:             ## Run unit tests (host, no VM needed)
	go test ./...

# The integration suites are destructive (they wipe Blackbox history, restore
# main to an earlier point, fail HA over), so they run in a throwaway VM of
# their own — never the VM holding your install. See scripts/test_vm.sh.
TEST_VM ?= fox-test
IN_TEST_VM = LIMA_INSTANCE=$(TEST_VM) lima

test-vm:          ## Create or start the throwaway VM the integration suites run in
	FOX_TEST_VM=$(TEST_VM) bash scripts/test_vm.sh

test-vm-stop:     ## Stop the test VM (frees its memory; keeps it for next time)
	limactl stop $(TEST_VM)

test-vm-delete:   ## Delete the test VM and everything in it
	limactl delete --force $(TEST_VM)

integration: test-vm      ## Run the full end-to-end integration test in the test VM
	$(IN_TEST_VM) bash -c 'cd "$(CURDIR)" && go build -o /tmp/fox ./cmd/fox' && $(IN_TEST_VM) bash "$(CURDIR)/scripts/integration_test.sh"

integration-v2: test-vm   ## Run the Blackbox 2.0 checks (behaviour-unchanged + new) in the test VM
	$(IN_TEST_VM) bash -c 'cd "$(CURDIR)" && go build -o /tmp/fox ./cmd/fox && go build -o /tmp/fox-verify ./cmd/fox-verify' && $(IN_TEST_VM) bash "$(CURDIR)/scripts/integration_ledger_v2.sh"

# The update suite hands the stack back to /usr/local/bin/fox when it finishes,
# so the test VM gets the current build installed there first.
integration-update: test-vm ## Run the `fox update` / new-release notice checks against a fake GitHub in the test VM
	$(IN_TEST_VM) bash -c 'cd "$(CURDIR)" && go build -o /tmp/fox ./cmd/fox && sudo install -m 0755 /tmp/fox /usr/local/bin/fox' && $(IN_TEST_VM) bash "$(CURDIR)/scripts/integration_update.sh"

# Builds a PostgreSQL 16 install, exports and restores it, upgrades it to the
# major this fox ships, rolls back, upgrades again and finalizes. It uninstalls
# the stack at both ends, so it runs on its own.
integration-pg-upgrade: test-vm ## Run the export/restore and `fox pg upgrade` checks (16 -> the shipped major) in the test VM
	$(IN_TEST_VM) bash -c 'cd "$(CURDIR)" && go build -o /tmp/fox ./cmd/fox' && $(IN_TEST_VM) bash "$(CURDIR)/scripts/integration_pg_upgrade.sh"

web-dev:          ## DEPRECATED: the engine serves the UI at https://localhost:8080 (`fox start`). Hot-reload dev server only.
	@echo "note: 'make web-dev' is deprecated — 'fox start' serves the UI at https://localhost:8080."
	@echo "      This runs a hot-reloading dev server for UI development only."
	npm --prefix web install --no-audit --no-fund && npm --prefix web run dev

web-build:        ## Build the web UI to web/dist (same-origin; embedded into the engine binary)
	npm --prefix web ci && VITE_API_URL= npm --prefix web run build

# Both build scripts are invoked through bash rather than relying on their
# exec bit: this repo is developed on Windows with core.filemode=false, where
# a dropped +x is invisible locally and surfaces only as "Permission denied"
# on the Linux runner.
wsl-zfs:          ## Build the OpenZFS modules + userland for the stock WSL2 kernel (Linux builder/CI only)
	bash deploy/wsl-zfs/build.sh

wsl-distro:       ## Build the prebuilt WSL2 distro image (Linux builder/CI with Docker)
	bash deploy/wsl-distro/build.sh

# The living feature document: edit docs/FOX_Feature_Implemented.html with every
# change, then re-render the PDF. Uses headless Chrome/Chromium; set CHROME to a
brand:            ## Regenerate everything derived from brand.json (see docs/branding.md)
	go run ./cmd/brandgen -root .

brand-check:      ## Fail if anything generated from brand.json is out of date
	go run ./cmd/brandgen -root . -check

# browser binary if it isn't found automatically.
feature-doc:      ## Render docs/FOX_Feature_Implemented.pdf and docs/FOX_Checklist.pdf from their HTML sources
	@chrome="$${CHROME:-}"; \
	for c in "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" google-chrome chromium chromium-browser; do \
		[ -n "$$chrome" ] && break; \
		if [ -x "$$c" ] || command -v "$$c" >/dev/null 2>&1; then chrome="$$c"; fi; \
	done; \
	[ -n "$$chrome" ] || { echo "Chrome/Chromium not found — set CHROME=/path/to/chrome"; exit 1; }; \
	bash scripts/test_feature_checklist.sh || exit 1; \
	for doc in FOX_Feature_Implemented FOX_Checklist; do \
		url="file://$$(printf '%s' "$(CURDIR)" | sed 's/ /%20/g')/docs/$$doc.html"; \
		"$$chrome" --headless --disable-gpu --no-pdf-header-footer --print-to-pdf-no-header \
			--print-to-pdf="$(CURDIR)/docs/$$doc.pdf" "$$url" 2>/dev/null && \
		echo "wrote docs/$$doc.pdf" || exit 1; \
	done
