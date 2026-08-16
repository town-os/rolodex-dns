-include .env
export QUAY_USERNAME
export QUAY_PASSWORD

# Unique instance ID from working directory path.
INSTANCE_ID := $(shell echo -n "$(CURDIR)" | md5sum | cut -c1-8)
export INSTANCE_ID

# DO NOT CHANGE: This is the canonical container image URL for rolodex-dns.
# The source repo may live elsewhere (e.g. gitea.com/town-os/rolodex-dns)
# but the published container image is always quay.io/town/rolodex.
RELEASE_IMAGE      := quay.io/town/rolodex
IMAGE_TAG ?=
export RELEASE_IMAGE IMAGE_TAG

# The REAL host architecture (uname -m, normalized). BUILD_ARCH is derived from
# TARGET below and may differ from it (a cross-arch build); HOST_ARCH never
# changes, so the build machinery can always tell the two apart.
HOST_ARCH := $(shell uname -m | sed -e 's/^amd64$$/x86_64/' -e 's/^arm64$$/aarch64/')

# TARGET selects the architecture for EVERY container target (image, push-arch,
# push-rc, push-release). Empty (the default) is a native build for the host
# arch. Recognized values:
#   x86_64 (x86, amd64)                    amd64 image
#   aarch64 (arm64)                        arm64 image
#   rpi                                    Raspberry Pi        -> aarch64
#   rg35xxpro (rg35xx-pro, rg35xx)         Anbernic RG35XX Pro -> aarch64
#   anbernic                               "                   -> aarch64
#
# The board flavors carry no image differences here — rolodex-dns ships one
# container image per architecture, not per board. They are accepted so a single
# TARGET= value can be passed across the town-os repos: `make image
# TARGET=rg35xxpro` builds a board-specific disk image in ../install and simply
# resolves to the aarch64 container image here, instead of failing on a value
# that is perfectly valid one directory over.
#
# Any TARGET builds from any host: the binaries are cross-compiled with
# cargo-zigbuild (make/cross.sh) and the runtime image has no RUN steps, so
# `podman build --platform` never executes a foreign binary. No emulation, no
# builder VM, and the native and foreign arches take the same code path.
TARGET ?=

# Derive BUILD_ARCH from TARGET. BUILD_ARCH is the image's architecture and thus
# the suffix for every arch-suffixed image tag (latest-<arch>, rc.latest-<arch>,
# release.YYYYMMDD-<arch>, ...). make/build.sh reads it from the environment.
ifeq ($(TARGET),)
BUILD_ARCH := $(HOST_ARCH)
else ifneq ($(filter x86_64 x86 amd64,$(TARGET)),)
BUILD_ARCH := x86_64
else ifneq ($(filter aarch64 arm64,$(TARGET)),)
BUILD_ARCH := aarch64
else ifeq ($(TARGET),rpi)
BUILD_ARCH := aarch64
else ifneq ($(filter rg35xxpro rg35xx-pro rg35xx anbernic,$(TARGET)),)
BUILD_ARCH := aarch64
else
$(error unknown TARGET '$(TARGET)' — expected one of: x86_64, aarch64, rpi, rg35xxpro)
endif

# CROSS is set when the requested arch differs from the host arch. It selects
# nothing by itself — every arch goes through cargo-zigbuild either way — but
# `make build` uses it to decide between a plain debug `cargo build` and the
# cross toolchain. Derived, not a user knob: set TARGET, not CROSS.
CROSS :=
ifneq ($(BUILD_ARCH),$(HOST_ARCH))
CROSS := 1
endif

export BUILD_ARCH

# Directory for timestamped test logs (see the test-log target).
LOG_DIR := /tmp/rolodex-dns/log
export LOG_DIR

.PHONY: help test test-log build clean go-test go-integration-test dev dev-release install lint bench
.PHONY: rust-test rust-integration-test prometheus-test translation-check check-townos-sync
.PHONY: deps python-deps js-lint js-test js-integration-test
.PHONY: image push push-arch push-rc push-release manifest manifest-rc manifest-release quay-login clean-containers
.PHONY: image-amd64 push-rc-amd64 push-release-amd64 push-rc-all push-release-all cross-deps

help: ## Show this help
	@printf "Usage: make <target> [IMAGE_TAG=...]\n"
	@awk 'BEGIN {FS = ":.*##"} \
	  /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5); next } \
	  /^[a-zA-Z0-9_-]+:.*##/ { printf "  \033[36m%-21s\033[0m %s\n", $$1, $$2 }' $(firstword $(MAKEFILE_LIST))

##@ Build & Test

lint: translation-check check-townos-sync ## Run the translation and contract checks, cargo fmt --check and clippy -D warnings
	cargo fmt -- --check
	cargo clippy --all-targets -- -D warnings

# The five documents each carry five translations, and nothing in the Rust test
# suite reads them — promql_docs_test only opens the English README.md and
# DESIGN.md. This compares every translated section against its English
# counterpart by line count, which is what catches a paragraph, bullet or table
# row that landed in English and never reached a locale.
#
# A prerequisite of `lint`, so it runs first and as part of `make test`. Exits
# non-zero on any drift, naming the section and its English/translation line
# counts. Pure Python with no network and no containers; needs python3 on PATH.
translation-check: python-deps ## Check the translated docs against English for dropped content
	python3 translation-drift-check.py

# Verifies TOWNOS_CONTRACT.md against the ../town-os and ../install checkouts on
# this machine: the methods Town OS's rolodex client declares, the forwarder
# scheme sets in the two hand-written parsers, and the fixed addresses each of
# the three repositories writes independently.
#
# Nothing is pinned to a revision — a pin goes stale silently and fails loudly on
# commits that changed nothing rolodex depends on. It SKIPS when neither checkout
# is present, so this repository still builds on a machine that has only it.
# Override the locations with TOWNOS_DIR= and INSTALL_DIR=.
check-townos-sync: ## Check TOWNOS_CONTRACT.md against local town-os/install checkouts
	bash make/check-townos-sync.sh

# Runs the documented PromQL through a real Prometheus, which is the only way to
# catch a query that is malformed *as PromQL* rather than merely naming a series
# that does not exist (promql_docs_test covers the latter).
#
# Part of `make test`. It needs podman and, on a cold image cache, the network —
# neither of which every machine has, so the test SKIPS rather than fails when
# podman is absent, and says so loudly on stderr. `make test` therefore stays
# green on a machine without a container runtime while never pretending the
# queries were checked. Set ROLODEX_PROMETHEUS_REQUIRED=1 (CI) to turn that skip
# into a failure, and ROLODEX_PROMETHEUS_IMAGE to point at a mirror.
prometheus-test: build ## Execute the documented PromQL against a containerised Prometheus
	ROLODEX_PROMETHEUS_TEST=1 cargo test --test prometheus_integration_test -- --nocapture

test: lint go-test rust-test js-test prometheus-test ## Run the full suite: lint, Go, Rust, JavaScript, and PromQL tests

test-log: ## Same as test, tee'd into a timestamped log file printed at the end even on failure
	@bash -c 'set -o pipefail; mkdir -p "$(LOG_DIR)"; logfile="$(LOG_DIR)/test-$$(date +%s).log"; echo "Logging to: $$logfile"; rc=0; $(MAKE) test 2>&1 | tee "$$logfile" || rc=$$?; echo "Log file: $$logfile"; exit $$rc'

rust-test: rust-integration-test ## Run all Rust tests (includes integration tests)
	cargo test

# The security_* suites assert the behaviour each open security issue requires
# and are EXPECTED TO FAIL until those issues are fixed. A failure there is the
# finding, not a broken test — see the module docs at the top of each file.
# Never weaken an assertion to make one pass.
rust-integration-test: build ## Run each Rust integration test file
	cargo test --test integration_test
	cargo test --test new_features_test
	cargo test --test cli_integration_test
	cargo test --test dhcp_integration_test
	cargo test --test acme_issuer_test
	cargo test --test auto_resolution_test
	cargo test --test forwarder_transport_test
	cargo test --test metrics_test
	cargo test --test blocking_metrics_test
	cargo test --test promql_docs_test
	# Compiles the file and runs its ungated half. The containerised half needs
	# ROLODEX_PROMETHEUS_TEST=1 and runs from the `prometheus-test` target, which
	# `test` also depends on.
	cargo test --test prometheus_integration_test
	cargo test --test blocklist_refusal_test
	cargo test --test dnssec_signing_test
	cargo test --test dnssec_serving_test
	cargo test --test dnssec_validation_test
	cargo test --test dnssec_hidden_cut_test
	cargo test --test arpa_refusal_test
	cargo test --test blocklist_nxdomain_test
	cargo test --test nodata_test
	cargo test --test zonemd_test
	cargo test --test dot_test
	cargo test --test doq_test
	cargo test --test doh_h3_test
	cargo test --test ddr_follow_test
	cargo test --test proxy_test
	cargo test --test tls_reload_test
	cargo test --test acme_admin_test
	cargo test --test acme_tlsa_endpoints_test
	cargo test --test security_acme_test
	cargo test --test security_dnssec_test
	cargo test --test security_forwarder_test
	cargo test --test security_resolver_test
	cargo test --test security_scope_test
	cargo test --test security_portal_test
	cargo test --test security_open_resolver_test
	cargo test --test security_local_access_test
	cargo test --test security_auth_hardening_test
	cargo test --test security_bailiwick_test
	cargo test --test security_dhcp_hostname_test
	cargo test --test security_tcp_limits_test
	cargo test --test security_dot_limits_test

build: ## Compile binaries for TARGET (debug natively; cross-compiled release for a foreign TARGET)
	@$(if $(CROSS),make/cross.sh build $(BUILD_ARCH),cargo build)

clean: ## Clean cargo build artifacts
	cargo clean

go-test: go-integration-test ## Run Go unit tests (includes integration tests)
	cd go && go test -v -count=1 .

go-integration-test: build ## Run Go integration tests against a real server
	cd go && ROLODEX_DNS_BINARY=$(CURDIR)/target/debug/rolodex-dns go test -v -count=1 -tags=integration .

deps: cross-deps python-deps ## Install build dependencies (Rust cross toolchain + JS dev deps + python3 check)
	cd js && npm install --no-audit --no-fund

# `translation-check` -- a prerequisite of `lint`, and so part of `make test` --
# runs a pure-standard-library Python script. Unlike everything else `deps`
# provisions, python3 is a system interpreter and cannot be installed without
# root, so this verifies it and names the package rather than installing it.
# `translation-check` depends on it too, so a missing interpreter fails with
# this message instead of a bare "python3: command not found".
python-deps: ## Verify python3 is present (required by translation-check)
	@command -v python3 >/dev/null 2>&1 || { \
	  printf 'error: python3 not found on PATH\n'; \
	  printf '  Required by `make translation-check`, which `make lint` and `make test` depend on.\n'; \
	  printf '  It cannot be installed rootlessly here; use your package manager:\n'; \
	  printf '    Debian/Ubuntu  apt install python3\n'; \
	  printf '    Fedora/RHEL    dnf install python3\n'; \
	  printf '    Arch           pacman -S python\n'; \
	  printf '    macOS          brew install python\n'; \
	  exit 1; }
	@printf 'python3 present: %s\n' "$$(python3 --version 2>&1)"

# The Rust cross-compilation toolchain: rustup std for both targets,
# cargo-zigbuild, and zig as the C cross-compiler/linker. `rustup target add`
# alone is not enough — rusqlite (bundled) compiles SQLite's C and ring compiles
# C/asm, so a real cross C toolchain has to be present. Everything here installs
# without root.
cross-deps: ## Install the Rust cross-compilation toolchain (rustup targets, cargo-zigbuild, zig)
	@make/cross.sh deps

js-lint: deps ## Run eslint on the JavaScript package
	cd js && npm run lint

js-test: js-integration-test ## Run JavaScript unit tests (includes integration tests)
	cd js && npm test

js-integration-test: build js-lint ## Run JavaScript integration tests against a real server
	cd js && ROLODEX_DNS_BINARY=$(CURDIR)/target/debug/rolodex-dns npm run test:integration

bench: ## Run criterion benchmarks (cargo bench --bench dns_perf)
	cargo bench --bench dns_perf

install: ## Install the binaries to the cargo bin directory
	cargo install --path .

##@ Development

dev-release: ## Build release and start a dev server using dev.yml
	cargo build --release
	@echo "Starting rolodex-dns dev server on 127.0.0.1:5300 with socket at /tmp/rolodex-dns.sock"
	$(CURDIR)/target/release/rolodex-dns -c $(CURDIR)/dev.yml

dev: ## Build debug and start a dev server using dev.yml
	cargo build
	@echo "Starting rolodex-dns dev server on 127.0.0.1:5300 with socket at /tmp/rolodex-dns.sock"
	$(CURDIR)/target/debug/rolodex-dns -c $(CURDIR)/dev.yml

##@ Containers

# Every target below tags with BUILD_ARCH, which comes from TARGET (default: the
# host arch). A foreign TARGET is cross-compiled (make/cross.sh) and packaged
# with `podman build --platform`, so any host can build any arch.
image: ## Build the container image for TARGET (<IMAGE_TAG|latest>-<arch>)
	@make/build.sh release

push: push-rc ## Alias for push-rc

# Build and push ONLY the TARGET arch's per-arch tag (no rc/release/latest
# aliases, no manifest). Produces quay.io/town/rolodex:<IMAGE_TAG|latest>-<arch>.
push-arch: image quay-login ## Push only the TARGET arch's per-arch tag (no aliases, no manifest)
	@make/build.sh push-arch

push-rc: image quay-login ## Push the TARGET-arch RC image (rc.YYYYMMDD-<arch> + rc.latest-<arch>, or IMAGE_TAG)
	@make/build.sh push-rc

push-release: image quay-login ## Push the TARGET-arch release image (release.YYYYMMDD-<arch> + latest-<arch>, or IMAGE_TAG)
	@make/build.sh push-release

# Manifest targets assemble a multi-arch manifest list from the per-arch image
# tags already pushed (via push-rc/push-release) from each native host. Run
# these once, after both the amd64 and arm64 images have been pushed.
manifest: manifest-rc ## Alias for manifest-rc

manifest-rc: quay-login ## Push multi-arch RC manifest lists (rc.YYYYMMDD + rc.latest, or IMAGE_TAG)
	@make/build.sh manifest-rc

manifest-release: quay-login ## Push multi-arch release manifest lists (release.YYYYMMDD + latest, or IMAGE_TAG)
	@make/build.sh manifest-release

quay-login: ## Log in to quay.io using QUAY_USERNAME/QUAY_PASSWORD (env or .env)
	@make/build.sh quay-login

clean-containers: ## Remove locally built per-arch container images
	-sudo podman rmi $(RELEASE_IMAGE):latest-x86_64 $(RELEASE_IMAGE):latest-aarch64 2>/dev/null || true

# Aliases for the TARGET=x86_64 form, kept because they are the documented
# interface. They no longer involve a VM — TARGET=x86_64 cross-compiles.
image-amd64: ## Alias for `make image TARGET=x86_64`
	@$(MAKE) image TARGET=x86_64

push-rc-amd64: ## Alias for `make push-rc TARGET=x86_64`
	@$(MAKE) push-rc TARGET=x86_64

push-release-amd64: ## Alias for `make push-release TARGET=x86_64`
	@$(MAKE) push-release TARGET=x86_64

# Full multi-arch publish from ONE host of either architecture: cross-compile
# each arch, then assemble the manifest from the per-arch tags in the registry.
# Sequenced via recursive make so the manifest is always assembled last.
push-rc-all: ## Publish both arches (cross-compiled) and the RC manifest
	$(MAKE) push-rc TARGET=x86_64
	$(MAKE) push-rc TARGET=aarch64
	$(MAKE) manifest-rc

push-release-all: ## Publish both arches (cross-compiled) and the release manifest
	$(MAKE) push-release TARGET=x86_64
	$(MAKE) push-release TARGET=aarch64
	$(MAKE) manifest-release
