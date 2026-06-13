-include .env
export QUAY_USERNAME
export QUAY_PASSWORD

# Unique instance ID from working directory path.
INSTANCE_ID := $(shell echo -n "$(CURDIR)" | md5sum | cut -c1-8)
export INSTANCE_ID

# Image names (unique per working directory).
PODMAN_BUILD_IMAGE := rolodex-dns-build-$(INSTANCE_ID)
# DO NOT CHANGE: This is the canonical container image URL for rolodex-dns.
# The source repo may live elsewhere (e.g. gitea.com/town-os/rolodex-dns)
# but the published container image is always quay.io/town/rolodex.
RELEASE_IMAGE      := quay.io/town/rolodex
IMAGE_TAG ?=
export PODMAN_BUILD_IMAGE RELEASE_IMAGE IMAGE_TAG

.PHONY: help test build clean go-test go-integration-test dev dev-release install lint bench
.PHONY: rust-test rust-integration-test
.PHONY: deps js-lint js-test js-integration-test
.PHONY: image push push-arch push-rc push-release manifest manifest-rc manifest-release quay-login clean-containers

help: ## Show this help
	@printf "Usage: make <target> [IMAGE_TAG=...]\n"
	@awk 'BEGIN {FS = ":.*##"} \
	  /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5); next } \
	  /^[a-zA-Z0-9_-]+:.*##/ { printf "  \033[36m%-21s\033[0m %s\n", $$1, $$2 }' $(firstword $(MAKEFILE_LIST))

##@ Build & Test

lint: ## Run cargo fmt --check and clippy -D warnings
	cargo fmt -- --check
	cargo clippy -- -D warnings

test: lint go-test rust-test js-test ## Run the full suite: lint, Go, Rust, and JavaScript tests

rust-test: rust-integration-test ## Run all Rust tests (includes integration tests)
	cargo test

rust-integration-test: build ## Run each Rust integration test file
	cargo test --test integration_test
	cargo test --test new_features_test
	cargo test --test cli_integration_test
	cargo test --test dhcp_integration_test
	cargo test --test acme_issuer_test

build: ## Compile debug binaries (rolodex-dns + rolodex-dns-cli)
	cargo build

clean: ## Clean cargo build artifacts
	cargo clean

go-test: go-integration-test ## Run Go unit tests (includes integration tests)
	cd go && go test -v -count=1 ./...

go-integration-test: build ## Run Go integration tests against a real server
	cd go && ROLODEX_DNS_BINARY=$(CURDIR)/target/debug/rolodex-dns go test -v -count=1 -tags=integration ./...

deps: ## Install JavaScript dev dependencies (npm install in js/)
	cd js && npm install --no-audit --no-fund

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

image: ## Build the host-arch container image (<IMAGE_TAG|latest>-<arch>)
	@make/build.sh release

push: push-rc ## Alias for push-rc

# Build and push ONLY the current host's per-arch tag (no rc/release/latest
# aliases, no manifest). Produces quay.io/town/rolodex:<IMAGE_TAG|latest>-<arch>.
push-arch: image quay-login ## Push only the current host's per-arch tag (no aliases, no manifest)
	@make/build.sh push-arch

push-rc: image quay-login ## Push the host-arch RC image (rc.YYYYMMDD-<arch> + rc.latest-<uname -m>, or IMAGE_TAG)
	@make/build.sh push-rc

push-release: image quay-login ## Push the host-arch release image (release.YYYYMMDD-<arch> + latest-<arch>, or IMAGE_TAG)
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
	-sudo podman rmi $(PODMAN_BUILD_IMAGE)-amd64 $(PODMAN_BUILD_IMAGE)-arm64 2>/dev/null || true
	-sudo podman rmi $(RELEASE_IMAGE):latest-amd64 $(RELEASE_IMAGE):latest-arm64 2>/dev/null || true
