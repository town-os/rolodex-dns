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

.PHONY: test build clean go-test go-integration-test dev dev-release install lint bench
.PHONY: rust-test rust-integration-test
.PHONY: image push push-rc push-release quay-login clean-containers

lint:
	cargo fmt -- --check
	cargo clippy -- -D warnings

test: lint go-test rust-test

rust-test: rust-integration-test
	cargo test

rust-integration-test: build
	cargo test --test integration_test
	cargo test --test new_features_test
	cargo test --test cli_integration_test
	cargo test --test dhcp_integration_test

build:
	cargo build

clean:
	cargo clean

go-test: go-integration-test
	cd go && go test -v -count=1 ./...

go-integration-test: build
	cd go && ROLODEX_DNS_BINARY=$(CURDIR)/target/debug/rolodex-dns go test -v -count=1 -tags=integration ./...

bench:
	cargo bench --bench dns_perf

install:
	cargo install --path .

dev-release:
	cargo build --release
	@echo "Starting rolodex-dns dev server on 127.0.0.1:5300 with socket at /tmp/rolodex-dns.sock"
	$(CURDIR)/target/release/rolodex-dns -c $(CURDIR)/dev.yml

dev:
	cargo build
	@echo "Starting rolodex-dns dev server on 127.0.0.1:5300 with socket at /tmp/rolodex-dns.sock"
	$(CURDIR)/target/debug/rolodex-dns -c $(CURDIR)/dev.yml

# ---------------------------------------------------------------------------
# Container targets
# ---------------------------------------------------------------------------

image:
	@make/build.sh release

push: push-rc

push-rc: image quay-login
	@make/build.sh push-rc

push-release: image quay-login
	@make/build.sh push-release

quay-login:
	@make/build.sh quay-login

clean-containers:
	-sudo podman rmi $(PODMAN_BUILD_IMAGE) $(RELEASE_IMAGE) 2>/dev/null || true
