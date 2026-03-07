-include .env
export QUAY_USERNAME
export QUAY_PASSWORD

# Unique instance ID from working directory path.
INSTANCE_ID := $(shell echo -n "$(CURDIR)" | md5sum | cut -c1-8)
export INSTANCE_ID

# Image names (unique per working directory).
PODMAN_BUILD_IMAGE := rolodex-build-$(INSTANCE_ID)
PODMAN_IMAGE       := rolodex-$(INSTANCE_ID)
RELEASE_IMAGE      := quay.io/town-os/rolodex
export PODMAN_BUILD_IMAGE PODMAN_IMAGE RELEASE_IMAGE

.PHONY: test build clean go-test go-integration-test dev dev-release install
.PHONY: production-image release-image release-build push-rc push-release quay-login clean-containers

test: go-test
	cargo test

build:
	cargo build

clean:
	cargo clean

go-test: go-integration-test
	cd go && go test -v -count=1 ./...

go-integration-test: build
	cd go && ROLODEX_BINARY=$(CURDIR)/target/debug/rolodex go test -v -count=1 -tags=integration ./...

install:
	cargo install --path .

dev-release:
	cargo build --release
	@echo "Starting rolodex dev server on 127.0.0.1:5300 with socket at /tmp/rolodex.sock"
	$(CURDIR)/target/release/rolodex -c $(CURDIR)/dev.yml

dev:
	cargo build
	@echo "Starting rolodex dev server on 127.0.0.1:5300 with socket at /tmp/rolodex.sock"
	$(CURDIR)/target/debug/rolodex -c $(CURDIR)/dev.yml

# ---------------------------------------------------------------------------
# Container targets
# ---------------------------------------------------------------------------

production-image:
	@make/build.sh production

release-image:
	@make/build.sh release

release-build: release-image

push-rc: quay-login
	@make/build.sh push-rc

push-release: release-build quay-login
	@make/build.sh push-release

quay-login:
	@make/build.sh quay-login

clean-containers:
	-sudo podman rmi $(PODMAN_BUILD_IMAGE) $(PODMAN_IMAGE) 2>/dev/null || true
