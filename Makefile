-include .env
export GITEA_USERNAME
export GITEA_PASSWORD

# Unique instance ID from working directory path.
INSTANCE_ID := $(shell echo -n "$(CURDIR)" | md5sum | cut -c1-8)
export INSTANCE_ID

# Image names (unique per working directory).
PODMAN_BUILD_IMAGE := rolodex-dns-build-$(INSTANCE_ID)
RELEASE_IMAGE      := gitea.com/town-os/rolodex-dns
export PODMAN_BUILD_IMAGE RELEASE_IMAGE

.PHONY: test build clean go-test go-integration-test dev dev-release install
.PHONY: image push push-rc push-release gitea-login clean-containers

test: go-test
	cargo test

build:
	cargo build

clean:
	cargo clean

go-test: go-integration-test
	cd go && go test -v -count=1 ./...

go-integration-test: build
	cd go && ROLODEX_DNS_BINARY=$(CURDIR)/target/debug/rolodex-dns go test -v -count=1 -tags=integration ./...

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

push-rc: image gitea-login
	@make/build.sh push-rc

push-release: image gitea-login
	@make/build.sh push-release

gitea-login:
	@make/build.sh gitea-login

clean-containers:
	-sudo podman rmi $(PODMAN_BUILD_IMAGE) $(RELEASE_IMAGE) 2>/dev/null || true
