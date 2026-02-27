.PHONY: test build clean go-test go-integration-test dev

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

dev: build
	cargo install --path .
	@echo "Starting rolodex dev server on 127.0.0.1:5300 with socket at /tmp/rolodex.sock"
	$(CURDIR)/target/debug/rolodex -c $(CURDIR)/dev.toml
