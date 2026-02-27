.PHONY: test build clean go-test go-integration-test

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
