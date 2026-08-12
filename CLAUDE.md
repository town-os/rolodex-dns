# Rolodex DNS Development Rules

> Languages: **English** | [繁體中文](CLAUDE.zh-TW.md) | [简体中文](CLAUDE.zh-CN.md) | [Español (España)](CLAUDE.es-ES.md) | [Español (México)](CLAUDE.es-MX.md) | [日本語](CLAUDE.ja.md)

Rolodex DNS is a split-horizon DNS server and recursive/forwarding resolver with remote management via gRPC, written in Rust and licensed under AGPL-3.0-only.

This file is the rules for working on it. It is deliberately short: **what the software does** is `DESIGN.md`, and nothing about behaviour, architecture or API surface belongs here.

## Where things are written down

| Document | Contents |
| -------- | -------- |
| `DESIGN.md` | The functional specification: architecture, resolution order, every management surface (gRPC, CLI, Go client, JavaScript client, metrics, configuration), the test-suite design, and the build system. Read this before changing behaviour. |
| `README.md` | User-facing reference, including the PromQL cookbook. |
| `CONFIGURATION.md` | Task-oriented configuration guide — worked deployment shapes, what needs a restart, troubleshooting by symptom. |
| `CHANGELOG.md` | Release history. |
| `CLAUDE.md` | This file. Development rules only. |

Each of the five has a Traditional Chinese (`.zh-TW.md`), Simplified Chinese (`.zh-CN.md`), European Spanish (`.es-ES.md`), Mexican Spanish (`.es-MX.md`) and Japanese (`.ja.md`) translation alongside it. **English is the source of truth**: change it first, and treat the translations as needing a follow-up rather than as a second place to edit. Nothing verifies that they agree — `tests/promql_docs_test.rs` reads only the English `README.md` and `DESIGN.md`, so a PromQL block or a family count inside a translation is documentation, not a checked assertion.

## Rules

- please do not run make tasks unless told to
- ensure deny(dead_code) and deny(unsafe) are at the top and honored
- handle all std::result::Result in an appropriate way
- do not use unwrap
- do not use unsafe code
- never run tests yourself
- write tests for everything, including integration and real tests
- use make test to validate any changes
- integration tests should not alter the host, ever
- tests: unless said otherwise, they perform with simulated input and produce output on the operations that would be performed. They never affect the running system.
- running tests: use the make tasks every time.
- tests should always include the linting checks
- lint checks should be a rust community standard of linters, run as the `lint` make tasks
- never use `let _ = expr;` to suppress unused variable warnings or work around the borrow checker. Fix the actual problem: use the variable, remove the parameter, or restructure the code.
- `#![deny(dead_code)]` and `#![deny(unsafe_code)]` are set at the crate level in both lib.rs and main.rs. Never add `#[allow(dead_code)]` or `#[allow(unsafe_code)]` to bypass them — remove dead code, and use safe abstractions (e.g., nix crate) instead of unsafe.
- do not modify the system beyond configuring hardware
- never delete, move, or modify git tags unless explicitly told to

## Validating a change

`make test` is the gate, and it is the operator's to run — see the rules above. It runs, in order: `lint` (`cargo fmt -- --check` and `cargo clippy --all-targets -- -D warnings`), the Go integration and unit tests, `prometheus-test`, every Rust integration test file explicitly, `cargo test`, and the JavaScript lint/integration/unit tests. `make test-log` captures the whole run to a timestamped log file, which is the better choice when the run is long.

Narrower targets exist and are listed in `DESIGN.md` under Build System — `make lint`, `make rust-test`, `make go-test`, `make js-test`, `make bench`.

Two obligations fall on whoever adds a test rather than on the person running it:

- **A new Rust integration test file must be added to the Makefile's `rust-integration-test` recipe.** That recipe names each file explicitly; a file only picked up by the trailing `cargo test` still runs, but it stops being visible as its own step and a failure inside it reads as a failure of everything.
- **A test must not touch the host.** Temp dirs, ephemeral ports and in-memory or per-test SQLite files only. Nothing writes to the working tree, binds a fixed privileged port, or reaches the public internet — the suites that exercise upstream resolution point their roots at a dead loopback address or at the in-process mock hierarchies precisely so a green run never depends on the network.

## Writing tests

The suites in this repository are built around one idea, stated in the module docs at the top of each file and worth repeating here: **an assertion without its control proves nothing.** A blocklist that blocks everything satisfies "the listed name is refused"; one that blocks nothing satisfies "the allowlisted name resolves". A DNSSEC validator that rejects everything passes every attack test and one that accepts everything passes every happy-path test. Write the pair.

- **Never weaken an assertion to make a test pass.** This applies with particular force to the `tests/security_*.rs` suites: each pins the behaviour one security finding requires, and a failure there is the finding, not a broken test.
- Prefer proving the property over proving the call returned `success`. Query *counts* are what distinguish a cache bug from its fix; a *verdict* is what distinguishes a validator from a parser; a re-derived signature is what distinguishes a checkable signature from a stored blob.
- Do not compare an encoder against itself. Wire-format expectations are written out longhand.
- Drive mutations through the real control plane (gRPC) and read results back over a real socket where the point is that the pipeline is wired up. Unit tests stay green through a regression that moved a gate relative to the response cache.

## Metrics

- **Every label dimension must be bounded** — a fixed enum, or bounded by configuration. Anything a client controls folds into a catch-all (`OTHER` for query types, `other` for TLDs). Query names are never labels.
- **New label values are appended, never inserted.** The `BLOCK_*`-style constants are positions in a pre-allocated array; an insertion silently relabels every existing counter.
- Adding or renaming a metric means updating the family count and the affected queries in `README.md` and `DESIGN.md` — `tests/promql_docs_test.rs` reads both, pins the documented family count against what the registry emits, and resolves every documented PromQL query against live exposition output. `tests/prometheus_integration_test.rs` then runs the same queries through a real Prometheus.

## Documentation

- Behaviour changes land in `DESIGN.md` in the same change that makes them. It is the specification, not a summary written afterwards.
- A new top-level documentation file must be added to the `include` list in `Cargo.toml`. The package ships its own tests, and a package carrying a test but not its input is a test that cannot run — which is exactly the relationship `tests/promql_docs_test.rs` has with `README.md` and `DESIGN.md`.
- `README.md` and `DESIGN.md` are the two files scanned for ```promql blocks. A block relabelled to another language stops being checked.
