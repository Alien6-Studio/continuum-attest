# Convenience wrapper around cargo. Nothing here is required to build or
# contribute — `cargo build`, `cargo test` and `cargo clippy` work on their
# own. The authoritative gates are in .github/workflows/ci.yml.

.PHONY: help build build-dev test lint fmt fmt-check check ci \
        dev-init dev-run bench docs docker install uninstall \
        audit deps update clean

RUST_LOG ?= info

help: ## Show this help message
	@echo "Continuum Attest"
	@echo ""
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ---------------------------------------------------------------- building

build: ## Build the release binary
	cargo build --release --locked

build-dev: ## Build in debug mode
	cargo build

install: build ## Install the binary to /usr/local/bin
	sudo cp target/release/attest /usr/local/bin/
	@echo "Installed. Run 'attest --help' to get started."

uninstall: ## Remove the locally installed binary
	sudo rm -f /usr/local/bin/attest

# ------------------------------------------------------------------ gates

fmt: ## Format the code
	cargo fmt --all

fmt-check: ## Check formatting without writing
	cargo fmt --all -- --check

# --lib --bins, not --all-targets: the workspace enables
# clippy::unwrap_used, denied in the library and expected in test code.
lint: ## Run clippy with warnings denied
	cargo clippy --lib --bins -- -D warnings

test: ## Run the test suite
	cargo test

check: fmt-check lint test ## Run every gate CI runs
	@echo "All gates passed."

ci: check ## Everything check does, plus a locked release build
	cargo build --release --locked

# ------------------------------------------------------------ development

dev-init: build-dev ## Initialize a throwaway workspace under target/dev
	@mkdir -p target/dev
	cd target/dev && RUST_LOG=$(RUST_LOG) $(CURDIR)/target/debug/attest init

dev-run: dev-init ## Run the throwaway pipeline with verification
	cd target/dev && RUST_LOG=$(RUST_LOG) $(CURDIR)/target/debug/attest run --verify

bench: ## Run the benchmarks
	cargo bench

docs: ## Build and open the API documentation
	cargo doc --no-deps --open

docker: ## Build the container image
	docker build -t continuum-attest:local .

# ----------------------------------------------------------- supply chain

# The same four checks CI enforces; see deny.toml for the policy.
audit: ## Check advisories, licences, bans and sources
	@command -v cargo-deny >/dev/null 2>&1 || cargo install cargo-deny --locked
	cargo deny check

deps: ## Show the dependency tree
	cargo tree

update: ## Update dependencies within the declared ranges
	cargo update

# ---------------------------------------------------------------- cleanup

clean: ## Remove build artifacts
	cargo clean
	rm -rf target/dev
	find . -name "*.profraw" -delete 2>/dev/null || true
