# Convenience wrappers around the cargo commands in CLAUDE.md.
# Run `make` or `make help` for the list.

CARGO ?= cargo
# Extra flags, e.g. `make test ARGS=chain`, `make run ARGS="--network test"`.
ARGS ?=

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# ---- build ---------------------------------------------------------------

.PHONY: build
build: ## Debug build of the whole workspace
	$(CARGO) build --workspace

.PHONY: release
release: ## Optimized build of the nulld binary
	$(CARGO) build --release -p null-node

.PHONY: doc
doc: ## Build the docs without dependencies
	$(CARGO) doc --workspace --no-deps

# ---- checks --------------------------------------------------------------

.PHONY: test
test: ## Run the workspace tests (make test ARGS=<filter>)
	$(CARGO) test --workspace $(ARGS)

.PHONY: clippy
clippy: ## Lint with warnings denied
	$(CARGO) clippy --workspace --all-targets -- -D warnings

.PHONY: fmt
fmt: ## Format the code in place
	$(CARGO) fmt --all

.PHONY: fmt-check
fmt-check: ## Check formatting without changing files
	$(CARGO) fmt --all -- --check

# Everything CI enforces, in one command. Run before committing.
.PHONY: check
check: fmt-check clippy test ## fmt-check + clippy + test, the pre-commit gate

# ---- running -------------------------------------------------------------

.PHONY: run
run: release ## Run a node (make run ARGS="--network test --mine <ADDR> ...")
	./target/release/nulld run $(ARGS)

.PHONY: keygen
keygen: release ## Print a fresh seed phrase, key and address
	./target/release/nulld keygen

.PHONY: wallet-rpc
wallet-rpc: release ## Run the wallet daemon (make wallet-rpc ARGS="--wallet w.redb --node-token-file rpc.token ...")
	./target/release/null-wallet-rpc $(ARGS)

.PHONY: desktop
desktop: ## Run the native wallet with its embedded node and RPC
	$(CARGO) run --release -p null-desktop -- $(ARGS)

.PHONY: testnet
testnet: ## Two-node local testnet with a payment and faucet (scripts/testnet.sh)
	./scripts/testnet.sh

.PHONY: testnet-docker
testnet-docker: ## Six-container testnet (scripts/testnet-docker.sh)
	./scripts/testnet-docker.sh

# ---- fuzzing (needs the nightly cargo-fuzz toolchain) --------------------

.PHONY: fuzz
fuzz: ## Fuzz the wire decoder (make fuzz ARGS="-- -max_total_time=60")
	cd fuzz && $(CARGO) +nightly fuzz run decode $(ARGS)

# ---- housekeeping --------------------------------------------------------

.PHONY: clean
clean: ## Remove build artifacts
	$(CARGO) clean
