# Shortcuts for the commands CI runs. `make` on its own lists them.
.DEFAULT_GOAL := help
.PHONY: help fmt lint test check audit ci build run demo docker clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

fmt: ## Format the code
	cargo fmt --all

lint: ## Format check + clippy, as CI runs them
	cargo fmt --all --check
	cargo clippy --all-targets --all-features -- -D warnings

test: ## Run every test
	cargo test --all-features --locked

check: ## Validate the example config
	cargo run --quiet -- --config vega.example.toml check

audit: ## Licence and advisory checks
	cargo deny check

ci: lint test check ## Everything CI would run
	@echo "ok"

build: ## Release build
	cargo build --release --locked

run: ## Run against the example config on port 1053
	cargo run -- --config vega.example.toml \
		--udp 127.0.0.1:1053 --tcp 127.0.0.1:1053 \
		--admin-listen 127.0.0.1:9100

demo: ## Build a throwaway zone in /tmp and query it
	@cargo run --quiet -- init --origin demo.test --output /tmp/demo.toml || true
	cargo run --quiet -- --config /tmp/demo.toml record add www A 203.0.113.10
	cargo run --quiet -- --config /tmp/demo.toml zone show
	@echo "now run: cargo run -- --config /tmp/demo.toml --udp 127.0.0.1:1053"

docker: ## Build the container image
	docker build -t vega:dev .

clean: ## Remove build artifacts
	cargo clean
