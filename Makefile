.DEFAULT_GOAL := help

CIRCUITS_DIR := circuits
EMV_DIR      := emv
CIRCUITS     := visa_fdda mastercard_dda
ANDROID_DIR  ?= /data/local/tmp/zkemv
ANDROID_OUT  := $(EMV_DIR)/target/android

.PHONY: help
help: ## Prints help menu
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: test-circuits
test-circuits: ## Runs the Noir circuit tests
	cd $(CIRCUITS_DIR) && nargo test --workspace

.PHONY: fixtures
fixtures: ## Regenerates circuits/fixtures/ and each circuit's src/tests/vectors.nr from the seed
	cd $(EMV_DIR) && cargo test --release --test fixtures -- --ignored
	cd $(CIRCUITS_DIR) && nargo fmt

.PHONY: test-e2e
test-e2e: ## Compiles the circuits, then proves and verifies the synthetic taps through the emv crate
	cd $(CIRCUITS_DIR) && nargo compile --workspace
	cd $(EMV_DIR) && cargo test --release

.PHONY: examples
examples: ## Compiles the circuits, then runs the examples: presence, per_verifier, per_event, bin_attributes
	cd $(CIRCUITS_DIR) && nargo compile --workspace
	cd $(EMV_DIR) && for e in presence per_verifier per_event bin_attributes; do cargo run --release --example $$e || exit 1; done

.PHONY: circuit-stats
circuit-stats: ## Compiles the circuits, then prints each one's R1CS constraint and witness counts under ProveKit
	cd $(CIRCUITS_DIR) && nargo compile --workspace
	@for c in $(CIRCUITS); do \
		out=$$(provekit-cli circuit-stats $(CIRCUITS_DIR)/target/$$c.json 2>&1) || { echo "$$out"; exit 1; }; \
		echo "$$c"; echo "$$out" | grep -E '^TOTAL (CONSTRAINTS|WITNESSES):' | sed 's/^/  /'; \
	done

.PHONY: bench
bench: ## Compiles the circuits, then benchmarks prove and verify of the synthetic taps with cargo-criterion
	cd $(CIRCUITS_DIR) && nargo compile --workspace
	cd $(EMV_DIR) && cargo criterion

.PHONY: bench-android
bench-android: ## Builds the benchmark for arm64 Android in Docker, then runs it on the adb device
	cd $(CIRCUITS_DIR) && nargo compile --workspace
	docker build -f Dockerfile.bench-android --output $(ANDROID_OUT) .
	adb shell 'rm -rf $(ANDROID_DIR) && mkdir -p $(ANDROID_DIR)/circuits/target $(ANDROID_DIR)/circuits/fixtures'
	adb push $(ANDROID_OUT)/prove_verify $(ANDROID_DIR)/
	adb push $(CIRCUITS_DIR)/target/*.json $(ANDROID_DIR)/circuits/target/
	adb push $(CIRCUITS_DIR)/fixtures/*.json $(ANDROID_DIR)/circuits/fixtures/
	adb shell 'cd $(ANDROID_DIR) && ZKEMV_CIRCUITS=$(ANDROID_DIR)/circuits ./prove_verify --bench --noplot'

.PHONY: lint
lint: lint-noir lint-rust ## Runs all lints to preserve quality of code

.PHONY: lint-noir
lint-noir: ## Fails on any Noir compiler warning, under-constrained value checks included
	cd $(CIRCUITS_DIR) && nargo check --workspace --deny-warnings

.PHONY: lint-rust
lint-rust: ## Lints the emv crate and checks its API docs
	! grep -rnE '#!?\[(allow|expect)\(' $(EMV_DIR)/src $(EMV_DIR)/tests $(EMV_DIR)/benches $(EMV_DIR)/examples
	cd $(EMV_DIR) && cargo clippy --all-targets -- -D warnings
	cd $(EMV_DIR) && RUSTDOCFLAGS="-D warnings" cargo doc --no-deps

.PHONY: format
format: ## Formats the Noir circuits and the emv crate
	cd $(CIRCUITS_DIR) && nargo fmt
	cd $(EMV_DIR) && cargo fmt

.PHONY: format-check
format-check: format-check-noir format-check-rust ## Runs source format checks

.PHONY: format-check-noir
format-check-noir: ## Fails if any Noir circuit is not formatted
	cd $(CIRCUITS_DIR) && nargo fmt --check

.PHONY: format-check-rust
format-check-rust: ## Fails if the emv crate is not formatted
	cd $(EMV_DIR) && cargo fmt --check

.PHONY: clean
clean: ## Removes build outputs and proving artifacts
	rm -rf $(CIRCUITS_DIR)/target $(CIRCUITS_DIR)/artifacts $(EMV_DIR)/target
