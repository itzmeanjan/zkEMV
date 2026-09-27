.DEFAULT_GOAL := help

CIRCUITS_DIR := circuits
EMV_DIR      := emv
PY_SCRIPTS   := $(CIRCUITS_DIR)/scripts
VENV         := .venv
VENV_BIN     := $(VENV)/bin
VENV_STAMP   := $(VENV)/.requirements-installed

.PHONY: help
help: ## Prints help menu
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: test-circuits
test-circuits: ## Runs the Noir circuit tests
	cd $(CIRCUITS_DIR) && nargo test --workspace

.PHONY: test-e2e
test-e2e: ## Compiles the circuits, then proves and verifies the synthetic taps through the emv crate
	cd $(CIRCUITS_DIR) && nargo compile --workspace
	cd $(EMV_DIR) && cargo test --release

$(VENV_STAMP): requirements.txt
	python3 -m venv $(VENV)
	$(VENV_BIN)/pip install -r requirements.txt
	touch $@

.PHONY: venv
venv: $(VENV_STAMP) ## Creates the Python venv from requirements.txt, if missing or outdated

.PHONY: lint
lint: $(VENV_STAMP) ## Type-checks the Python scripts, lints the emv crate, and checks its API docs
	$(VENV_BIN)/mypy
	cd $(EMV_DIR) && cargo clippy --all-targets -- -D warnings
	cd $(EMV_DIR) && RUSTDOCFLAGS="-D warnings" cargo doc --no-deps

.PHONY: format
format: $(VENV_STAMP) ## Formats the Python scripts, the Noir circuits and the emv crate
	$(VENV_BIN)/black $(PY_SCRIPTS)
	cd $(CIRCUITS_DIR) && nargo fmt
	cd $(EMV_DIR) && cargo fmt

.PHONY: format-check
format-check: $(VENV_STAMP) ## Fails if any Python, Noir or Rust source is not formatted
	$(VENV_BIN)/black --check $(PY_SCRIPTS)
	cd $(CIRCUITS_DIR) && nargo fmt --check
	cd $(EMV_DIR) && cargo fmt --check

.PHONY: clean
clean: ## Removes build outputs, proving artifacts and Python caches; keeps the venv
	rm -rf $(CIRCUITS_DIR)/target $(CIRCUITS_DIR)/artifacts $(EMV_DIR)/target .mypy_cache
	find . -path ./$(VENV) -prune -o -type d -name __pycache__ -exec rm -rf {} +
