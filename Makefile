.DEFAULT_GOAL := help

CIRCUITS_DIR := circuits
EMV_DIR      := emv
CIRCUITS     := visa_fdda mastercard_dda
PY_SCRIPTS   := $(CIRCUITS_DIR)/scripts
VENV         := .venv
VENV_BIN     := $(VENV)/bin
VENV_STAMP   := $(VENV)/.requirements-installed
ANDROID_DIR  ?= /data/local/tmp/zkemv
ANDROID_OUT  := $(EMV_DIR)/target/android
APP_DIR      := app
NATIVE_DIR   := $(APP_DIR)/native
APP_ASSETS   := $(APP_DIR)/assets/generated
APP_JNI      := $(APP_DIR)/android/app/src/main/jniLibs/arm64-v8a
# Flutter's default ndkVersion, and the app's minSdk.
NDK_VERSION  ?= 28.2.13676358
ANDROID_API  ?= 24
NDK_BIN      := $(ANDROID_HOME)/ndk/$(NDK_VERSION)/toolchains/llvm/prebuilt/linux-x86_64/bin
# Cargo features of the app's native library, e.g. self-test (proves the synthetic taps under the test CA).
NATIVE_FEATURES ?=

.PHONY: help
help: ## Prints help menu
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'

.PHONY: test-circuits
test-circuits: ## Runs the Noir circuit tests
	cd $(CIRCUITS_DIR) && nargo test --workspace

.PHONY: test-e2e
test-e2e: ## Compiles the circuits, then proves and verifies the synthetic taps through the emv crate
	cd $(CIRCUITS_DIR) && nargo compile --workspace
	cd $(EMV_DIR) && cargo test --release

.PHONY: examples
examples: ## Compiles the circuits, then runs the visa_fdda examples: presence, per_verifier, per_event
	cd $(CIRCUITS_DIR) && nargo compile --workspace
	cd $(EMV_DIR) && for e in presence per_verifier per_event; do cargo run --release --example $$e || exit 1; done

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

.PHONY: app-keys
app-keys: ## Compiles the circuits, then writes the app's proving and verifying keys and CA table to its assets
	cd $(CIRCUITS_DIR) && nargo compile --workspace
	cd $(NATIVE_DIR) && cargo run --locked --release --bin prepare-keys -- ../assets/generated/keys $(foreach c,$(CIRCUITS),../../$(CIRCUITS_DIR)/target/$(c).json)
	cp data/certificate-authority-public-keys.json $(APP_ASSETS)/

.PHONY: app-native
app-native: ## Cross-compiles the app's native library for arm64 Android with the NDK
	cd $(NATIVE_DIR) && \
	CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$(NDK_BIN)/aarch64-linux-android$(ANDROID_API)-clang \
	CC_aarch64_linux_android=$(NDK_BIN)/aarch64-linux-android$(ANDROID_API)-clang \
	AR_aarch64_linux_android=$(NDK_BIN)/llvm-ar \
	CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS="-C link-arg=-Wl,-z,max-page-size=16384" \
	cargo build --locked --release --target aarch64-linux-android --lib --features "$(NATIVE_FEATURES)"
	mkdir -p $(APP_JNI)
	cp $(NATIVE_DIR)/target/aarch64-linux-android/release/libzkemv.so $(APP_JNI)/

# The native library is built for arm64 only, and always in release: prove time is meaningless otherwise.
.PHONY: app-debug
app-debug: app-keys app-native ## Builds the app's debug APK
	cd $(APP_DIR) && flutter build apk --debug --target-platform android-arm64

.PHONY: app-release
app-release: app-keys app-native ## Builds the app's release APK
	cd $(APP_DIR) && flutter build apk --release --target-platform android-arm64

# `adb install -r` replaces the APK and keeps the app's data (its wallet). Both build types are
# signed with the debug key, so either can replace the other.
.PHONY: app-install-debug
app-install-debug: ## Installs the app's debug APK on the adb device, keeping its data
	adb install -r $(APP_DIR)/build/app/outputs/flutter-apk/app-debug.apk

.PHONY: app-install-release
app-install-release: ## Installs the app's release APK on the adb device, keeping its data
	adb install -r $(APP_DIR)/build/app/outputs/flutter-apk/app-release.apk

.PHONY: app-reinstall-debug
app-reinstall-debug: app-debug app-install-debug ## Rebuilds the debug APK and reinstalls it, keeping the app's data

.PHONY: app-reinstall-release
app-reinstall-release: app-release app-install-release ## Rebuilds the release APK and reinstalls it, keeping the app's data

.PHONY: test-app-native
test-app-native: ## Compiles the circuits, then tests the app's native library on the host
	cd $(CIRCUITS_DIR) && nargo compile --workspace
	cd $(NATIVE_DIR) && cargo test --locked --release --features self-test

$(VENV_STAMP): requirements.txt
	python3 -m venv $(VENV)
	$(VENV_BIN)/pip install -r requirements.txt
	touch $@

.PHONY: venv
venv: $(VENV_STAMP) ## Creates the Python venv from requirements.txt, if missing or outdated

.PHONY: lint
lint: lint-python lint-noir lint-rust ## Runs all lints to preserve quality of code

.PHONY: lint-python
lint-python: $(VENV_STAMP) ## Type-checks the Python scripts
	$(VENV_BIN)/mypy

.PHONY: lint-noir
lint-noir: ## Fails on any Noir compiler warning, under-constrained value checks included
	cd $(CIRCUITS_DIR) && nargo check --workspace --deny-warnings

.PHONY: lint-rust
lint-rust: ## Lints the emv crate and checks its API docs
	! grep -rnE '#!?\[(allow|expect)\(' $(EMV_DIR)/src $(EMV_DIR)/tests $(EMV_DIR)/benches $(EMV_DIR)/examples
	cd $(EMV_DIR) && cargo clippy --all-targets -- -D warnings
	cd $(EMV_DIR) && RUSTDOCFLAGS="-D warnings" cargo doc --no-deps

.PHONY: format
format: $(VENV_STAMP) ## Formats the Python scripts, the Noir circuits and the emv crate
	$(VENV_BIN)/black $(PY_SCRIPTS)
	cd $(CIRCUITS_DIR) && nargo fmt
	cd $(EMV_DIR) && cargo fmt

.PHONY: format-check
format-check: format-check-python format-check-noir format-check-rust ## Runs source format checks

.PHONY: format-check-python
format-check-python: $(VENV_STAMP) ## Fails if any Python script is not formatted
	$(VENV_BIN)/black --check $(PY_SCRIPTS)

.PHONY: format-check-noir
format-check-noir: ## Fails if any Noir circuit is not formatted
	cd $(CIRCUITS_DIR) && nargo fmt --check

.PHONY: format-check-rust
format-check-rust: ## Fails if the emv crate is not formatted
	cd $(EMV_DIR) && cargo fmt --check

.PHONY: clean
clean: ## Removes build outputs, proving artifacts and Python caches; keeps the venv
	rm -rf $(CIRCUITS_DIR)/target $(CIRCUITS_DIR)/artifacts $(EMV_DIR)/target .mypy_cache
	find . -path ./$(VENV) -prune -o -type d -name __pycache__ -exec rm -rf {} +
