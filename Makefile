# WASM PQC Subtle Build & Optimize

WASM_OPT := $(shell command -v wasm-opt 2>/dev/null)

.PHONY: all build optimize clean publish test fmt component smoke

all: optimize

build:
	wasm-pack build --target web --release

optimize: build
ifeq ($(WASM_OPT),)
	@echo "wasm-opt not found; skipping extra size optimization"
else
	@echo "Running extra size optimization with wasm-opt -Oz..."
	$(WASM_OPT) -Oz --enable-bulk-memory pkg/wasm_pqc_subtle_bg.wasm -o pkg/wasm_pqc_subtle_bg.wasm
	@echo "Optimized WASM size:"
	@ls -lh pkg/wasm_pqc_subtle_bg.wasm
endif

publish: optimize
	cd pkg && npm publish --access public

test:
	cargo test --all-features
	cargo fmt --all -- --check

# WebAssembly component (pqc-subtle:crypto@0.1.0) for wasm32-wasip2 -> dist/pqc-subtle.wasm
component:
	scripts/build-component.sh

# Compose tests/smoke-consumer with the component (wac plug) and run it under wasmtime
smoke: component
	scripts/smoke.sh

fmt:
	cargo fmt --all

clean:
	rm -rf target pkg dist
