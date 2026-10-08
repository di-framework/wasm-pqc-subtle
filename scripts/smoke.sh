#!/usr/bin/env bash
# Compose tests/smoke-consumer with dist/pqc-subtle.wasm (`wac plug`) and run
# the result under wasmtime. Proves the component works through real imports.
#
#   scripts/smoke.sh        (run scripts/build-component.sh first)
#
# Needs wasm-tools, wac, and wasmtime on PATH.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

log() { printf '[smoke] %s\n' "$*" >&2; }
die() { printf '[smoke] error: %s\n' "$*" >&2; exit 1; }

TARGET=wasm32-wasip2
for tool in wasm-tools wac wasmtime; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool not found on PATH"
done
PROVIDER=dist/pqc-subtle.wasm
[ -f "$PROVIDER" ] || die "$PROVIDER missing; run scripts/build-component.sh first"

log "building smoke consumer"
cargo build --locked --release --target "$TARGET" -p pqc-smoke-consumer
CONSUMER="target/$TARGET/release/pqc-smoke-consumer.wasm"
wasm-tools component wit "$CONSUMER" | grep -q 'import pqc-subtle:crypto/argon2@0.1.0' \
  || die "consumer does not import pqc-subtle:crypto/argon2@0.1.0"

mkdir -p target/smoke
COMPOSED=target/smoke/composed.wasm
log "composing with wac plug"
wac plug --plug "$PROVIDER" "$CONSUMER" -o "$COMPOSED"
# Only the type-only `types` interface may remain; every function import must be satisfied.
if wasm-tools component wit "$COMPOSED" | grep -E 'import pqc-subtle:crypto/(ml-kem|ml-dsa|argon2)'; then
  die "a pqc-subtle function interface is still imported after composition"
fi
log "running under wasmtime"
wasmtime run "$COMPOSED"
