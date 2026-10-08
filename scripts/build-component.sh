#!/usr/bin/env bash
# Build the pqc-subtle:crypto@0.1.0 WebAssembly component for wasm32-wasip2.
#
#   scripts/build-component.sh [--debug]
#
# Output: dist/pqc-subtle.wasm (the component), dist/pqc-subtle.wit (its
# resolved world), dist/BUILD-INFO. Needs the wasm32-wasip2 rust-std
# (`rustup target add wasm32-wasip2`) and wasm-tools on PATH.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

PROFILE=release
PROFILE_DIR=release
for arg in "$@"; do
  case "$arg" in
    --debug) PROFILE=dev; PROFILE_DIR=debug ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

log() { printf '[component] %s\n' "$*" >&2; }
die() { printf '[component] error: %s\n' "$*" >&2; exit 1; }

TARGET=wasm32-wasip2
command -v cargo >/dev/null 2>&1 || die "cargo not found"
command -v wasm-tools >/dev/null 2>&1 || die "wasm-tools not found (cargo binstall wasm-tools)"
if command -v rustup >/dev/null 2>&1 \
  && ! rustup target list --installed 2>/dev/null | grep -qx "$TARGET"; then
  log "installing $TARGET via rustup"
  rustup target add "$TARGET"
fi

log "rustc:      $(rustc --version)"
log "wasm-tools: $(wasm-tools --version)"
log "profile:    $PROFILE"
cargo build --locked --profile "$PROFILE" --target "$TARGET" \
  --no-default-features --features component -p wasm-pqc-subtle

WASM_IN="target/$TARGET/$PROFILE_DIR/wasm_pqc_subtle.wasm"
[ -f "$WASM_IN" ] || die "expected output missing: $WASM_IN"
mkdir -p dist
WASM_OUT="dist/pqc-subtle.wasm"
cp "$WASM_IN" "$WASM_OUT"
wasm-tools validate --features all "$WASM_OUT"
wasm-tools component wit "$WASM_OUT" > dist/pqc-subtle.wit
for iface in ml-kem ml-dsa argon2; do
  grep -q "export pqc-subtle:crypto/$iface@0.1.0" dist/pqc-subtle.wit \
    || die "component does not export pqc-subtle:crypto/$iface@0.1.0 (see dist/pqc-subtle.wit)"
done
{
  echo "component:  pqc-subtle:crypto@0.1.0"
  echo "profile:    $PROFILE"
  echo "built:      $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "rustc:      $(rustc --version)"
  echo "target:     $TARGET"
  echo "wasm-tools: $(wasm-tools --version)"
  echo "size:       $(wc -c < "$WASM_OUT" | tr -d ' ') bytes"
} > dist/BUILD-INFO
log "ok: $WASM_OUT ($(wc -c < "$WASM_OUT" | tr -d ' ') bytes)"
