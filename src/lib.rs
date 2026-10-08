//! Post-quantum key encapsulation (ML-KEM), signatures (ML-DSA), and Argon2id
//! password hashing, built two ways from one implementation:
//!
//! - `bindgen` (default): the wasm-bindgen surface published to npm as
//!   `wasm-pqc-subtle`, for browsers and Node (`wasm32-unknown-unknown`).
//! - `component`: a WebAssembly component exporting `pqc-subtle:crypto@0.1.0`
//!   (`wit/world.wit`), for `wasm32-wasip2`, composable into other components.
//!
//! `algorithms` is the shared core and is also usable from native Rust.

pub mod algorithms;

#[cfg(feature = "bindgen")]
mod bindgen;
#[cfg(feature = "bindgen")]
pub use bindgen::*;

// Only on wasm32: `export!` emits component export symbols the native linker cannot resolve.
#[cfg(all(feature = "component", target_arch = "wasm32"))]
mod component;
