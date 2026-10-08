// The component surface of @di-framework/wasm-pqc-subtle for JavaScript that runs inside a
// WebAssembly component (componentize-qjs, jco). Every export here is a WIT
// import of `pqc-subtle:crypto@0.1.0`; the bundler leaves these specifiers
// external and the build composes `pqc-subtle.wasm` in with `wac plug`. There
// is nothing to initialize and no `WebAssembly` API involved.
//
// Not for browsers or Node: use the package root there.
export * as mlKem from 'pqc-subtle:crypto/ml-kem@0.1.0';
export * as mlDsa from 'pqc-subtle:crypto/ml-dsa@0.1.0';
export * as argon2 from 'pqc-subtle:crypto/argon2@0.1.0';
export { hash as argon2idHash, verify as argon2Verify } from 'pqc-subtle:crypto/argon2@0.1.0';
