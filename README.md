# wasm-pqc-subtle

Post-quantum key encapsulation, digital signatures, and password hashing for the browser. A WebAssembly library implementing [ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) (FIPS 203), [ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) (FIPS 204), and [Argon2](https://datatracker.ietf.org/doc/html/rfc9106), compiled from Rust.

## Overview

This library provides ML-KEM, ML-DSA, and Argon2 via WebAssembly, enabling post-quantum key exchange, digital signatures, and modern password hashing in web applications. It wraps the [`ml-kem`](https://crates.io/crates/ml-kem), [`ml-dsa`](https://crates.io/crates/ml-dsa), and [`argon2`](https://crates.io/crates/argon2) Rust crates using [`wasm-bindgen`](https://crates.io/crates/wasm-bindgen) and targets the `wasm32-unknown-unknown` platform.

**WASM binary size:** ~68 KB (optimized with LTO + binaryen)

### Supported Algorithms

| Algorithm | NIST Security Level | Use Case |
|-----------|-------------------|----------|
| ML-KEM-768 | Level 3 (~192-bit) | Default. Recommended for most applications. |
| ML-KEM-1024 | Level 5 (~256-bit) | Higher security margin. |
| ML-DSA-44 | Level 2 (~128-bit) | Digital signatures (compact). |
| ML-DSA-65 | Level 3 (~192-bit) | Standard digital signatures. |
| ML-DSA-87 | Level 5 (~256-bit) | High-security digital signatures. |

## Installation

```bash
npm install wasm-pqc-subtle
```

## Usage

### Key Encapsulation (ML-KEM)

```javascript
import init, {
  ml_kem_768_generate_keypair,
  ml_kem_768_encapsulate,
  ml_kem_768_decapsulate,
} from "wasm-pqc-subtle";

await init();

// Generate a keypair
const keypair = ml_kem_768_generate_keypair();

// Encapsulate: produce a ciphertext and shared secret from the public key
const result = ml_kem_768_encapsulate(keypair.public_key);

// Decapsulate: recover the shared secret from the ciphertext and secret key
const sharedSecret = ml_kem_768_decapsulate(keypair.secret_key, result.ciphertext);

// result.shared_secret and sharedSecret are identical
```

ML-KEM-1024 functions follow the same pattern (`ml_kem_1024_generate_keypair`, etc.). Convenience aliases `kem_generate_keypair`, `kem_encapsulate`, and `kem_decapsulate` default to ML-KEM-768.

### Digital Signatures (ML-DSA)

```javascript
import init, {
  ml_dsa_65_generate_keypair,
  ml_dsa_65_sign,
  ml_dsa_65_verify,
} from "wasm-pqc-subtle";

await init();

const message = new TextEncoder().encode("Hello Post-Quantum!");

// Generate a keypair
const keypair = ml_dsa_65_generate_keypair();

// Sign
const signature = ml_dsa_65_sign(keypair.secret_key, message);

// Verify
const isValid = ml_dsa_65_verify(keypair.public_key, message, signature);
```

ML-DSA-44 and ML-DSA-87 functions follow the same pattern (`ml_dsa_44_generate_keypair`, etc.). Convenience aliases `dsa_generate_keypair`, `dsa_sign`, and `dsa_verify` default to ML-DSA-65.

### Password Hashing (Argon2)

```javascript
import init, { argon2id_hash, argon2_verify } from "wasm-pqc-subtle";

await init();

const password = new TextEncoder().encode("correct horse battery staple");

// Hash using Argon2id with a random salt and recommended defaults
const phc = argon2id_hash(password); // returns a PHC string like "$argon2id$v=19$m=...$...$..."

// Verify
const ok = argon2_verify(password, phc); // true
const bad = argon2_verify(new TextEncoder().encode("wrong"), phc); // false
```

Notes:
- `argon2id_hash` generates a secure random salt internally and returns a standard PHC string.
- `argon2_verify` parses the PHC string and verifies using parameters embedded in it.
- Defaults are tuned by the upstream `argon2` crate and suitable for browsers; adjust at build-time if you need stricter limits.

## WebAssembly component (wasm32-wasip2)

The same implementation also builds as a [WebAssembly component](https://component-model.bytecodealliance.org/) exporting `pqc-subtle:crypto@0.1.0` (`wit/world.wit`): interfaces `ml-kem`, `ml-dsa`, and `argon2`. Use it where there is no JavaScript `WebAssembly` API, for example inside another component (a QuickJS or Rust guest on wasmCloud or wasmtime), by composing it in at build time with [`wac plug`](https://github.com/bytecodealliance/wac).

```sh
rustup target add wasm32-wasip2
cargo binstall wasm-tools wac-cli     # or cargo install
make component                        # -> dist/pqc-subtle.wasm (+ .wit, BUILD-INFO)
make smoke                            # compose tests/smoke-consumer with it and run under wasmtime
```

A consumer declares the imports in its own WIT (the `imports` world in `wit/world.wit` is that list) and gets bindings from `wit-bindgen`, `jco`, or componentize-qjs. Then:

```sh
wac plug --plug dist/pqc-subtle.wasm consumer.wasm -o composed.wasm
```

After plugging, the only `pqc-subtle` name left on the composed component is the type-only `types` interface; every function import is satisfied. The component itself imports `wasi:random/random` for salts and keys, plus the `wasi:cli`/`wasi:io` set the Rust standard library needs.

```wit
interface argon2 {
  record params { memory-kib: u32, iterations: u32, parallelism: u32, output-length: option<u32> }
  hash: func(password: list<u8>, params: option<params>) -> result<string, error>;
  verify: func(password: list<u8>, phc: string) -> result<bool, error>;
}
```

`hash` with `params` absent uses the `argon2` crate defaults (m=19456 KiB, t=2, p=1). Pass explicit parameters for parity with hashes made elsewhere, for example Spring Security's m=16384, t=2, p=1; `verify` always reads the parameters from the PHC string. The wasm-bindgen surface gained `argon2id_hash_with_params(password, memory_kib, iterations, parallelism)` for the same reason.

Cargo features: `bindgen` (default) is the wasm-bindgen surface; `component` is the WIT world. The core lives in `src/algorithms.rs` and is plain Rust, also usable natively.

## API

### ML-KEM API

#### `ml_kem_768_generate_keypair() -> KemKeyPair`

Generates an ML-KEM-768 key pair.

#### `ml_kem_768_encapsulate(public_key: Uint8Array) -> CiphertextAndSharedSecret`

Encapsulates against a public key, returning a ciphertext and shared secret.

#### `ml_kem_768_decapsulate(secret_key: Uint8Array, ciphertext: Uint8Array) -> Uint8Array`

Decapsulates a ciphertext with a secret key, returning the shared secret.

#### `ml_kem_1024_generate_keypair()` / `ml_kem_1024_encapsulate()` / `ml_kem_1024_decapsulate()`

Same interface as above, using ML-KEM-1024 parameters.

#### `kem_generate_keypair()` / `kem_encapsulate()` / `kem_decapsulate()`

Convenience aliases that use ML-KEM-768.

### ML-DSA API

#### `ml_dsa_65_generate_keypair() -> DsaKeyPair`

Generates an ML-DSA-65 key pair.

#### `ml_dsa_65_sign(secret_key: Uint8Array, message: Uint8Array) -> Uint8Array`

Signs a message with a secret key.

#### `ml_dsa_65_verify(public_key: Uint8Array, message: Uint8Array, signature: Uint8Array) -> boolean`

Verifies a signature against a public key and message.

#### `ml_dsa_44_generate_keypair()` / `ml_dsa_44_sign()` / `ml_dsa_44_verify()`
#### `ml_dsa_87_generate_keypair()` / `ml_dsa_87_sign()` / `ml_dsa_87_verify()`

Same interface as above, using ML-DSA-44 or ML-DSA-87 parameters.

#### `dsa_generate_keypair()` / `dsa_sign()` / `dsa_verify()`

Convenience aliases that use ML-DSA-65.

### Argon2 API

#### `argon2id_hash(password: Uint8Array) -> string`

Hashes a password using Argon2id (v=0x13) with a securely generated random salt. Returns a PHC-formatted string suitable for storage.

#### `argon2_verify(password: Uint8Array, phc: string) -> boolean`

Verifies a password against a PHC-formatted Argon2 hash.

### Types

```typescript
class KemKeyPair {
  readonly public_key: Uint8Array;
  readonly secret_key: Uint8Array;
}

class DsaKeyPair {
  readonly public_key: Uint8Array;
  readonly secret_key: Uint8Array;
}

class CiphertextAndSharedSecret {
  readonly ciphertext: Uint8Array;
  readonly shared_secret: Uint8Array;
}
```

## Building from Source

### Prerequisites

- [Rust](https://rustup.rs/)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)
- [binaryen](https://github.com/WebAssembly/binaryen) (for `wasm-opt`)

### Build

```bash
make all
```

This runs `wasm-pack build --target web --release` followed by `wasm-opt -Oz` for size optimization. Output goes to `./pkg/`.

### Test

Open `index.html` in a browser (served over HTTP) to run the ML-KEM, ML-DSA, and Argon2 test suite.

### Publish

```bash
make publish
```

## Export Control Notice

This software implements cryptographic functionality and is subject to export controls.

**ECCN:** 5D002 — This software is classified under Export Control Classification Number 5D002 ("Information Security" software) on the Commerce Control List (CCL).

**License Exception:** This software is publicly available open-source encryption source code, distributed under License Exception TSU (Technology and Software Unrestricted) pursuant to 15 CFR 740.13(e) of the U.S. Export Administration Regulations (EAR). The compiled WebAssembly binary is distributed under License Exception ENC pursuant to 15 CFR 740.17(b).

**Notification:** In accordance with 15 CFR 742.15(b), a notification has been or should be submitted to the Bureau of Industry and Security (crypt@bis.gov) and the ENC Encryption Request Coordinator (enc@nsa.gov) prior to or concurrent with the first public release of this software.

**Restrictions:** This software may not be exported or re-exported to any country in U.S. Country Group E:1 (currently Cuba, Iran, North Korea, Syria, and the Crimea/Donetsk/Luhansk regions of Ukraine) or to any person or entity on the BIS Denied Persons List, Entity List, or Unverified List.

**International:** Users outside the United States should be aware that similar controls may apply under the Wassenaar Arrangement, EU Dual-Use Regulation (EU 2021/821), and other national export control regimes. The Wassenaar Arrangement's General Software Note provides decontrol for software that is "in the public domain," though implementation varies by jurisdiction.

**This is not legal advice.** Export control regulations are complex and subject to change. Consult a qualified export control attorney for compliance guidance specific to your circumstances.

## License

See repository for license terms.
