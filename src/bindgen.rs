//! The wasm-bindgen surface for browsers and Node: the `wasm-pqc-subtle` npm
//! package. Every function here delegates to `algorithms`.

use crate::algorithms::{self as alg, Argon2Params, Error, MlDsaSet, MlKemSet};
use wasm_bindgen::prelude::*;

fn js(error: Error) -> JsValue {
    JsValue::from_str(&error.to_string())
}

/// Key pair for ML-KEM (post-quantum KEM)
#[wasm_bindgen]
pub struct KemKeyPair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

#[wasm_bindgen]
impl KemKeyPair {
    /// Returns a copy of the ML-KEM public key (encapsulation key) as bytes
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    /// Returns a copy of the ML-KEM secret key (decapsulation key) as bytes
    #[wasm_bindgen(getter)]
    pub fn secret_key(&self) -> Vec<u8> {
        self.secret_key.clone()
    }
}

/// Key pair for ML-DSA (post-quantum digital signature scheme)
#[wasm_bindgen]
pub struct DsaKeyPair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

#[wasm_bindgen]
impl DsaKeyPair {
    /// Returns a copy of the ML-DSA verifying (public) key as bytes
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    /// Returns a copy of the ML-DSA signing (secret) key as bytes
    #[wasm_bindgen(getter)]
    pub fn secret_key(&self) -> Vec<u8> {
        self.secret_key.clone()
    }
}

/// Container for ML-KEM ciphertext + derived shared secret
#[wasm_bindgen]
pub struct CiphertextAndSharedSecret {
    ciphertext: Vec<u8>,
    shared_secret: Vec<u8>,
}

#[wasm_bindgen]
impl CiphertextAndSharedSecret {
    /// Returns a copy of the ML-KEM ciphertext
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    /// Returns a copy of the 32-byte shared secret derived from encapsulation
    #[wasm_bindgen(getter)]
    pub fn shared_secret(&self) -> Vec<u8> {
        self.shared_secret.clone()
    }
}

fn kem_pair(set: MlKemSet) -> KemKeyPair {
    let kp = alg::ml_kem_generate_keypair(set);
    KemKeyPair {
        public_key: kp.public_key,
        secret_key: kp.secret_key,
    }
}

fn kem_enc(set: MlKemSet, public_key: &[u8]) -> Result<CiphertextAndSharedSecret, JsValue> {
    let enc = alg::ml_kem_encapsulate(set, public_key).map_err(js)?;
    Ok(CiphertextAndSharedSecret {
        ciphertext: enc.ciphertext,
        shared_secret: enc.shared_secret,
    })
}

fn dsa_pair(set: MlDsaSet) -> DsaKeyPair {
    let kp = alg::ml_dsa_generate_keypair(set);
    DsaKeyPair {
        public_key: kp.public_key,
        secret_key: kp.secret_key,
    }
}

// ── ML-KEM-768 ──────────────────────────────────────────────────────────

/// Generates a fresh ML-KEM-768 key pair using OS RNG.
#[wasm_bindgen]
pub fn ml_kem_768_generate_keypair() -> Result<KemKeyPair, JsValue> {
    Ok(kem_pair(MlKemSet::MlKem768))
}

/// Performs ML-KEM-768 encapsulation using the provided public key (1184 bytes).
#[wasm_bindgen]
pub fn ml_kem_768_encapsulate(
    public_key_bytes: &[u8],
) -> Result<CiphertextAndSharedSecret, JsValue> {
    kem_enc(MlKemSet::MlKem768, public_key_bytes)
}

/// Performs ML-KEM-768 decapsulation (secret key 2400 bytes, ciphertext 1088 bytes).
#[wasm_bindgen]
pub fn ml_kem_768_decapsulate(
    secret_key_bytes: &[u8],
    ciphertext_bytes: &[u8],
) -> Result<Vec<u8>, JsValue> {
    alg::ml_kem_decapsulate(MlKemSet::MlKem768, secret_key_bytes, ciphertext_bytes).map_err(js)
}

// ── ML-KEM-1024 ─────────────────────────────────────────────────────────

/// Generates a fresh ML-KEM-1024 key pair using OS RNG.
#[wasm_bindgen]
pub fn ml_kem_1024_generate_keypair() -> Result<KemKeyPair, JsValue> {
    Ok(kem_pair(MlKemSet::MlKem1024))
}

/// Performs ML-KEM-1024 encapsulation.
#[wasm_bindgen]
pub fn ml_kem_1024_encapsulate(
    public_key_bytes: &[u8],
) -> Result<CiphertextAndSharedSecret, JsValue> {
    kem_enc(MlKemSet::MlKem1024, public_key_bytes)
}

/// Performs ML-KEM-1024 decapsulation.
#[wasm_bindgen]
pub fn ml_kem_1024_decapsulate(
    secret_key_bytes: &[u8],
    ciphertext_bytes: &[u8],
) -> Result<Vec<u8>, JsValue> {
    alg::ml_kem_decapsulate(MlKemSet::MlKem1024, secret_key_bytes, ciphertext_bytes).map_err(js)
}

// ── ML-KEM aliases (ML-KEM-768) ─────────────────────────────────────────

/// Alias: generate ML-KEM-768 key pair
#[wasm_bindgen]
pub fn kem_generate_keypair() -> Result<KemKeyPair, JsValue> {
    ml_kem_768_generate_keypair()
}

/// Alias: encapsulate using ML-KEM-768 public key
#[wasm_bindgen]
pub fn kem_encapsulate(public_key_bytes: &[u8]) -> Result<CiphertextAndSharedSecret, JsValue> {
    ml_kem_768_encapsulate(public_key_bytes)
}

/// Alias: decapsulate using ML-KEM-768 secret key + ciphertext
#[wasm_bindgen]
pub fn kem_decapsulate(
    secret_key_bytes: &[u8],
    ciphertext_bytes: &[u8],
) -> Result<Vec<u8>, JsValue> {
    ml_kem_768_decapsulate(secret_key_bytes, ciphertext_bytes)
}

// ── ML-DSA-44 ───────────────────────────────────────────────────────────

/// Generates a fresh ML-DSA-44 key pair.
#[wasm_bindgen]
pub fn ml_dsa_44_generate_keypair() -> Result<DsaKeyPair, JsValue> {
    Ok(dsa_pair(MlDsaSet::MlDsa44))
}

/// Signs a message using an ML-DSA-44 secret key.
#[wasm_bindgen]
pub fn ml_dsa_44_sign(secret_key_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, JsValue> {
    alg::ml_dsa_sign(MlDsaSet::MlDsa44, secret_key_bytes, message).map_err(js)
}

/// Verifies an ML-DSA-44 signature against a message and public key.
#[wasm_bindgen]
pub fn ml_dsa_44_verify(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, JsValue> {
    alg::ml_dsa_verify(
        MlDsaSet::MlDsa44,
        public_key_bytes,
        message,
        signature_bytes,
    )
    .map_err(js)
}

// ── ML-DSA-65 ───────────────────────────────────────────────────────────

/// Generates a fresh ML-DSA-65 key pair.
#[wasm_bindgen]
pub fn ml_dsa_65_generate_keypair() -> Result<DsaKeyPair, JsValue> {
    Ok(dsa_pair(MlDsaSet::MlDsa65))
}

/// Signs a message using an ML-DSA-65 secret key.
#[wasm_bindgen]
pub fn ml_dsa_65_sign(secret_key_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, JsValue> {
    alg::ml_dsa_sign(MlDsaSet::MlDsa65, secret_key_bytes, message).map_err(js)
}

/// Verifies an ML-DSA-65 signature.
#[wasm_bindgen]
pub fn ml_dsa_65_verify(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, JsValue> {
    alg::ml_dsa_verify(
        MlDsaSet::MlDsa65,
        public_key_bytes,
        message,
        signature_bytes,
    )
    .map_err(js)
}

// ── ML-DSA-87 ───────────────────────────────────────────────────────────

/// Generates a fresh ML-DSA-87 key pair.
#[wasm_bindgen]
pub fn ml_dsa_87_generate_keypair() -> Result<DsaKeyPair, JsValue> {
    Ok(dsa_pair(MlDsaSet::MlDsa87))
}

/// Signs a message using an ML-DSA-87 secret key.
#[wasm_bindgen]
pub fn ml_dsa_87_sign(secret_key_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, JsValue> {
    alg::ml_dsa_sign(MlDsaSet::MlDsa87, secret_key_bytes, message).map_err(js)
}

/// Verifies an ML-DSA-87 signature.
#[wasm_bindgen]
pub fn ml_dsa_87_verify(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, JsValue> {
    alg::ml_dsa_verify(
        MlDsaSet::MlDsa87,
        public_key_bytes,
        message,
        signature_bytes,
    )
    .map_err(js)
}

// ── ML-DSA aliases (ML-DSA-65) ──────────────────────────────────────────

/// Alias: generate ML-DSA-65 key pair (current default security level)
#[wasm_bindgen]
pub fn dsa_generate_keypair() -> Result<DsaKeyPair, JsValue> {
    ml_dsa_65_generate_keypair()
}

/// Alias: sign with ML-DSA-65
#[wasm_bindgen]
pub fn dsa_sign(secret_key_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, JsValue> {
    ml_dsa_65_sign(secret_key_bytes, message)
}

/// Alias: verify with ML-DSA-65
#[wasm_bindgen]
pub fn dsa_verify(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, JsValue> {
    ml_dsa_65_verify(public_key_bytes, message, signature_bytes)
}

// ── Argon2id ────────────────────────────────────────────────────────────

/// Hashes a password using Argon2id (v=0x13, the `argon2` crate's default
/// parameters: m=19456 KiB, t=2, p=1) and returns a PHC string with a random salt.
#[wasm_bindgen]
pub fn argon2id_hash(password: &[u8]) -> Result<String, JsValue> {
    alg::argon2id_hash(password, None).map_err(js)
}

/// Hashes a password using Argon2id with explicit cost parameters, for
/// parity with hashes produced elsewhere (for example Spring Security's
/// m=16384, t=2, p=1). Returns a PHC string with a random salt.
#[wasm_bindgen]
pub fn argon2id_hash_with_params(
    password: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<String, JsValue> {
    alg::argon2id_hash(
        password,
        Some(Argon2Params {
            memory_kib,
            iterations,
            parallelism,
            output_length: None,
        }),
    )
    .map_err(js)
}

/// Verifies that the provided password matches the stored PHC hash string.
#[wasm_bindgen]
pub fn argon2_verify(password: &[u8], phc: &str) -> Result<bool, JsValue> {
    alg::argon2_verify(password, phc).map_err(js)
}
