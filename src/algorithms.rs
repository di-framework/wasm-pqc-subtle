//! The primitives, free of any binding layer. `bindgen.rs` and `component.rs`
//! wrap these for wasm-bindgen and for the WIT world respectively.

use argon2::password_hash::phc::{PasswordHash, Salt};
use argon2::{Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version};
use ml_dsa::signature::{Signer, Verifier};
use ml_dsa::{
    EncodedSignature, EncodedSigningKey, EncodedVerifyingKey, KeyGen, MlDsa44, MlDsa65, MlDsa87,
    MlDsaParams, Signature, SigningKey, VerifyingKey,
};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem768, MlKem1024};
use rand_core::OsRng;

/// A generated key pair, encoded per FIPS 203 / FIPS 204.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

/// ML-KEM encapsulation output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Encapsulation {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

/// Why a primitive could not run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// A key, ciphertext, or signature had the wrong byte length.
    InvalidLength(String),
    /// Bytes had the right length but did not decode.
    InvalidEncoding(String),
    /// The primitive itself reported a failure.
    Failed(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidLength(m) | Error::InvalidEncoding(m) | Error::Failed(m) => {
                f.write_str(m)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlKemSet {
    MlKem768,
    MlKem1024,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlDsaSet {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

/// Argon2id cost parameters. `output_length` of `None` means 32 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Params {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub output_length: Option<u32>,
}

// ── ML-KEM ──────────────────────────────────────────────────────────────

pub fn ml_kem_generate_keypair(set: MlKemSet) -> KeyPair {
    match set {
        MlKemSet::MlKem768 => kem_generate::<MlKem768>(),
        MlKemSet::MlKem1024 => kem_generate::<MlKem1024>(),
    }
}

pub fn ml_kem_encapsulate(set: MlKemSet, public_key: &[u8]) -> Result<Encapsulation, Error> {
    match set {
        MlKemSet::MlKem768 => kem_encapsulate::<MlKem768>(public_key),
        MlKemSet::MlKem1024 => kem_encapsulate::<MlKem1024>(public_key),
    }
}

pub fn ml_kem_decapsulate(
    set: MlKemSet,
    secret_key: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    match set {
        MlKemSet::MlKem768 => kem_decapsulate::<MlKem768>(secret_key, ciphertext),
        MlKemSet::MlKem1024 => kem_decapsulate::<MlKem1024>(secret_key, ciphertext),
    }
}

fn kem_generate<K: KemCore>() -> KeyPair {
    let (sk, pk) = K::generate(&mut OsRng);
    KeyPair {
        public_key: pk.as_bytes().to_vec(),
        secret_key: sk.as_bytes().to_vec(),
    }
}

fn kem_encapsulate<K>(public_key: &[u8]) -> Result<Encapsulation, Error>
where
    K: KemCore,
    K::EncapsulationKey: EncodedSizeUser,
{
    let encoded: Encoded<K::EncapsulationKey> = public_key
        .try_into()
        .map_err(|_| Error::InvalidLength("Invalid public key length".into()))?;
    let pk = K::EncapsulationKey::from_bytes(&encoded);
    let (ct, ss) = pk
        .encapsulate(&mut OsRng)
        .map_err(|_| Error::Failed("Encapsulation failed".into()))?;
    Ok(Encapsulation {
        ciphertext: ct.to_vec(),
        shared_secret: ss.to_vec(),
    })
}

fn kem_decapsulate<K>(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error>
where
    K: KemCore,
    K::DecapsulationKey: EncodedSizeUser,
{
    let encoded: Encoded<K::DecapsulationKey> = secret_key
        .try_into()
        .map_err(|_| Error::InvalidLength("Invalid secret key length".into()))?;
    let sk = K::DecapsulationKey::from_bytes(&encoded);
    let ct: Ciphertext<K> = ciphertext
        .try_into()
        .map_err(|_| Error::InvalidLength("Invalid ciphertext length".into()))?;
    let ss = sk
        .decapsulate(&ct)
        .map_err(|_| Error::Failed("Decapsulation failed".into()))?;
    Ok(ss.to_vec())
}

// ── ML-DSA ──────────────────────────────────────────────────────────────

pub fn ml_dsa_generate_keypair(set: MlDsaSet) -> KeyPair {
    match set {
        MlDsaSet::MlDsa44 => dsa_generate::<MlDsa44>(),
        MlDsaSet::MlDsa65 => dsa_generate::<MlDsa65>(),
        MlDsaSet::MlDsa87 => dsa_generate::<MlDsa87>(),
    }
}

pub fn ml_dsa_sign(set: MlDsaSet, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, Error> {
    match set {
        MlDsaSet::MlDsa44 => dsa_sign::<MlDsa44>(secret_key, message),
        MlDsaSet::MlDsa65 => dsa_sign::<MlDsa65>(secret_key, message),
        MlDsaSet::MlDsa87 => dsa_sign::<MlDsa87>(secret_key, message),
    }
}

pub fn ml_dsa_verify(
    set: MlDsaSet,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, Error> {
    match set {
        MlDsaSet::MlDsa44 => dsa_verify::<MlDsa44>(public_key, message, signature),
        MlDsaSet::MlDsa65 => dsa_verify::<MlDsa65>(public_key, message, signature),
        MlDsaSet::MlDsa87 => dsa_verify::<MlDsa87>(public_key, message, signature),
    }
}

fn dsa_generate<P: MlDsaParams>() -> KeyPair {
    let kp = P::key_gen(&mut OsRng);
    KeyPair {
        public_key: kp.verifying_key().encode().to_vec(),
        secret_key: kp.signing_key().encode().to_vec(),
    }
}

fn dsa_sign<P: MlDsaParams>(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, Error> {
    let encoded: EncodedSigningKey<P> = secret_key
        .try_into()
        .map_err(|_| Error::InvalidLength("Invalid secret key length".into()))?;
    let sk = SigningKey::<P>::decode(&encoded);
    Ok(sk.sign(message).encode().to_vec())
}

fn dsa_verify<P: MlDsaParams>(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, Error> {
    let encoded: EncodedVerifyingKey<P> = public_key
        .try_into()
        .map_err(|_| Error::InvalidLength("Invalid public key length".into()))?;
    let pk = VerifyingKey::<P>::decode(&encoded);
    let encoded_sig: EncodedSignature<P> = signature
        .try_into()
        .map_err(|_| Error::InvalidLength("Invalid signature length".into()))?;
    let sig = Signature::<P>::decode(&encoded_sig)
        .ok_or_else(|| Error::InvalidEncoding("Invalid signature encoding".into()))?;
    Ok(pk.verify(message, &sig).is_ok())
}

// ── Argon2id ────────────────────────────────────────────────────────────

/// Hashes `password` with Argon2id v19 and a fresh random salt. `params` of
/// `None` means the `argon2` crate defaults (m=19456 KiB, t=2, p=1).
pub fn argon2id_hash(password: &[u8], params: Option<Argon2Params>) -> Result<String, Error> {
    let argon2 = match params {
        None => Argon2::default(),
        Some(p) => {
            let params = Params::new(
                p.memory_kib,
                p.iterations,
                p.parallelism,
                p.output_length.map(|n| n as usize),
            )
            .map_err(|e| Error::Failed(format!("Invalid Argon2 params: {e}")))?;
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        }
    };
    let salt = Salt::generate();
    let phc = argon2
        .hash_password_with_salt(password, &salt)
        .map_err(|e| Error::Failed(format!("Argon2 hash failed: {e}")))?;
    Ok(phc.to_string())
}

/// Verifies `password` against a PHC string using the parameters it carries.
pub fn argon2_verify(password: &[u8], phc: &str) -> Result<bool, Error> {
    let parsed = PasswordHash::new(phc)
        .map_err(|e| Error::InvalidEncoding(format!("Invalid PHC string: {e}")))?;
    Ok(Argon2::default().verify_password(password, &parsed).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_kem_round_trips_for_both_sets() {
        for set in [MlKemSet::MlKem768, MlKemSet::MlKem1024] {
            let kp = ml_kem_generate_keypair(set);
            let enc = ml_kem_encapsulate(set, &kp.public_key).unwrap();
            let ss = ml_kem_decapsulate(set, &kp.secret_key, &enc.ciphertext).unwrap();
            assert_eq!(ss, enc.shared_secret);
            assert_eq!(ss.len(), 32);
        }
        assert_eq!(
            ml_kem_generate_keypair(MlKemSet::MlKem768).public_key.len(),
            1184
        );
        assert_eq!(
            ml_kem_generate_keypair(MlKemSet::MlKem1024)
                .public_key
                .len(),
            1568
        );
    }

    #[test]
    fn ml_kem_rejects_wrong_lengths() {
        let kp = ml_kem_generate_keypair(MlKemSet::MlKem768);
        assert!(matches!(
            ml_kem_encapsulate(MlKemSet::MlKem1024, &kp.public_key),
            Err(Error::InvalidLength(_))
        ));
        assert!(matches!(
            ml_kem_decapsulate(MlKemSet::MlKem768, &kp.secret_key, &[0u8; 3]),
            Err(Error::InvalidLength(_))
        ));
        assert!(matches!(
            ml_kem_decapsulate(MlKemSet::MlKem768, &[0u8; 3], &[0u8; 1088]),
            Err(Error::InvalidLength(_))
        ));
    }

    #[test]
    fn ml_dsa_signs_and_verifies_for_all_sets() {
        for set in [MlDsaSet::MlDsa44, MlDsaSet::MlDsa65, MlDsaSet::MlDsa87] {
            let kp = ml_dsa_generate_keypair(set);
            let sig = ml_dsa_sign(set, &kp.secret_key, b"hello").unwrap();
            assert_eq!(ml_dsa_verify(set, &kp.public_key, b"hello", &sig), Ok(true));
            assert_eq!(
                ml_dsa_verify(set, &kp.public_key, b"hellp", &sig),
                Ok(false)
            );
            let mut bad = sig.clone();
            bad[0] ^= 1;
            assert!(matches!(
                ml_dsa_verify(set, &kp.public_key, b"hello", &bad),
                Ok(false) | Err(Error::InvalidEncoding(_))
            ));
            assert!(matches!(
                ml_dsa_verify(set, &kp.public_key, b"hello", &sig[1..]),
                Err(Error::InvalidLength(_))
            ));
            assert!(matches!(
                ml_dsa_sign(set, &[0u8; 4], b"x"),
                Err(Error::InvalidLength(_))
            ));
            assert!(matches!(
                ml_dsa_verify(set, &[0u8; 4], b"x", &sig),
                Err(Error::InvalidLength(_))
            ));
        }
    }

    /// Fresh random bytes for a test password, so no literal flows into `hash`.
    fn fresh_password() -> Vec<u8> {
        ml_kem_generate_keypair(MlKemSet::MlKem768).secret_key[..16].to_vec()
    }

    #[test]
    fn argon2id_hashes_with_defaults_and_explicit_params() {
        let password = fresh_password();
        let mut other = password.clone();
        other[0] ^= 1;
        let phc = argon2id_hash(&password, None).unwrap();
        assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert_eq!(argon2_verify(&password, &phc), Ok(true));
        assert_eq!(argon2_verify(&other, &phc), Ok(false));

        let spring = Argon2Params {
            memory_kib: 16384,
            iterations: 2,
            parallelism: 1,
            output_length: None,
        };
        let phc = argon2id_hash(&password, Some(spring)).unwrap();
        assert!(phc.starts_with("$argon2id$v=19$m=16384,t=2,p=1$"));
        assert_eq!(argon2_verify(&password, &phc), Ok(true));

        let long = argon2id_hash(
            &password,
            Some(Argon2Params {
                output_length: Some(64),
                ..spring
            }),
        )
        .unwrap();
        assert_eq!(argon2_verify(&password, &long), Ok(true));
    }

    #[test]
    fn argon2_rejects_bad_params_and_bad_phc() {
        let bad = Argon2Params {
            memory_kib: 1,
            iterations: 0,
            parallelism: 0,
            output_length: None,
        };
        let password = fresh_password();
        assert!(matches!(
            argon2id_hash(&password, Some(bad)),
            Err(Error::Failed(_))
        ));
        assert!(matches!(
            argon2_verify(&password, "not a phc"),
            Err(Error::InvalidEncoding(_))
        ));
        assert_eq!(format!("{}", Error::Failed("x".into())), "x");
    }
}
