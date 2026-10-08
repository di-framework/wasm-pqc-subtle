//! The WebAssembly component surface: the `pqc-subtle:crypto@0.1.0` world in
//! `wit/world.wit`, for composition into other components (`wac plug`) or
//! direct use from a component runtime. Built with
//! `--no-default-features --features component` for `wasm32-wasip2`.

use crate::algorithms::{self as alg, Argon2Params, Error, MlDsaSet, MlKemSet};

wit_bindgen::generate!({
    path: "wit",
    world: "pqc-subtle",
});

use exports::pqc_subtle::crypto::argon2::{Guest as Argon2Guest, Params};
use exports::pqc_subtle::crypto::ml_dsa::{Guest as MlDsaGuest, ParameterSet as DsaSet};
use exports::pqc_subtle::crypto::ml_kem::{Guest as MlKemGuest, ParameterSet as KemSet};
use pqc_subtle::crypto::types::{Encapsulation, Error as WitError, KeyPair};

struct Component;

impl From<Error> for WitError {
    fn from(error: Error) -> Self {
        match error {
            Error::InvalidLength(m) => WitError::InvalidLength(m),
            Error::InvalidEncoding(m) => WitError::InvalidEncoding(m),
            Error::Failed(m) => WitError::Failed(m),
        }
    }
}

impl From<alg::KeyPair> for KeyPair {
    fn from(kp: alg::KeyPair) -> Self {
        KeyPair {
            public_key: kp.public_key,
            secret_key: kp.secret_key,
        }
    }
}

impl From<KemSet> for MlKemSet {
    fn from(set: KemSet) -> Self {
        match set {
            KemSet::MlKem768 => MlKemSet::MlKem768,
            KemSet::MlKem1024 => MlKemSet::MlKem1024,
        }
    }
}

impl From<DsaSet> for MlDsaSet {
    fn from(set: DsaSet) -> Self {
        match set {
            DsaSet::MlDsa44 => MlDsaSet::MlDsa44,
            DsaSet::MlDsa65 => MlDsaSet::MlDsa65,
            DsaSet::MlDsa87 => MlDsaSet::MlDsa87,
        }
    }
}

impl MlKemGuest for Component {
    fn generate_keypair(set: KemSet) -> KeyPair {
        alg::ml_kem_generate_keypair(set.into()).into()
    }

    fn encapsulate(set: KemSet, public_key: Vec<u8>) -> Result<Encapsulation, WitError> {
        let enc = alg::ml_kem_encapsulate(set.into(), &public_key)?;
        Ok(Encapsulation {
            ciphertext: enc.ciphertext,
            shared_secret: enc.shared_secret,
        })
    }

    fn decapsulate(
        set: KemSet,
        secret_key: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, WitError> {
        Ok(alg::ml_kem_decapsulate(
            set.into(),
            &secret_key,
            &ciphertext,
        )?)
    }
}

impl MlDsaGuest for Component {
    fn generate_keypair(set: DsaSet) -> KeyPair {
        alg::ml_dsa_generate_keypair(set.into()).into()
    }

    fn sign(set: DsaSet, secret_key: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, WitError> {
        Ok(alg::ml_dsa_sign(set.into(), &secret_key, &message)?)
    }

    fn verify(
        set: DsaSet,
        public_key: Vec<u8>,
        message: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, WitError> {
        Ok(alg::ml_dsa_verify(
            set.into(),
            &public_key,
            &message,
            &signature,
        )?)
    }
}

impl Argon2Guest for Component {
    fn hash(password: Vec<u8>, params: Option<Params>) -> Result<String, WitError> {
        let params = params.map(|p| Argon2Params {
            memory_kib: p.memory_kib,
            iterations: p.iterations,
            parallelism: p.parallelism,
            output_length: p.output_length,
        });
        Ok(alg::argon2id_hash(&password, params)?)
    }

    fn verify(password: Vec<u8>, phc: String) -> Result<bool, WitError> {
        Ok(alg::argon2_verify(&password, &phc)?)
    }
}

export!(Component);
