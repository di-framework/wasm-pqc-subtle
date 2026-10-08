//! Exercises every interface of `pqc-subtle:crypto@0.1.0` through real
//! component imports. `make smoke` composes this with the provider.

wit_bindgen::generate!({
    path: "../../wit",
    world: "imports",
    generate_all,
});

use pqc_subtle::crypto::argon2::{self, Params};
use pqc_subtle::crypto::ml_dsa::{self, ParameterSet as Dsa};
use pqc_subtle::crypto::ml_kem::{self, ParameterSet as Kem};

fn main() {
    // A fresh shared secret doubles as the test password below, so no literal is hashed.
    let mut password = Vec::new();
    for set in [Kem::MlKem768, Kem::MlKem1024] {
        let kp = ml_kem::generate_keypair(set);
        let enc = ml_kem::encapsulate(set, &kp.public_key).expect("encapsulate");
        let ss = ml_kem::decapsulate(set, &kp.secret_key, &enc.ciphertext).expect("decapsulate");
        assert_eq!(ss, enc.shared_secret, "shared secret mismatch for {set:?}");
        assert!(ml_kem::encapsulate(set, &[0u8; 3]).is_err());
        password = ss;
    }
    let mut other = password.clone();
    other[0] ^= 1;
    for set in [Dsa::MlDsa44, Dsa::MlDsa65, Dsa::MlDsa87] {
        let kp = ml_dsa::generate_keypair(set);
        let sig = ml_dsa::sign(set, &kp.secret_key, b"smoke").expect("sign");
        assert!(matches!(
            ml_dsa::verify(set, &kp.public_key, b"smoke", &sig),
            Ok(true)
        ));
        assert!(matches!(
            ml_dsa::verify(set, &kp.public_key, b"smoked", &sig),
            Ok(false)
        ));
    }
    let spring = Params {
        memory_kib: 16384,
        iterations: 2,
        parallelism: 1,
        output_length: None,
    };
    let phc = argon2::hash(&password, Some(spring)).expect("hash");
    assert!(phc.starts_with("$argon2id$v=19$m=16384,t=2,p=1$"), "{phc}");
    assert!(matches!(argon2::verify(&password, &phc), Ok(true)));
    assert!(matches!(argon2::verify(&other, &phc), Ok(false)));
    assert!(argon2::verify(&password, "not a phc").is_err());
    let default = argon2::hash(&password, None).expect("hash default");
    assert!(
        default.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
        "{default}"
    );
    println!("smoke ok: ml-kem x2, ml-dsa x3, argon2id (m=16384,t=2,p=1 and defaults)");
}
