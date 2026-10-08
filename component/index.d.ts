/**
 * Types for `wasm-pqc-subtle/component`: the `pqc-subtle:crypto@0.1.0` WIT
 * world as componentize-qjs presents it. Enums are their case names, records
 * are camelCase objects, `option<T>` is `T | null`, `list<u8>` is a
 * `Uint8Array`, and a WIT `result` error is thrown with the variant on
 * `error.payload` as `{ tag, val }`.
 */

export interface KeyPair {
  publicKey: Uint8Array;
  /**
   * The seed form: 64 bytes for ML-KEM, 32 bytes for ML-DSA. `decapsulate` and
   * `sign` also accept the expanded encodings earlier releases produced.
   */
  secretKey: Uint8Array;
}

export interface Encapsulation {
  ciphertext: Uint8Array;
  /** Always 32 bytes. */
  sharedSecret: Uint8Array;
}

/** The payload on a thrown error from any function below. Non-exhaustive. */
export type CryptoError =
  | { tag: 'invalid-length'; val: string }
  | { tag: 'invalid-encoding'; val: string }
  | { tag: 'failed'; val: string }
  | { tag: string; val?: unknown };

export type MlKemParameterSet = 'ml-kem-768' | 'ml-kem-1024';
export type MlDsaParameterSet = 'ml-dsa-44' | 'ml-dsa-65' | 'ml-dsa-87';

export namespace mlKem {
  function generateKeypair(set: MlKemParameterSet): KeyPair;
  function encapsulate(set: MlKemParameterSet, publicKey: Uint8Array): Encapsulation;
  function decapsulate(set: MlKemParameterSet, secretKey: Uint8Array, ciphertext: Uint8Array): Uint8Array;
}

export namespace mlDsa {
  function generateKeypair(set: MlDsaParameterSet): KeyPair;
  function sign(set: MlDsaParameterSet, secretKey: Uint8Array, message: Uint8Array): Uint8Array;
  function verify(set: MlDsaParameterSet, publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;
}

/** Argon2id cost parameters. `outputLength` null means 32 bytes. */
export interface Argon2Params {
  memoryKib: number;
  iterations: number;
  parallelism: number;
  outputLength: number | null;
}

export namespace argon2 {
  /**
   * Hashes `password` with a fresh random salt and returns a PHC string.
   * `params` null means the `argon2` crate defaults (m=19456 KiB, t=2, p=1);
   * pass explicit parameters for parity with hashes made elsewhere.
   */
  function hash(password: Uint8Array, params: Argon2Params | null): string;
  /** Verifies against a PHC string using the parameters it carries. */
  function verify(password: Uint8Array, phc: string): boolean;
}

export const argon2idHash: typeof argon2.hash;
export const argon2Verify: typeof argon2.verify;
