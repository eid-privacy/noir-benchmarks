//! ECDSA curves, PEM key I/O, prehash sign/verify, and COSE ES256 for mdoc issuer signatures.

mod curve;
mod keys;
mod cose;

pub use curve::{Curve, normalize_signature};
pub use keys::{
    PubKeyCoords, extract_pubkey_xy, load_p256_signing_key, sign_prehash_normalized,
    verifying_key_xy_p256, verify_prehash_ecdsa, write_random_ecdsa_keypair,
};
pub use cose::{
    challenge_nonce_from_message, resolve_nonce_digest_for_sign, resolve_nonce_digest_for_verify,
    sign_cose_es256, sign_device_binding,
};
