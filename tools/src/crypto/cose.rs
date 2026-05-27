//! [COSE](https://www.rfc-editor.org/rfc/rfc9052) `COSE_Sign1` with **ES256** (P-256 + SHA-256).
//!
//! Used to mint issuer signatures over raw MSO CBOR for mdoc experiments. Also hosts small
//! helpers for hashing challenge messages and resolving device-binding digest CLI inputs.

use anyhow::{Context, Result};
use ciborium;
use coset::{AsCborValue, CoseSign1Builder, HeaderBuilder, iana};
use log::info;
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use rand::RngExt;
use sha2::{Digest, Sha256};

use super::curve::{Curve, normalize_signature};

/// Build a COSE_Sign1 over `payload` with ES256; returns CBOR bytes and normalized raw signature.
pub fn sign_cose_es256(payload: &[u8], signing_key: &SigningKey) -> Result<(Vec<u8>, [u8; 64])> {
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .build();

    let temp_cose = CoseSign1Builder::new()
        .protected(protected.clone())
        .payload(payload.to_vec())
        .build();

    let tbs_hash: [u8; 32] = Sha256::digest(temp_cose.tbs_data(&[])).into();
    let sig: Signature = signing_key
        .sign_prehash(&tbs_hash)
        .context("failed to sign COSE payload (issuer key)")?;
    let signature = normalize_signature(&sig.to_bytes().into(), Curve::P256);

    let cose_sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload.to_vec())
        .signature(signature.to_vec())
        .build();

    let mut cose_bytes = Vec::new();
    let cbor_val = cose_sign1
        .to_cbor_value()
        .map_err(|e| anyhow::anyhow!("COSE_Sign1 to CBOR: {e}"))?;
    ciborium::into_writer(&cbor_val, &mut cose_bytes).context("encode COSE_Sign1 CBOR")?;

    Ok((cose_bytes, signature))
}

/// SHA-256 digest used as `challenge_nonce` in mdoc circuits (32 bytes).
pub fn challenge_nonce_from_message(msg: &[u8]) -> [u8; 32] {
    Sha256::digest(msg).into()
}

/// P-256 device signature over a 32-byte challenge (normalized low-s).
pub fn sign_device_binding(
    challenge_nonce: &[u8; 32],
    device_sk: &SigningKey,
) -> Result<[u8; 64]> {
    let device_sig: Signature = device_sk
        .sign_prehash(challenge_nonce)
        .context("sign device challenge")?;
    Ok(normalize_signature(&device_sig.to_bytes().into(), Curve::P256))
}

/// Resolve nonce string vs hex digest for `device sign` (allows auto-random when both absent).
pub fn resolve_nonce_digest_for_sign(
    nonce: Option<&String>,
    digest_hex: Option<&String>,
) -> Result<[u8; 32]> {
    match (nonce, digest_hex) {
        (Some(n), None) => Ok(Sha256::digest(n.as_bytes()).into()),
        (None, Some(hex_str)) => {
            let bytes = hex::decode(hex_str).context("invalid --digest-hex")?;
            bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("digest_hex must be 32 bytes (64 hex chars)"))
        }
        (None, None) => {
            let nonce_bytes: [u8; 32] = rand::rng().random();
            info!("Auto-generated nonce (hex):  {}", hex::encode(nonce_bytes));
            info!("Auto-generated nonce (arr):  {:?}", nonce_bytes.as_slice());
            Ok(Sha256::digest(nonce_bytes).into())
        }
        (Some(_), Some(_)) => anyhow::bail!("provide either nonce or --digest-hex, not both"),
    }
}

/// Resolve nonce string vs hex digest for `device verify` (both absent is an error).
pub fn resolve_nonce_digest_for_verify(
    nonce: Option<&String>,
    digest_hex: Option<&String>,
) -> Result<[u8; 32]> {
    match (nonce, digest_hex) {
        (Some(n), None) => Ok(Sha256::digest(n.as_bytes()).into()),
        (None, Some(hex_str)) => {
            let bytes = hex::decode(hex_str).context("invalid --digest-hex")?;
            bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("digest_hex must be 32 bytes (64 hex chars)"))
        }
        (None, None) => anyhow::bail!("provide either --nonce or --digest-hex"),
        (Some(_), Some(_)) => anyhow::bail!("provide either --nonce or --digest-hex, not both"),
    }
}
