//! PEM-backed ECDSA keys (P-256 / secp256k1) and prehash sign/verify helpers for device binding.

use anyhow::{Context, Result};
use k256::{
    PublicKey as K256PublicKey,
    ecdsa::{Signature as K256Sig, SigningKey as K256SK, VerifyingKey as K256VK},
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::{
        DecodePrivateKey as K256DecodePrivateKey, DecodePublicKey as K256DecodePublicKey,
        EncodePrivateKey as K256EncodePrivateKey, EncodePublicKey as K256EncodePublicKey,
        LineEnding as K256LineEnding,
    },
};
use p256::PublicKey as P256PublicKey;
use p256::ecdsa::{Signature as P256Sig, SigningKey as P256SigningKey, VerifyingKey as P256VK};
use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::LineEnding as P256LineEnding;
use std::fs;
use std::path::Path;

use super::{normalize_signature, Curve};

/// Uncompressed affine coordinates (32-byte x, y) for P-256 / secp256k1 Noir wiring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PubKeyCoords {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

impl PubKeyCoords {
    pub fn from_xy_vecs(x: Vec<u8>, y: Vec<u8>) -> Result<Self> {
        Ok(Self {
            x: x
                .try_into()
                .map_err(|_| anyhow::anyhow!("public key x must be 32 bytes"))?,
            y: y
                .try_into()
                .map_err(|_| anyhow::anyhow!("public key y must be 32 bytes"))?,
        })
    }
}

/// Extract (x, y) coordinates from a PEM public key file.
pub fn extract_pubkey_xy(pem_path: &Path, curve: Curve) -> Result<PubKeyCoords> {
    let display = pem_path.display();
    let (x, y) = match curve {
        Curve::P256 => {
            let pk = P256PublicKey::read_public_key_pem_file(pem_path)
                .with_context(|| format!("cannot read P-256 public key from '{display}'"))?;
            let enc = pk.to_encoded_point(false);
            (
                enc.x()
                    .ok_or_else(|| anyhow::anyhow!("P-256 key: missing x coordinate"))?
                    .to_vec(),
                enc.y()
                    .ok_or_else(|| anyhow::anyhow!("P-256 key: missing y coordinate"))?
                    .to_vec(),
            )
        }
        Curve::K256 => {
            let pk = K256PublicKey::read_public_key_pem_file(pem_path)
                .with_context(|| format!("cannot read secp256k1 public key from '{display}'"))?;
            let enc = pk.to_encoded_point(false);
            (
                enc.x()
                    .ok_or_else(|| anyhow::anyhow!("K256 key: missing x coordinate"))?
                    .to_vec(),
                enc.y()
                    .ok_or_else(|| anyhow::anyhow!("K256 key: missing y coordinate"))?
                    .to_vec(),
            )
        }
    };
    PubKeyCoords::from_xy_vecs(x, y)
}

/// P-256 verifying key coordinates from an issuer/device signing key.
pub fn verifying_key_xy_p256(key: &P256SigningKey) -> PubKeyCoords {
    let point = key.verifying_key().to_encoded_point(false);
    PubKeyCoords {
        x: (*point.x().unwrap()).into(),
        y: (*point.y().unwrap()).into(),
    }
}

/// Load a P-256 PKCS#8 PEM signing key from disk.
pub fn load_p256_signing_key(path: &Path) -> Result<P256SigningKey> {
    let pem = fs::read_to_string(path)
        .with_context(|| format!("cannot read key file '{}'", path.display()))?;
    P256SigningKey::from_pkcs8_pem(&pem).context("invalid PKCS#8 PEM P-256 private key")
}

/// Write a random ECDSA keypair to PEM paths; returns uncompressed coordinates for Noir.
pub fn write_random_ecdsa_keypair(curve: Curve, prv_path: &Path, pub_path: &Path) -> Result<PubKeyCoords> {
    match curve {
        Curve::P256 => {
            let sk = P256SigningKey::random(&mut OsRng);
            let vk = sk.verifying_key();
            fs::write(prv_path, sk.to_pkcs8_pem(P256LineEnding::LF)?.as_bytes())
                .with_context(|| format!("write private key '{}'", prv_path.display()))?;
            fs::write(pub_path, vk.to_public_key_pem(P256LineEnding::LF)?)
                .with_context(|| format!("write public key '{}'", pub_path.display()))?;
            let enc = vk.to_encoded_point(false);
            PubKeyCoords::from_xy_vecs(
                enc.x().unwrap().to_vec(),
                enc.y().unwrap().to_vec(),
            )
        }
        Curve::K256 => {
            let sk = K256SK::random(&mut OsRng);
            let vk = sk.verifying_key();
            fs::write(prv_path, sk.to_pkcs8_pem(K256LineEnding::LF)?.as_bytes())
                .with_context(|| format!("write private key '{}'", prv_path.display()))?;
            fs::write(pub_path, vk.to_public_key_pem(K256LineEnding::LF)?)
                .with_context(|| format!("write public key '{}'", pub_path.display()))?;
            let enc = vk.to_encoded_point(false);
            PubKeyCoords::from_xy_vecs(
                enc.x().unwrap().to_vec(),
                enc.y().unwrap().to_vec(),
            )
        }
    }
}

/// Sign a 32-byte prehash with a PKCS#8 PEM private key; returns **low-s normalized** r||s (64 bytes).
pub fn sign_prehash_normalized(curve: Curve, key_path: &Path, digest: &[u8; 32]) -> Result<[u8; 64]> {
    match curve {
        Curve::P256 => {
            use p256::ecdsa::signature::hazmat::PrehashSigner;
            let sk = P256SigningKey::read_pkcs8_pem_file(key_path)
                .with_context(|| format!("read P-256 device key '{}'", key_path.display()))?;
            let sig: P256Sig = sk.sign_prehash(digest).context("sign (P-256)")?;
            Ok(normalize_signature(&sig.to_bytes().into(), curve))
        }
        Curve::K256 => {
            use k256::ecdsa::signature::hazmat::PrehashSigner;
            let key_pem = fs::read_to_string(key_path)
                .with_context(|| format!("read K256 device key '{}'", key_path.display()))?;
            let sk = K256SK::from_pkcs8_pem(&key_pem).context("parse K256 PKCS#8 PEM")?;
            let sig: K256Sig = sk.sign_prehash(digest).context("sign (K256)")?;
            Ok(normalize_signature(&sig.to_bytes().into(), curve))
        }
    }
}

/// Verify a **normalized** r||s ECDSA signature over a 32-byte prehash.
pub fn verify_prehash_ecdsa(
    curve: Curve,
    pubkey_path: &Path,
    digest: &[u8; 32],
    sig: &[u8; 64],
) -> Result<bool> {
    match curve {
        Curve::P256 => {
            use p256::ecdsa::signature::hazmat::PrehashVerifier;
            let vk = P256VK::read_public_key_pem_file(pubkey_path)
                .with_context(|| format!("read public key '{}'", pubkey_path.display()))?;
            let sig = P256Sig::from_bytes(&(*sig).into())?;
            Ok(vk.verify_prehash(digest, &sig).is_ok())
        }
        Curve::K256 => {
            use k256::ecdsa::signature::hazmat::PrehashVerifier;
            let pub_pem = fs::read_to_string(pubkey_path)
                .with_context(|| format!("read public key '{}'", pubkey_path.display()))?;
            let vk = K256VK::from_public_key_pem(&pub_pem).context("parse K256 public PEM")?;
            let sig = K256Sig::from_bytes(&(*sig).into())?;
            Ok(vk.verify_prehash(digest, &sig).is_ok())
        }
    }
}
