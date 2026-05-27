use clap::ValueEnum;
use crypto_bigint::U256;

const SECP256R1_ORDER: &str = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";
const SECP256K1_ORDER: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

#[derive(Clone, Copy, PartialEq, ValueEnum)]
pub enum Curve {
    P256,
    K256,
}

impl Curve {
    pub fn name(&self) -> &'static str {
        match self {
            Curve::P256 => "P-256",
            Curve::K256 => "secp256k1",
        }
    }
}

/// Normalize ECDSA signature to low-s form for Noir compatibility.
pub fn normalize_signature(signature: &[u8; 64], curve: Curve) -> [u8; 64] {
    let order_hex = match curve {
        Curve::P256 => SECP256R1_ORDER,
        Curve::K256 => SECP256K1_ORDER,
    };

    let n = U256::from_be_hex(order_hex);
    let n_half = n >> 1;
    let s_bytes: [u8; 32] = signature[32..64].try_into().unwrap();
    let s = U256::from_be_slice(&s_bytes);

    if s > n_half {
        let mut normalized = *signature;
        let s_low = n.wrapping_sub(&s);
        normalized[32..64].copy_from_slice(&s_low.to_be_bytes());
        normalized
    } else {
        *signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_low_s_unchanged_p256() {
        let mut sig = [0u8; 64];
        sig[31] = 1;
        sig[63] = 1;
        let out = normalize_signature(&sig, Curve::P256);
        assert_eq!(out, sig);
    }

    #[test]
    fn normalize_low_s_unchanged_k256() {
        let mut sig = [0u8; 64];
        sig[31] = 1;
        sig[63] = 1;
        let out = normalize_signature(&sig, Curve::K256);
        assert_eq!(out, sig);
    }

    #[test]
    fn normalize_high_s_reduces_p256() {
        let mut sig = [0u8; 64];
        sig[32..64].fill(0xFF);
        let out = normalize_signature(&sig, Curve::P256);
        assert_ne!(out[32..64], sig[32..64], "high-s should map to n - s");
    }

}
