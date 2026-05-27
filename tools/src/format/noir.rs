//! Pretty-printing helpers for pasting witness material into Noir source (`let x: [u8; N] = …`).

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::crypto::{Curve, PubKeyCoords};

/// Format public key coordinates as hex, base64url, and Noir literal declarations.
pub fn fmt_pubkey_noir(coords: PubKeyCoords, curve: Curve) -> String {
    let x = coords.x.as_slice();
    let y = coords.y.as_slice();
    format!(
        "{curve} Public Key X (hex):    {x_hex}\n\
         {curve} Public Key Y (hex):    {y_hex}\n\
         {curve} Public Key X (base64): {x_b64}\n\
         {curve} Public Key Y (base64): {y_b64}\n\
         \n\
         // Noir format:\n\
         let pub_x: [u8; 32] = {x_arr};\n\
         let pub_y: [u8; 32] = {y_arr};",
        curve = curve.name(),
        x_hex = hex::encode(x),
        y_hex = hex::encode(y),
        x_b64 = URL_SAFE_NO_PAD.encode(x),
        y_b64 = URL_SAFE_NO_PAD.encode(y),
        x_arr = fmt_noir_array(x),
        y_arr = fmt_noir_array(y),
    )
}

/// Format a byte slice as a Noir array literal: `[0x01, 0x02, ...]`.
pub fn fmt_noir_array(bytes: &[u8]) -> String {
    let inner: Vec<String> = bytes.iter().map(|b| format!("0x{:02x}", b)).collect();
    format!("[{}]", inner.join(", "))
}

/// Format a `let name: [u8; N] = [...];` declaration.
pub fn fmt_byte_array(name: &str, bytes: &[u8]) -> String {
    format!("let {}: [u8; {}] = {:?};", name, bytes.len(), bytes)
}

/// Body of a Rust `[u8; N]` / `challenge_nonce = [` block: decimal `u8`, `per_line` elements per line.
pub fn fmt_u8_array_body_decimal(bytes: &[u8], per_line: usize) -> String {
    bytes
        .chunks(per_line.max(1))
        .map(|chunk| {
            chunk
                .iter()
                .map(|b| b.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .collect::<Vec<_>>()
        .join(",\n    ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_noir_array_hex() {
        assert_eq!(fmt_noir_array(&[0, 255]), "[0x00, 0xff]");
    }

    #[test]
    fn fmt_byte_array_decl() {
        let s = fmt_byte_array("x", b"ab");
        assert!(s.contains("let x: [u8; 2]"));
        assert!(s.contains("97") && s.contains("98"), "{s}");
    }

    #[test]
    fn fmt_u8_array_body_decimal_wraps() {
        let body = fmt_u8_array_body_decimal(&[1, 2, 3], 2);
        assert!(body.contains("1, 2"));
        assert!(body.contains('3'));
    }
}
