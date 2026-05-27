/// COSE_Sign1 (RFC 9052) ES256 verification.
/// Sig_structure = ["Signature1", protected, external_aad, payload]

use crate::constants::{MSO_MAX_LEN, SIG_STRUCTURE_MAX_LEN, SIGNATURE_SIZE};
use sha256::sha256_var;

/// Pre-encoded CBOR: array(4) | text("Signature1") | bstr({1:-7}) | bstr('')
global SIG_STRUCTURE_PREFIX: [u8; 17] =
    [0x84, 0x6a, 83, 105, 103, 110, 97, 116, 117, 114, 101, 49, 0x43, 0xa1, 0x01, 0x26, 0x40];

/// Builds the COSE `Sig_structure` bytes for `Signature1`:
/// `[ "Signature1", body_protected, external_aad, payload ]`.
///
/// Layout produced here:
/// - `SIG_STRUCTURE_PREFIX` (constant first 17 bytes)
/// - CBOR bstr header `0x59` + 16-bit big-endian length (3 bytes; RFC 8949)
/// - payload bytes
///
/// Only the `0x59` (two-byte length) bstr header is used. Callers must ensure
/// `payload.len() >= 256` so this matches canonical encodings for large MSOs and
/// avoids duplicating payload-copy loops across CBOR header variants in the circuit.
/// Returns a `BoundedVec` whose logical length is the exact encoded size.
fn build_sig_structure(
    payload: BoundedVec<u8, MSO_MAX_LEN>,
) -> BoundedVec<u8, SIG_STRUCTURE_MAX_LEN> {
    let mut buf: [u8; SIG_STRUCTURE_MAX_LEN] = [0; SIG_STRUCTURE_MAX_LEN];
    for i in 0..17 {
        buf[i] = SIG_STRUCTURE_PREFIX[i];
    }
    let payload_len = payload.len();
    let payload_storage = payload.storage();

    assert(payload_len >= 256, "MSO payload too short for 2-byte CBOR bstr header");
    buf[17] = 0x59;
    buf[18] = ((payload_len >> 8) & 0xff) as u8;
    buf[19] = (payload_len & 0xff) as u8;
    for i in 0..MSO_MAX_LEN {
        buf[20 + i] = payload_storage[i];
    }
    BoundedVec::from_parts_unchecked(buf, 20 + payload_len)
}

/// Full COSE_Sign1 verification: build Sig_structure, hash, and verify.
pub fn verify_cose_signature(
    mso_bytes: BoundedVec<u8, MSO_MAX_LEN>,
    signature: [u8; SIGNATURE_SIZE],
    issuer_pub_x: [u8; 32],
    issuer_pub_y: [u8; 32],
) -> bool {
    let sig_structure = build_sig_structure(mso_bytes);
    let hash = sha256_var(sig_structure.storage(), sig_structure.len());
    std::ecdsa_secp256r1::verify_signature(issuer_pub_x, issuer_pub_y, signature, hash)
}
