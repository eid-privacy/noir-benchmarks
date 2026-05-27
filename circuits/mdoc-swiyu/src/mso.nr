/// MSO (Mobile Security Object) extraction and verification for ISO 18013-5.

use mdoc_cbor::cbor;
use crate::constants::{DISCLOSED_ATTR_MAX_LEN, MSO_MAX_LEN};
use sha256::sha256_var;

/// Extract device public key (x, y) from pre-computed MSO byte offsets.
pub fn extract_device_key<let N: u32>(
    mso_bytes: [u8; N],
    x_offset: u32,
    y_offset: u32,
) -> ([u8; 32], [u8; 32]) {
    (cbor::extract_bytes(mso_bytes, x_offset), cbor::extract_bytes(mso_bytes, y_offset))
}

/// Verify that SHA-256(disclosed_attribute) matches the digest stored in MSO at the given offset.
pub fn verify_disclosed_digest(
    mso_storage: [u8; MSO_MAX_LEN],
    digest_offset: u32,
    disclosed_attribute: BoundedVec<u8, DISCLOSED_ATTR_MAX_LEN>,
) {
    let disclosed_hash = sha256_var(disclosed_attribute.storage(), disclosed_attribute.len());
    let stored_hash: [u8; 32] = cbor::extract_bytes(mso_storage, digest_offset);
    for i in 0..32 {
        assert(stored_hash[i] == disclosed_hash[i], "DOB disclosure digest mismatch");
    }
}

fn test_mso_fixture() -> [u8; 165] {
    [
        0xa2, 0x6c, 118, 97, 108, 117, 101, 68, 105, 103, 101, 115, 116, 115, 0xa1, 0x71, 111, 114,
        103, 46, 105, 115, 111, 46, 49, 56, 48, 49, 51, 46, 53, 46, 49, 0xa1, 0x01, 0x58, 0x20, 1,
        2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
        27, 28, 29, 30, 31, 32, 0x6d, 100, 101, 118, 105, 99, 101, 75, 101, 121, 73, 110, 102, 111,
        0xa1, 0x69, 100, 101, 118, 105, 99, 101, 75, 101, 121, 0xa2, 0x21, 0x58, 0x20, 101, 102,
        103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120,
        121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 0x22, 0x58, 0x20, 201, 202, 203,
        204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221,
        222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232,
    ]
}

#[test]
fn test_mso_device_key_extraction() {
    let mso = test_mso_fixture();
    let expected_x: [u8; 32] = [
        101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118,
        119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132,
    ];
    let expected_y: [u8; 32] = [
        201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218,
        219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232,
    ];
    let (actual_x, actual_y) = extract_device_key(mso, 96, 131);

    for i in 0..32 {
        assert(actual_x[i] == expected_x[i], "Extracted device X mismatch");
        assert(actual_y[i] == expected_y[i], "Extracted device Y mismatch");
    }
}
