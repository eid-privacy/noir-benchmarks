mod constants;
mod cose;
mod mso;
mod date;

use constants::{DISCLOSED_ATTR_MAX_LEN, MSO_MAX_LEN, SIGNATURE_SIZE};

fn main(
    mso_bytes: BoundedVec<u8, MSO_MAX_LEN>,
    issuer_signature: [u8; SIGNATURE_SIZE],
    issuer_pub_x: pub [u8; 32],
    issuer_pub_y: pub [u8; 32],
    disclosed_attribute: BoundedVec<u8, DISCLOSED_ATTR_MAX_LEN>,
    dob_digest_offset: u32,
    device_key_x_offset: u32,
    device_key_y_offset: u32,
    now_date: pub [u32; 3],
    challenge_nonce: pub [u8; 32],
    device_signature: [u8; SIGNATURE_SIZE],
) {
    assert(
        cose::verify_cose_signature(mso_bytes, issuer_signature, issuer_pub_x, issuer_pub_y),
        "Invalid issuer signature on MSO",
    );

    mso::verify_disclosed_digest(mso_bytes.storage(), dob_digest_offset, disclosed_attribute);

    let birth_date_bytes = date::extract_birth_date_from_disclosed(disclosed_attribute);
    let birth_date: [u32; 3] = date::parse_birth_date(birth_date_bytes);
    assert(date::is_at_least_25_years_old(birth_date, now_date), "User must be 25 or older");

    let (device_pub_x, device_pub_y) = mso::extract_device_key(
        mso_bytes.storage(),
        device_key_x_offset,
        device_key_y_offset,
    );
    assert(
        std::ecdsa_secp256r1::verify_signature(
            device_pub_x,
            device_pub_y,
            device_signature,
            challenge_nonce,
        ),
        "Invalid device signature on challenge nonce",
    );
}

#[test]
fn test_mdoc_verification() {
    /*
    {
        "version": "1.0",
        "digestAlgorithm": "SHA-256",
        "docType": "org.iso.18013.5.1.mDL",

        "valueDigests": {
            "org.iso.18013.5.1": {
            0: h'...32 bytes...',
            1: h'...32 bytes...',
            2: h'...32 bytes...',
            3: h'...32 bytes...',   // this is the one checked against disclosed digestID=3
            4: h'...32 bytes...'
            }
        },

        "deviceKeyInfo": {
            "deviceKey": {
            1: 2,                   // kty = EC2
            -1: 1,                  // crv = P-256
            -2: h'...32 bytes...',  // x coordinate
            -3: h'...32 bytes...'   // y coordinate
            }
        },

        "validityInfo": {
            "signed":    0("2025-02-17T14:18:29Z"),
            "validFrom": 0("2025-02-17T14:18:29Z"),
            "validUntil":0("2025-05-17T23:59:59Z")
        }
    }
    */
    let mso_bytes_raw: [u8; 483] = [
        166, 103, 118, 101, 114, 115, 105, 111, 110, 99, 49, 46, 48, 111, 100, 105, 103, 101, 115,
        116, 65, 108, 103, 111, 114, 105, 116, 104, 109, 103, 83, 72, 65, 45, 50, 53, 54, 103, 100,
        111, 99, 84, 121, 112, 101, 117, 111, 114, 103, 46, 105, 115, 111, 46, 49, 56, 48, 49, 51,
        46, 53, 46, 49, 46, 109, 68, 76, 108, 118, 97, 108, 117, 101, 68, 105, 103, 101, 115, 116,
        115, 161, 113, 111, 114, 103, 46, 105, 115, 111, 46, 49, 56, 48, 49, 51, 46, 53, 46, 49,
        165, 0, 88, 32, 169, 218, 195, 22, 149, 191, 93, 199, 126, 165, 134, 207, 165, 158, 162,
        186, 226, 204, 192, 159, 217, 40, 167, 22, 47, 117, 52, 120, 36, 140, 214, 215, 1, 88, 32,
        215, 235, 152, 134, 208, 120, 85, 151, 84, 129, 9, 158, 73, 113, 130, 166, 157, 241, 159,
        109, 245, 136, 55, 60, 41, 239, 214, 67, 162, 197, 166, 10, 2, 88, 32, 138, 188, 220, 214,
        188, 57, 2, 43, 77, 223, 52, 72, 30, 54, 144, 175, 153, 233, 203, 34, 74, 250, 33, 241, 29,
        0, 128, 175, 112, 8, 212, 253, 3, 88, 32, 77, 236, 139, 97, 231, 186, 78, 180, 183, 125,
        251, 51, 26, 150, 159, 220, 220, 224, 81, 48, 232, 193, 5, 150, 176, 114, 39, 91, 195, 225,
        74, 12, 4, 88, 32, 48, 108, 142, 58, 107, 174, 226, 121, 209, 9, 111, 163, 47, 252, 114, 91,
        4, 71, 217, 157, 14, 237, 160, 107, 158, 96, 42, 164, 52, 119, 166, 74, 109, 100, 101, 118,
        105, 99, 101, 75, 101, 121, 73, 110, 102, 111, 161, 105, 100, 101, 118, 105, 99, 101, 75,
        101, 121, 164, 1, 2, 32, 1, 33, 88, 32, 224, 40, 127, 72, 16, 220, 85, 33, 226, 164, 183,
        143, 80, 26, 124, 203, 148, 71, 215, 197, 78, 150, 42, 213, 70, 211, 173, 250, 208, 126, 99,
        246, 34, 88, 32, 120, 248, 122, 60, 53, 208, 217, 198, 230, 231, 117, 186, 104, 191, 55,
        217, 122, 252, 44, 126, 79, 249, 180, 156, 166, 154, 190, 229, 227, 8, 151, 64, 108, 118,
        97, 108, 105, 100, 105, 116, 121, 73, 110, 102, 111, 163, 102, 115, 105, 103, 110, 101, 100,
        192, 116, 50, 48, 50, 53, 45, 48, 50, 45, 49, 55, 84, 49, 52, 58, 49, 56, 58, 50, 57, 90,
        105, 118, 97, 108, 105, 100, 70, 114, 111, 109, 192, 116, 50, 48, 50, 53, 45, 48, 50, 45,
        49, 55, 84, 49, 52, 58, 49, 56, 58, 50, 57, 90, 106, 118, 97, 108, 105, 100, 85, 110, 116,
        105, 108, 192, 116, 50, 48, 50, 53, 45, 48, 53, 45, 49, 55, 84, 50, 51, 58, 53, 57, 58, 53,
        57, 90,
    ];
    let mso_bytes = BoundedVec::from(mso_bytes_raw);

    let issuer_signature: [u8; SIGNATURE_SIZE] = [
        23, 14, 186, 49, 92, 67, 73, 54, 98, 95, 42, 127, 85, 45, 159, 59, 250, 162, 124, 196, 107,
        145, 101, 25, 41, 226, 211, 240, 141, 7, 83, 118, 17, 131, 91, 15, 59, 251, 208, 73, 201,
        46, 10, 86, 186, 219, 73, 158, 229, 53, 30, 206, 125, 23, 208, 218, 74, 101, 167, 228, 171,
        190, 55, 174,
    ];
    let issuer_pub_x: [u8; 32] = [
        167, 88, 242, 105, 202, 45, 43, 222, 196, 147, 26, 246, 10, 95, 170, 234, 159, 69, 58, 132,
        187, 67, 155, 67, 0, 203, 214, 51, 216, 74, 233, 238,
    ];
    let issuer_pub_y: [u8; 32] = [
        199, 128, 82, 222, 50, 34, 94, 194, 31, 221, 211, 226, 210, 93, 204, 148, 9, 221, 243, 248,
        105, 234, 53, 127, 104, 232, 215, 158, 176, 168, 237, 32,
    ];

    /*
        {
        "digestID": 3,
        "random": h'80bd89ea6f7d0008e59772d95ad34727',
        "elementIdentifier": "birth_date",
        "elementValue": 1004("1988-01-01")
        }
    */
    let disclosed_attribute_raw: [u8; 91] = [
        0xA4, 104, 100, 105, 103, 101, 115, 116, 73, 68, 3, 102, 114, 97, 110, 100, 111, 109, 80,
        128, 189, 137, 234, 111, 125, 0, 8, 229, 151, 114, 217, 90, 211, 71, 39, 113, 101, 108, 101,
        109, 101, 110, 116, 73, 100, 101, 110, 116, 105, 102, 105, 101, 114, 106, 98, 105, 114, 116,
        104, 95, 100, 97, 116, 101, 108, 101, 108, 101, 109, 101, 110, 116, 86, 97, 108, 117, 101,
        217, 3, 236, 106, 49, 57, 56, 56, 45, 48, 49, 45, 48, 49,
    ];
    let disclosed_attribute = BoundedVec::from(disclosed_attribute_raw);

    let dob_digest_offset: u32 = 206;
    let device_key_x_offset: u32 = 306;
    let device_key_y_offset: u32 = 341;
    let now_date: [u32; 3] = [2026, 1, 1];
    let challenge_nonce: [u8; 32] = [
        48, 251, 174, 141, 6, 203, 94, 133, 246, 173, 219, 209, 41, 187, 194, 34, 93, 219, 135, 66,
        214, 170, 177, 136, 170, 202, 56, 181, 238, 65, 250, 87,
    ];
    let device_signature: [u8; SIGNATURE_SIZE] = [
        219, 160, 152, 64, 23, 88, 109, 55, 231, 52, 133, 228, 214, 224, 76, 119, 171, 83, 31, 43,
        3, 68, 196, 192, 10, 56, 23, 128, 184, 156, 136, 32, 7, 71, 133, 126, 195, 102, 175, 169,
        119, 166, 87, 167, 166, 103, 66, 23, 39, 228, 157, 199, 81, 243, 218, 240, 36, 219, 93, 159,
        66, 125, 214, 4,
    ];

    main(
        mso_bytes,
        issuer_signature,
        issuer_pub_x,
        issuer_pub_y,
        disclosed_attribute,
        dob_digest_offset,
        device_key_x_offset,
        device_key_y_offset,
        now_date,
        challenge_nonce,
        device_signature,
    );
}
