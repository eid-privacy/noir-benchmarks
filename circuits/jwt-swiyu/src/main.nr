use noir_base64::{BASE64_URL_DECODER, BASE64_URL_ENCODER};
use sha256::sha256_var;

mod constants;
use constants::PAYLOAD_MAX_LEN;

// ============================================================================
// Derived Size Constants (calculated automatically)
// ============================================================================

/// Base64 encoded payload length: ceil(PAYLOAD_MAX_LEN * 4 / 3)
global ENCODED_PAYLOAD_MAX_LEN: u32 = (PAYLOAD_MAX_LEN * 4 + 2) / 3;

/// Signing input length: 38 (header) + 1 (dot) + encoded payload
global SIGNING_INPUT_MAX_LEN: u32 = 39 + ENCODED_PAYLOAD_MAX_LEN;

// ============================================================================
// Other Constants
// ============================================================================

global ASCII_DOT: u8 = 46;
global EIGHTEEN_YEARS_SECONDS: u64 = 18 * 365 * 24 * 60 * 60;
/// Max decimal digits when parsing a number from payload (e.g. dob as Unix seconds)
global EXTRACT_NUMBER_MAX_DIGITS: u32 = 10;

// Pre-encoded JWT header: {"typ":"JWT","alg":"ES256K"}
global ENCODED_HEADER: [u8; 38] = [
    101, 121, 74, 48, 101, 88, 65, 105, 79, 105, 74, 75, 86, 49, 81, 105, 76, 67, 74, 104, 98, 71,
    99, 105, 79, 105, 74, 70, 85, 122, 73, 49, 78, 107, 115, 105, 102, 81,
];

// ToDo: inputs: private(decoded payload as stringArray, signature as byteArray, device_signature), public: issuer_key, current_time, challenge_nonce
/*
Verification Steps:
1. signing_input: Encode the payload + header as base64 (encoded header is hardcoded in the circuit)
2. Hash the signing_input with SHA-256
3. Verify the jwt signature against the constructed hash using the input: issuer_key
4. Retrieve cnf.x and cnf.y from decoded payload
5. Hash the challenge_nonce 
6. Verify the challenge_nonce_signature against the hashed nonce using the device_key
7. Extract the date_of_birth claim from the decoded payload
8. Verify age >= 18 using current_time 

Difficult part:
 How to retrieve a value from the payload (CharArray)?
 - For fixed schema, we can do substring matching to extract the values
 - Second approach: 
    have the user provide the extracted values as private inputs 
    and reconstruct the payload in the circuit to compare hashes
*/

/// Extracts a decimal number from payload at given offset.
/// Uses a fixed number of iterations (EXTRACT_NUMBER_MAX_DIGITS) so the loop is fully constrained.
/// Caller must ensure offset + EXTRACT_NUMBER_MAX_DIGITS <= data_len.
/// Safety: Payload is verified via JWT signature.
fn extract_number<let N: u32>(data: [u8; N], offset: u32) -> u64 {
    let mut value: u64 = 0;
    let mut still_parsing: bool = true;

    for i in 0..EXTRACT_NUMBER_MAX_DIGITS {
        let idx = offset + i;
        let byte = data[idx];
        let is_digit = (byte >= 48) & (byte <= 57);

        still_parsing = still_parsing & is_digit;
        value = if still_parsing {
            value * 10 + ((byte - 48) as u64)
        } else {
            value
        };
    }
    value
}

fn main(
    payload: BoundedVec<u8, PAYLOAD_MAX_LEN>, // Raw JWT payload
    jwt_signature: [u8; 64],
    issuer_pub_x: pub [u8; 32],
    issuer_pub_y: pub [u8; 32],
    dob_offset: u32,
    x_offset: u32,
    y_offset: u32,
    time_now_unix: pub u64, // Current time for age verification
    challenge_nonce: pub [u8; 32],
    device_signature: [u8; 64],
) {
    // Encode the payload to Base64URL
    let encoded_payload = BASE64_URL_ENCODER::encode_var(payload);
    let mut signing_input: BoundedVec<u8, SIGNING_INPUT_MAX_LEN> = BoundedVec::from(ENCODED_HEADER);
    signing_input.push(ASCII_DOT);

    signing_input.extend_from_bounded_vec(encoded_payload);

    let signing_input_hash = sha256_var(signing_input.storage(), signing_input.len());

    let valid_jwt_sig = std::ecdsa_secp256k1::verify_signature(
        issuer_pub_x,
        issuer_pub_y,
        jwt_signature,
        signing_input_hash,
    );
    assert(valid_jwt_sig, "Invalid JWT signature");

    let payload_storage = payload.storage();
    // Verify "x":" pattern exists at claimed offset
    // Pattern: "x":" = [34, 120, 34, 58, 34]
    assert(payload_storage[x_offset] == 34, "X key not found"); // "
    assert(payload_storage[x_offset + 1] == 120, "X key not found"); // x
    assert(payload_storage[x_offset + 2] == 34, "X key not found"); // "
    assert(payload_storage[x_offset + 3] == 58, "X key not found"); // :
    assert(payload_storage[x_offset + 4] == 34, "X key not found"); // "

    // Verify "y":" pattern exists at claimed offset
    // Pattern: "y":" = [34, 121, 34, 58, 34]
    assert(payload_storage[y_offset] == 34, "Y key not found"); // "
    assert(payload_storage[y_offset + 1] == 121, "Y key not found"); // y
    assert(payload_storage[y_offset + 2] == 34, "Y key not found"); // "
    assert(payload_storage[y_offset + 3] == 58, "Y key not found"); // :
    assert(payload_storage[y_offset + 4] == 34, "Y key not found"); // "

    // Convert BoundedVec to fixed-size arrays for base64 decoding
    // P-256 coordinates are 32 bytes, which encode to 43 base64-url characters
    let mut device_key_x_bytes: [u8; 43] = [0; 43];
    let mut device_key_y_bytes: [u8; 43] = [0; 43];
    for i in 0..43 {
        device_key_x_bytes[i] = payload_storage[x_offset + 5 + i];
        device_key_y_bytes[i] = payload_storage[y_offset + 5 + i];
    }

    // Decode base64-url strings to bytes using the noir_base64 library
    let device_pub_x: [u8; 32] = BASE64_URL_DECODER::decode(device_key_x_bytes);
    let device_pub_y: [u8; 32] = BASE64_URL_DECODER::decode(device_key_y_bytes);

    // verify signature on challenge nonce using device_key

    // First verify "dob": pattern exists at claimed offset
    // Pattern: "dob": = [34, 100, 111, 98, 34, 58]
    assert(payload_storage[dob_offset] == 34, "DOB key not found"); // "
    assert(payload_storage[dob_offset + 1] == 100, "DOB key not found"); // d
    assert(payload_storage[dob_offset + 2] == 111, "DOB key not found"); // o
    assert(payload_storage[dob_offset + 3] == 98, "DOB key not found"); // b
    assert(payload_storage[dob_offset + 4] == 34, "DOB key not found"); // "
    assert(payload_storage[dob_offset + 5] == 58, "DOB key not found"); // :`

    // Safety: Parse the decimal string as u64. This is safe because we extracted it from verified payload.
    let date_of_birth = extract_number(payload_storage, dob_offset + 6);

    // We verify the device here - To be added later to focus on the age verification right now!
    let date_of_birth_plus_18: u64 = date_of_birth + EIGHTEEN_YEARS_SECONDS;
    assert(date_of_birth_plus_18 <= time_now_unix, "User must be 18 or older");

    // Verify device signature on the challenge nonce
    let valid_challenge_signature = std::ecdsa_secp256k1::verify_signature(
        device_pub_x,
        device_pub_y,
        device_signature,
        challenge_nonce,
    );

    assert(valid_challenge_signature, "Invalid device signature on challenge nonce");
}

// Test uses placeholder data - will fail until real secp256k1 test data is generated
#[test(should_fail)]
fn test_jwt_verification() {
    // Placeholder payload (same structure as experiment30, needs secp256k1 keys)
    let payload_bytes: [u8; 445] = [
        123, 34, 99, 110, 102, 34, 58, 123, 34, 107, 116, 121, 34, 58, 34, 69, 67, 34, 44, 34, 117,
        115, 101, 34, 58, 34, 115, 105, 103, 34, 44, 34, 99, 114, 118, 34, 58, 34, 80, 45, 50, 53,
        54, 34, 44, 34, 107, 105, 100, 34, 58, 34, 101, 53, 102, 100, 48, 98, 51, 55, 45, 53, 55,
        50, 97, 45, 52, 97, 57, 53, 45, 98, 53, 49, 53, 45, 100, 55, 100, 55, 52, 49, 50, 99, 100,
        53, 52, 102, 34, 44, 34, 120, 34, 58, 34, 52, 67, 104, 95, 83, 66, 68, 99, 86, 83, 72, 105,
        112, 76, 101, 80, 85, 66, 112, 56, 121, 53, 82, 72, 49, 56, 86, 79, 108, 105, 114, 86, 82,
        116, 79, 116, 45, 116, 66, 45, 89, 95, 89, 34, 44, 34, 121, 34, 58, 34, 101, 80, 104, 54,
        80, 68, 88, 81, 50, 99, 98, 109, 53, 51, 87, 54, 97, 76, 56, 51, 50, 88, 114, 56, 76, 72,
        53, 80, 45, 98, 83, 99, 112, 112, 113, 45, 53, 101, 77, 73, 108, 48, 65, 34, 125, 44, 34,
        105, 97, 116, 34, 58, 49, 55, 51, 57, 56, 48, 49, 57, 48, 57, 44, 34, 100, 111, 99, 117,
        109, 101, 110, 116, 95, 110, 117, 109, 98, 101, 114, 34, 58, 34, 66, 69, 84, 65, 45, 73, 68,
        45, 80, 53, 89, 55, 48, 48, 77, 83, 34, 44, 34, 103, 105, 118, 101, 110, 95, 110, 97, 109,
        101, 34, 58, 34, 72, 101, 108, 118, 101, 116, 105, 97, 34, 44, 34, 102, 97, 109, 105, 108,
        121, 95, 110, 97, 109, 101, 34, 58, 34, 78, 97, 116, 105, 111, 110, 97, 108, 34, 44, 34, 98,
        105, 114, 116, 104, 95, 100, 97, 116, 101, 34, 58, 34, 49, 57, 56, 56, 45, 48, 49, 45, 48,
        49, 34, 44, 34, 100, 111, 98, 34, 58, 50, 51, 51, 51, 49, 48, 48, 48, 44, 34, 98, 105, 114,
        116, 104, 95, 112, 108, 97, 99, 101, 34, 58, 34, 76, 117, 122, 101, 114, 110, 34, 44, 34,
        112, 108, 97, 99, 101, 95, 111, 102, 95, 111, 114, 105, 103, 105, 110, 34, 58, 34, 65, 108,
        116, 100, 111, 114, 102, 32, 85, 82, 34, 44, 34, 115, 101, 120, 34, 58, 34, 50, 34, 44, 34,
        110, 97, 116, 105, 111, 110, 97, 108, 105, 116, 121, 34, 58, 34, 67, 72, 34, 44, 34, 101,
        120, 112, 105, 114, 121, 95, 100, 97, 116, 101, 34, 58, 34, 50, 48, 50, 53, 45, 48, 53, 45,
        49, 55, 34, 125,
    ];
    let payload = BoundedVec::from(payload_bytes);

    // Placeholder signature (needs secp256k1 signature)
    let jwt_signature: [u8; 64] = [0; 64];

    // Placeholder issuer public key (needs secp256k1 key)
    let issuer_x: [u8; 32] = [0; 32];
    let issuer_y: [u8; 32] = [0; 32];

    // Current time (example: January 1, 2024)
    let time_now_unix: u64 = 1704067200;

    // Nonce: SHA-256("a498d1ef-280f-49fc-89de-a622936bd88c")
    let challenge_nonce: [u8; 32] = [
        201, 82, 46, 203, 200, 115, 255, 55, 140, 209, 10, 162, 111, 75, 104, 122, 39, 215, 82, 84,
        187, 125, 70, 181, 188, 126, 60, 14, 120, 86, 103, 181,
    ];

    // Placeholder device signature (needs secp256k1 signature)
    let device_signature: [u8; 64] = [0; 64];

    // Offsets for pattern matching
    let dob_offset: u32 = 320; // Position of "dob": in payload
    let x_offset: u32 = 90; // Position of "x": in payload (inside cnf)
    let y_offset: u32 = 140; // Position of "y": in payload (inside cnf)

    main(
        payload,
        jwt_signature,
        issuer_x,
        issuer_y,
        dob_offset,
        x_offset,
        y_offset,
        time_now_unix,
        challenge_nonce,
        device_signature,
    )
}
