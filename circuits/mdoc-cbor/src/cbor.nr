/// CBOR parser primitives (RFC 8949).
///
/// Initial byte layout: high 3 bits = major type, low 5 bits = additional info (`ai`).
/// Major types: 0=uint, 1=negint, 2=bstr, 3=tstr, 4=array, 5=map, 6=tag, 7=special.

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub global MAJOR_BSTR: u8 = 2;
pub global MAJOR_TSTR: u8 = 3;
pub global MAJOR_TAG: u8 = 6;

// ---------------------------------------------------------------------------
// Core decoding
// ---------------------------------------------------------------------------

/// Returns the CBOR major type (0-7) from an initial byte.
pub fn get_major_type(initial_byte: u8) -> u8 {
    initial_byte >> 5
}

/// Parse a CBOR unsigned integer argument (the `ai` and following bytes).
/// Returns `(value, new_offset)`.
pub fn parse_uint_arg<let N: u32>(data: [u8; N], offset: u32) -> (u64, u32) {
    let ai = data[offset] & 0x1f;

    if ai < 24 {
        (ai as u64, offset + 1)
    } else if ai == 24 {
        (data[offset + 1] as u64, offset + 2)
    } else if ai == 25 {
        let v = ((data[offset + 1] as u64) << 8) | (data[offset + 2] as u64);
        (v, offset + 3)
    } else if ai == 26 {
        let v = ((data[offset + 1] as u64) << 24)
            | ((data[offset + 2] as u64) << 16)
            | ((data[offset + 3] as u64) << 8)
            | (data[offset + 4] as u64);
        (v, offset + 5)
    } else if ai == 27 {
        let v = ((data[offset + 1] as u64) << 56)
            | ((data[offset + 2] as u64) << 48)
            | ((data[offset + 3] as u64) << 40)
            | ((data[offset + 4] as u64) << 32)
            | ((data[offset + 5] as u64) << 24)
            | ((data[offset + 6] as u64) << 16)
            | ((data[offset + 7] as u64) << 8)
            | (data[offset + 8] as u64);
        (v, offset + 9)
    } else {
        assert(false, "Unsupported CBOR additional info");
        (0, offset)
    }
}

// ---------------------------------------------------------------------------
// Typed header parsers
// ---------------------------------------------------------------------------

/// Parse a definite-length byte string header (major type 2).
/// Returns `(length, content_offset, end_offset)`.
pub fn parse_bytes_header<let N: u32>(data: [u8; N], offset: u32) -> (u32, u32, u32) {
    assert(get_major_type(data[offset]) == MAJOR_BSTR, "Expected byte string");
    let (length, content_offset) = parse_uint_arg(data, offset);
    (length as u32, content_offset, content_offset + (length as u32))
}

/// Parse a definite-length text string header (major type 3).
/// Returns `(length, content_offset, end_offset)`.
pub fn parse_text_header<let N: u32>(data: [u8; N], offset: u32) -> (u32, u32, u32) {
    assert(get_major_type(data[offset]) == MAJOR_TSTR, "Expected text string");
    let (length, content_offset) = parse_uint_arg(data, offset);
    (length as u32, content_offset, content_offset + (length as u32))
}

/// Parse a tag (major type 6). Returns `(tag_number, content_offset)`.
pub fn parse_tag<let N: u32>(data: [u8; N], offset: u32) -> (u64, u32) {
    assert(get_major_type(data[offset]) == MAJOR_TAG, "Expected tag");
    parse_uint_arg(data, offset)
}

// ---------------------------------------------------------------------------
// Higher-level helpers
// ---------------------------------------------------------------------------

/// Check whether the CBOR text string at `offset` equals `expected`.
pub fn text_equals<let N: u32, let M: u32>(data: [u8; N], offset: u32, expected: [u8; M]) -> bool {
    let (length, content_offset, _) = parse_text_header(data, offset);

    if length != M as u32 {
        false
    } else {
        let mut matches = true;
        for i in 0..M {
            if data[content_offset + i] != expected[i] {
                matches = false;
            }
        }
        matches
    }
}

/// Extract a CBOR byte string payload into a fixed-size array.
pub fn extract_bytes<let N: u32, let M: u32>(data: [u8; N], offset: u32) -> [u8; M] {
    let (length, content_offset, _) = parse_bytes_header(data, offset);
    assert(length == M as u32, "Byte string length mismatch");

    let mut result: [u8; M] = [0; M];
    for i in 0..M {
        result[i] = data[content_offset + i];
    }
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_parse_uint_arg() {
    // Inline value (ai < 24)
    let (val, off) = parse_uint_arg([0x17], 0);
    assert(val == 23);
    assert(off == 1);

    // 1-byte follow-up (ai == 24)
    let (val, off) = parse_uint_arg([0x18, 0x18], 0);
    assert(val == 24);
    assert(off == 2);

    // 2-byte big-endian (ai == 25)
    let (val, off) = parse_uint_arg([0x19, 0x01, 0x00], 0);
    assert(val == 256);
    assert(off == 3);
}

#[test]
fn test_text_equals() {
    // h'636f62' encodes text "cob" (0x63 = length 3, then ASCII)
    let data: [u8; 4] = [0x63, 0x64, 0x6f, 0x62];
    let expected: [u8; 3] = [0x64, 0x6f, 0x62];
    assert(text_equals(data, 0, expected));
}
