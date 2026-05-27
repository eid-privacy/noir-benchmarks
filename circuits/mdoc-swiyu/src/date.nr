/// Date parsing, validation, and age checking for ISO 18013-5 birth_date attribute.

use mdoc_cbor::cbor;
use crate::constants::{AGE_THRESHOLD, DISCLOSED_ATTR_MAX_LEN};

fn parse_digit(data: [u8; 10], idx: u32) -> u32 {
    let byte = data[idx];
    assert((byte >= 48) & (byte <= 57), "input is not a digit");
    (byte - 48) as u32
}

pub fn parse_birth_date(value: [u8; 10]) -> [u32; 3] {
    assert(value[4] == 45, "birth_date must be YYYY-MM-DD");
    assert(value[7] == 45, "birth_date must be YYYY-MM-DD");

    let year = parse_digit(value, 0) * 1000
        + parse_digit(value, 1) * 100
        + parse_digit(value, 2) * 10
        + parse_digit(value, 3);
    let month = parse_digit(value, 5) * 10 + parse_digit(value, 6);
    let day = parse_digit(value, 8) * 10 + parse_digit(value, 9);

    [year, month, day]
}

pub fn is_at_least_25_years_old(birth_date: [u32; 3], now_date: [u32; 3]) -> bool {
    let threshold = (birth_date[0] + AGE_THRESHOLD) * 10000 + birth_date[1] * 100 + birth_date[2];
    let now = now_date[0] * 10000 + now_date[1] * 100 + now_date[2];
    now >= threshold
}

fn find_map_value_offset<let K: u32>(
    data: [u8; DISCLOSED_ATTR_MAX_LEN],
    data_len: u32,
    encoded_key: [u8; K],
) -> u32 {
    let mut found = false;
    let mut value_offset: u32 = 0;
    let key_len: u32 = K;

    for i in 0..DISCLOSED_ATTR_MAX_LEN {
        if (!found) & (i + key_len <= data_len) {
            let mut matches = true;
            for j in 0..K {
                if data[i + j] != encoded_key[j] {
                    matches = false;
                }
            }
            if matches {
                found = true;
                value_offset = i + key_len;
            }
        }
    }

    assert(found, "Required key not found in disclosed attribute");
    value_offset
}

pub fn extract_birth_date_from_disclosed(
    disclosed_attribute: BoundedVec<u8, DISCLOSED_ATTR_MAX_LEN>,
) -> [u8; 10] {
    /*
    {
        "digestID": <int>,
        "random": h'...',
        "elementIdentifier": "birth_date",
        "elementValue": 1004("1999-03-21")
    } 
    */
    let data = disclosed_attribute.storage();
    let data_len = disclosed_attribute.len();

    let element_identifier_key: [u8; 18] =
        [113, 101, 108, 101, 109, 101, 110, 116, 73, 100, 101, 110, 116, 105, 102, 105, 101, 114];

    let element_value_key: [u8; 13] =
        [108, 101, 108, 101, 109, 101, 110, 116, 86, 97, 108, 117, 101];

    let identifier_offset = find_map_value_offset(data, data_len, element_identifier_key);
    let value_offset = find_map_value_offset(data, data_len, element_value_key);

    let birth_date_key: [u8; 10] = [98, 105, 114, 116, 104, 95, 100, 97, 116, 101];
    assert(cbor::text_equals(data, identifier_offset, birth_date_key), "Expected birth_date");

    let mut current = value_offset;
    if cbor::get_major_type(data[current]) == 6 {
        let (tag_number, tagged_value_offset) = cbor::parse_tag(data, current);
        assert(tag_number == 1004, "Unsupported birth_date tag");
        current = tagged_value_offset;
    }

    let (birth_date_len, content_offset, _) = cbor::parse_text_header(data, current);
    assert(birth_date_len == 10, "birth_date must be YYYY-MM-DD");

    let mut birth_date_bytes: [u8; 10] = [0; 10];
    for i in 0..10 {
        birth_date_bytes[i] = data[content_offset + i];
    }
    birth_date_bytes
}
