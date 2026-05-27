//! General-purpose CBOR encoding and map lookup helpers.
//!
//! Thin wrappers over `ciborium::Value` used throughout the mdoc and credential modules.
//! Wire-level `IssuerSigned` scanning stays in `mdoc::wire`.

use ciborium::Value as CborValue;

/// CBOR text string value.
pub fn text(s: impl Into<String>) -> CborValue {
    CborValue::Text(s.into())
}

/// Encode a CBOR value to bytes (canonical writer).
pub fn encode(value: &CborValue) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).unwrap();
    buf
}

/// Look up a map entry by string key (ISO mdoc maps use text keys).
pub fn map_lookup<'a>(m: &'a [(CborValue, CborValue)], key: &str) -> Option<&'a CborValue> {
    m.iter().find_map(|(k, v)| match k {
        CborValue::Text(t) if t == key => Some(v),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::de::from_reader;

    #[test]
    fn text_round_trip() {
        let v = text("hello");
        let bytes = encode(&v);
        let decoded: CborValue = from_reader(bytes.as_slice()).unwrap();
        assert_eq!(decoded, v);
    }

    #[test]
    fn map_lookup_finds_and_misses() {
        let m = vec![
            (text("a"), CborValue::Integer(1.into())),
            (text("b"), CborValue::Bool(true)),
        ];
        assert_eq!(
            map_lookup(&m, "a"),
            Some(&CborValue::Integer(1.into()))
        );
        assert!(map_lookup(&m, "missing").is_none());
    }

    #[test]
    fn encode_round_trip_map() {
        let m = CborValue::Map(vec![(text("k"), CborValue::Bytes(vec![1, 2, 3]))]);
        let bytes = encode(&m);
        let decoded: CborValue = from_reader(bytes.as_slice()).unwrap();
        assert_eq!(decoded, m);
    }
}
