//! Low-level CBOR scanning for `issuerAuth` and COSE bytes **without** re-encoding artifacts.
//!
//! IssuerSigned bundles may store `issuerAuth` as an inline CBOR structure or as a **bstr** wrapping
//! the COSE_Sign1 bytes; `ciborium` round-trips can change wire form, so we slice the original bytes.

use ciborium::value::Value as CborValue;
use ciborium_ll::{Decoder as LlDecoder, Header};
use coset::{CborSerializable, CoseSign1, TaggedCborSerializable};
use std::borrow::Cow;
use thiserror::Error;

/// Failures while scanning raw IssuerSigned / MSO bytes.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WireError {
    #[error("expected IssuerSigned top-level CBOR map")]
    NotTopLevelMap,
    #[error("\"issuerAuth\" not found in IssuerSigned map")]
    MissingIssuerAuth,
    #[error("expected CBOR text key")]
    ExpectedTextKey,
    #[error("unexpected CBOR break")]
    UnexpectedBreak,
    #[error("CBOR decode: {0}")]
    Decode(String),
    #[error("COSE_Sign1 parse: {0}")]
    CoseParse(String),
    #[error("{0}")]
    DeviceKey(String),
}

fn read_text(dec: &mut LlDecoder<&[u8]>) -> Result<String, WireError> {
    let h = dec
        .pull()
        .map_err(|e| WireError::Decode(format!("{e:?}")))?;
    let Header::Text(len) = h else {
        return Err(WireError::ExpectedTextKey);
    };
    let mut out = String::new();
    let mut segs = dec.text(len);
    while let Some(mut seg) = segs
        .pull()
        .map_err(|e| WireError::Decode(format!("{e:?}")))?
    {
        let mut buf = [0u8; 256];
        loop {
            match seg
                .pull(&mut buf)
                .map_err(|e| WireError::Decode(format!("{e:?}")))?
            {
                Some(part) => out.push_str(part),
                None => break,
            }
        }
    }
    Ok(out)
}

fn skip_value(dec: &mut LlDecoder<&[u8]>) -> Result<(), WireError> {
    let h = dec
        .pull()
        .map_err(|e| WireError::Decode(format!("{e:?}")))?;
    match h {
        Header::Bytes(len) => {
            let mut segs = dec.bytes(len);
            while let Some(mut seg) = segs
                .pull()
                .map_err(|e| WireError::Decode(format!("{e:?}")))?
            {
                let mut buf = [0u8; 1024];
                while seg
                    .pull(&mut buf)
                    .map_err(|e| WireError::Decode(format!("{e:?}")))?
                    .is_some()
                {}
            }
        }
        Header::Text(len) => {
            let mut segs = dec.text(len);
            while let Some(mut seg) = segs
                .pull()
                .map_err(|e| WireError::Decode(format!("{e:?}")))?
            {
                let mut buf = [0u8; 256];
                while seg
                    .pull(&mut buf)
                    .map_err(|e| WireError::Decode(format!("{e:?}")))?
                    .is_some()
                {}
            }
        }
        Header::Array(Some(n)) => {
            for _ in 0..n {
                skip_value(dec)?;
            }
        }
        Header::Array(None) => loop {
            let h2 = dec
                .pull()
                .map_err(|e| WireError::Decode(format!("{e:?}")))?;
            if h2 == Header::Break {
                break;
            }
            dec.push(h2);
            skip_value(dec)?;
        },
        Header::Map(Some(n)) => {
            for _ in 0..(2 * n) {
                skip_value(dec)?;
            }
        }
        Header::Map(None) => loop {
            let h2 = dec
                .pull()
                .map_err(|e| WireError::Decode(format!("{e:?}")))?;
            if h2 == Header::Break {
                break;
            }
            dec.push(h2);
            skip_value(dec)?;
            skip_value(dec)?;
        },
        Header::Tag(_) => skip_value(dec)?,
        Header::Break => return Err(WireError::UnexpectedBreak),
        _ => {}
    }
    Ok(())
}

/// Raw CBOR encoding of the `issuerAuth` map entry value (bstr or inline COSE array).
pub fn issuer_auth_value_wire(data: &[u8]) -> Result<&[u8], WireError> {
    let mut dec = LlDecoder::from(data);
    let h = dec
        .pull()
        .map_err(|e| WireError::Decode(format!("{e:?}")))?;
    let n = match h {
        Header::Map(Some(n)) => n,
        _ => return Err(WireError::NotTopLevelMap),
    };
    for _ in 0..n {
        let key = read_text(&mut dec)?;
        let v0 = dec.offset();
        skip_value(&mut dec)?;
        let v1 = dec.offset();
        if key == "issuerAuth" {
            return Ok(&data[v0..v1]);
        }
    }
    Err(WireError::MissingIssuerAuth)
}

/// True if `wire` is CBOR major type 2 (byte string) wrapping COSE_Sign1.
pub fn issuer_auth_value_is_bstr_wrapped(wire: &[u8]) -> bool {
    wire.first().is_some_and(|b| b >> 5 == 2)
}

/// Bytes passed to `CoseSign1::from_slice`: inner bstr for wrapped COSE, else the full wire slice.
pub fn cose_sign1_input_from_issuer_auth_value(slice: &[u8]) -> Result<Cow<'_, [u8]>, WireError> {
    let mut dec = LlDecoder::from(slice);
    let h = dec
        .pull()
        .map_err(|e| WireError::Decode(format!("{e:?}")))?;
    match h {
        Header::Bytes(len) => {
            let mut v = Vec::new();
            let mut segs = dec.bytes(len);
            while let Some(mut seg) = segs
                .pull()
                .map_err(|e| WireError::Decode(format!("{e:?}")))?
            {
                let mut buf = [0u8; 4096];
                loop {
                    match seg
                        .pull(&mut buf)
                        .map_err(|e| WireError::Decode(format!("{e:?}")))?
                    {
                        Some(chunk) => v.extend_from_slice(chunk),
                        None => break,
                    }
                }
            }
            Ok(Cow::Owned(v))
        }
        _ => {
            dec.push(h);
            Ok(Cow::Borrowed(slice))
        }
    }
}

/// `Cow` borrows from `raw` when possible; `top` is only used to detect IssuerSigned shape.
pub fn issuer_auth_cose_bytes<'a>(
    top: &CborValue,
    raw: &'a [u8],
) -> Result<Cow<'a, [u8]>, WireError> {
    match top {
        CborValue::Map(_) => {
            let wire = issuer_auth_value_wire(raw)?;
            cose_sign1_input_from_issuer_auth_value(wire)
        }
        _ => Ok(Cow::Borrowed(raw)),
    }
}

pub fn parse_cose_sign1(bytes: &[u8]) -> Result<CoseSign1, WireError> {
    match CoseSign1::from_slice(bytes) {
        Ok(s) => Ok(s),
        Err(e1) => CoseSign1::from_tagged_slice(bytes)
            .map_err(|e2| WireError::CoseParse(format!("untagged error {e1}; tagged error {e2}"))),
    }
}

/// Byte offsets of device public key x/y bstr(32) headers in raw MSO CBOR (after `deviceKeyInfo`).
pub fn device_key_offsets(mso: &[u8]) -> Result<(usize, usize), WireError> {
    let dki_key_text = b"deviceKeyInfo";
    let dki_start = mso
        .windows(dki_key_text.len())
        .position(|w| w == dki_key_text)
        .map(|pos| pos + dki_key_text.len())
        .ok_or_else(|| WireError::DeviceKey("deviceKeyInfo not found in MSO bytes".into()))?;

    let x_pattern: &[u8] = &[0x21, 0x58, 0x20];
    let device_key_x_offset = mso[dki_start..]
        .windows(x_pattern.len())
        .position(|w| w == x_pattern)
        .map(|pos| dki_start + pos + 1)
        .ok_or_else(|| {
            WireError::DeviceKey("device key x coordinate (-2) not found in MSO".into())
        })?;

    let y_pattern: &[u8] = &[0x22, 0x58, 0x20];
    let device_key_y_offset = mso[dki_start..]
        .windows(y_pattern.len())
        .position(|w| w == y_pattern)
        .map(|pos| dki_start + pos + 1)
        .ok_or_else(|| {
            WireError::DeviceKey("device key y coordinate (-3) not found in MSO".into())
        })?;

    Ok((device_key_x_offset, device_key_y_offset))
}

/// Return the byte length of the MSO payload inside an `IssuerSigned` CBOR file.
pub fn mso_payload_len(issuer_signed_bytes: &[u8]) -> Result<usize, WireError> {
    let top: CborValue = ciborium::from_reader(issuer_signed_bytes)
        .map_err(|e| WireError::CoseParse(format!("parse IssuerSigned CBOR: {e}")))?;
    let cose_in = issuer_auth_cose_bytes(&top, issuer_signed_bytes)?;
    let sign1 = parse_cose_sign1(cose_in.as_ref())?;
    Ok(sign1
        .payload
        .as_ref()
        .map_or(0, Vec::len))
}
