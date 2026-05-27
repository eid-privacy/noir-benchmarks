//! MSO and IssuerSignedItem construction from SWIYU JSON (ISO 18013-5 shaped).

use anyhow::Result;
use chrono::{DateTime, Utc};
use ciborium::Value as CborValue;
use p256::ecdsa::SigningKey;
use rand::RngExt;
use sha2::{Digest, Sha256};

use crate::config::{MDOC_DOC_TYPE, MDOC_NAMESPACE};
use crate::crypto::sign_cose_es256;
use crate::cbor::{encode as cbor_encode, text as cbor_text};

/// Single claim as encoded for `valueDigests` (salted IssuerSignedItem CBOR).
pub struct IssuerSignedItem {
    pub digest_id: u64,
    pub element_identifier: String,
    pub cbor_bytes: Vec<u8>,
}

impl IssuerSignedItem {
    pub fn new(digest_id: u64, element_identifier: &str, element_value: CborValue) -> Self {
        let salt: [u8; 16] = rand::rng().random();

        let item = CborValue::Map(vec![
            (cbor_text("digestID"), CborValue::Integer(digest_id.into())),
            (cbor_text("random"), CborValue::Bytes(salt.to_vec())),
            (
                cbor_text("elementIdentifier"),
                cbor_text(element_identifier),
            ),
            (cbor_text("elementValue"), element_value),
        ]);

        Self {
            digest_id,
            element_identifier: element_identifier.to_string(),
            cbor_bytes: cbor_encode(&item),
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(&self.cbor_bytes).into()
    }

    pub fn to_cbor_value(&self) -> Result<CborValue, ciborium::de::Error<std::io::Error>> {
        ciborium::from_reader(self.cbor_bytes.as_slice())
    }
}

pub fn cbor_datetime(dt: &DateTime<Utc>) -> CborValue {
    CborValue::Tag(
        0,
        Box::new(cbor_text(dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())),
    )
}

pub fn cbor_fulldate(date_str: &str) -> CborValue {
    CborValue::Tag(1004, Box::new(cbor_text(date_str)))
}

/// Build a COSE_Key (EC2, P-256) from raw x/y coordinates.
pub fn cose_ec2_key(x: &[u8], y: &[u8]) -> CborValue {
    CborValue::Map(vec![
        (CborValue::Integer(1.into()), CborValue::Integer(2.into())),
        (
            CborValue::Integer((-1_i64).into()),
            CborValue::Integer(1.into()),
        ),
        (
            CborValue::Integer((-2_i64).into()),
            CborValue::Bytes(x.to_vec()),
        ),
        (
            CborValue::Integer((-3_i64).into()),
            CborValue::Bytes(y.to_vec()),
        ),
    ])
}

pub struct Mso {
    pub cbor: CborValue,
    pub bytes: Vec<u8>,
}

impl Mso {
    pub fn new(
        device_key_x: &[u8],
        device_key_y: &[u8],
        items: &[IssuerSignedItem],
        signed_at: &DateTime<Utc>,
        valid_from: &DateTime<Utc>,
        valid_until: &DateTime<Utc>,
    ) -> Self {
        let digest_entries: Vec<(CborValue, CborValue)> = items
            .iter()
            .map(|item| {
                (
                    CborValue::Integer(item.digest_id.into()),
                    CborValue::Bytes(item.hash().to_vec()),
                )
            })
            .collect();

        let cbor = CborValue::Map(vec![
            (cbor_text("version"), cbor_text("1.0")),
            (cbor_text("digestAlgorithm"), cbor_text("SHA-256")),
            (cbor_text("docType"), cbor_text(MDOC_DOC_TYPE)),
            (
                cbor_text("valueDigests"),
                CborValue::Map(vec![(
                    cbor_text(MDOC_NAMESPACE),
                    CborValue::Map(digest_entries),
                )]),
            ),
            (
                cbor_text("deviceKeyInfo"),
                CborValue::Map(vec![(
                    cbor_text("deviceKey"),
                    cose_ec2_key(device_key_x, device_key_y),
                )]),
            ),
            (
                cbor_text("validityInfo"),
                CborValue::Map(vec![
                    (cbor_text("signed"), cbor_datetime(signed_at)),
                    (cbor_text("validFrom"), cbor_datetime(valid_from)),
                    (cbor_text("validUntil"), cbor_datetime(valid_until)),
                ]),
            ),
        ]);

        let bytes = cbor_encode(&cbor);
        Self { cbor, bytes }
    }

    pub fn sign(&self, signing_key: &SigningKey) -> Result<SignedMso> {
        let (cose_bytes, signature) = sign_cose_es256(&self.bytes, signing_key)?;
        Ok(SignedMso {
            cose_bytes,
            signature,
        })
    }
}

pub struct SignedMso {
    pub cose_bytes: Vec<u8>,
    pub signature: [u8; 64],
}
