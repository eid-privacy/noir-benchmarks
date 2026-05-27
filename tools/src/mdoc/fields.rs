//! SWIYU JSON field → IssuerSignedItem CBOR mapping.

use ciborium::Value as CborValue;
use serde_json::Value;

use crate::cbor::text as cbor_text;
use crate::credential::swiyu::{get_bool, get_int, get_str};

#[derive(Clone, Copy)]
pub enum FieldType {
    Text,
    FullDate,
    Integer,
    Bool,
}

fn cbor_fulldate(date_str: &str) -> CborValue {
    CborValue::Tag(1004, Box::new(cbor_text(date_str)))
}

impl FieldType {
    pub fn to_cbor_value(self, data: &Value, json_key: &str) -> Option<CborValue> {
        match self {
            FieldType::Text => get_str(data, json_key).map(cbor_text),
            FieldType::FullDate => get_str(data, json_key).map(|v| cbor_fulldate(&v)),
            FieldType::Integer => get_int(data, json_key).map(|v| CborValue::Integer(v.into())),
            FieldType::Bool => get_bool(data, json_key).map(CborValue::Bool),
        }
    }
}

pub struct ElementField {
    pub name: &'static str,
    pub field_type: FieldType,
}

pub const ELEMENT_FIELDS: &[ElementField] = &[
    ElementField {
        name: "issuance_date",
        field_type: FieldType::FullDate,
    },
    ElementField {
        name: "document_number",
        field_type: FieldType::Text,
    },
    ElementField {
        name: "birth_date",
        field_type: FieldType::FullDate,
    },
    ElementField {
        name: "family_name",
        field_type: FieldType::Text,
    },
    ElementField {
        name: "given_name",
        field_type: FieldType::Text,
    },
    ElementField {
        name: "sex",
        field_type: FieldType::Integer,
    },
    ElementField {
        name: "nationality",
        field_type: FieldType::Text,
    },
    ElementField {
        name: "issuing_country",
        field_type: FieldType::Text,
    },
    ElementField {
        name: "issuing_authority",
        field_type: FieldType::Text,
    },
    ElementField {
        name: "birth_place",
        field_type: FieldType::Text,
    },
    ElementField {
        name: "expiry_date",
        field_type: FieldType::FullDate,
    },
    ElementField {
        name: "age_birth_year",
        field_type: FieldType::Integer,
    },
    ElementField {
        name: "age_over_18",
        field_type: FieldType::Bool,
    },
    ElementField {
        name: "age_over_16",
        field_type: FieldType::Bool,
    },
    ElementField {
        name: "age_over_65",
        field_type: FieldType::Bool,
    },
    ElementField {
        name: "place_of_origin",
        field_type: FieldType::Text,
    },
    ElementField {
        name: "personal_administrative_number",
        field_type: FieldType::Text,
    },
];
