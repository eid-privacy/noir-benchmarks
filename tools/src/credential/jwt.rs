//! Structured JWT claims for SWIYU-shaped credentials (ES256 / `jwt-swiyu` witness tooling).
//!
//! These types mirror the JSON layout produced from flat SWIYU credential JSON when building
//! compact JWTs for Noir circuits. They are `serde`-serializable for `jsonwebtoken::encode`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct JwkValue {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CnfClaims {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    pub jwk: JwkValue,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusList {
    #[serde(rename = "type")]
    pub type_: String,
    pub idx: u64,
    pub uri: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusClaims {
    pub status_list: StatusList,
}

/// SWIYU JWT body used by `eid-tools jwt sign` (selective disclosure digests + cnf + status).
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub _sd: Vec<String>,
    #[serde(rename = "vct_metadata_uri#integrity")]
    pub vct_metadata_uri_integrity: String,
    pub vct_metadata_uri: String,
    pub vct: String,
    pub _sd_alg: String,
    pub iss: String,
    pub cnf: CnfClaims,
    pub iat: u64,
    pub status: StatusClaims,
}
