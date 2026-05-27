//! Accessors for **flat** SWIYU-shaped credential JSON (string fields holding dates, ints, bools).
//!
//! The sample `data/swiyu-eid.json` uses string values for most scalars; these helpers keep
//! `mdoc` field mapping and other tooling consistent without pulling in a full schema crate.

use serde_json::Value;

/// Extract a string field from a flat SWIYU JSON credential.
pub fn get_str(data: &Value, key: &str) -> Option<String> {
    data.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Parse a boolean-string field ("true"/"false") from a flat SWIYU JSON credential.
pub fn get_bool(data: &Value, key: &str) -> Option<bool> {
    data.get(key)
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
}

/// Parse an integer-string field from a flat SWIYU JSON credential.
pub fn get_int(data: &Value, key: &str) -> Option<i64> {
    data.get(key)
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
}
