/// Maximum MSO (Mobile Security Object) size in bytes.
/// Default matches `eid-tools bench` default `--max-length` (2000).
pub global MSO_MAX_LEN: u32 = 15000;

pub global SIGNATURE_SIZE: u32 = 64;

/// Maximum size of a disclosed IssuerSignedItem (CBOR encoded).
pub global DISCLOSED_ATTR_MAX_LEN: u32 = 128;

/// Maximum Sig_structure size: 17 prefix + 3 bstr header + MSO_MAX_LEN payload.
pub global SIG_STRUCTURE_MAX_LEN: u32 = 17 + 3 + MSO_MAX_LEN;
pub global AGE_THRESHOLD: u32 = 25;
