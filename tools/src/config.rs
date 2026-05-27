//! Default PEM paths, ISO mdoc namespace strings, and circuit alignment constants (`MSO_MAX_LEN`, …).
//!
//! Values here must stay consistent with the corresponding `constants.nr` / `main.nr` inputs in
//! each Noir experiment package under `circuits/`.

/// Default issuer private key path (relative to `tools/` when run from there).
pub const DEFAULT_ISSUER_KEY: &str = "../data/issuer.prv";
/// Default issuer public key path.
pub const DEFAULT_ISSUER_PUBKEY: &str = "../data/issuer.pub";
/// Default device private key path.
pub const DEFAULT_DEVICE_KEY: &str = "../data/device.prv";
/// Default device public key path.
pub const DEFAULT_DEVICE_PUBKEY: &str = "../data/device.pub";

/// Challenge message hashed to produce `challenge_nonce` for mdoc device binding (must match circuit).
pub const DEFAULT_CHALLENGE_MSG: &[u8] = b"swiyu-mdoc-age-over-25-device-binding";

/// ISO 18013-5 namespace for value digests in this project.
pub const MDOC_NAMESPACE: &str = "org.iso.18013.5.1";
/// Document type embedded in the MSO.
pub const MDOC_DOC_TYPE: &str = "org.iso.18013.5.1.mDL";

/// Maximum MSO size for experiment00-style `Prover.toml` output from `mdoc-build`.
pub const MSO_MAX_LEN_EXPERIMENT00: usize = 1024;

/// Upper bound for disclosed attribute CBOR in `Prover.toml` (`mdoc-build` / `mdoc-prover`).
pub const DISCLOSED_ATTR_MAX_LEN: usize = 128;
