//! CLI-distinguishable errors (e.g. verification failure vs I/O).

use thiserror::Error;

/// Signature or issuer verification failed (exit code 1, no error chain noise for users).
#[derive(Debug, Error)]
#[non_exhaustive]
#[error("{message}")]
pub struct VerificationFailed {
    pub message: String,
}

impl VerificationFailed {
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anyhow_downcasts_verification_failed() {
        let e = anyhow::Error::new(VerificationFailed::new("invalid"));
        assert!(e.downcast_ref::<VerificationFailed>().is_some());
    }
}
