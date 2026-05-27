//! Shared stdout vs file output and small byte utilities used by witness builders.

use anyhow::{Context, Result};
use std::io::{BufWriter, Write};
use std::path::Path;

/// First index of `needle` in `haystack` (byte substring search).
pub fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Open a buffered writer to `path`, or to locked stdout if `path` is `None`.
///
/// Stdout is not `Send` on some platforms (Rust 2024 stdio); the return type is `Write` only.
pub fn open_writer(path: Option<&Path>) -> Result<Box<dyn Write>> {
    match path {
        Some(p) => {
            let f = std::fs::File::create(p)
                .with_context(|| format!("cannot create '{}'", p.display()))?;
            Ok(Box::new(BufWriter::new(f)))
        }
        None => Ok(Box::new(BufWriter::new(std::io::stdout().lock()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_bytes_finds_substring() {
        assert_eq!(find_bytes(b"hello world", b"world"), Some(6));
        assert_eq!(find_bytes(b"abc", b"abc"), Some(0));
    }

    #[test]
    fn find_bytes_no_match() {
        assert_eq!(find_bytes(b"abc", b"z"), None);
    }

    #[test]
    fn find_bytes_first_match() {
        assert_eq!(find_bytes(b"abab", b"ab"), Some(0));
    }
}
