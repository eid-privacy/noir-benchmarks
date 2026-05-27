//! Serialize witness bytes as Noir `BoundedVec`-style TOML (`len` + zero-padded `storage`).
//!
//! Nargo expects this shape for variable-length private inputs; this is not a general TOML API.

use anyhow::Result;
use std::io::Write;

/// Format a Prover.toml-style bounded vec section: `[name]\nlen = N\nstorage = [...]`.
pub fn fmt_padded_storage(name: &str, bytes: &[u8], max_len: usize) -> String {
    let mut storage = bytes.to_vec();
    storage.resize(max_len, 0);
    format!("[{}]\nlen = {}\nstorage = {:?}", name, bytes.len(), storage)
}

/// Write `name.len` / `name.storage` for Noir `BoundedVec`-style TOML (errors if `bytes` longer than `max_len`).
pub fn write_bounded_vec_toml(
    w: &mut impl Write,
    name: &str,
    bytes: &[u8],
    max_len: usize,
) -> Result<()> {
    if bytes.len() > max_len {
        anyhow::bail!(
            "{} length {} exceeds max len {}",
            name,
            bytes.len(),
            max_len
        );
    }
    let mut storage = bytes.to_vec();
    storage.resize(max_len, 0);
    writeln!(w, "{}.len = {}", name, bytes.len())?;
    writeln!(w, "{}.storage = {:?}", name, storage)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn write_bounded_vec_toml_shape() {
        let mut buf = Cursor::new(Vec::new());
        write_bounded_vec_toml(&mut buf, "payload", b"hi", 4).unwrap();
        let s = String::from_utf8(buf.into_inner()).unwrap();
        assert!(s.contains("payload.len = 2"));
        assert!(s.contains("payload.storage"));
    }

    #[test]
    fn write_bounded_vec_toml_rejects_overflow() {
        let mut buf = Cursor::new(Vec::new());
        let err = write_bounded_vec_toml(&mut buf, "x", b"toolong", 3).unwrap_err();
        assert!(err.to_string().contains("exceeds max len"));
    }
}
