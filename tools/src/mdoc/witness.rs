//! Shared `Prover.toml` writer for mdoc-swiyu circuits.

use anyhow::Result;
use sha2::{Digest, Sha256};
use std::io::Write;

use crate::crypto::PubKeyCoords;
use crate::format::prover::write_bounded_vec_toml;

/// Byte offsets used by the mdoc circuit (digest bstr, device key coordinates).
#[derive(Clone, Copy, Debug)]
pub struct MsoOffsets {
    pub dob_digest: usize,
    pub device_key_x: usize,
    pub device_key_y: usize,
}

/// Disclosed IssuerSignedItem going into the witness.
#[derive(Clone, Debug)]
pub struct DisclosedAttr<'a> {
    pub digest_id: u64,
    pub element_identifier: &'a str,
    pub cbor_bytes: &'a [u8],
}

/// Witness bundle for mdoc Noir circuits (`mdoc build` / `mdoc witness`).
pub struct MdocWitness<'a> {
    pub mso_bytes: &'a [u8],
    pub mso_max_len: usize,
    pub disclosed_attr_max_len: usize,
    pub issuer_signature: [u8; 64],
    pub issuer_pub: PubKeyCoords,
    pub disclosed: DisclosedAttr<'a>,
    pub offsets: MsoOffsets,
    pub challenge_nonce: [u8; 32],
    pub device_signature: [u8; 64],
}

impl<'a> MdocWitness<'a> {
    /// `main_header_comment` is the primary line after the banner (e.g. target experiment).
    /// `extra_header_lines` are optional help lines (e.g. usage hints).
    pub fn write_prover_toml(
        &self,
        w: &mut impl Write,
        main_header_comment: &str,
        extra_header_lines: &[&str],
        reference_items: impl Iterator<Item = (u64, &'a str, &'a [u8])>,
    ) -> Result<()> {
        if self.disclosed.cbor_bytes.len() > self.disclosed_attr_max_len {
            anyhow::bail!(
                "disclosed attribute CBOR length {} exceeds {}",
                self.disclosed.cbor_bytes.len(),
                self.disclosed_attr_max_len
            );
        }

        writeln!(
            w,
            "# ============================================================"
        )?;
        writeln!(w, "# {main_header_comment}")?;
        for line in extra_header_lines {
            writeln!(w, "# {line}")?;
        }
        writeln!(
            w,
            "# ============================================================\n"
        )?;

        writeln!(
            w,
            "# MSO bytes (Mobile Security Object - full ISO 18013-5 structure)"
        )?;
        write_bounded_vec_toml(w, "mso_bytes", self.mso_bytes, self.mso_max_len)?;
        writeln!(w)?;

        writeln!(
            w,
            "# Issuer signature from COSE_Sign1 (64 bytes, normalized low-s)"
        )?;
        writeln!(w, "issuer_signature = {:?}\n", self.issuer_signature)?;

        writeln!(w, "# Issuer public key (P-256)")?;
        writeln!(w, "issuer_pub_x = {:?}", self.issuer_pub.x)?;
        writeln!(w, "issuer_pub_y = {:?}\n", self.issuer_pub.y)?;

        writeln!(
            w,
            "# Disclosed attribute: IssuerSignedItem for \"{}\" (digestID={})",
            self.disclosed.element_identifier, self.disclosed.digest_id
        )?;
        write_bounded_vec_toml(
            w,
            "disclosed_attribute",
            self.disclosed.cbor_bytes,
            self.disclosed_attr_max_len,
        )?;
        writeln!(w)?;

        writeln!(
            w,
            "# Byte offset of disclosed digest (bstr) in MSO bytes (dob_digest_offset)"
        )?;
        writeln!(w, "dob_digest_offset = {}\n", self.offsets.dob_digest)?;
        writeln!(w, "# Byte offsets of device public key (bstr) in MSO bytes")?;
        writeln!(w, "device_key_x_offset = {}", self.offsets.device_key_x)?;
        writeln!(w, "device_key_y_offset = {}\n", self.offsets.device_key_y)?;
        writeln!(
            w,
            "# Public date used for age threshold check [year, month, day]"
        )?;
        writeln!(w, "now_date = [2026, 1, 1]\n")?;
        writeln!(
            w,
            "# Challenge nonce (32-byte digest) and matching device signature"
        )?;
        writeln!(w, "challenge_nonce = {:?}", self.challenge_nonce)?;
        writeln!(w, "device_signature = {:?}\n", self.device_signature)?;

        writeln!(
            w,
            "\n# ============================================================"
        )?;
        writeln!(
            w,
            "# All IssuerSignedItems (for selective disclosure reference)"
        )?;
        writeln!(
            w,
            "# ============================================================"
        )?;
        for (digest_id, element_identifier, cbor_bytes) in reference_items {
            let h: [u8; 32] = Sha256::digest(cbor_bytes).into();
            writeln!(
                w,
                "\n# digestID={} identifier=\"{}\"",
                digest_id, element_identifier
            )?;
            writeln!(w, "# hash = {:?}", h)?;
            writeln!(
                w,
                "# cbor_bytes (len={}) = {:?}",
                cbor_bytes.len(),
                cbor_bytes
            )?;
        }

        Ok(())
    }
}
