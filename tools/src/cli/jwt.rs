//! `eid-tools jwt` — compact JWT witness and Prover.toml padding.

use anyhow::{Context, Result};
use base64::prelude::*;
use clap::{Args as ClapArgs, Subcommand};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use log::info;
use noir_eid_tools::config::DEFAULT_ISSUER_KEY;
use noir_eid_tools::credential::jwt::Claims;
use noir_eid_tools::crypto::{Curve, normalize_signature};
use noir_eid_tools::format::noir::fmt_byte_array;
use noir_eid_tools::io::find_bytes;
use std::fs;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum Cmd {
    /// Generate a JWT from SWIYU JSON
    Sign(SignArgs),
    /// Pad JWT `payload.storage` in Prover.toml to match `PAYLOAD_MAX_LEN`
    Pad(PadArgs),
}

impl Cmd {
    pub fn run(self) -> Result<()> {
        match self {
            Cmd::Sign(a) => run_sign(a),
            Cmd::Pad(a) => run_pad(a),
        }
    }
}

#[derive(ClapArgs)]
pub struct SignArgs {
    /// Path to SWIYU JSON credential file
    pub json_file: PathBuf,
    /// Path to issuer private key (PEM)
    #[arg(long, default_value = DEFAULT_ISSUER_KEY)]
    pub key: PathBuf,
}

#[derive(ClapArgs)]
pub struct PadArgs {
    /// Existing Prover.toml (full witness); payload bytes are taken from the first `payload.len` entries
    pub template: PathBuf,
    #[arg(long, short = 'o')]
    pub output: PathBuf,
    /// Pad `payload.storage` to this length (must equal circuit `PAYLOAD_MAX_LEN`)
    #[arg(long)]
    pub payload_max_len: usize,
}

pub fn run_sign(args: SignArgs) -> Result<()> {
    let claims: Claims = serde_json::from_str(
        &fs::read_to_string(&args.json_file)
            .with_context(|| format!("read '{}'", args.json_file.display()))?,
    )
    .context("parse SWIYU JSON as JWT claims")?;

    info!("Payload:\n{}", serde_json::to_string_pretty(&claims)?);
    let payload_json = serde_json::to_string(&claims)?;

    let key_pem = fs::read_to_string(&args.key)
        .with_context(|| format!("read issuer key '{}'", args.key.display()))?;

    let token = encode(
        &Header::new(Algorithm::ES256),
        &claims,
        &EncodingKey::from_ec_pem(key_pem.as_bytes()).context("parse issuer PEM for JWT")?,
    )
    .context("encode JWT")?;
    info!("JWT (ES256): {}", token);
    let parts: Vec<&str> = token.split('.').collect();
    let header_b64 = parts[0];
    let sig = BASE64_URL_SAFE_NO_PAD
        .decode(parts[2])
        .context("decode JWT signature segment")?;
    let normalized = normalize_signature(
        &sig.try_into()
            .map_err(|_| anyhow::anyhow!("JWT signature segment must be 64 bytes"))?,
        Curve::P256,
    );

    println!("{}", fmt_byte_array("header_bytes", header_b64.as_bytes()));
    println!();
    println!("{}", fmt_byte_array("jwt_signature", &normalized));
    println!();
    println!(
        "{}",
        fmt_byte_array("payload_bytes", payload_json.as_bytes())
    );
    println!();

    let payload_bytes = payload_json.as_bytes();

    let dob_sd_offset = claims
        ._sd
        .get(16)
        .and_then(|digest| find_bytes(payload_bytes, digest.as_bytes()))
        .context("birth_date _sd digest (index 16) not found in payload")?;
    let x_offset =
        find_bytes(payload_bytes, b"\"x\":\"").context("\"x\":\" not found in payload")?;
    let y_offset =
        find_bytes(payload_bytes, b"\"y\":\"").context("\"y\":\" not found in payload")?;

    println!("dob_sd_offset = {}", dob_sd_offset);
    println!();
    println!("x_offset = {}", x_offset);
    println!();
    println!("y_offset = {}", y_offset);

    Ok(())
}

pub fn run_pad(args: PadArgs) -> Result<()> {
    use toml::Value;

    let raw = fs::read_to_string(&args.template)
        .with_context(|| format!("read template '{}'", args.template.display()))?;
    let mut doc: Value = toml::from_str(&raw).context("parse Prover.toml")?;

    let root = doc
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("Prover.toml root must be a table"))?;
    let payload = root
        .get_mut("payload")
        .ok_or_else(|| {
            anyhow::anyhow!("missing `payload` table (use payload.len / payload.storage)")
        })?
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("`payload` must be a table"))?;

    let payload_len = payload
        .get("len")
        .and_then(Value::as_integer)
        .ok_or_else(|| anyhow::anyhow!("payload.len missing or not an integer"))?
        as usize;

    let storage_val = payload
        .get("storage")
        .ok_or_else(|| anyhow::anyhow!("payload.storage missing"))?
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("payload.storage must be an array"))?;

    if payload_len > args.payload_max_len {
        anyhow::bail!(
            "payload.len ({payload_len}) exceeds --payload-max-len ({})",
            args.payload_max_len
        );
    }

    let mut bytes = Vec::with_capacity(storage_val.len());
    for (i, v) in storage_val.iter().enumerate() {
        let b = v
            .as_integer()
            .ok_or_else(|| anyhow::anyhow!("payload.storage[{i}] must be an integer"))?;
        if b < 0 || b > 255 {
            anyhow::bail!("payload.storage[{i}] out of u8 range: {b}");
        }
        bytes.push(b as u8);
    }

    if bytes.len() < payload_len {
        anyhow::bail!(
            "payload.storage has {} elements but payload.len is {payload_len}",
            bytes.len()
        );
    }

    let mut new_storage = vec![0u8; args.payload_max_len];
    new_storage[..payload_len].copy_from_slice(&bytes[..payload_len]);

    let array: Vec<Value> = new_storage
        .iter()
        .map(|&b| Value::Integer(b as i64))
        .collect();
    payload.insert("storage".to_string(), Value::Array(array));

    let out = toml::to_string(&doc).context("serialize Prover.toml")?;
    fs::write(&args.output, out).with_context(|| format!("write '{}'", args.output.display()))?;
    info!(
        "Wrote {} (payload.len={payload_len}, storage len={})",
        args.output.display(),
        args.payload_max_len
    );
    Ok(())
}
