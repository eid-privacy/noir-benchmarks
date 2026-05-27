//! `eid-tools mdoc build` — MSO + COSE from SWIYU JSON.

use anyhow::{Context, Result};
use ciborium::Value as CborValue;
use clap::Args as ClapArgs;
use log::{debug, info};
use noir_eid_tools::config::{
    DEFAULT_CHALLENGE_MSG, DEFAULT_DEVICE_KEY, DEFAULT_ISSUER_KEY, DISCLOSED_ATTR_MAX_LEN,
    MDOC_NAMESPACE, MSO_MAX_LEN_EXPERIMENT00,
};
use noir_eid_tools::crypto::{
    challenge_nonce_from_message, load_p256_signing_key, sign_device_binding,
    verifying_key_xy_p256,
};
use noir_eid_tools::format::cbor::CborDisplay;
use noir_eid_tools::io::open_writer;
use noir_eid_tools::cbor::text as cbor_text;
use noir_eid_tools::mdoc::ELEMENT_FIELDS;
use noir_eid_tools::mdoc::mso::{IssuerSignedItem, Mso, cose_ec2_key};
use noir_eid_tools::mdoc::witness::{DisclosedAttr, MdocWitness, MsoOffsets};
use noir_eid_tools::mdoc::wire::device_key_offsets;
use noir_eid_tools::credential::swiyu;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

#[derive(ClapArgs)]
pub struct BuildArgs {
    /// Path to SWIYU JSON credential file
    pub json_file: PathBuf,
    /// Path to issuer private key (PEM)
    #[arg(long, default_value = DEFAULT_ISSUER_KEY)]
    pub key: PathBuf,
    /// Output path for the MDoc file
    #[arg(long, default_value = "swiyu-eid.mdoc")]
    pub output: PathBuf,
    /// Optional path to write full ISO 18013-5 IssuerSigned CBOR
    #[arg(long)]
    pub issuer_signed_out: Option<PathBuf>,
    /// Write Prover.toml output to a file instead of stdout
    #[arg(long)]
    pub prover_output: Option<PathBuf>,
    /// Path to device private key used to sign challenge nonce
    #[arg(long, default_value = DEFAULT_DEVICE_KEY)]
    pub device_key: PathBuf,
}

pub fn run_build(args: BuildArgs) -> Result<()> {
    let data: Value = serde_json::from_str(
        &fs::read_to_string(&args.json_file)
            .with_context(|| format!("read SWIYU JSON '{}'", args.json_file.display()))?,
    )
    .context("parse SWIYU JSON")?;

    let signing_key = load_p256_signing_key(&args.key)?;
    let device_signing_key = load_p256_signing_key(&args.device_key)?;

    let device_pk = verifying_key_xy_p256(&device_signing_key);
    let device_key_x = device_pk.x.as_slice();
    let device_key_y = device_pk.y.as_slice();

    let mut items: Vec<IssuerSignedItem> = Vec::new();
    for field in ELEMENT_FIELDS {
        if let Some(val) = field.field_type.to_cbor_value(&data, field.name) {
            items.push(IssuerSignedItem::new(items.len() as u64, field.name, val));
        }
    }
    items.push(IssuerSignedItem::new(
        items.len() as u64,
        "cnf",
        cose_ec2_key(device_key_x, device_key_y),
    ));

    info!("Built {} IssuerSignedItems:", items.len());
    for item in &items {
        info!(
            "  digestID={:2}  identifier={:<32}  item_len={:3}  hash={}",
            item.digest_id,
            item.element_identifier,
            item.cbor_bytes.len(),
            hex::encode(&item.hash()[..8]),
        );
    }

    let signed_at = swiyu::get_str(&data, "issuance_date")
        .and_then(|s| chrono::NaiveDate::parse_from_str(&s, "%Y-%m-%d").ok())
        .map(|d| d.and_hms_opt(0, 0, 0).unwrap().and_utc())
        .unwrap_or_else(chrono::Utc::now);
    let valid_from = signed_at;
    let valid_until = swiyu::get_str(&data, "expiry_date")
        .and_then(|s| chrono::NaiveDate::parse_from_str(&s, "%Y-%m-%d").ok())
        .map(|d| d.and_hms_opt(23, 59, 59).unwrap().and_utc())
        .unwrap_or_else(|| signed_at + chrono::Duration::days(30));

    let mso = Mso::new(
        device_key_x,
        device_key_y,
        &items,
        &signed_at,
        &valid_from,
        &valid_until,
    );
    info!("MSO structure (CBOR diagnostic):\n{}", mso.cbor.pretty());

    info!(
        "MSO bytes length: {} (max {})",
        mso.bytes.len(),
        MSO_MAX_LEN_EXPERIMENT00
    );
    if mso.bytes.len() > MSO_MAX_LEN_EXPERIMENT00 {
        anyhow::bail!(
            "MSO length {} exceeds MSO_MAX_LEN {} for experiment00 Prover.toml",
            mso.bytes.len(),
            MSO_MAX_LEN_EXPERIMENT00
        );
    }

    let signed = mso.sign(&signing_key)?;
    let mdoc_cbor: CborValue = ciborium::from_reader(signed.cose_bytes.as_slice())
        .context("decode signed COSE as CBOR for logging")?;
    info!(
        "MDoc COSE_Sign1 structure (CBOR diagnostic):\n{}",
        mdoc_cbor.pretty()
    );

    info!("IssuerSignedItem structures (CBOR diagnostic):");
    for item in &items {
        info!(
            "  digestID={} identifier=\"{}\"\n{}",
            item.digest_id,
            item.element_identifier,
            item.to_cbor_value()?.pretty()
        );
    }

    debug!(
        "COSE_Sign1 bytes (len={}): {:?}",
        signed.cose_bytes.len(),
        signed.cose_bytes
    );

    fs::write(&args.output, &signed.cose_bytes)
        .with_context(|| format!("write mdoc '{}'", args.output.display()))?;
    info!("Written MDoc to: {}", args.output.display());

    if let Some(ref path) = args.issuer_signed_out {
        let issuer_auth: CborValue = ciborium::from_reader(signed.cose_bytes.as_slice())
            .context("decode COSE for IssuerSigned bundle")?;
        let name_space_elements: Vec<CborValue> = items
            .iter()
            .map(|it| CborValue::Tag(24, Box::new(CborValue::Bytes(it.cbor_bytes.clone()))))
            .collect();
        let issuer_signed = CborValue::Map(vec![
            (cbor_text("issuerAuth"), issuer_auth),
            (
                cbor_text("nameSpaces"),
                CborValue::Map(vec![(
                    cbor_text(MDOC_NAMESPACE),
                    CborValue::Array(name_space_elements),
                )]),
            ),
        ]);
        let mut bundle = Vec::new();
        ciborium::into_writer(&issuer_signed, &mut bundle).context("encode IssuerSigned CBOR")?;
        fs::write(path, &bundle).with_context(|| format!("write '{}'", path.display()))?;
        info!("Written IssuerSigned CBOR to: {}", path.display());
    }

    let issuer_pub = verifying_key_xy_p256(&signing_key);

    let disclosed_item = items
        .iter()
        .find(|i| i.element_identifier == "birth_date")
        .context("birth_date attribute not found in SWIYU data")?;

    let birth_date_hash = disclosed_item.hash();
    let dob_digest_offset = mso
        .bytes
        .windows(32)
        .position(|w| w == birth_date_hash.as_slice())
        .map(|pos| pos.saturating_sub(2))
        .context("birth_date hash not found in MSO bytes")?;

    let (device_key_x_offset, device_key_y_offset) = device_key_offsets(&mso.bytes)?;

    info!(
        "dob_digest_offset = {} (bstr at MSO[{}..{}])",
        dob_digest_offset,
        dob_digest_offset,
        dob_digest_offset + 34
    );
    info!(
        "device_key_x_offset = {}, device_key_y_offset = {}",
        device_key_x_offset, device_key_y_offset
    );

    let challenge_nonce = challenge_nonce_from_message(DEFAULT_CHALLENGE_MSG);
    let device_signature = sign_device_binding(&challenge_nonce, &device_signing_key)?;

    let mut writer = open_writer(args.prover_output.as_deref())?;

    let ref_items = items.iter().map(|item| {
        (
            item.digest_id,
            item.element_identifier.as_str(),
            item.cbor_bytes.as_slice(),
        )
    });

    let witness = MdocWitness {
        mso_bytes: &mso.bytes,
        mso_max_len: MSO_MAX_LEN_EXPERIMENT00,
        disclosed_attr_max_len: DISCLOSED_ATTR_MAX_LEN,
        issuer_signature: signed.signature,
        issuer_pub,
        disclosed: DisclosedAttr {
            digest_id: disclosed_item.digest_id,
            element_identifier: disclosed_item.element_identifier.as_str(),
            cbor_bytes: &disclosed_item.cbor_bytes,
        },
        offsets: MsoOffsets {
            dob_digest: dob_digest_offset,
            device_key_x: device_key_x_offset,
            device_key_y: device_key_y_offset,
        },
        challenge_nonce,
        device_signature,
    };
    witness.write_prover_toml(
        &mut writer,
        "Prover.toml (paste below into experiment00/Prover.toml)",
        &[] as &[&str],
        ref_items,
    )?;

    Ok(())
}
