//! `eid-tools mdoc witness` — Prover.toml from IssuerSigned CBOR.

use anyhow::{Context, Result};
use ciborium::Value as CborValue;
use clap::Args as ClapArgs;
use log::info;
use noir_eid_tools::config::{
    DEFAULT_CHALLENGE_MSG, DEFAULT_DEVICE_KEY, DEFAULT_ISSUER_KEY, DISCLOSED_ATTR_MAX_LEN,
};
use noir_eid_tools::crypto::{
    Curve, challenge_nonce_from_message, load_p256_signing_key, normalize_signature,
    sign_device_binding, verifying_key_xy_p256,
};
use noir_eid_tools::io::open_writer;
use noir_eid_tools::mdoc::witness::{DisclosedAttr, MdocWitness, MsoOffsets};
use noir_eid_tools::cbor::{encode as cbor_encode, map_lookup};
use noir_eid_tools::mdoc::wire::{
    device_key_offsets, issuer_auth_cose_bytes, parse_cose_sign1,
};
use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

#[derive(Clone, ClapArgs)]
pub struct WitnessArgs {
    /// IssuerSigned CBOR (map with issuerAuth + nameSpaces)
    pub mdoc_file: PathBuf,
    /// Write Prover.toml here (default: stdout)
    #[arg(long, short = 'o')]
    pub output: Option<PathBuf>,
    /// Issuer private key PEM (used to derive public coordinates for the circuit)
    #[arg(long, default_value = DEFAULT_ISSUER_KEY)]
    pub key: PathBuf,
    /// Device private key PEM (for challenge signature)
    #[arg(long, default_value = DEFAULT_DEVICE_KEY)]
    pub device_key: PathBuf,
    /// elementIdentifier to disclose (must exist in nameSpaces)
    #[arg(long, default_value = "birth_date")]
    pub attribute: String,
    /// Pad `mso_bytes.storage` to this length (must match circuit `MSO_MAX_LEN`)
    #[arg(long, default_value_t = 1024)]
    pub mso_max_len: usize,
}

#[derive(Clone)]
struct ItemRef {
    digest_id: u64,
    element_identifier: String,
    cbor_bytes: Vec<u8>,
}

fn push_unique_bytes(out: &mut Vec<Vec<u8>>, b: Vec<u8>) {
    if !out.iter().any(|x| x == &b) {
        out.push(b);
    }
}

fn issuer_signed_item_candidates(elem: &CborValue) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    match elem {
        CborValue::Tag(24, inner) => {
            push_unique_bytes(&mut out, cbor_encode(&CborValue::Tag(24, inner.clone())));
            match inner.as_ref() {
                CborValue::Bytes(b) => {
                    push_unique_bytes(&mut out, b.clone());
                    if let Ok(v) = ciborium::from_reader::<CborValue, _>(b.as_slice()) {
                        push_unique_bytes(&mut out, cbor_encode(&v));
                    }
                }
                other => {
                    push_unique_bytes(&mut out, cbor_encode(other));
                }
            }
        }
        CborValue::Bytes(b) => {
            push_unique_bytes(&mut out, b.clone());
            if let Ok(v) = ciborium::from_reader::<CborValue, _>(b.as_slice()) {
                push_unique_bytes(&mut out, cbor_encode(&v));
            }
        }
        CborValue::Map(_) | CborValue::Array(_) => {
            push_unique_bytes(&mut out, cbor_encode(elem));
        }
        _ => {}
    }
    out
}

fn extract_digest_and_ident_from_map(v: &CborValue) -> Option<(u64, String)> {
    let CborValue::Map(entries) = v else {
        return None;
    };
    let mut digest_id = None;
    let mut ident = None;
    for (k, val) in entries {
        match k {
            CborValue::Text(t) if t == "digestID" => {
                if let CborValue::Integer(i) = val.clone() {
                    digest_id = i.try_into().ok();
                }
            }
            CborValue::Text(t) if t == "elementIdentifier" => {
                if let CborValue::Text(s) = val {
                    ident = Some(s.clone());
                }
            }
            _ => {}
        }
    }
    Some((digest_id?, ident?))
}

fn parse_item_meta(bytes: &[u8]) -> Option<(u64, String)> {
    let v: CborValue = ciborium::from_reader(bytes).ok()?;
    match v {
        CborValue::Map(_) => extract_digest_and_ident_from_map(&v),
        CborValue::Tag(24, inner) => match inner.as_ref() {
            CborValue::Bytes(b) => {
                let inner_val: CborValue = ciborium::from_reader(b.as_slice()).ok()?;
                extract_digest_and_ident_from_map(&inner_val)
            }
            other => extract_digest_and_ident_from_map(other),
        },
        _ => None,
    }
}

fn try_push_item_matching_mso(
    items: &mut Vec<ItemRef>,
    mso_root: &CborValue,
    elem: &CborValue,
) -> Result<()> {
    let expected_digest = |digest_id: u64| digest_from_mso_for_id(mso_root, digest_id);

    for cand in issuer_signed_item_candidates(elem) {
        let Some((digest_id, element_identifier)) = parse_item_meta(&cand) else {
            continue;
        };
        let expected = match expected_digest(digest_id) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let h: [u8; 32] = Sha256::digest(&cand).into();
        if h.as_slice() == expected.as_slice() {
            items.push(ItemRef {
                digest_id,
                element_identifier,
                cbor_bytes: cand,
            });
            return Ok(());
        }
    }
    Ok(())
}

fn collect_items_from_namespaces(
    mso_root: &CborValue,
    namespaces_val: &CborValue,
) -> Result<Vec<ItemRef>> {
    let mut items = Vec::new();
    let CborValue::Map(ns_root) = namespaces_val else {
        anyhow::bail!("nameSpaces is not a map");
    };
    for (_ns_key, ns_content) in ns_root {
        match ns_content {
            CborValue::Array(elems) => {
                for elem in elems {
                    try_push_item_matching_mso(&mut items, mso_root, elem)?;
                }
            }
            CborValue::Map(m) => {
                for (_k, v) in m {
                    try_push_item_matching_mso(&mut items, mso_root, v)?;
                }
            }
            _ => {}
        }
    }
    Ok(items)
}

fn unwrap_mso_value(mut v: CborValue) -> Result<CborValue> {
    loop {
        match v {
            CborValue::Tag(_, inner) => v = *inner,
            CborValue::Bytes(b) => {
                v = ciborium::from_reader(b.as_slice()).context("unwrap MSO inner CBOR")?;
            }
            _ => break,
        }
    }
    Ok(v)
}

fn digest_from_mso_for_id(mso_root: &CborValue, digest_id: u64) -> Result<Vec<u8>> {
    let CborValue::Map(entries) = mso_root else {
        anyhow::bail!("MSO is not a CBOR map");
    };
    let vd = map_lookup(entries, "valueDigests")
        .ok_or_else(|| anyhow::anyhow!("MSO missing valueDigests"))?;
    let CborValue::Map(ns_root) = vd else {
        anyhow::bail!("valueDigests is not a map");
    };
    let key_id = CborValue::Integer(digest_id.into());
    for (_ns, ns_map_val) in ns_root {
        let CborValue::Map(digests) = ns_map_val else {
            continue;
        };
        for (k, val) in digests {
            if k == &key_id {
                if let CborValue::Bytes(b) = val {
                    if b.len() == 32 {
                        return Ok(b.clone());
                    }
                }
                anyhow::bail!("valueDigest entry is not a 32-byte bstr");
            }
        }
    }
    anyhow::bail!("digestID {digest_id} not found in MSO valueDigests")
}

fn hash_digest_offset_in_mso(mso: &[u8], expected_hash: &[u8; 32]) -> Result<usize> {
    let pos = mso
        .windows(32)
        .position(|w| w == expected_hash.as_slice())
        .context("expected digest bytes not found in raw MSO CBOR")?;
    Ok(pos.saturating_sub(2))
}

fn extract_bstr32_at(mso: &[u8], off: usize) -> Result<[u8; 32]> {
    if off + 34 > mso.len() {
        anyhow::bail!("MSO slice too short at device key offset");
    }
    if mso[off] != 0x58 || mso[off + 1] != 0x20 {
        anyhow::bail!(
            "expected bstr(32) header 0x58 0x20 at MSO offset {}, got {:02x} {:02x}",
            off,
            mso[off],
            mso[off + 1]
        );
    }
    Ok(mso[off + 2..off + 34].try_into()?)
}

fn assert_device_key_matches_mso(
    mso: &[u8],
    x_off: usize,
    y_off: usize,
    device_sk: &SigningKey,
) -> Result<()> {
    let mx = extract_bstr32_at(mso, x_off)?;
    let my = extract_bstr32_at(mso, y_off)?;
    let pk = verifying_key_xy_p256(device_sk);
    if mx != pk.x || my != pk.y {
        anyhow::bail!(
            "Device private key (--device-key) does not match deviceKeyInfo in the MSO.\n\
For wallet-issued mdocs, use the holder's device PEM.\n\
For this repo's test keys, generate IssuerSigned from SWIYU JSON:\n\
  eid-tools mdoc build ../data/swiyu-eid.json --issuer-signed-out ../data/swiyu_IssuerSigned.cbor\n\
  eid-tools mdoc witness ../data/swiyu_IssuerSigned.cbor -o Prover.toml --mso-max-len 1024"
        );
    }
    Ok(())
}

pub fn run_witness(args: WitnessArgs) -> Result<()> {
    let raw = fs::read(&args.mdoc_file)
        .with_context(|| format!("read '{}'", args.mdoc_file.display()))?;
    let top: CborValue =
        ciborium::from_reader(raw.as_slice()).context("parse IssuerSigned CBOR")?;

    let CborValue::Map(ref entries) = top else {
        anyhow::bail!("expected IssuerSigned top-level CBOR map");
    };

    let namespaces_val = map_lookup(entries, "nameSpaces")
        .context("IssuerSigned map missing \"nameSpaces\"")?
        .clone();

    let cose_in = issuer_auth_cose_bytes(&top, &raw)?;
    let sign1 = parse_cose_sign1(cose_in.as_ref())?;
    let mso_bytes: Vec<u8> = sign1
        .payload
        .ok_or_else(|| anyhow::anyhow!("COSE_Sign1 has no payload"))?;

    let mso_decoded: CborValue =
        ciborium::from_reader(mso_bytes.as_slice()).context("decode MSO CBOR")?;
    let mso_root = unwrap_mso_value(mso_decoded)?;

    let all_items = collect_items_from_namespaces(&mso_root, &namespaces_val)?;
    if all_items.is_empty() {
        anyhow::bail!(
            "no IssuerSignedItems under nameSpaces matched MSO valueDigests (check encoding)"
        );
    }

    let disclosed = all_items
        .iter()
        .find(|i| i.element_identifier == args.attribute)
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no disclosed item with identifier {:?} (available: {:?})",
                args.attribute,
                all_items
                    .iter()
                    .map(|i| i.element_identifier.as_str())
                    .collect::<Vec<_>>()
            )
        })?;

    let digest_hash: [u8; 32] = Sha256::digest(&disclosed.cbor_bytes).into();
    let dob_digest_offset = hash_digest_offset_in_mso(&mso_bytes, &digest_hash)?;

    let (device_key_x_offset, device_key_y_offset) = device_key_offsets(&mso_bytes)?;

    let device_sk = load_p256_signing_key(&args.device_key)?;
    assert_device_key_matches_mso(
        &mso_bytes,
        device_key_x_offset,
        device_key_y_offset,
        &device_sk,
    )?;

    let sig_slice: [u8; 64] = sign1.signature.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "COSE signature must be 64 bytes, got {}",
            sign1.signature.len()
        )
    })?;
    let issuer_signature = normalize_signature(&sig_slice, Curve::P256);

    let issuer_sk = load_p256_signing_key(&args.key)?;
    let issuer_pub = verifying_key_xy_p256(&issuer_sk);

    let challenge_nonce = challenge_nonce_from_message(DEFAULT_CHALLENGE_MSG);
    let device_signature = sign_device_binding(&challenge_nonce, &device_sk)?;

    info!(
        "MSO len = {}, mso_max_len = {}, disclosed len = {}",
        mso_bytes.len(),
        args.mso_max_len,
        disclosed.cbor_bytes.len()
    );
    info!(
        "dob_digest_offset = {}, device_key_x_offset = {}, device_key_y_offset = {}",
        dob_digest_offset, device_key_x_offset, device_key_y_offset
    );

    let mut writer = open_writer(args.output.as_deref())?;

    const EXTRA: &[&str] = &[
        "Generated by `eid-tools mdoc witness`. Wallet mdocs need --device-key matching MSO deviceKeyInfo.",
        "With repo keys: eid-tools mdoc build ../data/swiyu-eid.json --issuer-signed-out ../data/swiyu_IssuerSigned.cbor \\",
        "  && eid-tools mdoc witness ../data/swiyu_IssuerSigned.cbor -o Prover.toml --mso-max-len <MSO_MAX_LEN>",
    ];
    let ref_items = all_items.iter().map(|item| {
        (
            item.digest_id,
            item.element_identifier.as_str(),
            item.cbor_bytes.as_slice(),
        )
    });

    let witness = MdocWitness {
        mso_bytes: &mso_bytes,
        mso_max_len: args.mso_max_len,
        disclosed_attr_max_len: DISCLOSED_ATTR_MAX_LEN,
        issuer_signature,
        issuer_pub,
        disclosed: DisclosedAttr {
            digest_id: disclosed.digest_id,
            element_identifier: disclosed.element_identifier.as_str(),
            cbor_bytes: &disclosed.cbor_bytes,
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
        "Prover.toml (experiment20 / mdoc-swiyu)",
        EXTRA,
        ref_items,
    )?;

    if let Some(p) = &args.output {
        info!("Wrote {}", p.display());
    }

    Ok(())
}
