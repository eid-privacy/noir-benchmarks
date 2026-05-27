//! `eid-tools bench` — max-length sweep (nargo + bb → CSV).
//!
//! Supports both mdoc (`MSO_MAX_LEN`) and JWT (`PAYLOAD_MAX_LEN`) experiments,
//! auto-detected from the constants file.

use super::common::{
    detect_circuit_name, detect_kind, find_repo_root, format_time_or_error, patch_constant,
    remove_bb_artifacts, resolve_constants_path, run_command_timed, ExperimentKind,
};
use crate::cli::{jwt, mdoc};
use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use log::{info, warn};
use noir_eid_tools::mdoc::wire::mso_payload_len;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(ClapArgs)]
pub struct Args {
    /// Noir experiment directory (must contain `Nargo.toml`, `src/constants.nr`, etc.)
    #[arg(long, default_value = ".")]
    pub dir: PathBuf,

    /// IssuerSigned CBOR input for `mdoc witness`
    #[arg(long)]
    pub mdoc: Option<PathBuf>,

    /// Walk up from `--dir` until `data/issuer.prv` exists; used for default paths
    #[arg(long)]
    pub repo_root: Option<PathBuf>,

    /// Max-length values to benchmark (repeat flag or comma-separated)
    #[arg(long = "max-length", value_delimiter = ',', num_args = 1.., default_value = "2000")]
    pub max_lengths: Vec<u32>,

    /// Path to `constants.nr` (relative to `--dir` unless absolute)
    #[arg(long, default_value = "src/constants.nr")]
    pub constants: PathBuf,

    /// Nargo package / bytecode base name (auto-detected from Nargo.toml when omitted)
    #[arg(long)]
    pub circuit: Option<String>,

    /// Output CSV path (default: `benchmark-YYYYMMDD_HHMMSS.csv` in `--dir`)
    #[arg(long, short = 'o')]
    pub csv: Option<PathBuf>,

    /// Passed through to `mdoc witness`
    #[arg(long, default_value = "birth_date")]
    pub attribute: String,

    /// Issuer PEM (default: `<repo-root>/data/issuer.prv`)
    #[arg(long)]
    pub issuer_key: Option<PathBuf>,

    /// Device PEM (default: `<repo-root>/data/device.prv`)
    #[arg(long)]
    pub device_key: Option<PathBuf>,

    /// Prover.toml output path (default: `<dir>/Prover.toml`)
    #[arg(long)]
    pub prover_toml: Option<PathBuf>,
}


/// Read `payload.len` from an existing Prover.toml (JWT experiments).
fn read_payload_len(prover_toml: &Path) -> Result<usize> {
    let content = fs::read_to_string(prover_toml)
        .with_context(|| format!("read {}", prover_toml.display()))?;
    let doc: toml::Value = toml::from_str(&content)
        .with_context(|| format!("parse {}", prover_toml.display()))?;
    let len = doc
        .get("payload")
        .and_then(|p| p.get("len"))
        .and_then(toml::Value::as_integer)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no payload.len in {} (is this a JWT Prover.toml?)",
                prover_toml.display()
            )
        })?;
    Ok(len as usize)
}


fn run_pipeline(experiment_dir: &Path, circuit: &str) -> Result<[Result<f64, String>; 5], String> {
    let bytecode_rel = format!("target/{circuit}.json");
    let bytecode_path = experiment_dir.join(&bytecode_rel);

    let target_dir = experiment_dir.join("target");
    if target_dir.is_dir() {
        let _ = fs::remove_dir_all(&target_dir);
    }

    let test_ok = Command::new("nargo")
        .args(["test"])
        .current_dir(experiment_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("nargo test: {e}"))?
        .success();
    if !test_ok {
        return Err("nargo test failed".into());
    }

    let c = run_command_timed(experiment_dir, "nargo", &["compile"]);
    if c.is_err() || !bytecode_path.is_file() {
        return Err("nargo compile failed or bytecode missing".into());
    }

    let gates_ok = Command::new("bb")
        .args(["gates", "-b", &bytecode_rel])
        .current_dir(experiment_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !gates_ok {
        return Err("bb gates failed".into());
    }

    let e = run_command_timed(experiment_dir, "nargo", &["execute"]);

    remove_bb_artifacts(experiment_dir);

    let w = run_command_timed(
        experiment_dir,
        "bb",
        &[
            "write_vk",
            "-b",
            &format!("./{bytecode_rel}"),
            "-o",
            "./target",
        ],
    );
    let gz_name = format!("./target/{circuit}.gz");
    let p = run_command_timed(
        experiment_dir,
        "bb",
        &[
            "prove",
            "-b",
            &format!("./{bytecode_rel}"),
            "-w",
            &gz_name,
            "-k",
            "./target/vk",
            "-o",
            "./target",
        ],
    );
    let v = run_command_timed(
        experiment_dir,
        "bb",
        &["verify", "-k", "./target/vk", "-p", "./target/proof"],
    );

    Ok([c, e, w, p, v])
}

fn default_csv_path(experiment_dir: &Path) -> PathBuf {
    let stamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    experiment_dir.join(format!("benchmark-{stamp}.csv"))
}

pub fn run(args: Args) -> Result<()> {
    let experiment_dir = args
        .dir
        .canonicalize()
        .map_err(|e| anyhow::anyhow!("--dir {:?}: {e}", args.dir))?;

    let csv_path = args
        .csv
        .clone()
        .unwrap_or_else(|| default_csv_path(&experiment_dir));

    let constants_path = resolve_constants_path(&experiment_dir, &args.constants);
    if !constants_path.is_file() {
        anyhow::bail!("constants file not found: {}", constants_path.display());
    }

    let kind = detect_kind(&constants_path)?;
    let circuit = match &args.circuit {
        Some(c) => c.clone(),
        None => detect_circuit_name(&experiment_dir)?,
    };
    info!("Circuit name: {circuit}");

    let prover_toml = args
        .prover_toml
        .clone()
        .map(|p| {
            if p.is_absolute() {
                p
            } else {
                experiment_dir.join(p)
            }
        })
        .unwrap_or_else(|| experiment_dir.join("Prover.toml"));

    match kind {
        ExperimentKind::Mdoc => run_mdoc_bench(&args, &experiment_dir, &constants_path, &csv_path, &circuit, &prover_toml),
        ExperimentKind::Jwt => run_jwt_bench(&args, &experiment_dir, &constants_path, &csv_path, &circuit, &prover_toml),
    }
}

fn run_mdoc_bench(
    args: &Args,
    experiment_dir: &Path,
    constants_path: &Path,
    csv_path: &Path,
    circuit: &str,
    prover_toml: &Path,
) -> Result<()> {
    let repo_root =
        find_repo_root(experiment_dir, args.repo_root.clone()).map_err(|e| anyhow::anyhow!(e))?;

    let mdoc_raw_path = args
        .mdoc
        .clone()
        .unwrap_or_else(|| repo_root.join("data").join("swiyu_IssuerSigned.cbor"));
    let mdoc_path = mdoc_raw_path.canonicalize().map_err(|e| {
        anyhow::anyhow!(
            "mdoc file {}: {e} (set --mdoc or ensure {} exists)",
            mdoc_raw_path.display(),
            repo_root.join("data/swiyu_IssuerSigned.cbor").display()
        )
    })?;
    if !mdoc_path.is_file() {
        anyhow::bail!("mdoc file not found: {}", mdoc_path.display());
    }

    let issuer_key = args
        .issuer_key
        .clone()
        .unwrap_or_else(|| repo_root.join("data").join("issuer.prv"));
    let device_key = args
        .device_key
        .clone()
        .unwrap_or_else(|| repo_root.join("data").join("device.prv"));

    let mdoc_raw = fs::read(&mdoc_path)
        .with_context(|| format!("read '{}'", mdoc_path.display()))?;
    let actual_len = mso_payload_len(&mdoc_raw)
        .context("could not determine MSO payload length")?;
    info!("Actual MSO payload length: {actual_len} bytes");

    let mut csv_file = fs::File::create(csv_path)
        .with_context(|| format!("create CSV '{}'", csv_path.display()))?;
    writeln!(
        csv_file,
        "max_length,nargo_compile,nargo_execute,bb_write_vk,bb_prove,bb_verify"
    )?;

    let mut any_fail = false;

    for &n in &args.max_lengths {
        if (n as usize) < actual_len {
            warn!(
                "Skipping MSO_MAX_LEN={n} (actual MSO is {actual_len} bytes, need at least {actual_len})"
            );
            writeln!(csv_file, "{n},skipped,skipped,skipped,skipped,skipped")?;
            continue;
        }

        info!("MSO_MAX_LEN={n}");
        if let Err(e) = patch_constant(constants_path, "MSO_MAX_LEN", n) {
            warn!("patch constants: {e}");
            writeln!(csv_file, "{n},error,error,error,error,error")?;
            any_fail = true;
            continue;
        }

        let witness_args = mdoc::WitnessArgs {
            mdoc_file: mdoc_path.clone(),
            output: Some(prover_toml.to_path_buf()),
            key: issuer_key.clone(),
            device_key: device_key.clone(),
            attribute: args.attribute.clone(),
            mso_max_len: n as usize,
        };
        if let Err(e) = mdoc::run_witness(witness_args) {
            warn!("mdoc witness: {e}");
            writeln!(csv_file, "{n},error,error,error,error,error")?;
            any_fail = true;
            continue;
        }

        write_pipeline_row(&mut csv_file, experiment_dir, circuit, n, &mut any_fail)?;
    }

    info!("Wrote {}", csv_path.display());
    if any_fail {
        anyhow::bail!("benchmark finished with one or more failures (see log and CSV)");
    }
    Ok(())
}

fn run_jwt_bench(
    args: &Args,
    experiment_dir: &Path,
    constants_path: &Path,
    csv_path: &Path,
    circuit: &str,
    prover_toml: &Path,
) -> Result<()> {
    if !prover_toml.is_file() {
        anyhow::bail!(
            "JWT bench requires an existing Prover.toml at {} (run `eid-tools jwt sign` + `jwt pad` first)",
            prover_toml.display()
        );
    }

    let actual_len = read_payload_len(prover_toml)?;
    info!("Actual JWT payload length: {actual_len} bytes");

    // Save the original Prover.toml as a template for re-padding
    let template_path = experiment_dir.join(".bench_template_Prover.toml");
    fs::copy(prover_toml, &template_path)
        .with_context(|| format!("copy {} → {}", prover_toml.display(), template_path.display()))?;

    let result = run_jwt_bench_inner(
        args,
        experiment_dir,
        constants_path,
        csv_path,
        circuit,
        prover_toml,
        &template_path,
        actual_len,
    );

    // Clean up template regardless of outcome
    let _ = fs::remove_file(&template_path);
    result
}

fn run_jwt_bench_inner(
    args: &Args,
    experiment_dir: &Path,
    constants_path: &Path,
    csv_path: &Path,
    circuit: &str,
    prover_toml: &Path,
    template_path: &Path,
    actual_len: usize,
) -> Result<()> {
    let mut csv_file = fs::File::create(csv_path)
        .with_context(|| format!("create CSV '{}'", csv_path.display()))?;
    writeln!(
        csv_file,
        "max_length,nargo_compile,nargo_execute,bb_write_vk,bb_prove,bb_verify"
    )?;

    let mut any_fail = false;

    for &n in &args.max_lengths {
        if (n as usize) < actual_len {
            warn!(
                "Skipping PAYLOAD_MAX_LEN={n} (actual payload is {actual_len} bytes, need at least {actual_len})"
            );
            writeln!(csv_file, "{n},skipped,skipped,skipped,skipped,skipped")?;
            continue;
        }

        info!("PAYLOAD_MAX_LEN={n}");
        if let Err(e) = patch_constant(constants_path, "PAYLOAD_MAX_LEN", n) {
            warn!("patch constants: {e}");
            writeln!(csv_file, "{n},error,error,error,error,error")?;
            any_fail = true;
            continue;
        }

        let pad_args = jwt::PadArgs {
            template: template_path.to_path_buf(),
            output: prover_toml.to_path_buf(),
            payload_max_len: n as usize,
        };
        if let Err(e) = jwt::run_pad(pad_args) {
            warn!("jwt pad: {e}");
            writeln!(csv_file, "{n},error,error,error,error,error")?;
            any_fail = true;
            continue;
        }

        write_pipeline_row(&mut csv_file, experiment_dir, circuit, n, &mut any_fail)?;
    }

    info!("Wrote {}", csv_path.display());
    if any_fail {
        anyhow::bail!("benchmark finished with one or more failures (see log and CSV)");
    }
    Ok(())
}

fn write_pipeline_row(
    csv_file: &mut fs::File,
    experiment_dir: &Path,
    circuit: &str,
    n: u32,
    any_fail: &mut bool,
) -> Result<()> {
    match run_pipeline(experiment_dir, circuit) {
        Ok([c, e, w, p, v]) => {
            if e.is_err() || w.is_err() || p.is_err() || v.is_err() {
                *any_fail = true;
            }
            writeln!(
                csv_file,
                "{},{},{},{},{},{}",
                n,
                format_time_or_error(&c),
                format_time_or_error(&e),
                format_time_or_error(&w),
                format_time_or_error(&p),
                format_time_or_error(&v),
            )?;
        }
        Err(msg) => {
            warn!("{msg} for max_length={n}");
            writeln!(csv_file, "{n},error,error,error,error,error")?;
            *any_fail = true;
        }
    }
    Ok(())
}
