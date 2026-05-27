//! Shared helpers for `bench` and `profile` subcommands.

use anyhow::{Context, Result};
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

/// Which kind of experiment we detected from `constants.nr`.
pub enum ExperimentKind {
    Mdoc,
    Jwt,
}

/// Walk up from `experiment_dir` until `data/issuer.prv` exists.
pub fn find_repo_root(experiment_dir: &Path, explicit: Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(p) = explicit {
        let c = p
            .canonicalize()
            .map_err(|e| format!("--repo-root {}: {e}", p.display()))?;
        return Ok(c);
    }
    let mut cur = experiment_dir
        .canonicalize()
        .map_err(|e| format!("--dir {}: {e}", experiment_dir.display()))?;
    loop {
        let candidate = cur.join("data").join("issuer.prv");
        if candidate.is_file() {
            return Ok(cur);
        }
        cur = cur
            .parent()
            .ok_or_else(|| {
                "could not find repo root (no data/issuer.prv in parents); pass --repo-root or --mdoc / --issuer-key / --device-key".to_string()
            })?
            .to_path_buf();
    }
}

/// Detect experiment kind from `constants.nr` content.
pub fn detect_kind(constants_path: &Path) -> Result<ExperimentKind> {
    let content = fs::read_to_string(constants_path)
        .with_context(|| format!("read {}", constants_path.display()))?;
    if content.contains("MSO_MAX_LEN") {
        Ok(ExperimentKind::Mdoc)
    } else if content.contains("PAYLOAD_MAX_LEN") {
        Ok(ExperimentKind::Jwt)
    } else {
        anyhow::bail!(
            "cannot detect experiment kind: {} contains neither MSO_MAX_LEN nor PAYLOAD_MAX_LEN",
            constants_path.display()
        )
    }
}

/// Read the Nargo package name from `Nargo.toml` in the experiment directory.
pub fn detect_circuit_name(experiment_dir: &Path) -> Result<String> {
    let nargo_path = experiment_dir.join("Nargo.toml");
    let content = fs::read_to_string(&nargo_path)
        .with_context(|| format!("read {}", nargo_path.display()))?;
    let re = Regex::new(r#"(?m)^name\s*=\s*"([^"]+)""#)?;
    let caps = re
        .captures(&content)
        .ok_or_else(|| anyhow::anyhow!("no `name = \"...\"` in {}", nargo_path.display()))?;
    Ok(caps[1].to_string())
}

/// Overwrite `pub global <name>: u32 = <digits>;` in a constants file.
pub fn patch_constant(constants_path: &Path, name: &str, value: u32) -> Result<()> {
    let content = fs::read_to_string(constants_path)
        .with_context(|| format!("read {}", constants_path.display()))?;
    let pattern = format!(r"(?m)^pub global {name}: u32 = \d+;$");
    let re = Regex::new(&pattern)?;
    if !re.is_match(&content) {
        anyhow::bail!(
            "no line matching `pub global {name}: u32 = <digits>;` in {}",
            constants_path.display()
        );
    }
    let replacement = format!("pub global {name}: u32 = {value};");
    let new_content = re.replace(&content, replacement.as_str());
    fs::write(constants_path, new_content.as_ref())
        .with_context(|| format!("write {}", constants_path.display()))?;
    Ok(())
}

/// Run a command, return elapsed seconds on success or an error message.
pub fn run_command_timed(experiment_dir: &Path, program: &str, args: &[&str]) -> Result<f64, String> {
    let start = Instant::now();
    let output = Command::new(program)
        .args(args)
        .current_dir(experiment_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("failed to spawn {program}: {e}"))?;
    let elapsed = start.elapsed().as_secs_f64();
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let snippet = if stderr.len() > 500 {
            &stderr[..500]
        } else {
            stderr.as_ref()
        };
        return Err(format!(
            "{program} exited with {}: {snippet}",
            output.status
        ));
    }
    Ok(elapsed)
}

/// Format a timing result for CSV output.
pub fn format_time_or_error(r: &Result<f64, String>) -> String {
    match r {
        Ok(s) => format!("{s:.3}"),
        Err(_) => "error".to_string(),
    }
}

/// Remove bb artifacts (vk, proof, public_inputs) from the target directory.
pub fn remove_bb_artifacts(experiment_dir: &Path) {
    for sub in ["vk", "proof", "public_inputs"] {
        let p = experiment_dir.join("target").join(sub);
        let _ = fs::remove_file(&p).or_else(|_| {
            if p.is_dir() {
                fs::remove_dir_all(&p)
            } else {
                Ok(())
            }
        });
    }
}

/// Resolve a constants path relative to the experiment directory.
pub fn resolve_constants_path(experiment_dir: &Path, constants: &Path) -> PathBuf {
    if constants.is_absolute() {
        constants.to_path_buf()
    } else {
        experiment_dir.join(constants)
    }
}

