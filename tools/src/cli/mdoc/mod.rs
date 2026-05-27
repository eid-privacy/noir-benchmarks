//! `eid-tools mdoc` — build IssuerSigned mdocs and generate Prover.toml witnesses.

mod build;
mod witness;

pub use build::{BuildArgs, run_build};
pub use witness::{WitnessArgs, run_witness};

use anyhow::Result;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum MdocCmd {
    /// Generate an MDoc/CBOR credential from SWIYU JSON
    Build(BuildArgs),
    /// Extract Prover.toml inputs from IssuerSigned mdoc CBOR
    Witness(WitnessArgs),
}

impl MdocCmd {
    pub fn run(self) -> Result<()> {
        match self {
            MdocCmd::Build(a) => run_build(a),
            MdocCmd::Witness(a) => run_witness(a),
        }
    }
}
