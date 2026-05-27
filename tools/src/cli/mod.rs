//! CLI subcommand implementations (binary crate only).

mod bench;
pub(crate) mod common;
mod jwt;
mod mdoc;

use anyhow::Result;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum Command {
    /// Compact JWT witness for the jwt-swiyu circuit
    #[command(subcommand)]
    Jwt(jwt::Cmd),
    /// ISO 18013-5 mdoc IssuerSigned / witness generation
    #[command(subcommand)]
    Mdoc(mdoc::MdocCmd),
    /// MAX_LEN sweep: patch constants, regen Prover.toml, nargo + bb → CSV
    Bench(bench::Args),
}

impl Command {
    pub fn run(self) -> Result<()> {
        match self {
            Command::Jwt(cmd) => cmd.run(),
            Command::Mdoc(cmd) => cmd.run(),
            Command::Bench(args) => bench::run(args),
        }
    }
}
