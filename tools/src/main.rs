use clap::Parser;
use clap_verbosity_flag::{InfoLevel, Verbosity};
use noir_eid_tools::error::VerificationFailed;
use std::process::ExitCode;

mod cli;

#[derive(Parser)]
#[command(
    name = "eid-tools",
    about = "CLI tools for generating Noir ZK circuit inputs (JWT, mdoc) and running benchmarks"
)]
struct Cli {
    #[command(flatten)]
    verbose: Verbosity<InfoLevel>,
    #[command(subcommand)]
    command: cli::Command,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    env_logger::Builder::new()
        .filter_level(cli.verbose.log_level_filter())
        .init();

    match cli.command.run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if let Some(vf) = e.downcast_ref::<VerificationFailed>() {
                eprintln!("{vf}");
            } else {
                eprintln!("Error: {e:#}");
            }
            ExitCode::FAILURE
        }
    }
}
