//! Program entry point: parses the top-level CLI and dispatches to fuzzing or coverage logic.

mod cli;
mod coverage;
mod fuzz;
mod util;

use anyhow::Context as _;
use clap::Parser as _;
use cli::{Cli, Commands};

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Fuzz(args) => fuzz::run(args).context("failed to run fuzz command"),
        Commands::Cover(args) => coverage::run(args).context("failed to run cover command"),
    }
}
