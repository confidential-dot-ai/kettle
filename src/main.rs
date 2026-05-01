use clap::{
    Parser, Subcommand,
    builder::{Styles, styling::AnsiColor},
};
use colored::Colorize;
use std::{path::PathBuf, process::exit};
use tracing::{debug, error};
use tracing_subscriber::FmtSubscriber;

use kettle::commands;

const STYLES: Styles = Styles::styled()
    .header(AnsiColor::Yellow.on_default())
    .usage(AnsiColor::Green.on_default())
    .literal(AnsiColor::Green.on_default())
    .placeholder(AnsiColor::Green.on_default());

/// Kettle creates and validates cryptographically secure software builds.
///
/// Use Kettle-attested builds to know the exact inputs to any build, and to be confident your
/// build process was not seen or interfered with by any third parties, thanks to attestations
/// provided by the Trusted Execution Environment where the build was run.
#[derive(Parser, Debug)]
#[command(version, styles=STYLES)]
struct Args {
    #[command(subcommand)]
    command: Commands,
    #[command(flatten)]
    verbosity: clap_verbosity_flag::Verbosity,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Build and attest a project inside a Trusted Execution Environment.
    Attest(commands::attest::AttestArgs),
    /// Build a project with SLSA v1.2 provenance
    Build {
        /// Path to the project to be built
        #[arg()]
        path: PathBuf,
    },
    /// Verify a Kettle build, including provenance and attestation
    Verify {
        /// Path to directory containing provenance.json and evidence.json
        #[arg(default_value = ".")]
        path: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let subscriber = FmtSubscriber::builder()
        .with_max_level(args.verbosity)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("log configuration failed");

    debug!("got args: {:?}", args);
    let result = match args.command {
        Commands::Attest(args) => commands::attest::attest(args).await,
        Commands::Build { ref path } => commands::build::build(path),
        Commands::Verify { ref path } => commands::verify::verify(path).await,
    };

    if let Err(e) = result {
        error!("{}", "Error during run:".red());
        error!("  {}", e);
        exit(1);
    }
}
