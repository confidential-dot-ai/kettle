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
    /// Build and attest a project inside a Trusted Execution Environment
    #[cfg(all(feature = "attest", target_os = "linux"))]
    Attest {
        #[arg()]
        path: PathBuf,
        /// Hex-encoded nonce for freshness binding (up to 32 bytes)
        #[arg(long)]
        nonce: Option<String>,
    },
    #[cfg(not(all(feature = "attest", target_os = "linux")))]
    #[command(hide = true)]
    Attest {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        nonce: Option<String>,
    },
    /// Build a project with SLSA v1.2 provenance
    Build {
        /// Path to the Cargo or Nix project
        #[arg()]
        path: PathBuf,
    },
    /// Verify a Kettle build, including provenance and attestation
    Verify {
        /// Path to directory containing provenance.json and evidence.b64
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
        Commands::Attest { ref path, ref nonce } => {
            let nonce_bytes = nonce.as_ref().map(|h| hex::decode(h).expect("invalid hex nonce"));
            commands::attest::attest(path, nonce_bytes.as_deref()).await
        }
        Commands::Build { ref path } => commands::build::build(path),
        Commands::Verify { ref path } => commands::verify::verify(path).await,
    };

    if let Err(e) = result {
        error!("{}", "Error during run:".red());
        error!("  {}", e);
        exit(1);
    }
}
