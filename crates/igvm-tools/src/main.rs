// This module is CLI glue. It parses arguments, calls library functions,
// and writes output. No complex logic belongs here.
//
// NOTE: This tool targets QEMU+KVM exclusively. The IGVM construction,
// page ordering, measurement algorithm (batch flushing), and VMSA overrides
// all replicate QEMU+KVM's specific behavior. The computed launch digest
// will match hardware attestation only when the guest runs on QEMU+KVM.

use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use igvm_tools::manifest::{
    sha256_hex, BuildConfig as ManifestBuildConfig, FileInfo, InputFiles, Manifest, MeasurementInfo,
};
use igvm_tools::measure;
use igvm_tools::{BootMode, BuildConfig, Platform};

#[derive(Parser)]
#[command(
    name = "igvm-tools",
    version,
    about = "Build and measure IGVM files for AMD SEV-SNP confidential VMs (QEMU+KVM)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build an IGVM file from firmware, kernel, and optional components
    Build(Box<BuildArgs>),
    /// Measure an existing IGVM file and print the SNP launch digest
    Measure(MeasureArgs),
}

#[derive(Parser)]
struct BuildArgs {
    /// OVMF firmware image
    #[arg(long, value_name = "FILE")]
    firmware: String,

    /// UEFI variable store (optional)
    #[arg(long, value_name = "FILE")]
    vars: Option<String>,

    /// Kernel EFI binary (optional)
    #[arg(long, value_name = "FILE")]
    kernel: Option<String>,

    /// Shim EFI binary (optional)
    #[arg(long, value_name = "FILE")]
    shim: Option<String>,

    /// Secure boot PK certificate (.auth file, optional)
    #[arg(long, value_name = "FILE")]
    pk: Option<String>,

    /// Secure boot KEK certificate (.auth file, optional)
    #[arg(long, value_name = "FILE")]
    kek: Option<String>,

    /// Secure boot db certificate (.auth file, optional)
    #[arg(long, value_name = "FILE")]
    db: Option<String>,

    /// Secure boot dbx revocation list (.auth file, optional)
    #[arg(long, value_name = "FILE")]
    dbx: Option<String>,

    /// Platform type
    #[arg(long, default_value = "snp")]
    platform: CliPlatform,

    /// Boot mode
    #[arg(long, default_value = "real16")]
    boot_mode: CliBootMode,

    /// Number of vCPUs
    #[arg(long, default_value = "1")]
    smp: u32,

    /// Output IGVM file
    #[arg(short, long, value_name = "FILE")]
    output: String,

    /// Output JSON manifest (optional)
    #[arg(long, value_name = "FILE")]
    manifest: Option<String>,

    /// Print OVMF metadata before building
    #[arg(long)]
    meta: bool,

    /// Verbose measurement output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Parser)]
struct MeasureArgs {
    /// IGVM file to measure
    igvm_file: String,

    /// Verbose measurement output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Clone, Debug, ValueEnum)]
enum CliPlatform {
    Snp,
    Native,
    #[value(name = "snp+native")]
    SnpNative,
}

#[derive(Clone, Debug, ValueEnum)]
enum CliBootMode {
    Real16,
    Flat32,
}

fn read_optional(path: &Option<String>, label: &str) -> Result<Option<Vec<u8>>, String> {
    path.as_ref()
        .map(|p| std::fs::read(p).map_err(|e| format!("read {label} {p}: {e}")))
        .transpose()
}

fn do_build(args: &BuildArgs) -> Result<(), String> {
    // Read inputs from disk
    let firmware = std::fs::read(&args.firmware)
        .map_err(|e| format!("read firmware {}: {e}", args.firmware))?;
    let vars_blob = read_optional(&args.vars, "vars")?;
    let kernel_blob = read_optional(&args.kernel, "kernel")?;
    let shim_blob = read_optional(&args.shim, "shim")?;
    let pk_blob = read_optional(&args.pk, "pk")?;
    let kek_blob = read_optional(&args.kek, "kek")?;
    let db_blob = read_optional(&args.db, "db")?;
    let dbx_blob = read_optional(&args.dbx, "dbx")?;

    // Print OVMF metadata if requested
    if args.meta {
        if let Some(meta) = igvm_tools::ovmfmeta::OvmfMeta::new(&firmware) {
            meta.print();
        } else {
            eprintln!("warning: no OVMF metadata found in firmware");
        }
    }

    // Build via library API
    let config = BuildConfig {
        firmware: &firmware,
        vars: vars_blob.as_deref(),
        kernel: kernel_blob.as_deref(),
        shim: shim_blob.as_deref(),
        pk: pk_blob.as_deref(),
        kek: kek_blob.as_deref(),
        db: db_blob.as_deref(),
        dbx: dbx_blob.as_deref(),
        platform: match args.platform {
            CliPlatform::Snp => Platform::Snp,
            CliPlatform::Native => Platform::Native,
            CliPlatform::SnpNative => Platform::SnpNative,
        },
        boot_mode: match args.boot_mode {
            CliBootMode::Real16 => BootMode::Real16,
            CliBootMode::Flat32 => BootMode::Flat32,
        },
        smp: args.smp,
        verbose: args.verbose,
    };

    let result = igvm_tools::build(&config)?;

    eprintln!(
        "SNP launch digest: {}",
        hex::encode(result.measurement.launch_digest)
    );
    eprintln!(
        "Pages: {}, VMSAs: {}",
        result.measurement.page_count, result.measurement.vmsa_count
    );

    // Write IGVM file
    std::fs::write(&args.output, &result.igvm_bytes)
        .map_err(|e| format!("write {}: {e}", args.output))?;
    eprintln!("Wrote {}", args.output);

    // Write manifest if requested
    if let Some(ref manifest_path) = args.manifest {
        let manifest = Manifest {
            version: 1,
            igvm_file: args.output.clone(),
            igvm_sha256: sha256_hex(&result.igvm_bytes),
            measurement: MeasurementInfo {
                snp_launch_digest: hex::encode(result.measurement.launch_digest),
                algorithm: "sha384".to_string(),
                page_count: result.measurement.page_count,
                vmsa_count: result.measurement.vmsa_count,
            },
            config: ManifestBuildConfig {
                platform: format!("{:?}", args.platform).to_lowercase(),
                boot_mode: format!("{:?}", args.boot_mode).to_lowercase(),
                smp: args.smp,
            },
            inputs: InputFiles {
                firmware: FileInfo {
                    path: args.firmware.clone(),
                    sha256: sha256_hex(&firmware),
                },
                vars: vars_blob.as_ref().map(|v| FileInfo {
                    path: args.vars.as_ref().expect("vars path set").clone(),
                    sha256: sha256_hex(v),
                }),
                kernel: kernel_blob.as_ref().map(|k| FileInfo {
                    path: args.kernel.as_ref().expect("kernel path set").clone(),
                    sha256: sha256_hex(k),
                }),
                shim: shim_blob.as_ref().map(|s| FileInfo {
                    path: args.shim.as_ref().expect("shim path set").clone(),
                    sha256: sha256_hex(s),
                }),
            },
            generated_at: chrono::Utc::now().to_rfc3339(),
        };

        let json = serde_json::to_string_pretty(&manifest)
            .map_err(|e| format!("serialize manifest: {e}"))?;
        std::fs::write(manifest_path, &json).map_err(|e| format!("write {manifest_path}: {e}"))?;
        eprintln!("Wrote {manifest_path}");
    }

    // Print digest to stdout for piping
    println!("{}", hex::encode(result.measurement.launch_digest));
    Ok(())
}

fn do_measure(args: &MeasureArgs) -> Result<(), String> {
    let blob =
        std::fs::read(&args.igvm_file).map_err(|e| format!("read {}: {e}", args.igvm_file))?;
    let igvm =
        igvm::IgvmFile::new_from_binary(&blob, None).map_err(|e| format!("parse igvm: {e}"))?;

    let result = measure::measure_snp(&igvm, args.verbose)?;

    eprintln!("Pages: {}, VMSAs: {}", result.page_count, result.vmsa_count);
    println!("{}", hex::encode(result.launch_digest));

    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match &cli.command {
        Commands::Build(ref args) => do_build(args),
        Commands::Measure(args) => do_measure(args),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
