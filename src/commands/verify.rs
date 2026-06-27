use anyhow::Result;
use attestation::VerificationResult;
use colored::Colorize;
use fs_err::DirEntry;
use std::path::{Path, PathBuf};
use std::vec::Vec;
use tabled::builder::Builder;
use tabled::settings::object::Columns;
use tabled::settings::themes::BorderCorrection;
use tabled::settings::{Alignment, Panel, Style};
use tracing::info;

use crate::provenance::Provenance;

#[derive(clap::Args, Debug)]
pub struct VerifyArgs {
    /// Path to the project to be verified
    #[arg()]
    path: PathBuf,
    /// Optional nonce, as hex string, to be checked against the attestation.
    /// Must be exactly 16 bytes (32 hex chars).
    #[arg(short, long)]
    nonce: Option<String>,
    /// Path to the IGVM file the CVM booted from. When set, verifies that the
    /// attested launch measurement matches this IGVM's launch digest.
    #[arg(long)]
    igvm: Option<PathBuf>,
    /// Path to the disk image (disk.raw). When set, verifies that the dm-verity
    /// roothash committed inside the IGVM matches the disk's stored roothash.
    /// Requires --igvm.
    #[arg(long, requires = "igvm")]
    image: Option<PathBuf>,
}

pub async fn verify(args: VerifyArgs) -> Result<()> {
    let path = args.path;
    let nonce = args.nonce;
    let igvm = args.igvm;
    let image = args.image;
    let build = Build::from_dir(&path)?;

    // Get the provenance and attestation
    let provenance = Provenance::from_json(&build.provenance_bytes)?;
    let verification = attestation::verify(&build.evidence_bytes, &Default::default()).await?;

    let mut results: Vec<Verification> = vec![];
    results.push(verify_signature(&verification));
    results.push(provenance.verify_predicate());
    results.push(verify_provenance(&verification, &provenance));
    let artifact_report = provenance.verify_artifacts(&build.top_level, &build.artifacts)?;
    results.extend(artifact_report.results);
    if let Some(nonce) = nonce {
        results.push(verify_nonce(&verification, nonce));
    }
    if let Some(igvm_path) = &igvm {
        results.push(verify_igvm_measurement(&verification, igvm_path));
    }
    if let (Some(igvm_path), Some(image_path)) = (&igvm, &image) {
        results.push(verify_image_roothash(igvm_path, image_path));
    }

    // Print build information
    print_table(
        vec![format!(
            "\n{} {}\n",
            "Verifying build dir".bold(),
            build_dir_name(&path)
        )],
        vec![
            vec!["Build ID".bold().to_string(), provenance.build_id().clone()],
            vec![
                "Built at".bold().to_string(),
                provenance.timestamp().clone(),
            ],
            vec![
                "Built with".bold().to_string(),
                format!("{}", provenance.toolchain()),
            ],
            vec![
                "Git commit".bold().to_string(),
                format!("{}", provenance.git_commit()),
            ],
        ],
        vec![],
    );

    // Print verification results
    let mut rows: Vec<Vec<String>> = results
        .iter()
        .map(|r| match r {
            Verification::Success { message } => vec!["✅".to_string(), message.clone()],
            Verification::Failure {
                message,
                details: _,
            } => vec!["⛔️".to_string(), message.clone()],
        })
        .collect();
    if results
        .iter()
        .any(|r| matches!(r, Verification::Failure { .. }))
    {
        rows.push(vec![
            "⛔️".to_string(),
            format!("{}", "Verification FAILED".red()),
        ]);
    } else {
        rows.push(vec![
            "✅".to_string(),
            format!("{}", "Verification PASSED".green()),
        ]);
    };
    let headers = vec![format!("{}", "Verification Results".bold())];
    let footers = vec![];
    print_table(headers, rows, footers);

    // Warnings are informational and do not affect the PASSED/FAILED verdict.
    for warning in &artifact_report.warnings {
        eprintln!("{}", format!("⚠️  {warning}").yellow());
    }

    // Print detailed information about failures (if any)
    for r in results {
        match r {
            Verification::Success { .. } => (),
            Verification::Failure { message, details } => {
                eprintln!("{}\n{}\n", message.red().bold(), details);
            }
        }
    }

    info!("{}\n{:?}", "Attestation claims".bold(), &verification);

    Ok(())
}

/// Best-effort human-readable name for the build directory being verified.
/// `Path::file_name` returns `None` for paths ending in `.`/`..` or the root
/// (e.g. `kettle verify .`), so canonicalize first to recover the real
/// directory name, falling back to the path as given.
fn build_dir_name(path: &Path) -> String {
    fs_err::canonicalize(path)
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| path.to_string_lossy().into_owned())
}

// Fixed-size nonces to prevent padding issues.
const NONCE_LEN: usize = 16;

fn verify_nonce(verification_result: &VerificationResult, nonce_string: String) -> Verification {
    let nonce = match hex::decode(&nonce_string) {
        Ok(bytes) => bytes,
        Err(e) => {
            return Verification::failure(
                "Invalid nonce hex",
                &format!("Could not decode nonce {nonce_string:?} as hex: {e}"),
            );
        }
    };
    if nonce.len() != NONCE_LEN {
        return Verification::failure(
            &format!("Nonce must be exactly {NONCE_LEN} bytes"),
            &format!(
                "Expected {NONCE_LEN} bytes ({} hex chars); got {} bytes",
                NONCE_LEN * 2,
                nonce.len()
            ),
        );
    }

    if let Some((_, signed_nonce)) = verification_result.claims.signed_data.split_at_checked(32) {
        // The attestation library may have removed trailing null bytes, add them if necessary.
        let matches = signed_nonce.len() <= NONCE_LEN && {
            let mut padded = [0u8; NONCE_LEN];
            padded[..signed_nonce.len()].copy_from_slice(signed_nonce);
            padded.as_slice() == nonce.as_slice()
        };

        tracing::debug!(
            "signed_nonce {:?} given nonce {:?} equal {}",
            hex::encode(signed_nonce),
            hex::encode(&nonce),
            matches
        );

        match matches {
            true => Verification::success("Nonce matches attestation"),
            false => Verification::failure(
                "Nonce mismatch",
                &format!(
                    "Expected attested nonce {:?}\nActual value was        {:?}",
                    hex::encode(&nonce),
                    hex::encode(signed_nonce)
                ),
            ),
        }
    } else {
        Verification::failure(
            "Nonce missing from attestation",
            &format!(
                "No nonce preset in attestation signed data {:?}",
                hex::encode(&verification_result.claims.signed_data),
            ),
        )
    }
}

fn verify_signature(verification_result: &VerificationResult) -> Verification {
    match verification_result.signature_valid {
        true => Verification::success("Attestation hardware signature valid"),
        false => Verification::failure(
            "Attestation hardware signature invalid",
            "signature verification failed",
        ),
    }
}

/// Compare a measured IGVM launch digest (hex) against the attested one.
/// Both are SHA-384 hex strings; comparison is case-insensitive.
fn compare_launch_digest(measured_hex: &str, attested_hex: &str) -> Verification {
    if measured_hex.eq_ignore_ascii_case(attested_hex) {
        Verification::success("IGVM launch measurement matches attestation")
    } else {
        Verification::failure(
            "IGVM launch measurement mismatch",
            &format!(
                "IGVM file launch digest   {measured_hex}\nAttested launch digest    {attested_hex}",
            ),
        )
    }
}

/// Measure the given IGVM file and compare its SNP launch digest to the
/// attested launch measurement. Any parse/measure error is reported as a
/// verification failure rather than aborting the whole `verify` run.
fn verify_igvm_measurement(
    verification_result: &VerificationResult,
    igvm_path: &Path,
) -> Verification {
    let bytes = match fs_err::read(igvm_path) {
        Ok(b) => b,
        Err(e) => return Verification::failure("Could not read IGVM file", &e.to_string()),
    };
    let igvm_file = match igvm::IgvmFile::new_from_binary(&bytes, None) {
        Ok(f) => f,
        Err(e) => return Verification::failure("Could not parse IGVM file", &e.to_string()),
    };
    let measured = match igvm_tools::measure::measure_snp(&igvm_file, false) {
        Ok(r) => hex::encode(r.launch_digest),
        Err(e) => return Verification::failure("Could not measure IGVM file", &e),
    };
    compare_launch_digest(&measured, &verification_result.claims.launch_digest)
}

/// Pull the `roothash=<hex>` value out of a kernel command line.
fn roothash_from_cmdline(cmdline: &str) -> Result<String, String> {
    cmdline
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("roothash="))
        .map(|s| s.to_string())
        .ok_or_else(|| "no roothash= in IGVM kernel command line".to_string())
}

/// Compare the roothash committed in the IGVM against the disk's stored roothash.
fn compare_roothash(igvm_roothash: &str, disk_roothash: &str) -> Verification {
    if igvm_roothash.eq_ignore_ascii_case(disk_roothash) {
        Verification::success("Disk image matches IGVM dm-verity roothash")
    } else {
        Verification::failure(
            "Disk image roothash mismatch",
            &format!(
                "IGVM-committed roothash   {igvm_roothash}\nDisk image roothash       {disk_roothash}",
            ),
        )
    }
}

/// Verify that the dm-verity roothash committed inside the IGVM matches the
/// roothash stored in the disk image.
fn verify_image_roothash(igvm_path: &Path, image_path: &Path) -> Verification {
    let bytes = match fs_err::read(igvm_path) {
        Ok(b) => b,
        Err(e) => return Verification::failure("Could not read IGVM file", &e.to_string()),
    };
    let igvm_file = match igvm::IgvmFile::new_from_binary(&bytes, None) {
        Ok(f) => f,
        Err(e) => return Verification::failure("Could not parse IGVM file", &e.to_string()),
    };
    let cmdline = match igvm_tools::extract::kernel_cmdline(&igvm_file) {
        Ok(c) => c,
        Err(e) => return Verification::failure("Could not read IGVM kernel command line", &e),
    };
    let igvm_roothash = match roothash_from_cmdline(&cmdline) {
        Ok(r) => r,
        Err(e) => return Verification::failure("No roothash in IGVM", &e),
    };
    let disk_roothash = match crate::verity::stored_roothash(image_path) {
        Ok(r) => r,
        Err(e) => {
            return Verification::failure("Could not read disk image roothash", &e.to_string());
        }
    };
    compare_roothash(&igvm_roothash, &disk_roothash)
}

fn verify_provenance(
    verification_result: &VerificationResult,
    provenance: &Provenance,
) -> Verification {
    compare_checksum(
        &verification_result.claims.signed_data,
        &provenance.checksum(),
    )
}

/// Compare the attested provenance checksum (the first 32 bytes of report_data)
/// against the expected provenance.json checksum.
///
/// The checksum occupies the first 32 bytes of the fixed 48-byte report_data,
/// but the attestation library strips trailing null bytes from `signed_data`. A
/// checksum ending in zeros — with no nonce, or an all-zero nonce slot — comes
/// back shorter than 32 bytes. Zero-extend the signed checksum back to the fixed
/// 32-byte width (the same trick `verify_nonce` uses) so trailing zeros are
/// restored deterministically and such a checksum still verifies.
fn compare_checksum(signed_data: &[u8], expected: &[u8]) -> Verification {
    if expected.len() != 32 {
        return Verification::Failure {
            message: "Provenance checksum invalid".to_string(),
            details: format!(
                "Expected provenance.json checksum {:?} to be 32 bytes",
                hex::encode(expected)
            ),
        };
    }

    let mut signed_checksum = [0u8; 32];
    let n = signed_data.len().min(32);
    signed_checksum[..n].copy_from_slice(&signed_data[..n]);

    match signed_checksum.as_slice() == expected {
        true => Verification::success("Provenance checksum match"),
        false => Verification::failure(
            "Provenance checksum mismatch",
            &format!(
                "Expected provenance.json checksum {:?}\nActual attested checksum          {:?}",
                hex::encode(expected),
                hex::encode(signed_checksum)
            ),
        ),
    }
}

struct Build {
    provenance_bytes: Vec<u8>,
    evidence_bytes: Vec<u8>,
    top_level: Vec<DirEntry>,
    artifacts: Vec<DirEntry>,
}

impl Build {
    fn from_dir(path: &PathBuf) -> Result<Build> {
        let project_dir = fs_err::canonicalize(path)?;
        let evidence_bytes = fs_err::read(project_dir.join("evidence.json"))?;
        let provenance_bytes = fs_err::read(project_dir.join("provenance.json"))?;

        // binaries are allowed to be at the top level
        let top_level = fs_err::read_dir(&project_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
            .collect();

        // binaries are also allowed to be inside `artifacts/`
        let artifacts_dir = project_dir.join("artifacts");
        let artifacts = if artifacts_dir.is_dir() {
            fs_err::read_dir(artifacts_dir)?
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
                .collect()
        } else {
            vec![]
        };

        Ok(Build {
            provenance_bytes,
            evidence_bytes,
            top_level,
            artifacts,
        })
    }
}

pub enum Verification {
    Success { message: String },
    Failure { message: String, details: String },
}

impl Verification {
    pub fn success(message: &str) -> Self {
        Self::Success {
            message: message.to_owned(),
        }
    }

    pub fn failure(message: &str, details: &str) -> Self {
        Self::Failure {
            message: message.to_owned(),
            details: details.to_owned(),
        }
    }
}

fn print_table(headers: Vec<String>, rows: Vec<Vec<String>>, footers: Vec<String>) {
    let mut b = Builder::with_capacity(rows.len(), 2);
    for row in rows {
        b.push_record(row.clone());
    }

    let mut table = b.build();
    table.modify(Columns::first(), Alignment::center());
    table.with(Style::modern());
    for footer in footers {
        table.with(Panel::footer(footer));
    }
    for header in headers {
        table.with(Panel::header(header));
    }
    table.with(BorderCorrection::span());
    println!("{}\n", table);
}

#[cfg(test)]
mod tests {
    use super::*;
    use attestation::{Claims, PlatformType, TcbInfo, VerificationResult};
    use tempfile::TempDir;

    const CARGO_FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/ripgrep/provenance.json");

    fn make_verification_result(signature_valid: bool, signed_data: Vec<u8>) -> VerificationResult {
        VerificationResult {
            signature_valid,
            platform: PlatformType::Snp,
            claims: Claims {
                launch_digest: String::new(),
                signed_data,
                report_data: vec![],
                init_data: vec![],
                tcb: TcbInfo::Snp {
                    bootloader: 0,
                    tee: 0,
                    snp: 0,
                    microcode: 0,
                    fmc: Some(0),
                },
                platform_data: Default::default(),
            },
            report_data_match: None,
            init_data_match: None,
            collateral_verified: true,
            tcb_status: None,
        }
    }

    // --- Verification constructors ---

    #[test]
    fn verification_success_constructor() {
        match Verification::success("msg") {
            Verification::Success { message } => assert_eq!(message, "msg"),
            _ => panic!("expected Success"),
        }
    }

    #[test]
    fn verification_failure_constructor() {
        match Verification::failure("msg", "details") {
            Verification::Failure { message, details } => {
                assert_eq!(message, "msg");
                assert_eq!(details, "details");
            }
            _ => panic!("expected Failure"),
        }
    }

    // --- verify_signature ---

    #[test]
    fn verify_signature_valid() {
        let vr = make_verification_result(true, vec![]);
        match verify_signature(&vr) {
            Verification::Success { .. } => {}
            Verification::Failure { message, .. } => panic!("expected success: {message}"),
        }
    }

    #[test]
    fn verify_signature_invalid() {
        let vr = make_verification_result(false, vec![]);
        match verify_signature(&vr) {
            Verification::Failure { message, .. } => {
                assert!(message.contains("invalid"), "message: {message}");
            }
            Verification::Success { .. } => panic!("expected failure"),
        }
    }

    // --- verify_report_data ---

    #[test]
    fn verify_signed_data_match() {
        let provenance = Provenance::from_json(CARGO_FIXTURE).unwrap();
        let signed_data = provenance.checksum();
        let vr = make_verification_result(true, signed_data);
        match verify_provenance(&vr, &provenance) {
            Verification::Success { message } => {
                assert!(message.contains("match"), "message: {message}");
            }
            Verification::Failure { message, .. } => panic!("expected success: {message}"),
        }
    }

    #[test]
    fn verify_provenance_mismatch_shows_attested_checksum() {
        let provenance = Provenance::from_json(CARGO_FIXTURE).unwrap();
        let signed_data = vec![0xab; 32];
        let vr = make_verification_result(true, signed_data);
        match verify_provenance(&vr, &provenance) {
            Verification::Failure { message, details } => {
                assert!(message.contains("mismatch"), "message: {message}");
                assert!(
                    details.contains(&"ab".repeat(32)),
                    "details should show the attested checksum hex: {details}"
                );
            }
            Verification::Success { .. } => panic!("expected failure"),
        }
    }

    #[test]
    fn verify_signed_nonce() {
        assert_verify_real_nonce("deadbeefdeadbeefdeadbeefdeadbeef");
        assert_verify_real_nonce("43c4ef48e21a45b886b2fa7d7cd0ef59");
        assert_verify_real_nonce("ffffffffffffffffffffffffffffffff");
        // ensure zero bytes still verify correctly
        assert_verify_real_nonce("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00");
        // ends in several zero bytes (most stripping, most zero-extension)
        assert_verify_real_nonce("deadbeefdeadbeefdeadbeef00000000");
    }

    /// Build `signed_data` like attest does: 32-byte checksum followed by
    /// 16-byte nonce, with trailing nulls stripped.
    fn assert_verify_real_nonce(nonce: &str) {
        let nonce_bytes = hex::decode(nonce).unwrap();
        assert_eq!(nonce_bytes.len(), 16, "test nonce must be exactly 16 bytes");

        let mut report_data = vec![0u8; 48];
        report_data[..32].copy_from_slice(&[0xab; 32]);
        report_data[32..].copy_from_slice(&nonce_bytes);

        // Mirror attestation's strip_trailing_nulls on the full report_data.
        let end = report_data
            .iter()
            .rposition(|&b| b != 0)
            .map_or(0, |i| i + 1);
        let signed_data = report_data[..end].to_vec();

        let vr = make_verification_result(true, signed_data);
        match verify_nonce(&vr, nonce.to_string()) {
            Verification::Success { message } => {
                assert!(message.contains("match"), "message: {message}");
            }
            Verification::Failure { message, .. } => {
                panic!("expected success for nonce {nonce:?}: {message}")
            }
        }
    }

    #[test]
    fn verify_nonce_rejects_non_16_byte_expected() {
        let mut signed_data = vec![0xab; 32];
        signed_data.extend_from_slice(&[0xcd; 16]);
        for nonce in [
            "",
            "cd",
            "cdcdcdcd",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",     // 15 bytes
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", // 17 bytes
        ] {
            let vr = make_verification_result(true, signed_data.clone());
            match verify_nonce(&vr, nonce.to_string()) {
                Verification::Failure { message, .. } => {
                    assert!(message.contains("16 bytes"), "nonce {nonce:?}: {message}");
                }
                Verification::Success { .. } => {
                    panic!("expected failure for non-16-byte nonce {nonce:?}")
                }
            }
        }
    }

    // A malformed (non-hex) expected nonce is reported as a failure, not a panic.
    #[test]
    fn verify_nonce_rejects_invalid_hex() {
        let mut signed_data = vec![0xab; 32];
        signed_data.extend_from_slice(&[0xcd; 16]);
        for nonce in ["zz", "deadbeefg", "not hex at all"] {
            let vr = make_verification_result(true, signed_data.clone());
            match verify_nonce(&vr, nonce.to_string()) {
                Verification::Failure { message, .. } => {
                    assert!(message.contains("hex"), "nonce {nonce:?}: {message}");
                }
                Verification::Success { .. } => {
                    panic!("expected failure for non-hex nonce {nonce:?}")
                }
            }
        }
    }

    #[test]
    fn verify_signed_nonce_errors() {
        // A valid 16-byte expected nonce, but signed_data has no room for one.
        let nonce = "deadbeefdeadbeefdeadbeefdeadbeef";
        assert_verify_nonce_fails(vec![], nonce, "missing");
        assert_verify_nonce_fails(vec![0; 3], nonce, "missing");
        assert_verify_nonce_fails(vec![0; 31], nonce, "missing");

        // Long enough to split, but the attested nonce (zero-extended to 16
        // bytes) differs from the expected one -> mismatch.
        assert_verify_nonce_fails(vec![0xab; 33], nonce, "mismatch");
        assert_verify_nonce_fails(vec![0xab; 48], nonce, "mismatch");
        // An over-long nonce region (more than 16 bytes) can never match.
        assert_verify_nonce_fails(vec![0xab; 49], nonce, "mismatch");
        assert_verify_nonce_fails(vec![0xab; 65], nonce, "mismatch");
    }

    fn assert_verify_nonce_fails(signed_data: Vec<u8>, nonce: &str, needle: &str) {
        let vr = make_verification_result(true, signed_data);
        match verify_nonce(&vr, nonce.to_owned()) {
            Verification::Failure { message, .. } => {
                assert!(message.contains(needle), "message: {message}");
            }
            Verification::Success { .. } => panic!("expected failure"),
        }
    }

    #[test]
    fn verify_signed_checksum_errors() {
        for len in [0, 3, 31, 32, 33, 49, 50, 51, 64, 65] {
            assert_verify_provenance_fails(vec![0; len], "mismatch");
        }
    }

    fn assert_verify_provenance_fails(signed_data: Vec<u8>, needle: &str) {
        let provenance = Provenance::from_json(CARGO_FIXTURE).unwrap();
        let vr = make_verification_result(true, signed_data);
        match verify_provenance(&vr, &provenance) {
            Verification::Failure { message, .. } => {
                assert!(message.contains(needle), "message: {message}");
            }
            Verification::Success { .. } => panic!("expected failure"),
        }
    }

    /// Build `signed_data` exactly as the real attest pipeline does for a given
    /// 32-byte checksum and optional 16-byte nonce: lay them into the 48-byte
    /// report_data slot, then strip all trailing null bytes (as the attestation
    /// library does when producing `signed_data`).
    fn signed_data_for(checksum: &[u8], nonce: Option<&[u8]>) -> Vec<u8> {
        assert_eq!(checksum.len(), 32, "checksum must be 32 bytes");
        let mut report_data = vec![0u8; 48];
        report_data[..32].copy_from_slice(checksum);
        if let Some(n) = nonce {
            assert_eq!(n.len(), 16, "nonce must be 16 bytes");
            report_data[32..].copy_from_slice(n);
        }
        let end = report_data
            .iter()
            .rposition(|&b| b != 0)
            .map_or(0, |i| i + 1);
        report_data[..end].to_vec()
    }

    fn assert_checksum_matches(signed_data: &[u8], expected: &[u8]) {
        match compare_checksum(signed_data, expected) {
            Verification::Success { message } => assert!(message.contains("match"), "{message}"),
            Verification::Failure { message, details } => {
                panic!("expected checksum success: {message}\n{details}")
            }
        }
    }

    #[test]
    fn verify_checksum_ending_in_zeros_without_nonce() {
        let mut checksum = vec![0xab; 32];
        checksum[30] = 0x00;
        checksum[31] = 0x00;
        let signed_data = signed_data_for(&checksum, None);
        assert!(
            signed_data.len() < 32,
            "precondition: the checksum tail should be stripped (got {} bytes)",
            signed_data.len()
        );
        assert_checksum_matches(&signed_data, &checksum);
    }

    #[test]
    fn verify_checksum_leading_and_trailing_zeros_without_nonce() {
        let mut checksum = vec![0xcd; 32];
        checksum[0] = 0x00;
        checksum[1] = 0x00;
        checksum[30] = 0x00;
        checksum[31] = 0x00;
        let signed_data = signed_data_for(&checksum, None);
        assert_checksum_matches(&signed_data, &checksum);
    }

    #[test]
    fn verify_checksum_and_nonce_both_ending_in_zeros() {
        let mut checksum = vec![0xab; 32];
        checksum[31] = 0x00;
        let mut nonce = vec![0x11; 16];
        nonce[14] = 0x00;
        nonce[15] = 0x00;
        let signed_data = signed_data_for(&checksum, Some(&nonce));

        assert_checksum_matches(&signed_data, &checksum);

        let vr = make_verification_result(true, signed_data);
        match verify_nonce(&vr, hex::encode(&nonce)) {
            Verification::Success { message } => assert!(message.contains("match"), "{message}"),
            Verification::Failure { message, .. } => panic!("expected nonce success: {message}"),
        }
    }

    // --- Build::from_dir ---

    #[test]
    fn build_from_dir_happy_path() {
        let tmp = TempDir::new().unwrap();
        fs_err::write(tmp.path().join("evidence.json"), b"{}").unwrap();
        fs_err::write(tmp.path().join("provenance.json"), CARGO_FIXTURE).unwrap();
        fs_err::create_dir(tmp.path().join("artifacts")).unwrap();
        fs_err::write(tmp.path().join("artifacts/rg"), b"binary").unwrap();

        let build = Build::from_dir(&tmp.path().to_path_buf()).unwrap();
        assert!(!build.provenance_bytes.is_empty());
        assert!(!build.evidence_bytes.is_empty());
        assert_eq!(build.artifacts.len(), 1);
        // top_level holds the two regular files in the root; the artifacts/
        // subdirectory is not a regular file and is excluded.
        assert_eq!(build.top_level.len(), 2);
    }

    #[test]
    fn build_from_dir_collects_top_level_binary() {
        let tmp = TempDir::new().unwrap();
        fs_err::write(tmp.path().join("evidence.json"), b"{}").unwrap();
        fs_err::write(tmp.path().join("provenance.json"), CARGO_FIXTURE).unwrap();
        // oras-style: binary dropped directly beside provenance.json, no artifacts/
        fs_err::write(tmp.path().join("rg"), b"binary").unwrap();

        let build = Build::from_dir(&tmp.path().to_path_buf()).unwrap();
        let names: Vec<String> = build
            .top_level
            .iter()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"rg".to_string()), "top_level: {names:?}");
        assert!(build.artifacts.is_empty());
    }

    #[test]
    fn build_from_dir_missing_evidence() {
        let tmp = TempDir::new().unwrap();
        fs_err::write(tmp.path().join("provenance.json"), CARGO_FIXTURE).unwrap();
        fs_err::create_dir(tmp.path().join("artifacts")).unwrap();
        assert!(Build::from_dir(&tmp.path().to_path_buf()).is_err());
    }

    #[test]
    fn build_from_dir_missing_provenance() {
        let tmp = TempDir::new().unwrap();
        fs_err::write(tmp.path().join("evidence.json"), b"{}").unwrap();
        fs_err::create_dir(tmp.path().join("artifacts")).unwrap();
        assert!(Build::from_dir(&tmp.path().to_path_buf()).is_err());
    }

    #[test]
    fn build_from_dir_missing_artifacts_is_ok() {
        // artifacts/ is optional now: absence is not an error.
        let tmp = TempDir::new().unwrap();
        fs_err::write(tmp.path().join("evidence.json"), b"{}").unwrap();
        fs_err::write(tmp.path().join("provenance.json"), CARGO_FIXTURE).unwrap();

        let build = Build::from_dir(&tmp.path().to_path_buf()).unwrap();
        assert!(build.artifacts.is_empty());
    }

    #[test]
    fn build_from_dir_empty_artifacts() {
        let tmp = TempDir::new().unwrap();
        fs_err::write(tmp.path().join("evidence.json"), b"{}").unwrap();
        fs_err::write(tmp.path().join("provenance.json"), CARGO_FIXTURE).unwrap();
        fs_err::create_dir(tmp.path().join("artifacts")).unwrap();

        let build = Build::from_dir(&tmp.path().to_path_buf()).unwrap();
        assert!(build.artifacts.is_empty());
    }

    // --- build_dir_name ---

    #[test]
    fn build_dir_name_for_dot_resolves_real_name() {
        let tmp = TempDir::new().unwrap();
        let nested = tmp.path().join("my-build");
        fs_err::create_dir(&nested).unwrap();
        // `.` has no `file_name()` component; this used to panic.
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&nested).unwrap();
        let name = build_dir_name(Path::new("."));
        std::env::set_current_dir(prev).unwrap();
        assert_eq!(name, "my-build");
    }

    #[test]
    fn build_dir_name_for_named_dir() {
        let tmp = TempDir::new().unwrap();
        let nested = tmp.path().join("trustee");
        fs_err::create_dir(&nested).unwrap();
        assert_eq!(build_dir_name(&nested), "trustee");
    }

    #[test]
    fn build_dir_name_falls_back_for_nonexistent_path() {
        // canonicalize fails, so we fall back to the path as given.
        assert_eq!(
            build_dir_name(Path::new("does-not-exist")),
            "does-not-exist"
        );
    }

    // --- verify_igvm_measurement (digest comparison) ---

    #[test]
    fn igvm_measurement_match() {
        let digest = "ab".repeat(48); // 96-char hex of a 48-byte (SHA-384) digest
        match compare_launch_digest(&digest, &digest.to_uppercase()) {
            Verification::Success { message } => assert!(message.contains("launch measurement")),
            Verification::Failure { message, .. } => panic!("expected success: {message}"),
        }
    }

    #[test]
    fn igvm_measurement_mismatch_shows_both() {
        let measured = "ab".repeat(48);
        let attested = "cd".repeat(48);
        match compare_launch_digest(&measured, &attested) {
            Verification::Failure { message, details } => {
                assert!(message.contains("mismatch"), "message: {message}");
                assert!(details.contains(&measured) && details.contains(&attested));
            }
            Verification::Success { .. } => panic!("expected failure"),
        }
    }

    // --- roothash_from_cmdline ---

    #[test]
    fn roothash_from_cmdline_extracts_hex() {
        let cmd = "console=hvc0 roothash=abc123def systemd.condition-first-boot=no";
        assert_eq!(roothash_from_cmdline(cmd).unwrap(), "abc123def");
    }

    #[test]
    fn roothash_from_cmdline_missing() {
        assert!(roothash_from_cmdline("console=hvc0 quiet").is_err());
    }

    // --- compare_roothash ---

    #[test]
    fn compare_roothash_match() {
        match compare_roothash("deadbeef", "DEADBEEF") {
            Verification::Success { message } => assert!(message.contains("roothash")),
            Verification::Failure { message, .. } => panic!("expected success: {message}"),
        }
    }

    #[test]
    fn compare_roothash_mismatch_shows_both() {
        match compare_roothash("aaaa", "bbbb") {
            Verification::Failure { message, details } => {
                assert!(message.contains("mismatch"));
                assert!(details.contains("aaaa") && details.contains("bbbb"));
            }
            Verification::Success { .. } => panic!("expected failure"),
        }
    }
}
