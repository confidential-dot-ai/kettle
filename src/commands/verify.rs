use anyhow::Result;
use attestation::VerificationResult;
use colored::Colorize;
use fs_err::DirEntry;
use std::path::PathBuf;
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
    /// Can be up to 16 bytes.
    #[arg(short, long)]
    nonce: Option<String>,
}

pub async fn verify(args: VerifyArgs) -> Result<()> {
    let path = args.path;
    let nonce = args.nonce;
    let build = Build::from_dir(&path)?;

    // Get the provenance and attestation
    let provenance = Provenance::from_json(&build.provenance_bytes)?;
    let verification = attestation::verify(&build.evidence_bytes, &Default::default()).await?;

    let mut results: Vec<Verification> = vec![];
    results.push(verify_signature(&verification));
    results.push(provenance.verify_predicate());
    results.push(verify_provenance(&verification, &provenance));
    results.extend(provenance.verify_artifacts(&build.artifacts)?);
    if let Some(nonce) = nonce {
        results.push(verify_nonce(&verification, nonce));
    }

    // Print build information
    print_table(
        vec![format!(
            "\n{} {}\n",
            "Verifying build dir".bold(),
            &path.file_name().unwrap().to_string_lossy()
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

fn verify_nonce(verification_result: &VerificationResult, nonce_string: String) -> Verification {
    let nonce = hex::decode(nonce_string).unwrap();
    if let Some(signed_data) = &verification_result.claims.signed_data.split_at_checked(32) {
        let signed_nonce = signed_data.1;

        tracing::debug!(
            "signed_nonce {:?} given nonce {:?} equal {}",
            hex::encode(signed_nonce),
            hex::encode(&nonce),
            signed_nonce == nonce
        );

        match signed_nonce == nonce {
            true => Verification::success("Nonce matches attestation"),
            false => Verification::failure(
                "Nonce mismatch",
                &format!(
                    "Expected attested nonce {:?}\nActual value was        {:?}",
                    hex::encode(nonce),
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

fn verify_provenance(
    verification_result: &VerificationResult,
    provenance: &Provenance,
) -> Verification {
    if let Some(signed_data) = &verification_result.claims.signed_data.split_at_checked(32) {
        let signed_checksum = signed_data.0;
        if signed_checksum.len() != 32 {
            return Verification::Failure {
                message: "Attested checksum invalid".to_string(),
                details: format!(
                    "Expected attestation checksum {:?} to be 32 bytes",
                    hex::encode(signed_checksum)
                ),
            };
        }

        let checksum = provenance.checksum();
        if checksum.len() != 32 {
            return Verification::Failure {
                message: "Provenance checksum invalid".to_string(),
                details: format!(
                    "Expected provenance.json checksum {:?} to be 32 bytes",
                    hex::encode(checksum)
                ),
            };
        }

        match signed_checksum == checksum {
            true => Verification::success("Provenance checksum match"),
            false => Verification::failure(
                "Provenance checksum mismatch",
                &format!(
                    "Expected provenance.json checksum {:?}\nActual provenance.json checksum   {:?}",
                    hex::encode(signed_checksum),
                    hex::encode(checksum)
                ),
            ),
        }
    } else {
        Verification::Failure {
            message: "Signed data invalid".to_owned(),
            details: format!(
                "Expected signed data {:?} to be at least 32 bytes",
                &verification_result.claims.signed_data
            ),
        }
    }
}

struct Build {
    provenance_bytes: Vec<u8>,
    evidence_bytes: Vec<u8>,
    artifacts: Vec<DirEntry>,
}

impl Build {
    fn from_dir(path: &PathBuf) -> Result<Build> {
        let project_dir = fs_err::canonicalize(path)?;
        let evidence_bytes = fs_err::read(project_dir.join("evidence.json"))?;
        let provenance_bytes = fs_err::read(project_dir.join("provenance.json"))?;
        let artifacts = fs_err::read_dir(project_dir.join("artifacts"))?
            .filter_map(|e| e.ok())
            .collect();

        let build = Build {
            provenance_bytes,
            evidence_bytes,
            artifacts,
        };

        Ok(build)
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
        assert_verify_nonce("");
        assert_verify_nonce("aa");
        assert_verify_nonce("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_verify_nonce("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_verify_nonce("deadbeefdeadbeefdeadbeefdeadbeef");
        assert_verify_nonce("43C4EF48E21A45B886B2FA7D7CD0EF59");
        assert_verify_nonce("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_verify_nonce("00");
        assert_verify_nonce("000000000000000000000000000000");
        assert_verify_nonce("00000000000000000000000000000000");
        assert_verify_nonce("0000000000000000000000000000000000");
    }

    fn assert_verify_nonce(nonce: &str) {
        let mut signed_data = vec![0; 32];
        let mut nonce_bytes = hex::decode(nonce).unwrap();
        signed_data.append(&mut nonce_bytes);

        let vr = make_verification_result(true, signed_data);
        match verify_nonce(&vr, nonce.to_string()) {
            Verification::Success { message } => {
                assert!(message.contains("match"), "message: {message}");
            }
            Verification::Failure { message, .. } => panic!("expected success: {message}"),
        }
    }

    #[test]
    fn verify_signed_nonce_errors() {
        assert_verify_nonce_fails(vec![], "", "missing");
        assert_verify_nonce_fails(vec![0; 3], "", "missing");
        assert_verify_nonce_fails(vec![0; 31], "", "missing");
        assert_verify_nonce_fails(vec![0; 33], "", "mismatch");
        assert_verify_nonce_fails(vec![0; 49], "", "mismatch");
        assert_verify_nonce_fails(vec![0; 50], "", "mismatch");
        assert_verify_nonce_fails(vec![0; 51], "", "mismatch");
        assert_verify_nonce_fails(vec![0; 64], "", "mismatch");
        assert_verify_nonce_fails(vec![0; 65], "", "mismatch");

        assert_verify_nonce_fails(vec![], "cafe", "missing");
        assert_verify_nonce_fails(vec![0; 3], "cafe", "missing");
        assert_verify_nonce_fails(vec![0; 31], "cafe", "missing");
        assert_verify_nonce_fails(vec![0; 33], "cafe", "mismatch");
        assert_verify_nonce_fails(vec![0; 49], "cafe", "mismatch");
        assert_verify_nonce_fails(vec![0; 50], "cafe", "mismatch");
        assert_verify_nonce_fails(vec![0; 51], "cafe", "mismatch");
        assert_verify_nonce_fails(vec![0; 64], "cafe", "mismatch");
        assert_verify_nonce_fails(vec![0; 65], "cafe", "mismatch");

        assert_verify_nonce_fails(vec![0; 50], "aa000000000000000000000000000000", "mismatch");
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
        assert_verify_provenance_fails(vec![], "invalid");
        assert_verify_provenance_fails(vec![0; 3], "invalid");
        assert_verify_provenance_fails(vec![0; 31], "invalid");
        assert_verify_provenance_fails(vec![0; 32], "mismatch");
        assert_verify_provenance_fails(vec![0; 33], "mismatch");
        assert_verify_provenance_fails(vec![0; 49], "mismatch");
        assert_verify_provenance_fails(vec![0; 50], "mismatch");
        assert_verify_provenance_fails(vec![0; 51], "mismatch");
        assert_verify_provenance_fails(vec![0; 64], "mismatch");
        assert_verify_provenance_fails(vec![0; 65], "mismatch");
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
    fn build_from_dir_missing_artifacts() {
        let tmp = TempDir::new().unwrap();
        fs_err::write(tmp.path().join("evidence.json"), b"{}").unwrap();
        fs_err::write(tmp.path().join("provenance.json"), CARGO_FIXTURE).unwrap();
        assert!(Build::from_dir(&tmp.path().to_path_buf()).is_err());
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
}
