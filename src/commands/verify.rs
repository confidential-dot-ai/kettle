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

pub async fn verify(path: &PathBuf) -> Result<()> {
    let build = Build::from_dir(path)?;

    // Get the provenance and attestation
    let provenance = Provenance::from_json(&build.provenance_bytes)?;
    let verification = attestation::verify(&build.evidence_bytes, &Default::default()).await?;

    let mut results: Vec<Verification> = vec![];
    results.push(verify_signature(&verification));
    results.push(provenance.verify_predicate());
    results.push(verify_report_data(&verification, &provenance));
    results.extend(provenance.verify_artifacts(&build.artifacts)?);

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

fn verify_signature(verification_result: &VerificationResult) -> Verification {
    match verification_result.signature_valid {
        true => Verification::success("Attestation hardware signature valid"),
        false => Verification::failure(
            "Attestation hardware signature invalid",
            "signature verification failed",
        ),
    }
}

fn verify_report_data(
    verification_result: &VerificationResult,
    provenance: &Provenance,
) -> Verification {
    let signed_data = &verification_result.claims.signed_data;
    let checksum = provenance.checksum();

    match *signed_data == checksum {
        true => Verification::success("Provenance checksum match"),
        false => Verification::failure(
            "Provenance checksum mismatch",
            &format!(
                "Expected provenance.json checksum {:?}\nActual provenance.json checksum   {:?}",
                signed_data, checksum
            ),
        ),
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
        match verify_report_data(&vr, &provenance) {
            Verification::Success { message } => {
                assert!(message.contains("match"), "message: {message}");
            }
            Verification::Failure { message, .. } => panic!("expected success: {message}"),
        }
    }

    #[test]
    fn verify_signed_data_mismatch() {
        let provenance = Provenance::from_json(CARGO_FIXTURE).unwrap();
        let signed_data = vec![0, 0, 0];
        let vr = make_verification_result(true, signed_data);
        match verify_report_data(&vr, &provenance) {
            Verification::Failure { message, .. } => {
                assert!(message.contains("mismatch"), "message: {message}");
            }
            Verification::Success { .. } => panic!("expected failure"),
        }
    }

    #[test]
    fn verify_signed_data_absent() {
        let provenance = Provenance::from_json(CARGO_FIXTURE).unwrap();
        let signed_data = vec![];
        let vr = make_verification_result(true, signed_data);
        match verify_report_data(&vr, &provenance) {
            Verification::Failure { message, .. } => {
                assert!(message.contains("mismatch"), "message: {message}");
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
