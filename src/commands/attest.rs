use anyhow::Result;
use anyhow::anyhow;
use std::path::PathBuf;

#[derive(clap::Args, Debug)]
pub struct AttestArgs {
    /// Path to the project to be built and attested
    #[arg()]
    pub path: PathBuf,
    /// Optional nonce, as hex string, to be included in the attestation.
    /// Can be up to 16 bytes. For a unique nonce, use e.g. `uuidgen`.
    #[arg(short, long)]
    pub nonce: Option<String>,
}

pub async fn attest(args: AttestArgs) -> Result<()> {
    attest_with_sink(args, &crate::toolchain::EventSink::noop()).await
}

#[cfg(all(feature = "attest", target_os = "linux"))]
pub async fn attest_with_sink(args: AttestArgs, sink: &crate::toolchain::EventSink) -> Result<()> {
    let path = &args.path;
    let nonce = args.nonce;
    use crate::provenance::Provenance;

    crate::commands::build::build_with_sink(path, sink)?;

    let platform = attestation::detect().expect("no TEE platform detected");
    println!("Running on platform: {}", platform);
    sink.emit(crate::api::Event::Attest {
        msg: format!("Running on platform: {platform}"),
    }).await;

    let provenance_bytes = fs_err::read(path.join("kettle-build/provenance.json"))?;
    let provenance = Provenance::from_json(&provenance_bytes)?;
    let provenance_checksum = provenance.checksum();
    println!("Attesting build provenance.json with checksum {}",
             hex::encode(&provenance_checksum));
    sink.emit(crate::api::Event::Attest {
        msg: format!("Attesting provenance.json (checksum {})",
                     hex::encode(&provenance_checksum)),
    }).await;

    let mut report_data = [0u8; 48];
    report_data[..32].copy_from_slice(&provenance_checksum);

    if let Some(nonce_string) = nonce {
        let nonce_data = hex::decode(nonce_string.replace("-", ""))?;
        if nonce_data.len() > 16 {
            return Err(anyhow!(
                "Nonce {} is too long! Must be 16 bytes (32 chars of hex) or less.",
                nonce_string
            ));
        }
        report_data[32..(32 + nonce_data.len())].copy_from_slice(&nonce_data);
    };

    tracing::debug!("attesting with report_data {}", hex::encode(report_data));
    let evidence_json = attestation::attest(platform, report_data.as_slice(), &Default::default())
        .await
        .expect("attestation failed");
    let evidence_json = embed_snp_vcek(evidence_json).await?;
    fs_err::write(path.join("kettle-build/evidence.json"), evidence_json)?;

    println!("Attestation complete! Evidence written to file `evidence.json`");
    sink.emit(crate::api::Event::Attest {
        msg: "Attestation complete! evidence.json written".into(),
    }).await;

    Ok(())
}

#[cfg(not(all(feature = "attest", target_os = "linux")))]
pub async fn attest_with_sink(_args: AttestArgs, _sink: &crate::toolchain::EventSink) -> Result<()> {
    Err(anyhow!(
        "Attestation is disabled. Rebuild Kettle with `--features attest` to enable this command."
    ))
}

// SEV firmware sometimes returns an SnpEvidence with no cert chain (the host
// hasn't provisioned the VCEK). Browser-side verifiers can't reach AMD KDS, so
// we fetch the VCEK here and embed it before writing the evidence.
#[cfg(all(feature = "attest", target_os = "linux"))]
async fn embed_snp_vcek(evidence_json: Vec<u8>) -> Result<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use sev::firmware::guest::AttestationReport;
    use sev::parser::ByteParser;

    let mut envelope: serde_json::Value = serde_json::from_slice(&evidence_json)?;
    if envelope.get("platform").and_then(|p| p.as_str()) != Some("snp") {
        return Ok(evidence_json);
    }
    let evidence = envelope.get_mut("evidence").ok_or_else(|| anyhow!("evidence missing"))?;
    if !evidence.get("cert_chain").is_some_and(|c| c.is_null()) {
        return Ok(evidence_json);
    }
    let report_b64 = evidence
        .get("attestation_report")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("attestation_report missing"))?;
    let report_bytes = BASE64.decode(report_b64).map_err(|e| anyhow!("report base64: {e}"))?;
    let report = AttestationReport::from_bytes(&report_bytes)
        .map_err(|e| anyhow!("SNP report parse: {e}"))?;

    let cpuid_fam = report.cpuid_fam_id.unwrap_or(0);
    let cpuid_mod = report.cpuid_mod_id.unwrap_or(0);
    let processor_gen = attestation::ProcessorGeneration::from_cpuid(cpuid_fam, cpuid_mod)
        .ok_or_else(|| anyhow!("unknown SNP processor family={cpuid_fam:#x} model={cpuid_mod:#x}"))?;

    let mut chip_id = [0u8; 64];
    chip_id.copy_from_slice(&report.chip_id[..]);
    let tcb = attestation::SnpTcb {
        bootloader: report.reported_tcb.bootloader,
        tee: report.reported_tcb.tee,
        snp: report.reported_tcb.snp,
        microcode: report.reported_tcb.microcode,
        fmc: if processor_gen == attestation::ProcessorGeneration::Turin {
            report.reported_tcb.fmc
        } else {
            None
        },
    };

    let provider = attestation::DefaultCertProvider::new();
    let vcek_der = attestation::CertProvider::get_snp_vcek(&provider, processor_gen, &chip_id, &tcb)
        .await
        .map_err(|e| anyhow!("VCEK fetch from AMD KDS failed: {e}"))?;
    evidence["cert_chain"] = serde_json::json!({
        "vcek": BASE64.encode(&vcek_der),
        "ask": null,
        "ark": null,
    });
    tracing::info!("embedded VCEK ({} bytes) into SnpEvidence", vcek_der.len());
    Ok(serde_json::to_vec(&envelope)?)
}
