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
