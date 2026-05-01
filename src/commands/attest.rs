use anyhow::Result;
use std::path::PathBuf;

#[derive(clap::Args, Debug)]
pub struct AttestArgs {
    /// Path to the project to be built and attested
    #[arg()]
    path: PathBuf,
}

#[cfg(all(feature = "attest", target_os = "linux"))]
pub async fn attest(args: AttestArgs) -> Result<()> {
    let path = &args.path;
    use crate::provenance::Provenance;

    // Build the thing from scratch before we attest it
    crate::commands::build::build(path)?;

    let platform = attestation::detect().expect("no TEE platform detected");
    println!("Running on platform: {}", platform);

    let provenance_bytes = fs_err::read(path.join("kettle-build/provenance.json"))?;
    let provenance = Provenance::from_json(&provenance_bytes)?;
    let provenance_checksum = provenance.checksum();
    println!(
        "Attesting build provenance.json with checksum {}",
        hex::encode(&provenance_checksum)
    );

    let evidence_json = attestation::attest(platform, provenance_checksum.as_slice())
        .await
        .expect("attestation failed");
    fs_err::write(path.join("kettle-build/evidence.json"), evidence_json)?;

    println!("Attestation complete! Evidence written to file `evidence.json`");

    Ok(())
}

#[cfg(not(all(feature = "attest", target_os = "linux")))]
pub async fn attest(_args: AttestArgs) -> Result<()> {
    use anyhow::anyhow;
    Err(anyhow!(
        "Attestation is disabled. Rebuild Kettle with `--features attest` to enable this command."
    ))
}
