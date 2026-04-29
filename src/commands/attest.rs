use anyhow::Result;
use std::path::PathBuf;

#[cfg(all(feature = "attest", target_os = "linux"))]
pub async fn attest(path: &PathBuf, nonce: Option<&[u8]>) -> Result<()> {
    use crate::provenance::Provenance;

    // Build the thing from scratch before we attest it
    crate::commands::build::build(path)?;

    let platform = attestation::detect()
        .map_err(|e| anyhow::anyhow!("no TEE platform detected: {e}"))?;
    println!("Running on platform: {}", platform);

    let provenance_bytes = fs_err::read(path.join("kettle-build/provenance.json"))?;
    let provenance = Provenance::from_json(&provenance_bytes)?;
    let provenance_checksum = provenance.checksum();
    println!(
        "Attesting build provenance.json with checksum {}",
        hex::encode(&provenance_checksum)
    );

    // Construct 64-byte report_data:
    //   [0:32]  = SHA256(provenance.json) — binds evidence to build output
    //   [32:64] = caller nonce            — proves freshness (anti-replay)
    let mut report_data = vec![0u8; 64];
    report_data[..32].copy_from_slice(&provenance_checksum);
    if let Some(n) = nonce {
        let len = n.len().min(32);
        report_data[32..32 + len].copy_from_slice(&n[..len]);
        println!("Nonce bound into attestation report_data[32:64]");
    }

    let evidence_json = attestation::attest(platform, &report_data)
        .await
        .map_err(|e| anyhow::anyhow!("attestation failed: {e}"))?;
    fs_err::write(path.join("kettle-build/evidence.json"), &evidence_json)?;

    // Write nonce alongside evidence so verifiers know what to check
    if let Some(n) = nonce {
        fs_err::write(path.join("kettle-build/nonce"), n)?;
    }

    println!("Attestation complete! Evidence written to file `evidence.json`");

    Ok(())
}

#[cfg(not(all(feature = "attest", target_os = "linux")))]
pub async fn attest(_path: &PathBuf, _nonce: Option<&[u8]>) -> Result<()> {
    use anyhow::anyhow;
    Err(anyhow!(
        "Attestation is disabled. Rebuild Kettle with `--features attest` to enable this command."
    ))
}
