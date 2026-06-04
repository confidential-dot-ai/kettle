// This module exists to define the JSON manifest schema. It is serde structs
// and a file-hashing helper. No complex logic.

use serde::Serialize;
use sha2::{Digest, Sha256};

/// JSON build manifest recording inputs, configuration, and measurement output.
#[derive(Serialize)]
pub struct Manifest {
    pub version: u32,
    pub igvm_file: String,
    pub igvm_sha256: String,
    pub measurement: MeasurementInfo,
    pub config: BuildConfig,
    pub inputs: InputFiles,
    pub generated_at: String,
}

/// SNP launch digest and associated measurement metadata.
#[derive(Serialize)]
pub struct MeasurementInfo {
    pub snp_launch_digest: String,
    pub algorithm: String,
    pub page_count: u64,
    pub vmsa_count: u32,
}

/// Build-time configuration (platform, boot mode, vCPU count).
#[derive(Serialize)]
pub struct BuildConfig {
    pub platform: String,
    pub boot_mode: String,
    pub smp: u32,
}

/// Paths and SHA-256 hashes of all input files used in the build.
#[derive(Serialize)]
pub struct InputFiles {
    pub firmware: FileInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vars: Option<FileInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel: Option<FileInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shim: Option<FileInfo>,
}

/// A single input file's path and content hash.
#[derive(Serialize)]
pub struct FileInfo {
    pub path: String,
    pub sha256: String,
}

/// Compute the SHA-256 hex digest of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    hex::encode(hash)
}
