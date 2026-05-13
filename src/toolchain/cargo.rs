use anyhow::{Context, Result, anyhow};
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::debug;

use crate::{
    provenance::{Digest, InternalParameters, ResolvedDependency, Toolchain, ToolchainVersion},
    toolchain::{
        Artifact, BuildOutput, GitContext, ProvenanceFields, ToolBinaryInfo, ToolchainDriver,
    },
};

pub(crate) fn build(path: &PathBuf) -> Result<()> {
    crate::toolchain::runner::run::<CargoInputs>(path)
}

#[derive(Debug)]
struct CargoInputs {
    kettle_version: String,
    kettle_hash: String,
    rustc_version: String,
    rustc_hash: String,
    cargo_version: String,
    cargo_hash: String,
    lockfile_hash: String,
    resolved_deps: Vec<ResolvedDependency>,
}

impl ToolchainDriver for CargoInputs {
    fn lockfile_filename() -> &'static str {
        "Cargo.lock"
    }

    fn build_command_display() -> &'static str {
        "cargo build --locked --release"
    }

    fn collect_inputs(
        path: &Path,
        _git: &GitContext,
        lockfile_hash: &str,
        lockfile_bytes: &[u8],
    ) -> Result<Self> {
        let rustc = ToolBinaryInfo::via_rustup("rustc")?;
        debug!("rustc info {:?}", rustc);
        let cargo = ToolBinaryInfo::via_rustup("cargo")?;
        debug!("cargo info {:?}", rustc);
        let kettle = ToolBinaryInfo::kettle_info()?;
        debug!("kettle info {:?}", rustc);
        let resolved_deps = crate::toolchain::cargo_lock::resolve_dependencies(path, lockfile_bytes)?;
        debug!("found deps {:?}", resolved_deps);
        Ok(Self {
            kettle_version: kettle.version,
            kettle_hash: kettle.sha256,
            rustc_version: rustc.version,
            rustc_hash: rustc.sha256,
            cargo_version: cargo.version,
            cargo_hash: cargo.sha256,
            lockfile_hash: lockfile_hash.to_string(),
            resolved_deps,
        })
    }

    fn merkle_entries(&self, git: &GitContext, lockfile_hash: &str) -> Vec<String> {
        // Ordering is a frozen contract — do not change without bumping the build_type URI.
        let mut entries = vec![
            git.commit.clone(),
            git.tree.clone(),
            self.rustc_hash.clone(),
            self.rustc_version.clone(),
            self.cargo_hash.clone(),
            self.cargo_version.clone(),
            lockfile_hash.to_string(),
        ];
        entries.extend(self.resolved_deps.iter().map(|d| d.uri.clone()));
        entries
    }

    fn run_build(path: &Path) -> Result<BuildOutput> {
        let output = Command::new("cargo")
            .args(["build", "--locked", "--release"])
            .current_dir(path)
            .output()
            .context("failed to spawn cargo")?;
        if !output.status.success() {
            return Err(anyhow!(
                "cargo build failed (exit {:?})",
                output.status.code()
            ));
        }
        Ok(BuildOutput {
            stdout: output.stdout,
        })
    }

    fn collect_artifacts(
        _output: &BuildOutput,
        path: &Path,
        artifacts_dir: &Path,
    ) -> Result<Vec<Artifact>> {
        let release_dir = path.join("target").join("release");
        Artifact::in_dir(&release_dir)?
            .into_iter()
            .map(|a| {
                let dest = artifacts_dir.join(&a.name);
                fs_err::copy(&a.path, &dest)?;
                Ok(Artifact {
                    name: a.name,
                    path: dest,
                    checksum: a.checksum,
                })
            })
            .collect()
    }

    fn provenance_fields(self, _git: &GitContext, _merkle_root: &str) -> ProvenanceFields {
        ProvenanceFields {
            build_type: "https://lunal.dev/kettle/cargo@v1".to_string(),
            external_build_command: "cargo build".to_string(),
            internal_parameters: InternalParameters {
                evaluation: None,
                flake_inputs: None,
                lockfile_hash: Digest::Sha256 {
                    sha256: self.lockfile_hash,
                },
                toolchain: Toolchain::RustToolchain {
                    rustc: ToolchainVersion {
                        version: self.rustc_version,
                        digest: Digest::Sha256 {
                            sha256: self.rustc_hash,
                        },
                    },
                    cargo: ToolchainVersion {
                        version: self.cargo_version,
                        digest: Digest::Sha256 {
                            sha256: self.cargo_hash,
                        },
                    },
                    kettle: ToolchainVersion {
                        version: self.kettle_version,
                        digest: Digest::Sha256 {
                            sha256: self.kettle_hash,
                        },
                    },
                },
            },
            resolved_dependencies: self.resolved_deps,
        }
    }
}

