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
        _path: &Path,
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
        let resolved_deps = parse_cargo_lock(lockfile_bytes)?;
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
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!(
                "cargo build failed (exit {:?}): {}",
                output.status.code(),
                stderr.chars().take(4000).collect::<String>()
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

fn parse_cargo_lock(bytes: &[u8]) -> Result<Vec<ResolvedDependency>> {
    let content = std::str::from_utf8(bytes)?;
    let lock: toml::Value = toml::from_str(content)?;
    let Some(packages) = lock.get("package").and_then(|v| v.as_array()) else {
        return Ok(vec![]);
    };

    let mut deps = Vec::new();
    for pkg in packages {
        let name = pkg.get("name").and_then(|v| v.as_str()).unwrap_or_default();
        let version = pkg
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if let Some(checksum) = pkg.get("checksum").and_then(|v| v.as_str()) {
            deps.push(ResolvedDependency {
                annotations: None,
                digest: Digest::Sha256 {
                    sha256: checksum.to_string(),
                },
                name: name.to_string(),
                uri: format!("pkg:cargo/{name}@{version}?checksum=sha256:{checksum}"),
            });
        }
    }

    deps.sort_by_cached_key(|e| e.uri.clone());
    Ok(deps)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CARGO_LOCK_FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/ripgrep/Cargo.lock");

    #[test]
    fn happy_path() {
        let deps = parse_cargo_lock(CARGO_LOCK_FIXTURE).unwrap();
        // Fixture has 5 registry packages (my-project has no checksum)
        assert_eq!(deps.len(), 51);
        // Each entry has proper URI format
        for dep in &deps {
            assert!(
                dep.uri.starts_with("pkg:cargo/"),
                "URI should start with pkg:cargo/: {}",
                dep.uri
            );
            assert!(
                dep.uri.contains("?checksum=sha256:"),
                "URI should contain checksum: {}",
                dep.uri
            );
        }
        // Should be sorted by uri
        let uris: Vec<&str> = deps.iter().map(|d| d.uri.as_str()).collect();
        let mut sorted = uris.clone();
        sorted.sort();
        assert_eq!(uris, sorted, "dependencies should be sorted by URI");
        // Workspace member (my-project) should be excluded
        assert!(
            deps.iter().all(|d| d.name != "my-project"),
            "workspace member should be excluded"
        );
    }

    #[test]
    fn empty_package_list() {
        let toml = b"[metadata]\nkey = \"value\"";
        let deps = parse_cargo_lock(toml).unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn invalid_toml() {
        assert!(parse_cargo_lock(b"{{{{not valid toml}}}}").is_err());
    }

    #[test]
    fn utf8_error() {
        // Invalid UTF-8 sequence
        let bytes: &[u8] = &[0xff, 0xfe, 0xfd];
        assert!(parse_cargo_lock(bytes).is_err());
    }

    #[test]
    fn deterministic_ordering() {
        let r1 = parse_cargo_lock(CARGO_LOCK_FIXTURE).unwrap();
        let r2 = parse_cargo_lock(CARGO_LOCK_FIXTURE).unwrap();
        assert_eq!(r1.len(), r2.len());
        for (a, b) in r1.iter().zip(r2.iter()) {
            assert_eq!(a.uri, b.uri);
            assert_eq!(a.name, b.name);
            assert_eq!(a.digest.value(), b.digest.value());
        }
    }
}
