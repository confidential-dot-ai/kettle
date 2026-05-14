use anyhow::{Context, Result, anyhow};
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::debug;

use crate::{
    provenance::{Digest, InternalParameters, ResolvedDependency, Toolchain, ToolchainVersion},
    toolchain::{
        Artifact, BuildOutput, GitContext, ProvenanceFields, ToolBinaryInfo, ToolchainDriver,
    },
};

pub(crate) fn build(path: &PathBuf, sink: &crate::toolchain::EventSink) -> Result<()> {
    crate::toolchain::runner::run::<PnpmInputs>(path, sink)
}

#[derive(Debug)]
struct PnpmInputs {
    node_version: String,
    node_hash: String,
    pnpm_version: String,
    pnpm_hash: String,
    kettle_version: String,
    kettle_hash: String,
    lockfile_hash: String,
    deps: Vec<ResolvedDependency>,
}

impl ToolchainDriver for PnpmInputs {
    fn lockfile_filename() -> &'static str {
        "pnpm-lock.yaml"
    }

    fn build_command_display() -> &'static str {
        "pnpm install --frozen-lockfile && pnpm build"
    }

    fn collect_inputs(
        _path: &Path,
        _git: &GitContext,
        lockfile_hash: &str,
        lockfile_bytes: &[u8],
    ) -> Result<Self> {
        let node = ToolBinaryInfo::via_which("node")?;
        debug!("node info {:?}", node);
        let pnpm = ToolBinaryInfo::via_which("pnpm")?;
        debug!("pnpm info {:?}", pnpm);
        let kettle = ToolBinaryInfo::kettle_info()?;
        debug!("kettle info {:?}", kettle);
        let deps = parse_pnpm_lock(lockfile_bytes)?;
        debug!("found deps {:?}", deps);
        Ok(Self {
            node_version: node.version,
            node_hash: node.sha256,
            pnpm_version: pnpm.version,
            pnpm_hash: pnpm.sha256,
            kettle_version: kettle.version,
            kettle_hash: kettle.sha256,
            lockfile_hash: lockfile_hash.to_string(),
            deps,
        })
    }

    fn merkle_entries(&self, git: &GitContext, lockfile_hash: &str) -> Vec<String> {
        // Ordering is a frozen contract — do not change without bumping the build_type URI.
        let mut entries = vec![
            git.commit.clone(),
            git.tree.clone(),
            self.node_hash.clone(),
            self.node_version.clone(),
            self.pnpm_hash.clone(),
            self.pnpm_version.clone(),
            lockfile_hash.to_string(),
        ];
        entries.extend(self.deps.iter().map(|d| d.uri.clone()));
        entries
    }

    fn run_build(path: &Path, sink: &crate::toolchain::EventSink) -> Result<BuildOutput> {
        let mut install_cmd = Command::new("pnpm");
        install_cmd
            .args(["install", "--frozen-lockfile"])
            .current_dir(path);
        let _ = crate::toolchain::runner::stream_command(&mut install_cmd, sink)
            .map_err(|e| anyhow!("pnpm install --frozen-lockfile failed: {}", e))?;

        let mut build_cmd = Command::new("pnpm");
        build_cmd.arg("build").current_dir(path);
        let stdout = crate::toolchain::runner::stream_command(&mut build_cmd, sink)
            .map_err(|e| anyhow!("pnpm build failed: {}", e))?;

        Ok(BuildOutput { stdout })
    }

    fn collect_artifacts(
        _output: &BuildOutput,
        path: &Path,
        artifacts_dir: &Path,
    ) -> Result<Vec<Artifact>> {
        let dist_dir = path.join("dist");
        if !dist_dir.exists() {
            return Err(anyhow!("dist/ directory not found in {:?}", path));
        }

        let tarball_path = artifacts_dir.join("dist.tar.gz");
        let tarball_str = tarball_path
            .to_str()
            .ok_or_else(|| anyhow!("path is not valid UTF-8: {:?}", tarball_path))?;
        let path_str = path
            .to_str()
            .ok_or_else(|| anyhow!("path is not valid UTF-8: {:?}", path))?;
        let tar = Command::new("tar")
            .args(["-czf", tarball_str, "-C", path_str, "dist"])
            .output()
            .context("failed to spawn tar")?;
        if !tar.status.success() {
            return Err(anyhow!(
                "tar failed (exit {:?}): {}",
                tar.status.code(),
                String::from_utf8_lossy(&tar.stderr)
            ));
        }

        let checksum = hex::encode(Sha256::digest(fs_err::read(&tarball_path)?));
        Ok(vec![Artifact {
            name: "dist.tar.gz".into(),
            path: tarball_path,
            checksum,
        }])
    }

    fn provenance_fields(self, _git: &GitContext, _merkle_root: &str) -> ProvenanceFields {
        ProvenanceFields {
            build_type: "https://lunal.dev/kettle/pnpm@v1".to_string(),
            external_build_command: "pnpm build".to_string(),
            internal_parameters: InternalParameters {
                evaluation: None,
                flake_inputs: None,
                lockfile_hash: Digest::Sha256 {
                    sha256: self.lockfile_hash,
                },
                toolchain: Toolchain::PnpmToolchain {
                    node: ToolchainVersion {
                        version: self.node_version,
                        digest: Digest::Sha256 {
                            sha256: self.node_hash,
                        },
                    },
                    pnpm: ToolchainVersion {
                        version: self.pnpm_version,
                        digest: Digest::Sha256 {
                            sha256: self.pnpm_hash,
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
            resolved_dependencies: self.deps,
        }
    }
}

fn parse_pnpm_lock(bytes: &[u8]) -> Result<Vec<ResolvedDependency>> {
    let data: serde_yaml::Value =
        serde_yaml::from_slice(bytes).context("malformed pnpm-lock.yaml")?;
    let Some(packages) = data.get("packages").and_then(|p| p.as_mapping()) else {
        return Ok(vec![]);
    };
    let mut deps = Vec::new();
    for (key, value) in packages {
        let key_str = key
            .as_str()
            .ok_or_else(|| anyhow!("pnpm-lock.yaml: package key is not a string"))?;
        let integrity = value
            .get("resolution")
            .and_then(|r| r.get("integrity"))
            .and_then(|i| i.as_str())
            .filter(|s| !s.is_empty());
        let (name, version) = parse_key(key_str)?;

        if let Some(checksum) = integrity {
            let uri = format!("pkg:npm/{}@{}?checksum={}", name, version, checksum);

            deps.push(ResolvedDependency {
                annotations: None,
                digest: Digest::Sha512 {
                    sha512: checksum.to_string(),
                },
                name,
                uri,
            });
        } else {
            let uri = value
                .get("resolution")
                .and_then(|r| r.get("tarball"))
                .and_then(|i| i.as_str())
                .filter(|s| !s.is_empty() && s.contains("codeload.github.com"))
                .ok_or_else(|| {
                    anyhow!(
                        "pnpm-lock.yaml: package {:?} missing resolution with integrity or commit tarball",
                        key_str
                    )
                })?;
            let checksum = uri.split("/").last().unwrap();
            deps.push(ResolvedDependency {
                annotations: None,
                digest: Digest::Sha512 {
                    sha512: checksum.to_string(),
                },
                name,
                uri: uri.to_string(),
            });
        }
    }
    deps.sort_by_cached_key(|d| d.uri.clone());
    Ok(deps)
}

fn parse_key(key: &str) -> Result<(String, String)> {
    // Strip peer-dep suffix: trailing (...)
    let key = if let Some(pos) = key.find('(') {
        &key[..pos]
    } else {
        key
    };
    if let Some(rest) = key.strip_prefix('@') {
        // scoped: @scope/name@version — find second '@' in rest
        let inner_at = rest
            .find('@')
            .ok_or_else(|| anyhow!("pnpm-lock.yaml: cannot parse scoped key {:?}", key))?;
        let name = format!("@{}", &rest[..inner_at]);
        let version = rest[inner_at + 1..].to_string();
        Ok((name, version))
    } else {
        let at = key
            .find('@')
            .ok_or_else(|| anyhow!("pnpm-lock.yaml: cannot parse key {:?}", key))?;
        Ok((key[..at].to_string(), key[at + 1..].to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_unscoped() {
        let (name, version) = parse_key("semver@7.6.0").unwrap();
        assert_eq!(name, "semver");
        assert_eq!(version, "7.6.0");
    }

    #[test]
    fn parse_scoped() {
        let (name, version) = parse_key("@types/node@20.11.5").unwrap();
        assert_eq!(name, "@types/node");
        assert_eq!(version, "20.11.5");
    }

    #[test]
    fn parse_peer_dep_stripped() {
        let (name, version) = parse_key("@types/react@18.0.0(@types/prop-types@15.7.0)").unwrap();
        assert_eq!(name, "@types/react");
        assert_eq!(version, "18.0.0");
    }

    #[test]
    fn parse_pnpm_lock_happy_path() {
        let bytes = include_bytes!("../../tests/fixtures/openclaw/pnpm-lock.yaml");
        let deps = parse_pnpm_lock(bytes).unwrap();
        assert_eq!(deps.len(), 1477);
        // Should be sorted by uri
        let uris: Vec<&str> = deps.iter().map(|d| d.uri.as_str()).collect();
        let mut sorted = uris.clone();
        sorted.sort();
        assert_eq!(uris, sorted, "dependencies should be sorted by URI");
    }

    #[test]
    fn parse_pnpm_lock_empty_packages() {
        let yaml = b"lockfileVersion: '9.0'\n\npackages: {}\n";
        let deps = parse_pnpm_lock(yaml).unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn parse_pnpm_lock_missing_integrity() {
        let yaml = b"lockfileVersion: '9.0'\n\npackages:\n  semver@7.6.0:\n    resolution: {}\n";
        let result = parse_pnpm_lock(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("missing resolution"), "error: {err}");
    }

    #[test]
    fn parse_pnpm_lock_empty_integrity() {
        let yaml = b"lockfileVersion: '9.0'\n\npackages:\n  semver@7.6.0:\n    resolution:\n      integrity: \"\"\n";
        let result = parse_pnpm_lock(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("missing resolution"), "error: {err}");
    }

    #[test]
    fn parse_pnpm_lock_malformed_yaml() {
        let result = parse_pnpm_lock(b"not: yaml: content: [unclosed");
        assert!(result.is_err());
    }

    #[test]
    fn deterministic_ordering() {
        let bytes = include_bytes!("../../tests/fixtures/openclaw/pnpm-lock.yaml");
        let r1 = parse_pnpm_lock(bytes).unwrap();
        let r2 = parse_pnpm_lock(bytes).unwrap();
        assert_eq!(r1.len(), r2.len());
        for (a, b) in r1.iter().zip(r2.iter()) {
            assert_eq!(a.uri, b.uri);
            assert_eq!(a.name, b.name);
            assert_eq!(a.digest.value(), b.digest.value());
        }
    }

    #[test]
    fn uri_format_validation() {
        let bytes = include_bytes!("../../tests/fixtures/openclaw/pnpm-lock.yaml");
        let deps = parse_pnpm_lock(bytes).unwrap();
        for dep in &deps {
            if dep.uri.starts_with("pkg:npm/") {
                assert!(
                    dep.uri.contains("?checksum="),
                    "URI should contain ?checksum=: {}",
                    dep.uri
                );
            } else {
                assert!(
                    dep.uri.starts_with("https://codeload.github.com"),
                    "URI should be a commit tarball: {}",
                    dep.uri
                )
            }
        }
    }
}
