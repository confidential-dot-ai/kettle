use anyhow::{Context as _, Result, anyhow};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{
    provenance::{
        Annotation, Digest, Evaluation, FlakeInput, InternalParameters, ResolvedDependency,
        Toolchain, ToolchainVersion,
    },
    toolchain::{
        Artifact, BuildOutput, GitContext, ProvenanceFields, ToolBinaryInfo, ToolchainDriver,
    },
};

#[derive(Debug)]
struct FlakeDep {
    name: String,
    nar_hash: Option<String>,
}

#[derive(Debug)]
struct FetchEntry {
    name: String,
    drv_path: String,
    output_hash: String,
    output_hash_algo: String,
    output_hash_mode: Option<String>,
    url: Option<String>,
    urls: Option<String>,
}

pub(crate) fn build(path: &PathBuf, sink: &crate::toolchain::EventSink) -> Result<()> {
    crate::toolchain::runner::run::<NixInputs>(path, sink)
}

const BUILD_ARGS: &[&str] = &[
    "build",
    "--no-link",
    "--print-out-paths",
    "--extra-experimental-features",
    "nix-command",
    "--extra-experimental-features",
    "flakes",
];

#[derive(Debug)]
struct NixInputs {
    kettle_version: String,
    kettle_hash: String,
    nix_version: String,
    nix_hash: String,
    lockfile_hash: String,
    flake_deps: Vec<FlakeDep>,
    fetches: Vec<FetchEntry>,
    derivation_count: usize,
}

impl ToolchainDriver for NixInputs {
    fn lockfile_filename() -> &'static str {
        "flake.lock"
    }

    fn build_command_display() -> String {
        format!("nix {}", BUILD_ARGS.join(" "))
    }

    fn collect_inputs(
        path: &Path,
        _git: &GitContext,
        lockfile_hash: &str,
        lockfile_bytes: &[u8],
    ) -> Result<Self> {
        let nix = ToolBinaryInfo::via_which("nix")?;
        let kettle = ToolBinaryInfo::kettle_info()?;
        let flake_deps = parse_flake_lock(lockfile_bytes)?;
        let graph = evaluate_derivation_graph(path)?;
        let derivation_count = graph.as_object().map(|o| o.len()).unwrap_or(0);
        let fetches = extract_fixed_output_hashes(&graph);
        Ok(Self {
            kettle_version: kettle.version,
            kettle_hash: kettle.sha256,
            nix_version: nix.version,
            nix_hash: nix.sha256,
            lockfile_hash: lockfile_hash.to_string(),
            flake_deps,
            fetches,
            derivation_count,
        })
    }

    fn merkle_entries(&self, git: &GitContext, lockfile_hash: &str) -> Vec<String> {
        // Ordering is a frozen contract — do not change without bumping the build_type URI.
        let mut entries = vec![
            git.commit.clone(),
            git.tree.clone(),
            lockfile_hash.to_string(),
        ];
        for fod in &self.fetches {
            entries.push(format!(
                "fetch:{}:{}:{}",
                fod.name, fod.output_hash_algo, fod.output_hash
            ));
        }
        entries.push(self.nix_hash.clone());
        entries.push(self.nix_version.clone());
        entries
    }

    fn run_build(path: &Path, sink: &crate::toolchain::EventSink) -> Result<BuildOutput> {
        let mut cmd = Command::new("nix");
        cmd.args(BUILD_ARGS).current_dir(path);
        let stdout = crate::toolchain::runner::stream_command(&mut cmd, sink)
            .map_err(|e| anyhow!("nix build failed: {}", e))?;
        Ok(BuildOutput { stdout })
    }

    fn collect_artifacts(
        output: &BuildOutput,
        _path: &Path,
        artifacts_dir: &Path,
    ) -> Result<Vec<Artifact>> {
        let store_paths_str = std::str::from_utf8(&output.stdout)?;
        nix_artifacts_from_store_paths(store_paths_str, artifacts_dir)
    }

    fn provenance_fields(self, _git: &GitContext, _merkle_root: &str) -> ProvenanceFields {
        let fetch_count = self.fetches.len();

        let resolved_dependencies: Vec<ResolvedDependency> = self
            .fetches
            .into_iter()
            .map(|fetch| {
                let uri = format!(
                    "pkg:nix-fetch/{}?hash={}:{}",
                    fetch.name, fetch.output_hash_algo, fetch.output_hash
                );
                ResolvedDependency {
                    annotations: Some(Annotation {
                        drv_path: fetch.drv_path,
                        output_hash_mode: fetch.output_hash_mode,
                        url: fetch.url,
                        urls: fetch.urls,
                    }),
                    digest: Digest::Sha256 {
                        sha256: fetch.output_hash,
                    },
                    name: fetch.name,
                    uri,
                }
            })
            .collect();

        // Flake inputs are always included in internalParameters for human context
        let flake_inputs: Vec<FlakeInput> = self
            .flake_deps
            .into_iter()
            .filter_map(|dep| {
                dep.nar_hash.map(|nar_hash| FlakeInput {
                    name: dep.name,
                    nar_hash,
                })
            })
            .collect();

        // Evaluation metadata only present in deep mode
        let evaluation = Evaluation {
            derivation_count: serde_json::Number::from(self.derivation_count),
            fetch_count: serde_json::Number::from(fetch_count),
        };

        ProvenanceFields {
            build_type: crate::toolchain::BUILD_TYPE.to_string(),
            external_build_command: Self::build_command_display(),
            internal_parameters: InternalParameters {
                evaluation: Some(evaluation),
                flake_inputs: if flake_inputs.is_empty() {
                    None
                } else {
                    Some(flake_inputs)
                },
                lockfile_hash: Digest::Sha256 {
                    sha256: self.lockfile_hash,
                },
                toolchain: Toolchain::NixToolchain {
                    nix: ToolchainVersion {
                        version: self.nix_version,
                        digest: Digest::Sha256 {
                            sha256: self.nix_hash,
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
            resolved_dependencies,
        }
    }
}

fn parse_flake_lock(bytes: &[u8]) -> Result<Vec<FlakeDep>> {
    let data: Value = serde_json::from_slice(bytes)?;
    let Some(nodes) = data.get("nodes").and_then(|n| n.as_object()) else {
        return Ok(vec![]);
    };
    let Some(root_inputs) = nodes
        .get("root")
        .and_then(|r| r.get("inputs"))
        .and_then(|i| i.as_object())
    else {
        return Ok(vec![]);
    };

    let mut deps = Vec::new();
    for (input_name, input_ref) in root_inputs {
        // input_ref is a string key or an object with an "id" field
        let node_key = if let Some(s) = input_ref.as_str() {
            s.to_string()
        } else if let Some(id) = input_ref.get("id").and_then(|v| v.as_str()) {
            id.to_string()
        } else {
            continue;
        };

        let Some(locked) = nodes.get(&node_key).and_then(|n| n.get("locked")) else {
            continue;
        };

        let nar_hash = locked
            .get("narHash")
            .and_then(|v| v.as_str())
            .map(String::from);

        deps.push(FlakeDep {
            name: input_name.clone(),
            nar_hash,
        });
    }

    deps.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(deps)
}

fn evaluate_derivation_graph(path: &Path) -> Result<Value> {
    let output = Command::new("nix")
        .args([
            "derivation",
            "show",
            "--recursive",
            "--extra-experimental-features",
            "flakes",
            "--extra-experimental-features",
            "nix-command",
        ])
        .current_dir(path)
        .output()
        .context("nix not found")?;
    if !output.status.success() {
        return Err(anyhow!(
            "nix derivation show failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn extract_fixed_output_hashes(graph: &Value) -> Vec<FetchEntry> {
    // New nix format nests derivations under a "derivations" key; old format uses top-level
    let derivations = if let Some(inner) = graph.get("derivations").and_then(|d| d.as_object()) {
        inner
    } else if let Some(obj) = graph.as_object() {
        obj
    } else {
        return vec![];
    };

    let mut fetches = Vec::new();
    for (drv_path, drv_data) in derivations {
        let Some(drv_obj) = drv_data.as_object() else {
            continue;
        };
        let env = drv_obj.get("env").and_then(|e| e.as_object());
        let outputs = drv_obj.get("outputs").and_then(|o| o.as_object());

        let mut output_hash: Option<String> = None;
        let mut hash_algo = "sha256".to_string();
        let mut hash_mode: Option<String> = None;

        if let Some(outputs) = outputs {
            'outer: for (_, out_spec) in outputs {
                if let Some(hash_str) = out_spec.get("hash").and_then(|h| h.as_str()) {
                    if let Some((algo, hash)) = hash_str.split_once('-') {
                        hash_algo = algo.to_string();
                        output_hash = Some(hash.to_string());
                    } else {
                        output_hash = Some(hash_str.to_string());
                    }
                    hash_mode = out_spec
                        .get("method")
                        .and_then(|m| m.as_str())
                        .map(String::from);
                    break 'outer;
                }
            }
        }

        let Some(output_hash) = output_hash else {
            continue;
        };

        let name = drv_obj
            .get("name")
            .or_else(|| env.and_then(|e| e.get("name")))
            .and_then(|n| n.as_str())
            .unwrap_or("unknown")
            .to_string();

        let url = env
            .and_then(|e| e.get("url"))
            .and_then(|u| u.as_str())
            .map(String::from);
        let urls = env.and_then(|e| e.get("urls")).map(|u| {
            if let Some(arr) = u.as_array() {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            } else {
                u.as_str().unwrap_or("").to_string()
            }
        });

        fetches.push(FetchEntry {
            name,
            drv_path: drv_path.clone(),
            output_hash,
            output_hash_algo: hash_algo,
            output_hash_mode: hash_mode,
            url,
            urls,
        });
    }

    fetches.sort_by(|a, b| a.name.cmp(&b.name));
    fetches
}

fn nix_artifacts_from_store_paths(
    store_paths_str: &str,
    artifacts_dir: &Path,
) -> Result<Vec<Artifact>> {
    let mut artifacts = Vec::new();

    for line in store_paths_str.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let bin_dir = PathBuf::from(line).join("bin");
        if !bin_dir.is_dir() {
            continue;
        }

        for entry in fs_err::read_dir(&bin_dir)? {
            let entry = entry?;
            let item = entry.path();
            if !item.is_file() {
                continue;
            }
            if fs_err::metadata(&item)?.permissions().mode() & 0o111 == 0 {
                continue;
            }

            let name = item.file_name().unwrap().to_string_lossy().into_owned();
            let dest = artifacts_dir.join(&name);

            // Remove any existing file first — nix store copies may be read-only
            if dest.exists() {
                let mut perms = fs_err::metadata(&dest)?.permissions();
                perms.set_mode(0o644);
                fs_err::set_permissions(&dest, perms)?;
                fs_err::remove_file(&dest)?;
            }

            fs_err::copy(&item, &dest)?;
            let checksum = hex::encode(Sha256::digest(fs_err::read(&dest)?));
            artifacts.push(Artifact {
                name,
                path: dest,
                checksum,
            });
        }
    }

    Ok(artifacts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const FLAKE_LOCK_FIXTURE: &[u8] = br#"{
      "nodes": {
        "root": {
          "inputs": {
            "nixpkgs": "nixpkgs",
            "flake-utils": "flake-utils"
          }
        },
        "nixpkgs": {
          "locked": {
            "narHash": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
          }
        },
        "flake-utils": {
          "locked": {
            "narHash": "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
          }
        }
      },
      "root": "root",
      "version": 7
    }"#;

    const NIX_DRV: &[u8] = br#"{
      "derivations": {
        "/nix/store/aaa-source.drv": {
          "name": "source",
          "outputs": {
            "out": {
              "hash": "sha256-c291cmNlaGFzaHNvdXJjZWhhc2hzb3VyY2VoYXNoCg==",
              "method": "recursive"
            }
          },
          "env": {
            "name": "source",
            "urls": [
              "https://example.com/source.tar.gz",
              "https://mirror.example.com/source.tar.gz"
            ]
          }
        },
        "/nix/store/bbb-other-fetch.drv": {
          "name": "other-fetch",
          "outputs": {
            "out": {
              "hash": "sha256-b3RoZXJoYXNob3RoZXJoYXNob3RoZXJoYXNob3RoZXI=",
              "method": "flat"
            }
          },
          "env": {
            "name": "other-fetch",
            "url": "https://example.com/other.patch"
          }
        },
        "/nix/store/ccc-non-fixed.drv": {
          "name": "non-fixed-output",
          "outputs": {
            "out": {
              "path": "/nix/store/ddd-non-fixed"
            }
          },
          "env": {
            "name": "non-fixed-output"
          }
        }
      }
    }"#;

    // --- parse_flake_lock ---

    #[test]
    fn parse_flake_lock_happy_path() {
        let deps = parse_flake_lock(FLAKE_LOCK_FIXTURE).unwrap();
        assert_eq!(deps.len(), 2);
        // Sorted by name
        assert_eq!(deps[0].name, "flake-utils");
        assert_eq!(deps[1].name, "nixpkgs");
        // Both should have nar_hash
        assert!(deps[0].nar_hash.is_some());
        assert!(deps[1].nar_hash.is_some());
    }

    #[test]
    fn parse_flake_lock_empty_nodes() {
        let json = br#"{"nodes": {}}"#;
        let deps = parse_flake_lock(json).unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn parse_flake_lock_missing_nodes_key() {
        let json = br#"{"version": 7}"#;
        let deps = parse_flake_lock(json).unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn parse_flake_lock_root_no_inputs() {
        let json = br#"{"nodes": {"root": {}}, "root": "root", "version": 7}"#;
        let deps = parse_flake_lock(json).unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn parse_flake_lock_invalid_json() {
        assert!(parse_flake_lock(b"not json").is_err());
    }

    #[test]
    fn parse_flake_lock_sorted_by_name() {
        let deps = parse_flake_lock(FLAKE_LOCK_FIXTURE).unwrap();
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }

    // --- extract_fixed_output_hashes ---

    #[test]
    fn extract_fod_new_format() {
        let graph: Value = serde_json::from_slice(NIX_DRV).unwrap();
        let fetches = extract_fixed_output_hashes(&graph);
        // Fixture has 2 fixed-output derivations (source, other-fetch) and 1 non-fixed
        assert_eq!(fetches.len(), 2);
        // Sorted by name
        assert_eq!(fetches[0].name, "other-fetch");
        assert_eq!(fetches[1].name, "source");
        // Hash algo split from "sha256-<base64>"
        assert_eq!(fetches[0].output_hash_algo, "sha256");
        assert_eq!(
            fetches[0].output_hash,
            "b3RoZXJoYXNob3RoZXJoYXNob3RoZXJoYXNob3RoZXI="
        );
        // Method comes from outputs.<name>.method
        assert_eq!(fetches[0].output_hash_mode.as_deref(), Some("flat"));
        assert_eq!(fetches[1].output_hash_mode.as_deref(), Some("recursive"));
        // URL (single, string form) from env.url
        assert_eq!(
            fetches[0].url.as_deref(),
            Some("https://example.com/other.patch")
        );
        assert!(fetches[0].urls.is_none());
        // URLs (array form) from env.urls, joined by comma
        assert!(fetches[1].url.is_none());
        assert_eq!(
            fetches[1].urls.as_deref(),
            Some("https://example.com/source.tar.gz,https://mirror.example.com/source.tar.gz")
        );
    }

    #[test]
    fn extract_fod_non_fixed_excluded() {
        let graph: Value = serde_json::from_slice(NIX_DRV).unwrap();
        let fetches = extract_fixed_output_hashes(&graph);
        // Fixture has 3 derivations; only the 2 with hashes should appear.
        assert_eq!(fetches.len(), 2);
        assert!(
            fetches.iter().all(|f| f.name != "non-fixed-output"),
            "non-fixed-output derivations should be excluded"
        );
    }

    #[test]
    fn extract_fod_sorted_by_name() {
        let graph: Value = serde_json::from_slice(NIX_DRV).unwrap();
        let fetches = extract_fixed_output_hashes(&graph);
        let names: Vec<&str> = fetches.iter().map(|f| f.name.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }

    // --- nix_artifacts_from_store_paths ---

    fn make_executable(path: &std::path::Path) {
        let mut perms = fs_err::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        fs_err::set_permissions(path, perms).unwrap();
    }

    #[test]
    fn nix_artifacts_happy_path() {
        let tmp = TempDir::new().unwrap();
        let store_path = tmp.path().join("store-abc");
        let bin_dir = store_path.join("bin");
        fs_err::create_dir_all(&bin_dir).unwrap();
        fs_err::write(bin_dir.join("mybin"), b"binary content").unwrap();
        make_executable(&bin_dir.join("mybin"));

        let artifacts_dir = tmp.path().join("artifacts");
        fs_err::create_dir_all(&artifacts_dir).unwrap();

        let artifacts =
            nix_artifacts_from_store_paths(store_path.to_str().unwrap(), &artifacts_dir).unwrap();

        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].name, "mybin");
        assert!(artifacts_dir.join("mybin").exists());
        // Verify checksum
        let expected = hex::encode(sha2::Sha256::digest(b"binary content"));
        assert_eq!(artifacts[0].checksum, expected);
    }

    #[test]
    fn nix_artifacts_non_executable_skipped() {
        let tmp = TempDir::new().unwrap();
        let store_path = tmp.path().join("store-abc");
        let bin_dir = store_path.join("bin");
        fs_err::create_dir_all(&bin_dir).unwrap();
        fs_err::write(bin_dir.join("noexec"), b"data").unwrap();
        // Don't make it executable

        let artifacts_dir = tmp.path().join("artifacts");
        fs_err::create_dir_all(&artifacts_dir).unwrap();

        let artifacts =
            nix_artifacts_from_store_paths(store_path.to_str().unwrap(), &artifacts_dir).unwrap();
        assert!(artifacts.is_empty());
    }

    #[test]
    fn nix_artifacts_no_bin_dir() {
        let tmp = TempDir::new().unwrap();
        let store_path = tmp.path().join("store-abc");
        fs_err::create_dir_all(&store_path).unwrap();
        // No bin/ directory

        let artifacts_dir = tmp.path().join("artifacts");
        fs_err::create_dir_all(&artifacts_dir).unwrap();

        let artifacts =
            nix_artifacts_from_store_paths(store_path.to_str().unwrap(), &artifacts_dir).unwrap();
        assert!(artifacts.is_empty());
    }

    #[test]
    fn nix_artifacts_multiple_store_paths() {
        let tmp = TempDir::new().unwrap();

        let store1 = tmp.path().join("store-1");
        let bin1 = store1.join("bin");
        fs_err::create_dir_all(&bin1).unwrap();
        fs_err::write(bin1.join("bin1"), b"content1").unwrap();
        make_executable(&bin1.join("bin1"));

        let store2 = tmp.path().join("store-2");
        let bin2 = store2.join("bin");
        fs_err::create_dir_all(&bin2).unwrap();
        fs_err::write(bin2.join("bin2"), b"content2").unwrap();
        make_executable(&bin2.join("bin2"));

        let artifacts_dir = tmp.path().join("artifacts");
        fs_err::create_dir_all(&artifacts_dir).unwrap();

        let input = format!("{}\n{}", store1.display(), store2.display());
        let artifacts = nix_artifacts_from_store_paths(&input, &artifacts_dir).unwrap();
        assert_eq!(artifacts.len(), 2);
    }

    #[test]
    fn nix_artifacts_empty_input() {
        let tmp = TempDir::new().unwrap();
        let artifacts_dir = tmp.path().join("artifacts");
        fs_err::create_dir_all(&artifacts_dir).unwrap();

        let artifacts = nix_artifacts_from_store_paths("", &artifacts_dir).unwrap();
        assert!(artifacts.is_empty());
    }

    #[test]
    fn nix_artifacts_overwrite_readonly_existing() {
        let tmp = TempDir::new().unwrap();
        let store_path = tmp.path().join("store-abc");
        let bin_dir = store_path.join("bin");
        fs_err::create_dir_all(&bin_dir).unwrap();
        fs_err::write(bin_dir.join("mybin"), b"new content").unwrap();
        make_executable(&bin_dir.join("mybin"));

        let artifacts_dir = tmp.path().join("artifacts");
        fs_err::create_dir_all(&artifacts_dir).unwrap();
        // Pre-create a read-only file at the destination
        let dest = artifacts_dir.join("mybin");
        fs_err::write(&dest, b"old content").unwrap();
        let mut perms = fs_err::metadata(&dest).unwrap().permissions();
        perms.set_mode(0o444);
        fs_err::set_permissions(&dest, perms).unwrap();

        let artifacts =
            nix_artifacts_from_store_paths(store_path.to_str().unwrap(), &artifacts_dir).unwrap();
        assert_eq!(artifacts.len(), 1);
        // Checksum should be of new content
        let expected = hex::encode(sha2::Sha256::digest(b"new content"));
        assert_eq!(artifacts[0].checksum, expected);
    }
}
