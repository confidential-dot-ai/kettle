use anyhow::Result;
use fs_err::DirEntry;
use serde::{Deserialize, Serialize};
use serde_json::Number;
use sha2::{Digest as _, Sha256};
use std::fmt::Display;

use crate::commands::verify::Verification;

#[derive(Serialize, Deserialize)]
pub struct Provenance {
    pub _type: String,
    pub predicate: Predicate,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub subject: Vec<Subject>,
}

impl Provenance {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self).expect("could not generate JSON")
    }

    pub fn checksum(&self) -> Vec<u8> {
        Sha256::digest(self.to_json()).to_vec()
    }

    pub fn toolchain(&self) -> &Toolchain {
        &self
            .predicate
            .build_definition
            .internal_parameters
            .toolchain
    }

    pub fn build_id(&self) -> &String {
        &self.predicate.run_details.metadata.invocation_id
    }

    pub fn timestamp(&self) -> &String {
        &self.predicate.run_details.metadata.started_on
    }

    pub fn git_commit(&self) -> &String {
        &self
            .predicate
            .build_definition
            .external_parameters
            .source
            .digest
            .git_commit
    }

    pub fn verify_predicate(&self) -> Verification {
        let _type = "https://in-toto.io/Statement/v1";
        let predicate = "https://slsa.dev/provenance/v1";
        if self.predicate_type == predicate && self._type == _type {
            Verification::success("Provenance is valid SLSA v1.2")
        } else {
            Verification::failure(
                "Provenance not valid SLSA v1.2",
                &format!(
                    "Expected _type {} and predicateType {:?}\nActual _type {:?} and predicateType   {:?}",
                    _type, predicate, &self._type, &self.predicate_type
                ),
            )
        }
    }

    pub fn verify_artifacts(&self, artifacts: &[DirEntry]) -> Result<Vec<Verification>> {
        artifacts
            .iter()
            .map(|entry| {
                let name = entry.file_name().to_string_lossy().into_owned();
                let checksum = Sha256::digest(fs_err::read(entry.path())?);
                let subject = self.subject.iter().find(|s| s.name == name);
                if let Some(subject) = subject {
                    if hex::encode(checksum) == subject.digest.value() {
                        Ok(Verification::success(&format!(
                            "Checksum match for binary `{}`",
                            name
                        )))
                    } else {
                        Ok(Verification::failure(
                            "Checksum mismatch for `{}`!",
                            &format!(
                                "Provenance did not contain checksum for binary named {:?}",
                                name
                            ),
                        ))
                    }
                } else {
                    Ok(Verification::failure(
                        &format!("Checksum missing for `{}`!", name),
                        &format!(
                            "Provenance did not contain checksum for binary named {:?}",
                            name
                        ),
                    ))
                }
            })
            .collect()
    }
}

#[derive(Serialize, Deserialize)]
pub struct Subject {
    pub(crate) digest: Digest,
    pub(crate) name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum Digest {
    Sha256 {
        sha256: String,
    },
    Sha512 {
        sha512: String,
    },
    GitCommit {
        #[serde(rename = "gitCommit")]
        git_commit: String,
    },
}

impl Digest {
    pub(crate) fn value(&self) -> &str {
        match self {
            Self::Sha256 { sha256 } => sha256,
            Self::Sha512 { sha512 } => sha512,
            Self::GitCommit { git_commit } => git_commit,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Predicate {
    pub(crate) build_definition: BuildDefiniton,
    pub(crate) run_details: RunDetails,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BuildDefiniton {
    pub(crate) build_type: String,
    pub(crate) external_parameters: ExternalParameters,
    pub(crate) internal_parameters: InternalParameters,
    pub(crate) resolved_dependencies: Vec<ResolvedDependency>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ResolvedDependency {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) annotations: Option<Annotation>,
    pub(crate) digest: Digest,
    pub(crate) name: String,
    pub(crate) uri: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct RunDetails {
    pub(crate) builder: Builder,
    pub(crate) byproducts: Vec<Byproduct>,
    pub(crate) metadata: Metadata,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExternalParameters {
    pub(crate) build_command: String,
    pub(crate) source: Source,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Source {
    pub(crate) digest: SourceDigest,
    pub(crate) uri: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SourceDigest {
    pub(crate) git_commit: String,
    pub(crate) git_tree: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InternalParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) evaluation: Option<Evaluation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) flake_inputs: Option<Vec<FlakeInput>>,
    pub(crate) lockfile_hash: Digest,
    pub(crate) toolchain: Toolchain,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Builder {
    pub(crate) id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Metadata {
    pub(crate) invocation_id: String,
    pub(crate) started_on: String,
    pub(crate) finished_on: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Byproduct {
    pub(crate) digest: Digest,
    pub(crate) name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Toolchain {
    NixToolchain {
        nix: ToolchainVersion,
        kettle: ToolchainVersion,
    },
    RustToolchain {
        cargo: ToolchainVersion,
        rustc: ToolchainVersion,
        kettle: ToolchainVersion,
    },
    PnpmToolchain {
        pnpm: ToolchainVersion,
        node: ToolchainVersion,
        kettle: ToolchainVersion,
    },
}

impl Display for Toolchain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Toolchain::NixToolchain { kettle: _, nix } => write!(f, "{}", nix.version),
            Toolchain::RustToolchain {
                kettle: _,
                cargo: _,
                rustc,
            } => write!(f, "{}", rustc.version),
            Toolchain::PnpmToolchain {
                kettle: _,
                node: _,
                pnpm,
            } => write!(f, "{}", pnpm.version),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolchainVersion {
    pub(crate) digest: Digest,
    pub(crate) version: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Annotation {
    pub(crate) drv_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) output_hash_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) urls: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Evaluation {
    pub(crate) derivation_count: Number,
    pub(crate) fetch_count: Number,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FlakeInput {
    pub(crate) name: String,
    pub(crate) nar_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::{assert_eq, assert_ne};
    use tempfile::TempDir;

    const CARGO_FIXTURE: &[u8] = include_bytes!("../tests/fixtures/ripgrep/provenance.json");
    const NIX_FIXTURE: &[u8] = include_bytes!("../tests/fixtures/alejandra/provenance.json");
    const PNPM_FIXTURE: &[u8] = include_bytes!("../tests/fixtures/openclaw/provenance.json");

    // --- Provenance::from_json ---

    #[test]
    fn from_json_happy_path_cargo() {
        let p = Provenance::from_json(CARGO_FIXTURE).unwrap();
        assert_eq!(p._type, "https://in-toto.io/Statement/v1");
        assert_eq!(p.predicate_type, "https://slsa.dev/provenance/v1");
        assert_eq!(
            p.predicate.build_definition.build_type,
            "https://lunal.dev/kettle/cargo@v1"
        );
        assert_eq!(
            p.predicate
                .build_definition
                .external_parameters
                .build_command,
            "cargo build"
        );
        assert_eq!(p.subject.len(), 1);
        assert_eq!(p.subject[0].name, "rg");
        // Toolchain should be RustToolchain
        match &p.predicate.build_definition.internal_parameters.toolchain {
            Toolchain::RustToolchain {
                cargo,
                rustc,
                kettle: _,
            } => {
                assert!(rustc.version.starts_with("rustc"));
                assert!(cargo.version.starts_with("cargo"));
            }
            _ => panic!("expected RustToolchain"),
        }
    }

    #[test]
    fn from_json_happy_path_nix() {
        let p = Provenance::from_json(NIX_FIXTURE).unwrap();
        assert_eq!(p._type, "https://in-toto.io/Statement/v1");
        assert_eq!(p.predicate_type, "https://slsa.dev/provenance/v1");
        assert_eq!(
            p.predicate.build_definition.build_type,
            "https://lunal.dev/kettle/nix@v1"
        );
        match &p.predicate.build_definition.internal_parameters.toolchain {
            Toolchain::NixToolchain { nix, kettle: _ } => {
                assert!(nix.version.contains("nix"));
            }
            _ => panic!("expected NixToolchain"),
        }
        assert!(
            p.predicate
                .build_definition
                .internal_parameters
                .evaluation
                .is_some()
        );
        assert!(
            p.predicate
                .build_definition
                .internal_parameters
                .flake_inputs
                .is_some()
        );
    }

    #[test]
    fn from_json_invalid_json() {
        assert!(Provenance::from_json(b"not json at all {{{").is_err());
    }

    #[test]
    fn from_json_missing_required_field() {
        // Missing predicateType
        let json = r#"{"_type":"x","predicate":{},"subject":[]}"#;
        assert!(Provenance::from_json(json.as_bytes()).is_err());
    }

    #[test]
    fn from_json_unknown_extra_fields_ignored() {
        // Add an extra field to the root — serde should ignore it
        let mut val: serde_json::Value = serde_json::from_slice(CARGO_FIXTURE).unwrap();
        val["extraUnknownField"] = serde_json::json!("should be ignored");
        let bytes = serde_json::to_vec(&val).unwrap();
        let p = Provenance::from_json(&bytes).unwrap();
        assert_eq!(p._type, "https://in-toto.io/Statement/v1");
    }

    #[test]
    fn serde_rename_predicate_type_roundtrip() {
        let p = Provenance::from_json(CARGO_FIXTURE).unwrap();
        let json = p.to_json();
        // Must contain "predicateType" as a key, not "predicate_type"
        assert!(json.contains("\"predicateType\""));
        assert!(!json.contains("\"predicate_type\""));
    }

    // --- Provenance::to_json / round-trip ---

    #[test]
    fn roundtrip_cargo() {
        let p1 = Provenance::from_json(CARGO_FIXTURE).unwrap();
        let json = p1.to_json();
        let p2 = Provenance::from_json(json.as_bytes()).unwrap();
        assert_eq!(p1.to_json(), p2.to_json());
    }

    #[test]
    fn roundtrip_nix() {
        let p1 = Provenance::from_json(NIX_FIXTURE).unwrap();
        let json = p1.to_json();
        let p2 = Provenance::from_json(json.as_bytes()).unwrap();
        assert_eq!(p1.to_json(), p2.to_json());
    }

    #[test]
    fn to_json_no_predicate_type_key() {
        let p = Provenance::from_json(CARGO_FIXTURE).unwrap();
        let json = p.to_json();
        assert!(!json.contains("\"predicate_type\""));
        assert!(json.contains("\"predicateType\""));
    }

    #[test]
    fn optional_fields_absent_when_none() {
        let p = Provenance::from_json(CARGO_FIXTURE).unwrap();
        let json = p.to_json();
        // Cargo provenance has no evaluation or flake_inputs
        assert!(!json.contains("\"evaluation\""));
        assert!(!json.contains("\"flakeInputs\""));
    }

    // --- Provenance::checksum ---

    #[test]
    fn checksum_deterministic() {
        let p = Provenance::from_json(CARGO_FIXTURE).unwrap();
        let c1 = p.checksum();
        let c2 = p.checksum();
        assert_eq!(c1, c2);
    }

    #[test]
    fn checksum_normalized_whitespace() {
        // Pretty-printed and compact should produce same checksum after round-trip
        let p_compact = Provenance::from_json(CARGO_FIXTURE).unwrap();
        let compact_json = serde_json::to_string(&p_compact).unwrap();
        let p_from_compact = Provenance::from_json(compact_json.as_bytes()).unwrap();
        let pretty_json = serde_json::to_string_pretty(&p_compact).unwrap();
        let p_from_pretty = Provenance::from_json(pretty_json.as_bytes()).unwrap();
        assert_eq!(p_from_compact.checksum(), p_from_pretty.checksum());
    }

    #[test]
    fn checksum_changes_on_mutation() {
        let p1 = Provenance::from_json(CARGO_FIXTURE).unwrap();
        let c1 = p1.checksum();
        // Mutate git_commit
        let mut val: serde_json::Value = serde_json::from_slice(CARGO_FIXTURE).unwrap();
        val["predicate"]["buildDefinition"]["externalParameters"]["source"]["digest"]["gitCommit"] =
            serde_json::json!("0000000000000000000000000000000000000000");
        let bytes = serde_json::to_vec(&val).unwrap();
        let p2 = Provenance::from_json(&bytes).unwrap();
        let c2 = p2.checksum();
        assert_ne!(c1, c2);
    }

    #[test]
    fn checksum_is_32_bytes() {
        let p = Provenance::from_json(CARGO_FIXTURE).unwrap();
        assert_eq!(p.checksum().len(), 32);
    }

    // --- Provenance::verify_predicate ---

    #[test]
    fn verify_predicate_success() {
        let p = Provenance::from_json(CARGO_FIXTURE).unwrap();
        match p.verify_predicate() {
            Verification::Success { .. } => {}
            Verification::Failure { message, .. } => panic!("expected success, got: {message}"),
        }
    }

    #[test]
    fn verify_predicate_wrong_type() {
        let mut val: serde_json::Value = serde_json::from_slice(CARGO_FIXTURE).unwrap();
        val["_type"] = serde_json::json!("https://example.com/bad");
        let bytes = serde_json::to_vec(&val).unwrap();
        let p = Provenance::from_json(&bytes).unwrap();
        match p.verify_predicate() {
            Verification::Failure { message, .. } => {
                assert!(message.contains("Provenance not valid SLSA v1.2"));
            }
            Verification::Success { .. } => panic!("expected failure"),
        }
    }

    #[test]
    fn verify_predicate_wrong_predicate_type() {
        let mut val: serde_json::Value = serde_json::from_slice(CARGO_FIXTURE).unwrap();
        val["predicateType"] = serde_json::json!("https://example.com/bad");
        let bytes = serde_json::to_vec(&val).unwrap();
        let p = Provenance::from_json(&bytes).unwrap();
        match p.verify_predicate() {
            Verification::Failure { .. } => {}
            Verification::Success { .. } => panic!("expected failure"),
        }
    }

    #[test]
    fn verify_predicate_both_wrong() {
        let mut val: serde_json::Value = serde_json::from_slice(CARGO_FIXTURE).unwrap();
        val["_type"] = serde_json::json!("bad");
        val["predicateType"] = serde_json::json!("bad");
        let bytes = serde_json::to_vec(&val).unwrap();
        let p = Provenance::from_json(&bytes).unwrap();
        match p.verify_predicate() {
            Verification::Failure { .. } => {}
            Verification::Success { .. } => panic!("expected failure"),
        }
    }

    // --- Provenance::verify_artifacts ---

    fn write_file_to_dir(dir: &std::path::Path, name: &str, content: &[u8]) {
        fs_err::write(dir.join(name), content).unwrap();
    }

    #[test]
    fn verify_artifacts_checksum_match() {
        let tmp = TempDir::new().unwrap();
        let content = b"hello binary";
        let checksum = hex::encode(Sha256::digest(content));
        write_file_to_dir(tmp.path(), "rg", content);

        let p = Provenance {
            _type: String::new(),
            predicate_type: String::new(),
            predicate: Predicate {
                build_definition: BuildDefiniton {
                    build_type: String::new(),
                    external_parameters: ExternalParameters {
                        build_command: String::new(),
                        source: Source {
                            digest: SourceDigest {
                                git_commit: String::new(),
                                git_tree: String::new(),
                            },
                            uri: String::new(),
                        },
                    },
                    internal_parameters: InternalParameters {
                        evaluation: None,
                        flake_inputs: None,
                        lockfile_hash: Digest::Sha256 {
                            sha256: String::new(),
                        },
                        toolchain: Toolchain::RustToolchain {
                            rustc: ToolchainVersion {
                                version: String::new(),
                                digest: Digest::Sha256 {
                                    sha256: String::new(),
                                },
                            },
                            cargo: ToolchainVersion {
                                version: String::new(),
                                digest: Digest::Sha256 {
                                    sha256: String::new(),
                                },
                            },
                            kettle: ToolchainVersion {
                                version: String::new(),
                                digest: Digest::Sha256 {
                                    sha256: String::new(),
                                },
                            },
                        },
                    },
                    resolved_dependencies: vec![],
                },
                run_details: RunDetails {
                    builder: Builder { id: String::new() },
                    byproducts: vec![],
                    metadata: Metadata {
                        invocation_id: String::new(),
                        started_on: String::new(),
                        finished_on: None,
                    },
                },
            },
            subject: vec![Subject {
                name: "rg".to_string(),
                digest: Digest::Sha256 { sha256: checksum },
            }],
        };

        let entries: Vec<fs_err::DirEntry> = fs_err::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        let results = p.verify_artifacts(&entries).unwrap();
        assert_eq!(results.len(), 1);
        match &results[0] {
            Verification::Success { message } => {
                assert!(message.contains("rg"));
            }
            Verification::Failure { message, .. } => panic!("expected success, got: {message}"),
        }
    }

    #[test]
    fn verify_artifacts_checksum_mismatch() {
        let tmp = TempDir::new().unwrap();
        write_file_to_dir(tmp.path(), "rg", b"hello binary");

        let p = Provenance {
            _type: String::new(),
            predicate_type: String::new(),
            predicate: Predicate {
                build_definition: BuildDefiniton {
                    build_type: String::new(),
                    external_parameters: ExternalParameters {
                        build_command: String::new(),
                        source: Source {
                            digest: SourceDigest {
                                git_commit: String::new(),
                                git_tree: String::new(),
                            },
                            uri: String::new(),
                        },
                    },
                    internal_parameters: InternalParameters {
                        evaluation: None,
                        flake_inputs: None,
                        lockfile_hash: Digest::Sha256 {
                            sha256: String::new(),
                        },
                        toolchain: Toolchain::RustToolchain {
                            rustc: ToolchainVersion {
                                version: String::new(),
                                digest: Digest::Sha256 {
                                    sha256: String::new(),
                                },
                            },
                            cargo: ToolchainVersion {
                                version: String::new(),
                                digest: Digest::Sha256 {
                                    sha256: String::new(),
                                },
                            },
                            kettle: ToolchainVersion {
                                version: String::new(),
                                digest: Digest::Sha256 {
                                    sha256: String::new(),
                                },
                            },
                        },
                    },
                    resolved_dependencies: vec![],
                },
                run_details: RunDetails {
                    builder: Builder { id: String::new() },
                    byproducts: vec![],
                    metadata: Metadata {
                        invocation_id: String::new(),
                        started_on: String::new(),
                        finished_on: None,
                    },
                },
            },
            subject: vec![Subject {
                name: "rg".to_string(),
                digest: Digest::Sha256 {
                    sha256: "0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                },
            }],
        };

        let entries: Vec<fs_err::DirEntry> = fs_err::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        let results = p.verify_artifacts(&entries).unwrap();
        assert_eq!(results.len(), 1);
        match &results[0] {
            Verification::Failure { .. } => {}
            Verification::Success { .. } => panic!("expected failure"),
        }
    }

    #[test]
    fn verify_artifacts_missing_from_subjects() {
        let tmp = TempDir::new().unwrap();
        write_file_to_dir(tmp.path(), "unknown-binary", b"data");

        let p = Provenance {
            _type: String::new(),
            predicate_type: String::new(),
            predicate: Predicate {
                build_definition: BuildDefiniton {
                    build_type: String::new(),
                    external_parameters: ExternalParameters {
                        build_command: String::new(),
                        source: Source {
                            digest: SourceDigest {
                                git_commit: String::new(),
                                git_tree: String::new(),
                            },
                            uri: String::new(),
                        },
                    },
                    internal_parameters: InternalParameters {
                        evaluation: None,
                        flake_inputs: None,
                        lockfile_hash: Digest::Sha256 {
                            sha256: String::new(),
                        },
                        toolchain: Toolchain::RustToolchain {
                            rustc: ToolchainVersion {
                                version: String::new(),
                                digest: Digest::Sha256 {
                                    sha256: String::new(),
                                },
                            },
                            cargo: ToolchainVersion {
                                version: String::new(),
                                digest: Digest::Sha256 {
                                    sha256: String::new(),
                                },
                            },
                            kettle: ToolchainVersion {
                                version: String::new(),
                                digest: Digest::Sha256 {
                                    sha256: String::new(),
                                },
                            },
                        },
                    },
                    resolved_dependencies: vec![],
                },
                run_details: RunDetails {
                    builder: Builder { id: String::new() },
                    byproducts: vec![],
                    metadata: Metadata {
                        invocation_id: String::new(),
                        started_on: String::new(),
                        finished_on: None,
                    },
                },
            },
            subject: vec![], // No subjects
        };

        let entries: Vec<fs_err::DirEntry> = fs_err::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        let results = p.verify_artifacts(&entries).unwrap();
        assert_eq!(results.len(), 1);
        match &results[0] {
            Verification::Failure { message, .. } => {
                assert!(message.contains("Checksum missing"));
            }
            Verification::Success { .. } => panic!("expected failure"),
        }
    }

    #[test]
    fn verify_artifacts_empty_slice() {
        let p = Provenance::from_json(CARGO_FIXTURE).unwrap();
        let results = p.verify_artifacts(&[]).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn verify_artifacts_multiple() {
        let tmp = TempDir::new().unwrap();
        let content_a = b"binary a";
        let checksum_a = hex::encode(Sha256::digest(content_a));
        let content_b = b"binary b";
        write_file_to_dir(tmp.path(), "a", content_a);
        write_file_to_dir(tmp.path(), "b", content_b);
        write_file_to_dir(tmp.path(), "c", b"binary c");

        let p = Provenance {
            _type: String::new(),
            predicate_type: String::new(),
            predicate: Predicate {
                build_definition: BuildDefiniton {
                    build_type: String::new(),
                    external_parameters: ExternalParameters {
                        build_command: String::new(),
                        source: Source {
                            digest: SourceDigest {
                                git_commit: String::new(),
                                git_tree: String::new(),
                            },
                            uri: String::new(),
                        },
                    },
                    internal_parameters: InternalParameters {
                        evaluation: None,
                        flake_inputs: None,
                        lockfile_hash: Digest::Sha256 {
                            sha256: String::new(),
                        },
                        toolchain: Toolchain::RustToolchain {
                            rustc: ToolchainVersion {
                                version: String::new(),
                                digest: Digest::Sha256 {
                                    sha256: String::new(),
                                },
                            },
                            cargo: ToolchainVersion {
                                version: String::new(),
                                digest: Digest::Sha256 {
                                    sha256: String::new(),
                                },
                            },
                            kettle: ToolchainVersion {
                                version: String::new(),
                                digest: Digest::Sha256 {
                                    sha256: String::new(),
                                },
                            },
                        },
                    },
                    resolved_dependencies: vec![],
                },
                run_details: RunDetails {
                    builder: Builder { id: String::new() },
                    byproducts: vec![],
                    metadata: Metadata {
                        invocation_id: String::new(),
                        started_on: String::new(),
                        finished_on: None,
                    },
                },
            },
            subject: vec![
                Subject {
                    name: "a".to_string(),
                    digest: Digest::Sha256 {
                        sha256: checksum_a, // match
                    },
                },
                Subject {
                    name: "b".to_string(),
                    digest: Digest::Sha256 {
                        sha256: "bad_checksum".to_string(), // mismatch
                    },
                },
                // "c" is not in subjects at all
            ],
        };

        let mut entries: Vec<fs_err::DirEntry> = fs_err::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.file_name());
        let results = p.verify_artifacts(&entries).unwrap();
        assert_eq!(results.len(), 3);

        // Check each result
        let mut saw_success = false;
        let mut saw_mismatch = false;
        let mut saw_missing = false;
        for r in &results {
            match r {
                Verification::Success { message } if message.contains("a") => saw_success = true,
                Verification::Failure { message, .. } if message.contains("mismatch") => {
                    saw_mismatch = true
                }
                Verification::Failure { message, .. } if message.contains("missing") => {
                    saw_missing = true
                }
                _ => {}
            }
        }
        assert!(saw_success, "expected a success for file 'a'");
        // b has a subject but wrong checksum → mismatch
        assert!(saw_mismatch, "expected a mismatch for file 'b'");
        // c has no subject → missing
        assert!(saw_missing, "expected a missing for file 'c'");
    }

    #[test]
    fn verify_artifacts_io_error_deleted_file() {
        let tmp = TempDir::new().unwrap();
        write_file_to_dir(tmp.path(), "rg", b"content");
        let entries: Vec<fs_err::DirEntry> = fs_err::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        // Delete the file after getting the DirEntry
        fs_err::remove_file(tmp.path().join("rg")).unwrap();

        let p = Provenance::from_json(CARGO_FIXTURE).unwrap();
        let result = p.verify_artifacts(&entries);
        assert!(result.is_err(), "expected Err for deleted file");
    }

    // --- Accessor methods ---

    #[test]
    fn accessor_toolchain() {
        let p = Provenance::from_json(CARGO_FIXTURE).unwrap();
        match p.toolchain() {
            Toolchain::RustToolchain { .. } => {}
            _ => panic!("expected RustToolchain"),
        }
    }

    #[test]
    fn accessor_build_id() {
        let p = Provenance::from_json(CARGO_FIXTURE).unwrap();
        assert_eq!(p.build_id(), "build-20260520-215052-17223ff8");
    }

    #[test]
    fn accessor_timestamp() {
        let p = Provenance::from_json(CARGO_FIXTURE).unwrap();
        assert_eq!(p.timestamp(), "2026-05-20T21:50:52.083557+00:00");
    }

    #[test]
    fn accessor_git_commit() {
        let p = Provenance::from_json(CARGO_FIXTURE).unwrap();
        assert_eq!(p.git_commit(), "4519153e5e461527f4bca45b042fff45c4ec6fb9");
    }

    // --- Toolchain Display ---

    #[test]
    fn toolchain_display_nix() {
        let t = Toolchain::NixToolchain {
            nix: ToolchainVersion {
                version: "nix 2.18.1".to_string(),
                digest: Digest::Sha256 {
                    sha256: String::new(),
                },
            },
            kettle: ToolchainVersion {
                version: "kettle 1.0.0".to_string(),
                digest: Digest::Sha256 {
                    sha256: String::new(),
                },
            },
        };
        assert_eq!(format!("{t}"), "nix 2.18.1");
    }

    #[test]
    fn toolchain_display_rust() {
        let t = Toolchain::RustToolchain {
            rustc: ToolchainVersion {
                version: "rustc 1.78.0".to_string(),
                digest: Digest::Sha256 {
                    sha256: String::new(),
                },
            },
            cargo: ToolchainVersion {
                version: "cargo 1.78.0".to_string(),
                digest: Digest::Sha256 {
                    sha256: String::new(),
                },
            },
            kettle: ToolchainVersion {
                version: "kettle 1.0.0".to_string(),
                digest: Digest::Sha256 {
                    sha256: String::new(),
                },
            },
        };
        assert_eq!(format!("{t}"), "rustc 1.78.0");
    }

    #[test]
    fn key_ordering_matches_when_regenerated_cargo() {
        let p = Provenance::from_json(CARGO_FIXTURE).unwrap();
        let regenerated = serde_json::to_string_pretty(&p).unwrap();
        assert_eq!(
            String::from_utf8_lossy(CARGO_FIXTURE),
            String::from_utf8_lossy(regenerated.as_bytes()),
            "regenerated provenance changed!"
        );
    }

    #[test]
    fn key_ordering_matches_when_regenerated_pnpm() {
        let p = Provenance::from_json(PNPM_FIXTURE).unwrap();
        let regenerated = serde_json::to_string_pretty(&p).unwrap();
        assert_eq!(
            String::from_utf8_lossy(PNPM_FIXTURE),
            String::from_utf8_lossy(regenerated.as_bytes()),
            "regenerated pnpm provenance changed!"
        );
    }

    #[test]
    fn digest_git_commit_serializes_as_gitcommit_key() {
        let d = Digest::GitCommit {
            git_commit: "952489ea39cbb300828af5c1268eff3387cfe4b5".to_string(),
        };
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(
            json,
            r#"{"gitCommit":"952489ea39cbb300828af5c1268eff3387cfe4b5"}"#
        );
    }

    #[test]
    fn digest_git_commit_value_returns_commit() {
        let d = Digest::GitCommit {
            git_commit: "abc123".to_string(),
        };
        assert_eq!(d.value(), "abc123");
    }

    #[test]
    fn digest_git_commit_roundtrip() {
        let original = Digest::GitCommit {
            git_commit: "952489ea39cbb300828af5c1268eff3387cfe4b5".to_string(),
        };
        let json = serde_json::to_string(&original).unwrap();
        let parsed: Digest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.value(), original.value());
        match parsed {
            Digest::GitCommit { .. } => {}
            _ => panic!("expected GitCommit variant after roundtrip"),
        }
    }
}
