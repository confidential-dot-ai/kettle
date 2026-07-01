use anyhow::{Context as _, Result, anyhow};
use rs_merkle::MerkleTree;
use sha2::{Digest as _, Sha256};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use tracing::debug;

use crate::provenance::{
    BuildDefiniton, Builder, Byproduct, Digest, ExternalParameters, Metadata, Predicate,
    Provenance, RunDetails, Source, SourceDigest, Subject,
};

use super::driver::{Artifact, BuildMetadata, GitContext, ProvenanceFields, ToolchainDriver};

/// Spawn `cmd`, pipe its stdout/stderr through `BufReader::lines`, and emit each
/// line as `Event::Build` on `sink`. Returns the captured stdout bytes (each
/// line as emitted, joined with '\n'). Stderr is emitted but not captured.
///
/// Fails if the child does not exit successfully OR if reading either pipe
/// errors mid-stream. The latter is required because callers (notably nix)
/// parse stdout for artifact discovery — silently truncating it would
/// produce incorrect provenance.
pub(crate) fn stream_command(cmd: &mut Command, sink: &crate::toolchain::EventSink) -> Result<Vec<u8>> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().context("failed to spawn child")?;
    let stdout = child.stdout.take().expect("piped");
    let stderr = child.stderr.take().expect("piped");

    let stdout_buf = Arc::new(Mutex::new(Vec::<u8>::new()));

    let sink_out = sink.clone();
    let stdout_buf_c = stdout_buf.clone();
    let stdout_thread = thread::spawn(move || -> std::io::Result<()> {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            let line = line?;
            {
                let mut buf = stdout_buf_c.lock().unwrap();
                buf.extend_from_slice(line.as_bytes());
                buf.push(b'\n');
            }
            sink_out.try_emit(crate::api::Event::Build { msg: line });
        }
        Ok(())
    });
    let sink_err = sink.clone();
    let stderr_thread = thread::spawn(move || -> std::io::Result<()> {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            let line = line?;
            sink_err.try_emit(crate::api::Event::Build { msg: line });
        }
        Ok(())
    });

    let status = child.wait().context("waiting for child")?;
    let stdout_result = stdout_thread.join()
        .map_err(|_| anyhow!("stdout reader thread panicked"))?;
    let stderr_result = stderr_thread.join()
        .map_err(|_| anyhow!("stderr reader thread panicked"))?;
    stdout_result.context("reading child stdout")?;
    stderr_result.context("reading child stderr")?;
    if !status.success() {
        return Err(anyhow!("child exited unsuccessfully (exit {:?})", status.code()));
    }
    let buf = Arc::try_unwrap(stdout_buf)
        .expect("reader threads joined; only one Arc remains")
        .into_inner()
        .unwrap_or_else(|e| e.into_inner());
    Ok(buf)
}

pub(crate) fn run<T: ToolchainDriver + std::fmt::Debug>(
    path: &PathBuf,
    sink: &crate::toolchain::EventSink,
) -> Result<()> {
    debug!("input dir: {:?}", path);

    // 1. Clean / create output dir
    let output_dir = path.join("kettle-build");
    debug!("output dir: {:?}", output_dir);
    if fs_err::exists(&output_dir)? {
        fs_err::remove_dir_all(&output_dir)?;
    }
    fs_err::create_dir_all(&output_dir)?;

    // 2. Git context (shared)
    let git = GitContext::from_dir(path)?;
    debug!("git context: {:?}", git);

    // 3. Read and hash lockfile (shared)
    let lockfile_bytes = fs_err::read(path.join(T::lockfile_filename()))?;
    let lockfile_hash = hex::encode(Sha256::digest(&lockfile_bytes));
    debug!("lockfile hash: {}", lockfile_hash);

    // 4. Toolchain-specific inputs
    let inputs = T::collect_inputs(path, &git, &lockfile_hash, &lockfile_bytes)?;
    debug!("inputs: {:?}", inputs);

    // 5. Start metadata
    let mut build_metadata = BuildMetadata::start();
    debug!("build metadata: {:?}", build_metadata);

    // 6. Run build
    let cmd_display = T::build_command_display();
    println!("Running `{}`", cmd_display);
    sink.try_emit(crate::api::Event::Build {
        msg: format!("Running `{}`", cmd_display),
    });
    let build_output = T::run_build(path, sink)?;
    sink.try_emit(crate::api::Event::Build {
        msg: "Build command finished".into(),
    });

    // 7. Collect artifacts (each impl stages into artifacts_dir itself)
    let artifacts_dir = output_dir.join("artifacts");
    fs_err::create_dir_all(&artifacts_dir)?;
    let artifacts = T::collect_artifacts(&build_output, path, &artifacts_dir)?;

    // 8. Finish metadata
    build_metadata.finish();

    // 9. Merkle root (shared)
    let merkle_root = compute_merkle_root(inputs.merkle_entries(&git, &lockfile_hash))?;

    // 10. Assemble and write provenance (shared)
    let pf = inputs.provenance_fields(&git, &merkle_root);
    let provenance = assemble_provenance(&git, &build_metadata, &artifacts, &merkle_root, pf);
    fs_err::write(
        output_dir.join("provenance.json"),
        serde_json::to_string_pretty(&provenance)?,
    )?;
    sink.try_emit(crate::api::Event::Provenance {
        msg: "Wrote provenance.json".into(),
    });

    println!(
        "Build in {:?} complete, output located in `kettle-build`",
        path
    );
    Ok(())
}

fn compute_merkle_root(entries: Vec<String>) -> Result<String> {
    let leaves: Vec<[u8; 32]> = entries
        .iter()
        .map(|e| Sha256::digest(e.as_bytes()).into())
        .collect();
    let tree = MerkleTree::<rs_merkle::algorithms::Sha256>::from_leaves(&leaves);
    let root = tree
        .root()
        .ok_or(anyhow!("Merkle tree root calculation failed!"))?;
    Ok(hex::encode(root))
}

fn assemble_provenance(
    git: &GitContext,
    metadata: &BuildMetadata,
    artifacts: &[Artifact],
    merkle_root: &str,
    pf: ProvenanceFields,
) -> Provenance {
    Provenance {
        _type: "https://in-toto.io/Statement/v1".to_string(),
        predicate_type: "https://slsa.dev/provenance/v1".to_string(),
        subject: artifacts
            .iter()
            .map(|a| Subject {
                name: a.name.clone(),
                digest: Digest::Sha256 {
                    sha256: a.checksum.clone(),
                },
            })
            .collect(),
        predicate: Predicate {
            build_definition: BuildDefiniton {
                build_type: pf.build_type,
                external_parameters: ExternalParameters {
                    build_command: pf.external_build_command,
                    source: Source {
                        digest: SourceDigest {
                            git_commit: git.commit.clone(),
                            git_tree: git.tree.clone(),
                        },
                        uri: git.source_uri.clone(),
                    },
                },
                internal_parameters: pf.internal_parameters,
                resolved_dependencies: pf.resolved_dependencies,
            },
            run_details: RunDetails {
                builder: Builder {
                    id: "https://confidential.ai/attested-builds".to_string(),
                },
                metadata: Metadata {
                    invocation_id: metadata.invocation_id.clone(),
                    started_on: metadata.started_on.clone(),
                    finished_on: metadata.finished_on.clone(),
                },
                byproducts: vec![Byproduct {
                    name: "input_merkle_root".to_string(),
                    digest: Digest::Sha256 {
                        sha256: merkle_root.to_string(),
                    },
                }],
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::{Digest, InternalParameters, Toolchain, ToolchainVersion};
    use std::path::PathBuf;

    fn make_git_context() -> GitContext {
        GitContext {
            commit: "a".repeat(40),
            tree: "b".repeat(40),
            source_uri: "https://github.com/test/repo".to_string(),
        }
    }

    fn make_build_metadata() -> BuildMetadata {
        let mut m = BuildMetadata::start();
        m.finish();
        m
    }

    fn make_provenance_fields() -> ProvenanceFields {
        ProvenanceFields {
            build_type: crate::toolchain::BUILD_TYPE.to_string(),
            external_build_command: "cargo build".to_string(),
            internal_parameters: InternalParameters {
                evaluation: None,
                flake_inputs: None,
                lockfile_hash: Digest::Sha256 {
                    sha256: "c".repeat(64),
                },
                toolchain: Toolchain::RustToolchain {
                    rustc: ToolchainVersion {
                        version: "rustc 1.78.0".to_string(),
                        digest: Digest::Sha256 {
                            sha256: "d".repeat(64),
                        },
                    },
                    cargo: ToolchainVersion {
                        version: "cargo 1.78.0".to_string(),
                        digest: Digest::Sha256 {
                            sha256: "e".repeat(64),
                        },
                    },
                    kettle: ToolchainVersion {
                        version: "kettle 1.0.0".to_string(),
                        digest: Digest::Sha256 {
                            sha256: "f".repeat(64),
                        },
                    },
                },
            },
            resolved_dependencies: vec![],
        }
    }

    // --- compute_merkle_root ---

    #[test]
    fn merkle_root_happy_path() {
        let entries = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let root = compute_merkle_root(entries).unwrap();
        assert_eq!(root.len(), 64, "should be 64-char hex string");
        assert!(root.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn merkle_root_single_leaf() {
        let entries = vec!["single".to_string()];
        let root = compute_merkle_root(entries).unwrap();
        assert_eq!(root.len(), 64);
        assert!(root.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn merkle_root_empty_entries() {
        let result = compute_merkle_root(vec![]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Merkle tree root calculation failed"),
            "error: {err}"
        );
    }

    #[test]
    fn merkle_root_deterministic() {
        let entries = vec!["a".to_string(), "b".to_string()];
        let r1 = compute_merkle_root(entries.clone()).unwrap();
        let r2 = compute_merkle_root(entries).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn merkle_root_order_sensitive() {
        let r1 = compute_merkle_root(vec!["a".to_string(), "b".to_string()]).unwrap();
        let r2 = compute_merkle_root(vec!["b".to_string(), "a".to_string()]).unwrap();
        assert_ne!(r1, r2, "different ordering should produce different roots");
    }

    // --- assemble_provenance ---

    #[test]
    fn assemble_provenance_structure() {
        let git = make_git_context();
        let metadata = make_build_metadata();
        let artifacts = vec![Artifact {
            name: "mybin".to_string(),
            path: PathBuf::from("/tmp/mybin"),
            checksum: "f".repeat(64),
        }];
        let pf = make_provenance_fields();

        let p = assemble_provenance(&git, &metadata, &artifacts, &"0".repeat(64), pf);

        assert_eq!(p._type, "https://in-toto.io/Statement/v1");
        assert_eq!(p.predicate_type, "https://slsa.dev/provenance/v1");
        assert_eq!(
            p.predicate.run_details.builder.id,
            "https://confidential.ai/attested-builds"
        );
        // Subject corresponds to artifacts
        assert_eq!(p.subject.len(), 1);
        assert_eq!(p.subject[0].name, "mybin");
        assert_eq!(p.subject[0].digest.value(), "f".repeat(64));
        // Byproducts
        assert_eq!(p.predicate.run_details.byproducts.len(), 1);
        assert_eq!(
            p.predicate.run_details.byproducts[0].name,
            "input_merkle_root"
        );
    }

    #[test]
    fn assemble_provenance_preserves_resolved_deps_order() {
        let git = make_git_context();
        let metadata = make_build_metadata();
        let mut pf = make_provenance_fields();
        pf.resolved_dependencies = vec![
            crate::provenance::ResolvedDependency {
                annotations: None,
                digest: Digest::Sha256 {
                    sha256: "1".repeat(64),
                },
                name: "zzz".to_string(),
                uri: "pkg:cargo/zzz@1.0".to_string(),
            },
            crate::provenance::ResolvedDependency {
                annotations: None,
                digest: Digest::Sha256 {
                    sha256: "2".repeat(64),
                },
                name: "aaa".to_string(),
                uri: "pkg:cargo/aaa@1.0".to_string(),
            },
        ];

        let p = assemble_provenance(&git, &metadata, &[], &"0".repeat(64), pf);
        // Order should be preserved: zzz first, aaa second (not re-sorted)
        assert_eq!(
            p.predicate.build_definition.resolved_dependencies[0].name,
            "zzz"
        );
        assert_eq!(
            p.predicate.build_definition.resolved_dependencies[1].name,
            "aaa"
        );
    }
}
