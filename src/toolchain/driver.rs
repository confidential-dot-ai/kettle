use anyhow::{Context as _, Result, anyhow};
use chrono::DateTime;
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::debug;

use crate::provenance::{InternalParameters, ResolvedDependency};

shadow_rs::shadow!(binary);

// --- Moved from toolchain.rs ---

#[derive(Debug)]
pub(crate) struct BuildMetadata {
    pub(crate) invocation_id: String,
    pub(crate) started_on: String,
    pub(crate) finished_on: Option<String>,
}

impl BuildMetadata {
    pub(crate) fn start() -> Self {
        let now = chrono::Utc::now();
        let id_suffix = &hex::encode(uuid::Uuid::new_v4())[..8];
        let invocation_id = format!("build-{}-{}", now.format("%Y%m%d-%H%M%S"), id_suffix);
        Self {
            invocation_id,
            started_on: Self::ts(now),
            finished_on: None,
        }
    }

    fn ts(now: DateTime<chrono::Utc>) -> String {
        now.to_rfc3339_opts(chrono::SecondsFormat::Micros, false)
    }

    pub(crate) fn finish(&mut self) {
        self.finished_on = Some(Self::ts(chrono::Utc::now()));
    }
}

pub(crate) struct Artifact {
    pub(crate) name: String,
    pub(crate) path: PathBuf,
    pub(crate) checksum: String,
}

impl Artifact {
    pub(crate) fn in_dir(path: &PathBuf) -> Result<Vec<Artifact>> {
        let mut artifacts = Vec::new();
        for entry in fs_err::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            let is_dotfile = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .starts_with(".");

            if !path.is_file() || is_dotfile {
                continue;
            }
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext.is_empty() || ext == "exe" {
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                let checksum = hex::encode(Sha256::digest(fs_err::read(&path)?));
                artifacts.push(Artifact {
                    name,
                    path,
                    checksum,
                });
            }
        }
        Ok(artifacts)
    }
}

pub(crate) fn git_cmd(path: &PathBuf, args: &[&str]) -> Result<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(args)
        .output()
        .context("git not found")?;
    if !out.status.success() {
        return Err(anyhow!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}

#[derive(Debug)]
pub(crate) struct GitContext {
    pub(crate) commit: String,
    pub(crate) tree: String,
    pub(crate) source_uri: String,
}

impl GitContext {
    pub(crate) fn from_dir(path: &PathBuf) -> Result<Self> {
        let source_uri = git_cmd(path, &["remote", "get-url", "origin"]).unwrap_or_default();
        let commit = git_cmd(path, &["rev-parse", "HEAD"])?;
        let tree = git_cmd(path, &["rev-parse", "HEAD^{tree}"])?;
        Ok(Self {
            commit,
            tree,
            source_uri,
        })
    }
}

pub(crate) struct BuildOutput {
    pub(crate) stdout: Vec<u8>,
}

pub(crate) struct ProvenanceFields {
    pub(crate) build_type: String,
    pub(crate) external_build_command: String,
    pub(crate) internal_parameters: InternalParameters,
    pub(crate) resolved_dependencies: Vec<ResolvedDependency>,
}

#[derive(Debug)]
pub(crate) struct ToolBinaryInfo {
    pub(crate) version: String,
    pub(crate) sha256: String,
}

impl ToolBinaryInfo {
    pub(crate) fn via_rustup(cmd: &str) -> Result<Self> {
        let ver = Command::new(cmd)
            .arg("--version")
            .output()
            .with_context(|| format!("{cmd} not found"))?;
        let version = String::from_utf8(ver.stdout)?.trim().to_string();

        let which = Command::new("rustup")
            .args(["which", cmd])
            .output()
            .with_context(|| format!("could not locate {cmd}"))?;
        let bin = PathBuf::from(String::from_utf8(which.stdout)?.trim().to_string());
        let sha256 = hex::encode(Sha256::digest(fs_err::read(&bin)?));
        Ok(Self { version, sha256 })
    }

    /// For system tools located via `which` (nix, node, pip, etc.).
    pub(crate) fn via_which(cmd: &str) -> Result<Self> {
        let which = Command::new("which")
            .arg(cmd)
            .output()
            .with_context(|| format!("which {cmd} failed"))?;

        debug!("which {cmd} output: {:?}", which);
        if which.stdout.is_empty() {
            return Err(anyhow!("could not find command named `{}`", cmd));
        }

        let bin = PathBuf::from(String::from_utf8(which.stdout)?.trim().to_string());
        let sha256 = hex::encode(Sha256::digest(fs_err::read(&bin)?));

        let ver = Command::new(cmd)
            .arg("--version")
            .output()
            .with_context(|| format!("{cmd} --version failed"))?;
        let version = String::from_utf8(ver.stdout)?.trim().to_string();
        Ok(Self { version, sha256 })
    }

    pub(crate) fn kettle_info() -> Result<Self> {
        let version = binary::VERSION.to_string();
        let sha256 = binary::VERSION.to_string();
        Ok(Self { version, sha256 })
    }
}

pub(crate) trait ToolchainDriver: Sized {
    /// Lockfile filename relative to the project root (e.g. "Cargo.lock", "flake.lock").
    fn lockfile_filename() -> &'static str;

    /// Human-readable build invocation for printing (e.g. "cargo build --locked --release").
    fn build_command_display() -> &'static str;

    /// Collect toolchain-specific inputs.
    /// Receives pre-computed git context, lockfile hash, and raw lockfile bytes.
    fn collect_inputs(
        path: &Path,
        git: &GitContext,
        lockfile_hash: &str,
        lockfile_bytes: &[u8],
    ) -> Result<Self>;

    /// Ordered strings to be hashed as Merkle leaves.
    ///
    /// IMPORTANT: leaf ordering determines the Merkle root. For existing toolchains
    /// this ordering is a frozen contract — changing it breaks provenance determinism
    /// for any build already attested.
    fn merkle_entries(&self, git: &GitContext, lockfile_hash: &str) -> Vec<String>;

    /// Run the build subprocess.
    fn run_build(path: &Path) -> Result<BuildOutput>;

    /// Collect and stage artifacts into `artifacts_dir`.
    /// Returns Vec<Artifact> with `path` fields pointing into `artifacts_dir`.
    /// Each impl is responsible for the actual file copying (Nix needs special
    /// permission handling for read-only store paths).
    fn collect_artifacts(
        output: &BuildOutput,
        path: &Path,
        artifacts_dir: &Path,
    ) -> Result<Vec<Artifact>>;

    /// Return provenance fields for the shared scaffold to assemble.
    /// Takes `self` by value so impls can move owned fields (e.g. Vec<ResolvedDependency>)
    /// without requiring Clone on provenance types.
    fn provenance_fields(self, git: &GitContext, merkle_root: &str) -> ProvenanceFields;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // --- BuildMetadata::start ---

    #[test]
    fn build_metadata_invocation_id_format() {
        let m = BuildMetadata::start();
        let re = regex_lite::Regex::new(r"^build-\d{8}-\d{6}-[0-9a-f]{8}$").unwrap();
        assert!(
            re.is_match(&m.invocation_id),
            "invocation_id should match pattern: {}",
            m.invocation_id
        );
    }

    #[test]
    fn build_metadata_started_on_rfc3339() {
        let m = BuildMetadata::start();
        // Should parse as valid RFC3339 with microseconds and +00:00
        assert!(
            chrono::DateTime::parse_from_rfc3339(&m.started_on).is_ok(),
            "started_on should be valid RFC 3339: {}",
            m.started_on
        );
        assert!(
            m.started_on.ends_with("+00:00"),
            "should end with +00:00: {}",
            m.started_on
        );
        assert!(
            m.started_on.contains('.'),
            "should contain microsecond precision: {}",
            m.started_on
        );
    }

    #[test]
    fn build_metadata_finished_on_none_initially() {
        let m = BuildMetadata::start();
        assert!(m.finished_on.is_none());
    }

    // --- BuildMetadata::finish ---

    #[test]
    fn build_metadata_finish_sets_timestamp() {
        let mut m = BuildMetadata::start();
        m.finish();
        assert!(m.finished_on.is_some());
        let finished = m.finished_on.as_ref().unwrap();
        assert!(chrono::DateTime::parse_from_rfc3339(finished).is_ok());
    }

    #[test]
    fn build_metadata_finish_after_start() {
        let mut m = BuildMetadata::start();
        m.finish();
        let started = chrono::DateTime::parse_from_rfc3339(&m.started_on).unwrap();
        let finished =
            chrono::DateTime::parse_from_rfc3339(m.finished_on.as_ref().unwrap()).unwrap();
        assert!(finished >= started);
    }

    // --- Artifact::in_dir ---

    #[test]
    fn artifact_in_dir_no_extension() {
        let tmp = TempDir::new().unwrap();
        fs_err::write(tmp.path().join("rg"), b"binary data").unwrap();
        let artifacts = Artifact::in_dir(&tmp.path().to_path_buf()).unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].name, "rg");
    }

    #[test]
    fn artifact_in_dir_exe_extension() {
        let tmp = TempDir::new().unwrap();
        fs_err::write(tmp.path().join("rg.exe"), b"binary data").unwrap();
        let artifacts = Artifact::in_dir(&tmp.path().to_path_buf()).unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].name, "rg.exe");
    }

    #[test]
    fn artifact_in_dir_other_extensions_excluded() {
        let tmp = TempDir::new().unwrap();
        fs_err::write(tmp.path().join("lib.d"), b"data").unwrap();
        fs_err::write(tmp.path().join("lib.rlib"), b"data").unwrap();
        fs_err::write(tmp.path().join("lib.pdb"), b"data").unwrap();
        fs_err::write(tmp.path().join("lib.so"), b"data").unwrap();
        fs_err::write(tmp.path().join("lib.dylib"), b"data").unwrap();
        let artifacts = Artifact::in_dir(&tmp.path().to_path_buf()).unwrap();
        assert!(
            artifacts.is_empty(),
            "files with extensions .d, .rlib, .pdb, .so, .dylib should be excluded"
        );
    }

    #[test]
    fn artifact_in_dir_dotfile_excluded() {
        let tmp = TempDir::new().unwrap();
        fs_err::write(tmp.path().join(".gitkeep"), b"").unwrap();
        let artifacts = Artifact::in_dir(&tmp.path().to_path_buf()).unwrap();
        assert!(artifacts.is_empty(), "dotfiles should be excluded");
    }

    #[test]
    fn artifact_in_dir_directory_excluded() {
        let tmp = TempDir::new().unwrap();
        fs_err::create_dir(tmp.path().join("subdir")).unwrap();
        let artifacts = Artifact::in_dir(&tmp.path().to_path_buf()).unwrap();
        assert!(artifacts.is_empty(), "directories should be excluded");
    }

    #[test]
    fn artifact_in_dir_empty() {
        let tmp = TempDir::new().unwrap();
        let artifacts = Artifact::in_dir(&tmp.path().to_path_buf()).unwrap();
        assert!(artifacts.is_empty());
    }

    #[test]
    fn artifact_in_dir_checksum_correct() {
        let tmp = TempDir::new().unwrap();
        let content = b"known content for checksum test";
        fs_err::write(tmp.path().join("mybin"), content).unwrap();
        let artifacts = Artifact::in_dir(&tmp.path().to_path_buf()).unwrap();
        assert_eq!(artifacts.len(), 1);
        let expected = hex::encode(sha2::Sha256::digest(content));
        assert_eq!(artifacts[0].checksum, expected);
    }

    // --- git_cmd ---

    #[test]
    fn git_cmd_success() {
        // Use the kettle repo itself
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let sha = git_cmd(&repo, &["rev-parse", "HEAD"]).unwrap();
        assert_eq!(sha.len(), 40, "should be 40-char hex SHA");
        assert!(
            sha.chars().all(|c| c.is_ascii_hexdigit()),
            "should be hex: {sha}"
        );
    }

    #[test]
    fn git_cmd_failure() {
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let result = git_cmd(&repo, &["rev-parse", "NOREF"]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("git rev-parse NOREF failed:"),
            "error should contain the command: {err}"
        );
    }

    #[test]
    fn git_cmd_not_a_repo() {
        let tmp = TempDir::new().unwrap();
        let result = git_cmd(&tmp.path().to_path_buf(), &["rev-parse", "HEAD"]);
        assert!(result.is_err());
    }

    // --- GitContext::from_dir ---

    #[test]
    fn git_context_happy_path() {
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let ctx = GitContext::from_dir(&repo).unwrap();
        assert_eq!(ctx.commit.len(), 40);
        assert!(ctx.commit.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(ctx.tree.len(), 40);
        assert!(ctx.tree.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!ctx.source_uri.is_empty());
    }

    #[test]
    fn git_context_no_remote() {
        let tmp = TempDir::new().unwrap();
        // Initialize a git repo with no remote
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(tmp.path())
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["config", "user.email", "kettle-ci@lunal.dev"])
            .current_dir(tmp.path())
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["config", "user.name", "Kettle CI"])
            .current_dir(tmp.path())
            .output()
            .unwrap();

        // why is this failing but only on GitHub actions?
        let output = std::process::Command::new("git")
            .args(["commit", "--allow-empty", "-n", "-m", "init"])
            .current_dir(tmp.path())
            .output()
            .unwrap();
        println!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let ctx = GitContext::from_dir(&tmp.path().to_path_buf()).unwrap();
        assert!(
            ctx.source_uri.is_empty(),
            "no remote → source_uri should be empty"
        );
    }

    #[test]
    fn git_context_not_a_repo_errors() {
        let tmp = TempDir::new().unwrap();
        let result = GitContext::from_dir(&tmp.path().to_path_buf());
        assert!(result.is_err(), "should error when not in a git repo");
    }

    // --- ToolBinaryInfo ---

    #[test]
    fn tool_binary_info_via_rustup_rustc() {
        let info = ToolBinaryInfo::via_rustup("rustc").unwrap();
        assert!(
            info.version.starts_with("rustc"),
            "version should start with rustc: {}",
            info.version
        );
        assert_eq!(info.sha256.len(), 64, "sha256 should be 64 hex chars");
        assert!(info.sha256.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn tool_binary_info_via_rustup_cargo() {
        let info = ToolBinaryInfo::via_rustup("cargo").unwrap();
        assert!(
            info.version.starts_with("cargo"),
            "version should start with cargo: {}",
            info.version
        );
        assert_eq!(info.sha256.len(), 64);
    }

    #[test]
    fn tool_binary_info_nonexistent_via_rustup() {
        let result = ToolBinaryInfo::via_rustup("no-such-tool-xyz");
        assert!(result.is_err());
    }

    #[test]
    fn tool_binary_info_nonexistent_via_which() {
        let result = ToolBinaryInfo::via_which("no-such-tool-xyz");
        assert!(result.is_err());
    }
}
