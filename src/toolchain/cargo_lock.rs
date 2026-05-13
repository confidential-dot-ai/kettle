use anyhow::{Context as _, Result, anyhow};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::toolchain::driver::git_cmd;

/// Error if `path` is a git repository with uncommitted changes
/// (modified, deleted, renamed, or untracked files). Used to enforce
/// that an external path dependency's source is fully described by its
/// recorded git commit SHA.
fn assert_clean(path: &Path) -> Result<()> {
    let out = git_cmd(&path.to_path_buf(), &["status", "--porcelain"])?;
    if !out.is_empty() {
        return Err(anyhow!(
            "path dependency at {} has uncommitted changes:\n{}",
            path.display(),
            out
        ));
    }
    Ok(())
}

/// Return the SHA of HEAD at `path`. Errors if `path` is not a git repository.
fn git_sha_at(path: &Path) -> Result<String> {
    git_cmd(&path.to_path_buf(), &["rev-parse", "HEAD"])
}

/// Walk the project's Cargo.toml (and any workspace-member manifests)
/// to collect every `path = "..."` declaration whose target lives outside
/// the project directory tree.
///
/// Returns `name -> canonical absolute path` for each such external
/// dependency. Workspace-internal paths are filtered out (they're covered
/// by the project's own git commit).
fn collect_external_path_deps(project_path: &Path) -> Result<HashMap<String, PathBuf>> {
    let project_canon = fs_err::canonicalize(project_path)
        .with_context(|| format!("canonicalize project path {}", project_path.display()))?;
    let mut map: HashMap<String, PathBuf> = HashMap::new();
    let manifests = discover_manifests(&project_canon)?;
    for manifest_path in manifests {
        extract_paths_from_manifest(&manifest_path, &project_canon, &mut map)?;
    }
    Ok(map)
}

/// Return the list of Cargo.toml paths to inspect (project root plus any
/// workspace members). Task 5 expands this for workspace handling.
fn discover_manifests(project_canon: &Path) -> Result<Vec<PathBuf>> {
    Ok(vec![project_canon.join("Cargo.toml")])
}

/// Parse one manifest, find `path = "..."` declarations under
/// [dependencies], [dev-dependencies], [build-dependencies],
/// [target.*.dependencies], and [patch.*]. Insert each external one into
/// `map`, keyed by package name. Errors if two manifests disagree on a name.
fn extract_paths_from_manifest(
    manifest_path: &Path,
    project_canon: &Path,
    map: &mut HashMap<String, PathBuf>,
) -> Result<()> {
    let bytes = fs_err::read(manifest_path)
        .with_context(|| format!("read manifest {}", manifest_path.display()))?;
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("manifest {} is not utf-8", manifest_path.display()))?;
    let doc: toml::Value = toml::from_str(text)
        .with_context(|| format!("parse manifest {}", manifest_path.display()))?;

    let manifest_dir = manifest_path
        .parent()
        .context("manifest path has no parent directory")?;

    let mut visit_dep_table = |table: &toml::value::Table| -> Result<()> {
        for (name, value) in table {
            let Some(dep_table) = value.as_table() else { continue };
            let Some(rel_path) = dep_table.get("path").and_then(|v| v.as_str()) else {
                continue;
            };
            let joined = manifest_dir.join(rel_path);
            let canon = fs_err::canonicalize(&joined).with_context(|| {
                format!(
                    "canonicalize path dep `{name}` at {} (declared in {})",
                    joined.display(),
                    manifest_path.display()
                )
            })?;
            if canon.starts_with(project_canon) {
                continue; // workspace-internal, skip
            }
            if let Some(existing) = map.get(name) {
                if existing != &canon {
                    return Err(anyhow!(
                        "conflicting path declarations for `{name}`: {} vs {}",
                        existing.display(),
                        canon.display()
                    ));
                }
            } else {
                map.insert(name.clone(), canon);
            }
        }
        Ok(())
    };

    // [dependencies], [dev-dependencies], [build-dependencies]
    for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(t) = doc.get(key).and_then(|v| v.as_table()) {
            visit_dep_table(t)?;
        }
    }

    // [target.*.dependencies], [target.*.dev-dependencies], [target.*.build-dependencies]
    if let Some(targets) = doc.get("target").and_then(|v| v.as_table()) {
        for (_triple, target_block) in targets {
            let Some(tt) = target_block.as_table() else { continue };
            for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
                if let Some(t) = tt.get(key).and_then(|v| v.as_table()) {
                    visit_dep_table(t)?;
                }
            }
        }
    }

    // [patch.<registry-or-url>]
    if let Some(patch) = doc.get("patch").and_then(|v| v.as_table()) {
        for (_registry, patch_block) in patch {
            let Some(pt) = patch_block.as_table() else { continue };
            visit_dep_table(pt)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    /// Initialize a tempdir as a git repo with a single committed file.
    /// Returns the tempdir (kept alive by the caller).
    fn init_repo() -> TempDir {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        Command::new("git").args(["init"]).current_dir(p).output().unwrap();
        Command::new("git")
            .args(["config", "user.email", "test@example.com"])
            .current_dir(p)
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(p)
            .output()
            .unwrap();
        fs_err::write(p.join("file.txt"), "hello").unwrap();
        Command::new("git")
            .args(["add", "file.txt"])
            .current_dir(p)
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-n", "-m", "init"])
            .current_dir(p)
            .output()
            .unwrap();
        dir
    }

    #[test]
    fn assert_clean_passes_on_clean_repo() {
        let repo = init_repo();
        assert_clean(repo.path()).unwrap();
    }

    #[test]
    fn assert_clean_errors_on_modified_file() {
        let repo = init_repo();
        fs_err::write(repo.path().join("file.txt"), "modified").unwrap();
        let err = assert_clean(repo.path()).unwrap_err().to_string();
        assert!(
            err.contains("uncommitted changes"),
            "error should mention uncommitted changes: {err}"
        );
        assert!(err.contains("file.txt"), "error should include file: {err}");
    }

    #[test]
    fn assert_clean_errors_on_untracked_file() {
        let repo = init_repo();
        fs_err::write(repo.path().join("new.txt"), "untracked").unwrap();
        let err = assert_clean(repo.path()).unwrap_err().to_string();
        assert!(err.contains("uncommitted changes"), "error: {err}");
        assert!(err.contains("new.txt"), "error: {err}");
    }

    #[test]
    fn git_sha_at_returns_head_commit() {
        let repo = init_repo();
        let sha = git_sha_at(repo.path()).unwrap();
        assert_eq!(sha.len(), 40, "expected 40-char SHA, got: {sha}");
        assert!(sha.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn git_sha_at_errors_on_non_repo() {
        let dir = TempDir::new().unwrap();
        let result = git_sha_at(dir.path());
        assert!(result.is_err());
    }

    fn write_manifest(dir: &std::path::Path, contents: &str) {
        fs_err::write(dir.join("Cargo.toml"), contents).unwrap();
    }

    #[test]
    fn no_path_deps_returns_empty_map() {
        let project = TempDir::new().unwrap();
        write_manifest(
            project.path(),
            r#"
[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = "1"
"#,
        );
        let map = collect_external_path_deps(project.path()).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn workspace_internal_path_dep_is_filtered_out() {
        let project = TempDir::new().unwrap();
        fs_err::create_dir_all(project.path().join("inner")).unwrap();
        write_manifest(
            &project.path().join("inner"),
            r#"
[package]
name = "inner"
version = "0.1.0"
"#,
        );
        write_manifest(
            project.path(),
            r#"
[package]
name = "demo"
version = "0.1.0"

[dependencies]
inner = { path = "inner" }
"#,
        );
        let map = collect_external_path_deps(project.path()).unwrap();
        assert!(map.is_empty(), "internal path should be filtered: {map:?}");
    }

    #[test]
    fn external_path_dep_is_kept() {
        let parent = TempDir::new().unwrap();
        let project_dir = parent.path().join("project");
        let external_dir = parent.path().join("external");
        fs_err::create_dir_all(&project_dir).unwrap();
        fs_err::create_dir_all(&external_dir).unwrap();
        write_manifest(
            &external_dir,
            r#"
[package]
name = "external"
version = "0.1.0"
"#,
        );
        write_manifest(
            &project_dir,
            r#"
[package]
name = "demo"
version = "0.1.0"

[dependencies]
external = { path = "../external" }
"#,
        );
        let map = collect_external_path_deps(&project_dir).unwrap();
        assert_eq!(map.len(), 1);
        let canonical_external = fs_err::canonicalize(&external_dir).unwrap();
        assert_eq!(map.get("external"), Some(&canonical_external));
    }

    #[test]
    fn external_patch_is_kept() {
        let parent = TempDir::new().unwrap();
        let project_dir = parent.path().join("project");
        let external_dir = parent.path().join("patched");
        fs_err::create_dir_all(&project_dir).unwrap();
        fs_err::create_dir_all(&external_dir).unwrap();
        write_manifest(
            &external_dir,
            r#"
[package]
name = "patched"
version = "0.1.0"
"#,
        );
        write_manifest(
            &project_dir,
            r#"
[package]
name = "demo"
version = "0.1.0"

[patch.crates-io]
patched = { path = "../patched" }
"#,
        );
        let map = collect_external_path_deps(&project_dir).unwrap();
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("patched"));
    }

    #[test]
    fn internal_patch_is_filtered_out() {
        let project = TempDir::new().unwrap();
        fs_err::create_dir_all(project.path().join("crates/tss")).unwrap();
        write_manifest(
            &project.path().join("crates/tss"),
            r#"
[package]
name = "tss"
version = "0.1.0"
"#,
        );
        write_manifest(
            project.path(),
            r#"
[package]
name = "demo"
version = "0.1.0"

[patch.crates-io]
tss = { path = "crates/tss" }
"#,
        );
        let map = collect_external_path_deps(project.path()).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn target_specific_external_path_dep_is_kept() {
        let parent = TempDir::new().unwrap();
        let project_dir = parent.path().join("project");
        let external_dir = parent.path().join("linux_extra");
        fs_err::create_dir_all(&project_dir).unwrap();
        fs_err::create_dir_all(&external_dir).unwrap();
        write_manifest(
            &external_dir,
            r#"
[package]
name = "linux-extra"
version = "0.1.0"
"#,
        );
        write_manifest(
            &project_dir,
            r#"
[package]
name = "demo"
version = "0.1.0"

[target.'cfg(target_os = "linux")'.dependencies]
linux-extra = { path = "../linux_extra" }
"#,
        );
        let map = collect_external_path_deps(&project_dir).unwrap();
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("linux-extra"));
    }
}
