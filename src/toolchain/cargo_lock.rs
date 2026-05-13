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
/// workspace members).
fn discover_manifests(project_canon: &Path) -> Result<Vec<PathBuf>> {
    let root = project_canon.join("Cargo.toml");
    let mut manifests = vec![root.clone()];

    // If the root manifest has a [workspace] section, expand its members.
    let bytes = fs_err::read(&root)
        .with_context(|| format!("read manifest {}", root.display()))?;
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("manifest {} is not utf-8", root.display()))?;
    let doc: toml::Value = toml::from_str(text)
        .with_context(|| format!("parse manifest {}", root.display()))?;

    let Some(workspace) = doc.get("workspace").and_then(|v| v.as_table()) else {
        return Ok(manifests);
    };
    let Some(members) = workspace.get("members").and_then(|v| v.as_array()) else {
        return Ok(manifests);
    };
    for member in members {
        let Some(pattern) = member.as_str() else { continue };
        for member_dir in expand_member_pattern(project_canon, pattern)? {
            let m = member_dir.join("Cargo.toml");
            if !m.exists() {
                return Err(anyhow!(
                    "workspace member `{pattern}` resolved to {} but no Cargo.toml is present",
                    member_dir.display()
                ));
            }
            manifests.push(m);
        }
    }
    Ok(manifests)
}

/// Expand a single `workspace.members` entry into a list of member dirs.
/// Supports a literal path or a single trailing `*` (e.g. `crates/*`).
/// Anything more elaborate errors out.
fn expand_member_pattern(project_canon: &Path, pattern: &str) -> Result<Vec<PathBuf>> {
    if !pattern.contains('*') {
        return Ok(vec![project_canon.join(pattern)]);
    }
    if pattern.matches('*').count() > 1 || !pattern.ends_with('*') {
        return Err(anyhow!(
            "unsupported glob pattern in workspace.members: `{pattern}` \
            (only literal paths or a single trailing `*` are supported)"
        ));
    }
    // Strip the trailing `*` (and possibly trailing `/`)
    let prefix = pattern.trim_end_matches('*').trim_end_matches('/');
    let base = if prefix.is_empty() {
        project_canon.to_path_buf()
    } else {
        project_canon.join(prefix)
    };
    let mut dirs = Vec::new();
    for entry in fs_err::read_dir(&base)
        .with_context(|| format!("read workspace member dir {}", base.display()))?
    {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            dirs.push(entry.path());
        }
    }
    Ok(dirs)
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
    fn workspace_explicit_members_are_walked() {
        let parent = TempDir::new().unwrap();
        let project_dir = parent.path().join("project");
        let external_dir = parent.path().join("ext");
        fs_err::create_dir_all(project_dir.join("a")).unwrap();
        fs_err::create_dir_all(project_dir.join("b")).unwrap();
        fs_err::create_dir_all(&external_dir).unwrap();
        write_manifest(
            &external_dir,
            r#"
[package]
name = "ext"
version = "0.1.0"
"#,
        );
        // Root virtual workspace manifest
        write_manifest(
            &project_dir,
            r#"
[workspace]
members = ["a", "b"]
"#,
        );
        // Member `a` declares an external path dep
        write_manifest(
            &project_dir.join("a"),
            r#"
[package]
name = "a"
version = "0.1.0"

[dependencies]
ext = { path = "../../ext" }
"#,
        );
        // Member `b` does not
        write_manifest(
            &project_dir.join("b"),
            r#"
[package]
name = "b"
version = "0.1.0"
"#,
        );

        let map = collect_external_path_deps(&project_dir).unwrap();
        assert_eq!(map.len(), 1, "expected only `ext`, got {map:?}");
        assert!(map.contains_key("ext"));
    }

    #[test]
    fn workspace_glob_members_are_expanded() {
        let parent = TempDir::new().unwrap();
        let project_dir = parent.path().join("project");
        let external_dir = parent.path().join("ext");
        fs_err::create_dir_all(project_dir.join("crates/a")).unwrap();
        fs_err::create_dir_all(project_dir.join("crates/b")).unwrap();
        fs_err::create_dir_all(&external_dir).unwrap();
        write_manifest(
            &external_dir,
            r#"
[package]
name = "ext"
version = "0.1.0"
"#,
        );
        write_manifest(
            &project_dir,
            r#"
[workspace]
members = ["crates/*"]
"#,
        );
        write_manifest(
            &project_dir.join("crates/a"),
            r#"
[package]
name = "a"
version = "0.1.0"

[dependencies]
ext = { path = "../../../ext" }
"#,
        );
        write_manifest(
            &project_dir.join("crates/b"),
            r#"
[package]
name = "b"
version = "0.1.0"
"#,
        );

        let map = collect_external_path_deps(&project_dir).unwrap();
        assert_eq!(map.len(), 1, "got {map:?}");
        assert!(map.contains_key("ext"));
    }

    #[test]
    fn missing_workspace_member_errors() {
        let project = TempDir::new().unwrap();
        write_manifest(
            project.path(),
            r#"
[workspace]
members = ["doesnotexist"]
"#,
        );
        let err = collect_external_path_deps(project.path()).unwrap_err().to_string();
        assert!(
            err.contains("doesnotexist") || err.contains("no Cargo.toml"),
            "error should mention the missing member: {err}"
        );
    }

    #[test]
    fn unsupported_glob_pattern_errors() {
        let project = TempDir::new().unwrap();
        write_manifest(
            project.path(),
            r#"
[workspace]
members = ["**/*"]
"#,
        );
        let err = collect_external_path_deps(project.path()).unwrap_err().to_string();
        assert!(err.contains("unsupported glob pattern"), "error: {err}");
    }

    #[test]
    fn conflicting_path_declarations_error() {
        let parent = TempDir::new().unwrap();
        let project_dir = parent.path().join("project");
        let ext_a = parent.path().join("ext-a");
        let ext_b = parent.path().join("ext-b");
        fs_err::create_dir_all(project_dir.join("a")).unwrap();
        fs_err::create_dir_all(project_dir.join("b")).unwrap();
        fs_err::create_dir_all(&ext_a).unwrap();
        fs_err::create_dir_all(&ext_b).unwrap();
        write_manifest(&ext_a, "[package]\nname = \"ext\"\nversion = \"0.1.0\"\n");
        write_manifest(&ext_b, "[package]\nname = \"ext\"\nversion = \"0.1.0\"\n");
        write_manifest(
            &project_dir,
            r#"
[workspace]
members = ["a", "b"]
"#,
        );
        write_manifest(
            &project_dir.join("a"),
            r#"
[package]
name = "a"
version = "0.1.0"

[dependencies]
ext = { path = "../../ext-a" }
"#,
        );
        write_manifest(
            &project_dir.join("b"),
            r#"
[package]
name = "b"
version = "0.1.0"

[dependencies]
ext = { path = "../../ext-b" }
"#,
        );
        let err = collect_external_path_deps(&project_dir).unwrap_err().to_string();
        assert!(err.contains("conflicting"), "error: {err}");
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
