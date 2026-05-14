use anyhow::{Context as _, Result, anyhow};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::provenance::{Digest, ResolvedDependency};
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
    let bytes = fs_err::read(&root).with_context(|| format!("read manifest {}", root.display()))?;
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("manifest {} is not utf-8", root.display()))?;
    let doc: toml::Value =
        toml::from_str(text).with_context(|| format!("parse manifest {}", root.display()))?;

    let Some(workspace) = doc.get("workspace").and_then(|v| v.as_table()) else {
        return Ok(manifests);
    };
    let Some(members) = workspace.get("members").and_then(|v| v.as_array()) else {
        return Ok(manifests);
    };
    for member in members {
        let Some(pattern) = member.as_str() else {
            continue;
        };
        let is_glob = pattern.contains('*');
        for member_dir in expand_member_pattern(project_canon, pattern)? {
            let m = member_dir.join("Cargo.toml");
            if !m.exists() {
                if is_glob {
                    continue; // matches cargo's silent-skip behavior for glob expansions
                }
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
            let Some(dep_table) = value.as_table() else {
                continue;
            };
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
            let Some(tt) = target_block.as_table() else {
                continue;
            };
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
            let Some(pt) = patch_block.as_table() else {
                continue;
            };
            visit_dep_table(pt)?;
        }
    }

    Ok(())
}

/// Compute the path from `from` to `to` using `..` segments as needed.
/// Both paths must be absolute and canonicalized. Returns a relative
/// `PathBuf` like `../sibling`.
fn relative_path(from: &Path, to: &Path) -> PathBuf {
    let mut from_iter = from.components();
    let mut to_iter = to.components();
    // Skip the common prefix
    loop {
        let from_peek = from_iter.clone().next();
        let to_peek = to_iter.clone().next();
        match (from_peek, to_peek) {
            (Some(f), Some(t)) if f == t => {
                from_iter.next();
                to_iter.next();
            }
            _ => break,
        }
    }
    let mut result = PathBuf::new();
    for _ in from_iter {
        result.push("..");
    }
    for c in to_iter {
        result.push(c.as_os_str());
    }
    result
}

/// Percent-encode the characters that would confuse a PURL parser when
/// embedded as a qualifier value: `?`, `#`, `&`, and space.
fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '?' => out.push_str("%3F"),
            '#' => out.push_str("%23"),
            '&' => out.push_str("%26"),
            ' ' => out.push_str("%20"),
            _ => out.push(c),
        }
    }
    out
}

/// Classify a single `[[package]]` entry from Cargo.lock.
/// Returns `Some(dep)` if it should appear in resolved_dependencies,
/// `None` if it's a workspace member (skip), or `Err` if unaccounted-for.
fn classify_package(
    pkg: &toml::Value,
    external_paths: &HashMap<String, PathBuf>,
    project_canon: &Path,
) -> Result<Option<ResolvedDependency>> {
    let name = pkg
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("lockfile package missing name field"))?;
    let version = pkg
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("lockfile package `{name}` missing version field"))?;
    let source = pkg.get("source").and_then(|v| v.as_str());

    match source {
        Some(src) if src.starts_with("registry+") => {
            let checksum = pkg
                .get("checksum")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    anyhow!("cargo dependency {name}@{version} from registry has no checksum")
                })?;
            Ok(Some(ResolvedDependency {
                annotations: None,
                digest: Digest::Sha256 {
                    sha256: checksum.to_string(),
                },
                name: name.to_string(),
                uri: format!("pkg:cargo/{name}@{version}?checksum=sha256:{checksum}"),
            }))
        }
        Some(src) if src.starts_with("git+") => {
            // Strip "git+" prefix, split on '#' to separate url and commit.
            let rest = &src["git+".len()..];
            let (url, commit) = rest.rsplit_once('#').ok_or_else(|| {
                anyhow!("cargo dependency {name}@{version} has git source without commit: {src}")
            })?;
            Ok(Some(ResolvedDependency {
                annotations: None,
                digest: Digest::GitCommit {
                    git_commit: commit.to_string(),
                },
                name: name.to_string(),
                uri: format!(
                    "pkg:cargo/{name}@{version}?vcs_url=git+{}@{commit}",
                    pct_encode(url)
                ),
            }))
        }
        Some(other) => Err(anyhow!(
            "cargo dependency {name}@{version} has unrecognized source: {other}"
        )),
        None => {
            // No source: either workspace member or external path dep.
            if let Some(abs_path) = external_paths.get(name) {
                assert_clean(abs_path).map_err(|e| {
                    anyhow!(
                        "verifying path dependency {name} at {}: {e}",
                        abs_path.display()
                    )
                })?;
                let commit = git_sha_at(abs_path).map_err(|e| {
                    anyhow!(
                        "path dependency {name} at {} is not a git repository: {e}",
                        abs_path.display()
                    )
                })?;
                let relpath = relative_path(project_canon, abs_path)
                    .to_string_lossy()
                    .to_string();
                Ok(Some(ResolvedDependency {
                    annotations: None,
                    digest: Digest::GitCommit {
                        git_commit: commit.clone(),
                    },
                    name: name.to_string(),
                    uri: format!(
                        "pkg:cargo/{name}@{version}?vcs_url=git+file:{}@{commit}",
                        pct_encode(&relpath)
                    ),
                }))
            } else {
                Ok(None)
            }
        }
    }
}

/// Public entry point. Parses `Cargo.lock`, classifies each package, and
/// returns a sorted list of `ResolvedDependency` (workspace members
/// excluded). Errors on any package that can't be accounted for, or on
/// a dirty external path dep working tree.
pub(crate) fn resolve_dependencies(
    project_path: &Path,
    lockfile_bytes: &[u8],
) -> Result<Vec<ResolvedDependency>> {
    let project_canon = fs_err::canonicalize(project_path)
        .with_context(|| format!("canonicalize project path {}", project_path.display()))?;
    let external_paths = collect_external_path_deps(project_path)?;

    let text = std::str::from_utf8(lockfile_bytes).context("Cargo.lock is not utf-8")?;
    let lock: toml::Value = toml::from_str(text).context("parse Cargo.lock")?;
    let Some(packages) = lock.get("package").and_then(|v| v.as_array()) else {
        return Ok(vec![]);
    };

    let mut deps = Vec::new();
    for pkg in packages {
        if let Some(dep) = classify_package(pkg, &external_paths, &project_canon)? {
            deps.push(dep);
        }
    }
    deps.sort_by(|a, b| a.uri.cmp(&b.uri));
    Ok(deps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::Digest;
    use pretty_assertions::assert_eq;
    use std::process::Command;
    use tempfile::TempDir;

    /// Initialize an existing directory as a git repo with one committed file.
    fn init_repo_at(path: &std::path::Path) {
        Command::new("git")
            .args(["init"])
            .current_dir(path)
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.email", "test@example.com"])
            .current_dir(path)
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(path)
            .output()
            .unwrap();
        fs_err::write(path.join("file.txt"), "hello").unwrap();
        Command::new("git")
            .args(["add", "file.txt"])
            .current_dir(path)
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-n", "-m", "init"])
            .current_dir(path)
            .output()
            .unwrap();
    }

    /// Initialize a tempdir as a git repo with a single committed file.
    /// Returns the tempdir (kept alive by the caller).
    fn init_repo() -> TempDir {
        let dir = TempDir::new().unwrap();
        init_repo_at(dir.path());
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
        let err = collect_external_path_deps(project.path())
            .unwrap_err()
            .to_string();
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
        let err = collect_external_path_deps(project.path())
            .unwrap_err()
            .to_string();
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
        let err = collect_external_path_deps(&project_dir)
            .unwrap_err()
            .to_string();
        assert!(err.contains("conflicting"), "error: {err}");
    }

    #[test]
    fn workspace_glob_skips_dirs_without_cargo_toml() {
        let parent = TempDir::new().unwrap();
        let project_dir = parent.path().join("project");
        let external_dir = parent.path().join("ext");
        // Real crate at crates/a
        fs_err::create_dir_all(project_dir.join("crates/a")).unwrap();
        // Non-crate directory at crates/scripts (no Cargo.toml)
        fs_err::create_dir_all(project_dir.join("crates/scripts")).unwrap();
        fs_err::write(
            project_dir.join("crates/scripts/run.sh"),
            "#!/bin/sh\necho hi\n",
        )
        .unwrap();
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

        // The non-crate dir `crates/scripts` should be silently skipped.
        let map = collect_external_path_deps(&project_dir).unwrap();
        assert_eq!(map.len(), 1, "got {map:?}");
        assert!(map.contains_key("ext"));
    }

    fn pkg_from_toml(toml_str: &str) -> toml::Value {
        toml::from_str(toml_str).unwrap()
    }

    #[test]
    fn pct_encode_handles_purl_breaking_chars() {
        assert_eq!(pct_encode("plain"), "plain");
        assert_eq!(pct_encode("a?b#c&d e"), "a%3Fb%23c%26d%20e");
        // The `=` and `@` chars are NOT encoded; they're not problematic
        // inside a PURL qualifier value.
        assert_eq!(pct_encode("a=b@c"), "a=b@c");
        // / and : pass through (URLs need them readable)
        assert_eq!(pct_encode("https://x.y/z"), "https://x.y/z");
    }

    #[test]
    fn classify_registry_dep_with_checksum() {
        let pkg = pkg_from_toml(
            r#"
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abc"
"#,
        );
        let empty: HashMap<String, PathBuf> = HashMap::new();
        let dep = classify_package(&pkg, &empty, Path::new("/"))
            .unwrap()
            .unwrap();
        assert_eq!(dep.name, "serde");
        assert_eq!(
            dep.uri,
            "pkg:cargo/serde@1.0.228?checksum=sha256:abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abc"
        );
        match dep.digest {
            Digest::Sha256 { sha256 } => {
                assert_eq!(
                    sha256,
                    "abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abc"
                );
            }
            _ => panic!("expected Sha256 digest"),
        }
    }

    #[test]
    fn classify_git_dep() {
        let pkg = pkg_from_toml(
            r#"
name = "sev"
version = "7.1.0"
source = "git+https://github.com/virtee/sev#900d42d6a1f9102ed52faa3a3889b54e8a7e12c8"
"#,
        );
        let empty: HashMap<String, PathBuf> = HashMap::new();
        let dep = classify_package(&pkg, &empty, Path::new("/"))
            .unwrap()
            .unwrap();
        assert_eq!(dep.name, "sev");
        assert_eq!(
            dep.uri,
            "pkg:cargo/sev@7.1.0?vcs_url=git+https://github.com/virtee/sev@900d42d6a1f9102ed52faa3a3889b54e8a7e12c8"
        );
        match dep.digest {
            Digest::GitCommit { git_commit } => {
                assert_eq!(git_commit, "900d42d6a1f9102ed52faa3a3889b54e8a7e12c8");
            }
            _ => panic!("expected GitCommit digest"),
        }
    }

    #[test]
    fn classify_git_dep_with_query_string_in_url() {
        // Git source URLs frequently carry ?branch=... or ?rev=... in the query.
        // The split must be at the LAST '#', not the first.
        let pkg = pkg_from_toml(
            r#"
name = "attestation"
version = "0.4.0"
source = "git+https://github.com/lunal-dev/attestation-rs?branch=usize#952489ea39cbb300828af5c1268eff3387cfe4b5"
"#,
        );
        let empty: HashMap<String, PathBuf> = HashMap::new();
        let dep = classify_package(&pkg, &empty, Path::new("/"))
            .unwrap()
            .unwrap();
        assert_eq!(
            dep.uri,
            "pkg:cargo/attestation@0.4.0?vcs_url=git+https://github.com/lunal-dev/attestation-rs%3Fbranch=usize@952489ea39cbb300828af5c1268eff3387cfe4b5"
        );
        match dep.digest {
            Digest::GitCommit { git_commit } => {
                assert_eq!(git_commit, "952489ea39cbb300828af5c1268eff3387cfe4b5");
            }
            _ => panic!("expected GitCommit digest"),
        }
    }

    #[test]
    fn classify_workspace_member_is_none() {
        let pkg = pkg_from_toml(
            r#"
name = "my-project"
version = "0.1.0"
"#,
        );
        let empty: HashMap<String, PathBuf> = HashMap::new();
        let result = classify_package(&pkg, &empty, Path::new("/")).unwrap();
        assert!(result.is_none(), "workspace member should return None");
    }

    #[test]
    fn classify_registry_without_checksum_errors() {
        let pkg = pkg_from_toml(
            r#"
name = "foo"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        );
        let empty: HashMap<String, PathBuf> = HashMap::new();
        let err = classify_package(&pkg, &empty, Path::new("/"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("no checksum"), "error: {err}");
        assert!(err.contains("foo"), "error: {err}");
    }

    #[test]
    fn classify_unknown_source_errors() {
        let pkg = pkg_from_toml(
            r#"
name = "weird"
version = "0.0.1"
source = "ftp://example.com/weird.tar.gz"
"#,
        );
        let empty: HashMap<String, PathBuf> = HashMap::new();
        let err = classify_package(&pkg, &empty, Path::new("/"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("unrecognized source"), "error: {err}");
        assert!(err.contains("ftp"), "error: {err}");
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

    #[test]
    fn classify_git_dep_without_commit_errors() {
        let pkg = pkg_from_toml(
            r#"
name = "sev"
version = "7.1.0"
source = "git+https://github.com/virtee/sev"
"#,
        );
        let empty: HashMap<String, PathBuf> = HashMap::new();
        let err = classify_package(&pkg, &empty, Path::new("/"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("without commit"), "error: {err}");
        assert!(err.contains("sev"), "error: {err}");
    }

    #[test]
    fn classify_external_path_dep_clean() {
        let repo = init_repo();
        let head = git_sha_at(repo.path()).unwrap();

        let project = TempDir::new().unwrap();
        let project_canon = fs_err::canonicalize(project.path()).unwrap();

        let mut external_paths = HashMap::new();
        external_paths.insert("ext".to_string(), repo.path().to_path_buf());

        let pkg = pkg_from_toml(
            r#"
name = "ext"
version = "0.1.0"
"#,
        );
        let dep = classify_package(&pkg, &external_paths, &project_canon)
            .unwrap()
            .unwrap();
        assert_eq!(dep.name, "ext");
        match &dep.digest {
            Digest::GitCommit { git_commit } => assert_eq!(git_commit, &head),
            _ => panic!("expected GitCommit digest"),
        }
        assert!(dep.uri.starts_with("pkg:cargo/ext@0.1.0?vcs_url=git+file:"));
        assert!(dep.uri.ends_with(&format!("@{head}")));
        // Relpath must be `../`-relative so provenance is reproducible across machines.
        assert!(
            dep.uri.contains("git+file:.."),
            "URI relpath should be ../-relative, got: {}",
            dep.uri
        );
        assert!(
            !dep.uri
                .contains(&format!("git+file:{}", repo.path().display())),
            "URI must not contain machine-specific absolute path: {}",
            dep.uri
        );
    }

    #[test]
    fn classify_external_path_dep_dirty_errors() {
        let repo = init_repo();
        // Make the repo dirty
        fs_err::write(repo.path().join("file.txt"), "modified").unwrap();

        let project = TempDir::new().unwrap();
        let project_canon = fs_err::canonicalize(project.path()).unwrap();

        let mut external_paths = HashMap::new();
        external_paths.insert("ext".to_string(), repo.path().to_path_buf());

        let pkg = pkg_from_toml(
            r#"
name = "ext"
version = "0.1.0"
"#,
        );
        let err = classify_package(&pkg, &external_paths, &project_canon)
            .unwrap_err()
            .to_string();
        assert!(err.contains("uncommitted changes"), "error: {err}");
        assert!(err.contains("ext"), "error should mention dep name: {err}");
    }

    #[test]
    fn classify_external_path_dep_not_a_repo_errors() {
        let non_repo = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        let project_canon = fs_err::canonicalize(project.path()).unwrap();

        let mut external_paths = HashMap::new();
        external_paths.insert("ext".to_string(), non_repo.path().to_path_buf());

        let pkg = pkg_from_toml(
            r#"
name = "ext"
version = "0.1.0"
"#,
        );
        let err = classify_package(&pkg, &external_paths, &project_canon)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("not a git repository") || err.contains("git rev-parse"),
            "error should indicate it's not a git repo: {err}"
        );
    }

    const CARGO_LOCK_FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/ripgrep/Cargo.lock");

    #[test]
    fn resolve_dependencies_ripgrep_regression() {
        let project = TempDir::new().unwrap();
        // Minimal Cargo.toml so collect_external_path_deps doesn't choke.
        write_manifest(
            project.path(),
            r#"
[package]
name = "ripgrep-fixture"
version = "0.1.0"
"#,
        );
        let deps = resolve_dependencies(project.path(), CARGO_LOCK_FIXTURE).unwrap();
        // 51 registry deps (the same count as the pre-existing parse_cargo_lock test).
        assert_eq!(deps.len(), 51, "expected 51 deps, got {}", deps.len());
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
        // Sorted by URI
        let uris: Vec<&str> = deps.iter().map(|d| d.uri.as_str()).collect();
        let mut sorted = uris.clone();
        sorted.sort();
        assert_eq!(uris, sorted, "deps should be sorted by URI");
        // Workspace member my-project must not appear
        assert!(
            deps.iter().all(|d| d.name != "my-project"),
            "workspace member should be excluded"
        );
    }

    #[test]
    fn resolve_dependencies_invalid_toml_errors() {
        let project = TempDir::new().unwrap();
        write_manifest(
            project.path(),
            r#"
[package]
name = "demo"
version = "0.1.0"
"#,
        );
        let result = resolve_dependencies(project.path(), b"{{{{not valid toml}}}}");
        assert!(result.is_err());
    }

    #[test]
    fn resolve_dependencies_empty_package_list_returns_empty() {
        let project = TempDir::new().unwrap();
        write_manifest(
            project.path(),
            r#"
[package]
name = "demo"
version = "0.1.0"
"#,
        );
        let deps = resolve_dependencies(project.path(), b"[metadata]\nkey = \"value\"").unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn resolve_dependencies_with_git_and_external_path_deps() {
        let parent = TempDir::new().unwrap();
        let project_dir = parent.path().join("project");
        let external_repo = parent.path().join("ext");
        fs_err::create_dir_all(&project_dir).unwrap();
        fs_err::create_dir_all(&external_repo).unwrap();

        // Initialize external as a git repo with one committed file.
        init_repo_at(&external_repo);
        let head = git_cmd(&external_repo.to_path_buf(), &["rev-parse", "HEAD"]).unwrap();

        // Project Cargo.toml declares the external path dep.
        write_manifest(
            &project_dir,
            r#"
[package]
name = "demo"
version = "0.1.0"

[dependencies]
ext = { path = "../ext" }
"#,
        );

        // A synthetic Cargo.lock with three entries: workspace, git, external path.
        let lockfile = r#"
version = 4

[[package]]
name = "demo"
version = "0.1.0"

[[package]]
name = "ext"
version = "0.1.0"

[[package]]
name = "sev"
version = "7.1.0"
source = "git+https://github.com/virtee/sev#900d42d6a1f9102ed52faa3a3889b54e8a7e12c8"
"#;

        let deps = resolve_dependencies(&project_dir, lockfile.as_bytes()).unwrap();
        assert_eq!(
            deps.len(),
            2,
            "demo workspace member should be excluded; got {deps:?}"
        );

        let ext = deps
            .iter()
            .find(|d| d.name == "ext")
            .expect("ext dep present");
        match &ext.digest {
            Digest::GitCommit { git_commit } => assert_eq!(git_commit, &head),
            _ => panic!("expected GitCommit digest for ext"),
        }
        assert!(
            ext.uri.contains("?vcs_url=git+file:"),
            "ext uri should encode file vcs_url: {}",
            ext.uri
        );
        assert!(ext.uri.ends_with(&format!("@{head}")));
        assert!(
            ext.uri.contains("git+file:.."),
            "URI relpath should be ../-relative, got: {}",
            ext.uri
        );
        assert!(
            !ext.uri.contains(external_repo.to_str().unwrap()),
            "URI must not leak machine-specific absolute path, got: {}",
            ext.uri
        );

        let sev = deps
            .iter()
            .find(|d| d.name == "sev")
            .expect("sev dep present");
        match &sev.digest {
            Digest::GitCommit { git_commit } => {
                assert_eq!(git_commit, "900d42d6a1f9102ed52faa3a3889b54e8a7e12c8");
            }
            _ => panic!("expected GitCommit digest for sev"),
        }
        assert_eq!(
            sev.uri,
            "pkg:cargo/sev@7.1.0?vcs_url=git+https://github.com/virtee/sev@900d42d6a1f9102ed52faa3a3889b54e8a7e12c8"
        );
    }

    #[test]
    fn resolve_dependencies_aborts_on_dirty_external_path() {
        let parent = TempDir::new().unwrap();
        let project_dir = parent.path().join("project");
        let external_repo = parent.path().join("ext");
        fs_err::create_dir_all(&project_dir).unwrap();
        fs_err::create_dir_all(&external_repo).unwrap();
        init_repo_at(&external_repo);
        // Add an untracked file to make it dirty
        fs_err::write(external_repo.join("untracked.rs"), "fn x() {}").unwrap();

        write_manifest(
            &project_dir,
            r#"
[package]
name = "demo"
version = "0.1.0"

[dependencies]
ext = { path = "../ext" }
"#,
        );

        let lockfile = r#"
version = 4

[[package]]
name = "ext"
version = "0.1.0"
"#;

        let err = resolve_dependencies(&project_dir, lockfile.as_bytes())
            .unwrap_err()
            .to_string();
        assert!(err.contains("uncommitted changes"), "error: {err}");
        assert!(
            err.contains("untracked.rs"),
            "error should name untracked: {err}"
        );
    }
}
