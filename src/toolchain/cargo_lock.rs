use anyhow::{Context as _, Result, anyhow};
use std::path::Path;

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
}
