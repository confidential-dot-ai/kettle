use anyhow::{Result, anyhow};
use fs_err::exists;
use std::path::PathBuf;

#[derive(Debug)]
pub(crate) enum ProjectToolchain {
    Cargo,
    Nix,
    Pnpm,
}
impl ProjectToolchain {
    fn from_dir(path: &PathBuf) -> Result<Self> {
        if exists(path.join("flake.nix"))? {
            Ok(Self::Nix)
        } else if exists(path.join("Cargo.lock"))? {
            Ok(Self::Cargo)
        } else if exists(path.join("pnpm-lock.yaml"))? {
            Ok(Self::Pnpm)
        } else {
            Err(anyhow!(
                "Could not determine toolchain. Is {:?} a rust, nix, or pnpm project?",
                path
            ))
        }
    }
}

pub fn build(path: &PathBuf) -> Result<()> {
    build_with_sink(path, &crate::toolchain::EventSink::noop())
}

pub fn build_with_sink(path: &PathBuf, sink: &crate::toolchain::EventSink) -> Result<()> {
    println!("Building project in: {:?}", path);

    let toolchain = ProjectToolchain::from_dir(path)?;
    println!("Found {:?} project", toolchain);
    futures::executor::block_on(sink.emit(crate::api::Event::Detect {
        msg: format!("Detected {:?} project", toolchain),
    }));

    match toolchain {
        ProjectToolchain::Cargo => crate::toolchain::cargo::build(path, sink)?,
        ProjectToolchain::Nix => crate::toolchain::nix::build(path, sink)?,
        ProjectToolchain::Pnpm => crate::toolchain::pnpm::build(path, sink)?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn from_dir_flake_nix() {
        let tmp = TempDir::new().unwrap();
        fs_err::write(tmp.path().join("flake.nix"), b"{}").unwrap();
        match ProjectToolchain::from_dir(&tmp.path().to_path_buf()).unwrap() {
            ProjectToolchain::Nix => {}
            other => panic!("expected Nix, got {:?}", other),
        }
    }

    #[test]
    fn from_dir_cargo_lock() {
        let tmp = TempDir::new().unwrap();
        fs_err::write(tmp.path().join("Cargo.lock"), b"version = 4").unwrap();
        match ProjectToolchain::from_dir(&tmp.path().to_path_buf()).unwrap() {
            ProjectToolchain::Cargo => {}
            other => panic!("expected Cargo, got {:?}", other),
        }
    }

    #[test]
    fn from_dir_both_flake_wins() {
        let tmp = TempDir::new().unwrap();
        fs_err::write(tmp.path().join("flake.nix"), b"{}").unwrap();
        fs_err::write(tmp.path().join("Cargo.lock"), b"version = 4").unwrap();
        match ProjectToolchain::from_dir(&tmp.path().to_path_buf()).unwrap() {
            ProjectToolchain::Nix => {}
            other => panic!("expected Nix when both present, got {:?}", other),
        }
    }

    #[test]
    fn from_dir_neither_present() {
        let tmp = TempDir::new().unwrap();
        let result = ProjectToolchain::from_dir(&tmp.path().to_path_buf());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Could not determine toolchain"),
            "error: {err}"
        );
    }

    #[test]
    fn pnpm_lock_detected() {
        let tmp = TempDir::new().unwrap();
        fs_err::write(tmp.path().join("pnpm-lock.yaml"), b"lockfileVersion: 5").unwrap();
        match ProjectToolchain::from_dir(&tmp.path().to_path_buf()).unwrap() {
            ProjectToolchain::Pnpm => {}
            other => panic!("expected Pnpm, got {:?}", other),
        }
    }

    #[test]
    fn flake_wins_over_pnpm() {
        let tmp = TempDir::new().unwrap();
        fs_err::write(tmp.path().join("flake.nix"), b"{}").unwrap();
        fs_err::write(tmp.path().join("pnpm-lock.yaml"), b"lockfileVersion: 5").unwrap();
        match ProjectToolchain::from_dir(&tmp.path().to_path_buf()).unwrap() {
            ProjectToolchain::Nix => {}
            other => panic!("expected Nix when both present, got {:?}", other),
        }
    }

    #[test]
    fn cargo_wins_over_pnpm() {
        let tmp = TempDir::new().unwrap();
        fs_err::write(tmp.path().join("Cargo.lock"), b"version = 4").unwrap();
        fs_err::write(tmp.path().join("pnpm-lock.yaml"), b"lockfileVersion: 5").unwrap();
        match ProjectToolchain::from_dir(&tmp.path().to_path_buf()).unwrap() {
            ProjectToolchain::Cargo => {}
            other => panic!("expected Cargo when both present, got {:?}", other),
        }
    }

    #[test]
    fn from_dir_symlink_flake_nix() {
        let tmp = TempDir::new().unwrap();
        let real = tmp.path().join("real_flake.nix");
        fs_err::write(&real, b"{}").unwrap();
        std::os::unix::fs::symlink(&real, tmp.path().join("flake.nix")).unwrap();
        match ProjectToolchain::from_dir(&tmp.path().to_path_buf()).unwrap() {
            ProjectToolchain::Nix => {}
            other => panic!("expected Nix via symlink, got {:?}", other),
        }
    }

    #[test]
    fn from_dir_symlink_cargo_lock() {
        let tmp = TempDir::new().unwrap();
        let real = tmp.path().join("real_cargo.lock");
        fs_err::write(&real, b"version = 4").unwrap();
        std::os::unix::fs::symlink(&real, tmp.path().join("Cargo.lock")).unwrap();
        match ProjectToolchain::from_dir(&tmp.path().to_path_buf()).unwrap() {
            ProjectToolchain::Cargo => {}
            other => panic!("expected Cargo via symlink, got {:?}", other),
        }
    }

    #[test]
    fn from_dir_broken_symlink() {
        let tmp = TempDir::new().unwrap();
        // Broken symlink: points to non-existent target
        std::os::unix::fs::symlink("/nonexistent/flake.nix", tmp.path().join("flake.nix")).unwrap();
        // Broken symlink should not count as presence
        let result = ProjectToolchain::from_dir(&tmp.path().to_path_buf());
        assert!(
            result.is_err(),
            "broken symlink should not satisfy exists()"
        );
    }
}
