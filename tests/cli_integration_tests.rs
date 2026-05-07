use std::process::Command;
use tempfile::TempDir;

fn kettle_bin() -> String {
    // Use the debug binary built by cargo test
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push("debug");
    path.push("kettle");
    path.to_string_lossy().to_string()
}

// kettle build

#[test]
fn cli_build_error_unknown_project() {
    let tmp = TempDir::new().unwrap();
    let output = Command::new(kettle_bin())
        .args(["build", tmp.path().to_str().unwrap()])
        .output()
        .expect("failed to execute kettle");

    assert!(
        !output.status.success(),
        "should fail on empty dir: {:?}",
        output.status
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Could not determine toolchain"),
        "stderr should mention toolchain detection failure: {stdout}"
    );
}

#[test]
fn cli_build_error_no_cargo_lock() {
    let tmp = TempDir::new().unwrap();
    // Create only Cargo.toml, no Cargo.lock
    std::fs::write(
        tmp.path().join("Cargo.toml"),
        r#"[package]
name = "fake"
version = "0.1.0"
edition = "2021"
"#,
    )
    .unwrap();

    let output = Command::new(kettle_bin())
        .args(["build", tmp.path().to_str().unwrap()])
        .output()
        .expect("failed to execute kettle");

    assert!(
        !output.status.success(),
        "should fail without Cargo.lock: {:?}",
        output.status
    );
}

// kettle verify

#[test]
fn cli_verify() {
    let output = Command::new(kettle_bin())
        .args(["verify", "./tests/fixtures/alejandra"])
        .output()
        .expect("failed to execute kettle verify");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Verification PASSED"),
        "expected verify to pass, got {}",
        stdout
    );
}

#[test]
fn cli_verify_with_nonce() {
    let output = Command::new(kettle_bin())
        .args(["verify", "./tests/fixtures/kex"])
        .output()
        .expect("failed to execute kettle verify");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Verification PASSED"),
        "expected verify to pass, got {}",
        stdout
    );
}

// kettle attest

#[cfg(not(all(feature = "attest", target_os = "linux")))]
#[test]
fn cli_attest_feature_disabled() {
    let tmp = TempDir::new().unwrap();
    let output = Command::new(kettle_bin())
        .args(["attest", tmp.path().to_str().unwrap()])
        .output()
        .expect("failed to execute kettle");

    assert!(
        !output.status.success(),
        "should fail without attest feature {:?}",
        output.status,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Attestation is disabled"),
        "should say attestation is disabled, but got: {:?}",
        stdout,
    );
}

#[cfg(all(feature = "attest", target_os = "linux"))]
#[ignore]
#[test]
fn cli_attest_ripgrep() -> anyhow::Result<()> {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().to_string_lossy();
    Command::new("git")
        .args([
            "clone",
            "--revision",
            "cb66736f146f093497f4dc537b33d0826f9af33c",
            "https://github.com/burntsushi/ripgrep",
            &path,
        ])
        .output()
        .expect("failed to git clone kettle");

    let output = Command::new(kettle_bin())
        .args(["attest", &path])
        .output()
        .expect("failed to kettle attest");

    assert!(output.status.success());

    let build_dir = tmp.path().join("kettle-build");
    let output = Command::new(kettle_bin())
        .args(["verify", &build_dir.to_string_lossy()])
        .output()
        .expect("failed to kettle verify");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Verification PASSED"),
        "expected verify to pass, got {}",
        stdout
    );

    fs_err::rename(tmp.path().join("kettle-build"), "/tmp/ripgrep-build")?;

    Ok(())
}

#[cfg(all(feature = "attest", target_os = "linux"))]
#[ignore]
#[test]
fn cli_attest_alejandra() -> anyhow::Result<()> {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().to_string_lossy();
    Command::new("git")
        .args([
            "clone",
            "--revision",
            "8f47c5e82ee8e6e8adcc1748be0056a1e349f7e8",
            "https://github.com/kamadorueda/alejandra",
            &path,
        ])
        .output()
        .expect("failed to git clone kettle");

    let output = Command::new(kettle_bin())
        .args(["attest", &path])
        .output()
        .expect("failed to kettle attest");

    assert!(output.status.success());

    let build_dir = tmp.path().join("kettle-build");
    let output = Command::new(kettle_bin())
        .args(["verify", &build_dir.to_string_lossy()])
        .output()
        .expect("failed to kettle verify");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Verification PASSED"),
        "expected verify to pass, got {}",
        stdout
    );

    fs_err::rename(tmp.path().join("kettle-build"), "/tmp/alejandra-build")?;

    Ok(())
}
