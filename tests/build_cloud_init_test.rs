use std::process::Command;

#[test]
fn build_cloud_init_writes_user_data() {
    // Skip gracefully if docker isn't available — bin/reproduce-build needs it.
    if std::process::Command::new("which").arg("docker").output()
        .map(|o| !o.status.success()).unwrap_or(true) {
        eprintln!("skipping: docker not available");
        return;
    }

    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let status = Command::new(format!("{manifest}/bin/build-cloud-init"))
        .current_dir(&manifest)
        .status()
        .expect("failed to run bin/build-cloud-init");
    assert!(status.success(), "script exited non-zero: {status:?}");

    let out = std::path::PathBuf::from(&manifest).join("target/reproducible/server-user-data.yml");
    assert!(out.exists(), "expected {out:?} to exist");
    let body = std::fs::read_to_string(&out).unwrap();

    assert!(body.contains("#cloud-config"), "missing cloud-config header");
    assert!(body.contains("write_files:"), "missing write_files");
    assert!(body.contains("/usr/local/bin/kettle-server"), "missing binary path");
    assert!(body.contains("permissions: '0755'"), "missing 0755 mode");
    assert!(body.contains("/etc/systemd/system/kettle-server.service"), "missing unit path");
    assert!(body.contains("encoding: b64"), "binary must be base64-encoded");
    assert!(body.contains("runcmd:"), "missing runcmd");
    assert!(body.contains("systemctl daemon-reload"), "missing daemon-reload");
    assert!(body.contains("systemctl enable --now kettle-server.service"),
            "missing enable --now");
}
