use std::{fs, path::PathBuf};

fn repo_file(path: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn active_config_lines(contents: &str) -> Vec<&str> {
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

#[test]
fn image_declares_only_nix_as_kettle_specific_state() {
    let state = repo_file("image/mkosi.extra/usr/lib/confai/state.d/60-kettle.conf");

    assert_eq!(active_config_lines(&state), ["nix"]);
}

#[test]
fn image_bakes_in_the_kettle_service_contract() {
    let unit = repo_file("image/mkosi.extra/usr/lib/systemd/system/kettle-server.service");
    let preset = repo_file("image/mkosi.extra/usr/lib/systemd/system-preset/20-kettle.preset");

    for directive in [
        "ExecStart=/bin/bash -lc 'exec /usr/local/bin/kettle-server'",
        "User=kettle",
        "Group=kettle",
        "SupplementaryGroups=sev-guest",
        "NoNewPrivileges=yes",
        "WantedBy=multi-user.target",
    ] {
        assert!(
            unit.lines().any(|line| line == directive),
            "missing {directive}"
        );
    }

    assert_eq!(
        active_config_lines(&preset),
        ["enable kettle-server.service"]
    );
}

#[test]
fn image_bakes_in_sev_guest_device_permissions() {
    let rule = repo_file("image/mkosi.extra/usr/lib/udev/rules.d/99-sev-guest.rules");

    assert_eq!(
        active_config_lines(&rule),
        [r#"KERNEL=="sev-guest", GROUP="sev-guest", MODE="0660""#]
    );
}

#[test]
fn image_build_rejects_identity_collisions_before_provisioning() {
    let script = repo_file("bin/image-build");

    let guard_start = script.find("require_absent() {").unwrap();
    let guard_end = script[guard_start..]
        .find("\n}\n")
        .map(|offset| guard_start + offset)
        .unwrap();
    let guard_body = &script[guard_start..guard_end];
    for command in [
        r#"if getent "$database" "$name" >/dev/null; then"#,
        "refusing to build image: base image already defines",
        "exit 1",
    ] {
        assert!(
            guard_body.contains(command),
            "missing fail-closed behavior: {command}"
        );
    }

    let groupadd = script.find("groupadd --system sev-guest").unwrap();
    let useradd = script.find("useradd --create-home").unwrap();
    for guard in [
        "require_absent passwd kettle",
        "require_absent group kettle",
        "require_absent group sev-guest",
    ] {
        let guard = script
            .find(guard)
            .unwrap_or_else(|| panic!("missing fail-closed identity guard: {guard}"));
        assert!(guard < groupadd, "identity guard must run before groupadd");
        assert!(guard < useradd, "identity guard must run before useradd");
    }

    assert!(!script.contains("usermod --append"));
    assert!(!script.contains("|| groupadd"));
    assert!(script.contains("--user-group --groups sev-guest kettle"));
}

#[test]
fn image_build_uses_measured_configuration_without_cloud_init() {
    let script = repo_file("bin/image-build");

    let stage_reset = script.find(r#"rm -rf "$REPO_ROOT/target/steep""#).unwrap();
    let stage_copy = script.find("cp -a").unwrap();
    let groupadd = script.find("groupadd --system sev-guest").unwrap();
    let useradd = script.find("useradd --create-home").unwrap();
    let build = script
        .find(r#""$CONFOS" build "$REPO_ROOT/target/image""#)
        .unwrap();

    assert!(!script.contains("if [[ $FORCE -eq 1 ]]; then"));
    assert!(
        stage_reset < stage_copy,
        "staging must be reset before static files are copied"
    );
    assert!(
        stage_copy < build,
        "static files must be staged before the image build"
    );
    assert!(
        groupadd < useradd,
        "the supplementary group must exist before the user"
    );
    assert!(script.contains(r#"CONFOS="${CONFOS:-$HOME/confidential-os-builder/bin/confos}""#));
    assert!(script.contains(r#"[[ ! -x "$CONFOS" ]]"#));
    assert!(script.contains("set CONFOS to the path of its bin/confos wrapper"));
    assert!(script.contains(r#""$CONFOS" build "$REPO_ROOT/target/image""#));

    for obsolete in ["--cloud-init", "user-data.yml", "bin/steep", "cd ~/steep"] {
        assert!(
            !script.contains(obsolete),
            "obsolete image setup remains: {obsolete}"
        );
    }
}
