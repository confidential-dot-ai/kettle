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

    let directives = active_config_lines(&unit);
    for directive in [
        "ExecStart=/bin/bash -lc 'exec /usr/local/bin/kettle-server'",
        "User=kettle",
        "Group=kettle",
        "SupplementaryGroups=sev-guest",
        // Lets the server drop sev-guest from build children (src/toolchain/confine.rs).
        "AmbientCapabilities=CAP_SETGID",
        "CapabilityBoundingSet=CAP_SETGID",
        "NoNewPrivileges=yes",
        "WantedBy=multi-user.target",
    ] {
        assert!(directives.contains(&directive), "missing {directive}");
    }

    assert_eq!(
        active_config_lines(&preset),
        ["enable kettle-server.service"]
    );
}

#[test]
fn image_pins_service_identities() {
    let sysusers = repo_file("image/mkosi.extra/usr/lib/sysusers.d/kettle.conf");
    let entries: Vec<String> = active_config_lines(&sysusers)
        .iter()
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect();
    let has = |prefix: &str| entries.iter().any(|entry| entry.starts_with(prefix));

    assert!(
        has("g kettle 900"),
        "kettle group must be pinned: {entries:?}"
    );
    assert!(
        has("g sev-guest 901"),
        "sev-guest group must be pinned: {entries:?}"
    );
    assert!(
        has("u kettle 900:900"),
        "kettle user must be pinned: {entries:?}"
    );
    assert!(
        has("m kettle sev-guest"),
        "kettle must join sev-guest: {entries:?}"
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
fn image_build_stages_measured_inputs_in_order() {
    let script = repo_file("bin/image-build");
    // Search the code only, so comments cannot satisfy an assertion.
    let code = active_config_lines(&script).join("\n");
    let position = |needle: &str| {
        code.find(needle)
            .unwrap_or_else(|| panic!("bin/image-build lacks `{needle}`"))
    };

    let stage_reset = position(r#"rm -rf "$REPO_ROOT/target/steep""#);
    let stage_copy = position(r#"cp -a "$REPO_ROOT/image/mkosi.extra""#);
    let nix_verify = position(r#"echo "$NIX_SHA256  $NIX_CACHE/$NIX_TARBALL" | sha256sum -c -"#);
    let nix_stage = position(r#"cp "$NIX_CACHE/$NIX_TARBALL""#);
    let sysusers = position("systemd-sysusers");
    let nix_install = position("./install --no-daemon");
    let normalize = position(r#"chmod -R u=rwX,go=rX "$REPO_ROOT/target/steep""#);
    let build = position(r#""$CONFOS" build "$REPO_ROOT/target/image""#);

    assert!(
        stage_reset < stage_copy,
        "staging must be reset before static files are copied"
    );
    assert!(
        nix_verify < nix_stage,
        "the Nix tarball digest must be checked before staging"
    );
    assert!(
        sysusers < nix_install,
        "identities must exist before Nix installs as kettle"
    );
    assert!(
        stage_copy < normalize && normalize < build,
        "modes must be normalised after staging, before the build"
    );
    assert!(
        code.contains("umask 022"),
        "staged modes must not depend on the operator's umask"
    );
    assert!(
        !code.contains("--cloud-init"),
        "first-boot configuration must be measured, not cloud-init"
    );
}
