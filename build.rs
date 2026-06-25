fn main() {
    // Shadow is only needed by the CLI binary. Skip it for library-only builds
    // (consumers that depend on kettle with `default-features = false`).
    if std::env::var_os("CARGO_FEATURE_CLI").is_none() {
        return;
    }

    let mut deny = std::collections::BTreeSet::new();
    deny.insert(shadow_rs::CARGO_MANIFEST_DIR);

    shadow_rs::ShadowBuilder::builder()
        .deny_const(deny)
        .build()
        .unwrap();
}
