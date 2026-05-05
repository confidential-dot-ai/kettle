fn main() {
    let mut deny = std::collections::BTreeSet::new();
    deny.insert(shadow_rs::CARGO_MANIFEST_DIR);

    shadow_rs::ShadowBuilder::builder()
        .deny_const(deny)
        .build()
        .unwrap();
}
