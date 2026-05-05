use shadow_rs::CARGO_MANIFEST_DIR;
use std::collections::BTreeSet;

fn main() {
    let mut deny = BTreeSet::new();
    deny.insert(CARGO_MANIFEST_DIR);

    shadow_rs::ShadowBuilder::builder()
        .deny_const(deny)
        .build()
        .unwrap();
}
