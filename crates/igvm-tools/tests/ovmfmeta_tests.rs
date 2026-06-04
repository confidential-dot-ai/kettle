use igvm_tools::ovmfmeta::OvmfMeta;

#[test]
fn empty_firmware_returns_none() {
    assert!(OvmfMeta::new(&[]).is_none());
}

#[test]
fn firmware_without_metadata_guid_returns_none() {
    // 256 bytes of zeros — passes the size check but has no OVMF_META_LIST GUID
    let fw = vec![0u8; 256];
    assert!(OvmfMeta::new(&fw).is_none());
}
