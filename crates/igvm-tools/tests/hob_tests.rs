use igvm_tools::hob::{IgvmDataList, IgvmDataType, EFI_IGVM_DATA_HOB_GUID};

#[test]
fn empty_list_produces_end_marker_only() {
    let list = IgvmDataList::new(0x20000000);
    let hobs = list.hobs();

    assert_eq!(hobs.len(), 8, "empty HOB list = 8-byte end marker");
    assert_eq!(u16::from_le_bytes([hobs[0], hobs[1]]), 0xFFFF, "end type");
    assert_eq!(u16::from_le_bytes([hobs[2], hobs[3]]), 8, "end length");
}

#[test]
fn single_entry_hob_binary_layout() {
    let data = vec![0xABu8; 100];
    let mut list = IgvmDataList::new(0x20000000);
    list.add(&data, IgvmDataType::Kernel, true);
    let hobs = list.hobs();

    // One 0x30-byte HOB entry + 8-byte end marker
    assert_eq!(hobs.len(), 0x38);

    // Header
    assert_eq!(
        u16::from_le_bytes([hobs[0], hobs[1]]),
        0x0004,
        "GUID ext type"
    );
    assert_eq!(u16::from_le_bytes([hobs[2], hobs[3]]), 0x30, "entry length");

    // GUID
    assert_eq!(&hobs[8..24], &EFI_IGVM_DATA_HOB_GUID.to_bytes(), "GUID");

    // Payload fields
    let addr = u64::from_le_bytes(hobs[24..32].try_into().unwrap());
    let len = u64::from_le_bytes(hobs[32..40].try_into().unwrap());
    let dtype = u32::from_le_bytes(hobs[40..44].try_into().unwrap());
    assert_eq!(addr, 0x20000000, "blob address");
    assert_eq!(len, 100, "blob length");
    assert_eq!(dtype, 0x201, "data type = Kernel");

    // End marker follows
    assert_eq!(u16::from_le_bytes([hobs[0x30], hobs[0x31]]), 0xFFFF);
}

#[test]
fn addresses_are_4k_aligned_sequential() {
    let blob_100 = vec![0u8; 100];
    let blob_5000 = vec![0u8; 5000];
    let blob_4096 = vec![0u8; 4096];

    let mut list = IgvmDataList::new(0x1000_0000);
    list.add(&blob_100, IgvmDataType::Pk, true); // rounds to 4096
    list.add(&blob_5000, IgvmDataType::Kek, true); // rounds to 8192
    list.add(&blob_4096, IgvmDataType::Db, true); // exact page

    let blobs = list.blobs(true);
    assert_eq!(blobs.len(), 3);
    assert_eq!(blobs[0].0, 0x1000_0000);
    assert_eq!(blobs[1].0, 0x1000_1000, "base + 4096 (100 rounds up)");
    assert_eq!(
        blobs[2].0, 0x1000_3000,
        "base + 4096 + 8192 (5000 rounds up)"
    );
}

#[test]
fn measured_unmeasured_filtering() {
    let data = vec![0u8; 64];
    let mut list = IgvmDataList::new(0x2000_0000);

    list.add(&data, IgvmDataType::Pk, true); // measured
    list.add(&data, IgvmDataType::Shim, false); // unmeasured
    list.add(&data, IgvmDataType::Kernel, true); // measured

    assert_eq!(list.blobs(true).len(), 2, "measured blobs");
    assert_eq!(list.blobs(false).len(), 1, "unmeasured blobs");
}
