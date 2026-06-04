use igvm::IgvmDirectiveHeader;
use igvm_tools::builder::Builder;
use igvm_tools::x86regs::real_mode_regs_at;

/// Helper: extract PageData GPAs from finalized IGVM directives, in order.
fn page_gpas(builder: &Builder) -> Vec<u64> {
    let igvm = builder.finalize().expect("finalize");
    igvm.directives()
        .iter()
        .filter_map(|d| {
            if let IgvmDirectiveHeader::PageData { gpa, .. } = d {
                Some(*gpa)
            } else {
                None
            }
        })
        .collect()
}

/// Pages must be sorted by GPA after finalize (wrong order = wrong measurement).
#[test]
fn finalize_sorts_pages_by_gpa() {
    let mut builder = Builder::new();
    builder.add_snp_platform();
    builder.add_data_pages(0x3000, &[0u8; 4096]);
    builder.add_data_pages(0x1000, &[0u8; 4096]);
    builder.add_data_pages(0x2000, &[0u8; 4096]);

    let gpas = page_gpas(&builder);
    assert_eq!(gpas, vec![0x1000, 0x2000, 0x3000]);
}

/// ParameterArea must come before ParameterInsert in the directive stream.
#[test]
fn finalize_preserves_non_page_directive_order() {
    let mut builder = Builder::new();
    builder.add_snp_platform();
    builder.add_igvm_param_area(0, 4096);
    builder.add_igvm_param_insert(0, 0x80000);
    builder.add_data_pages(0x100000, &[0u8; 4096]);

    let igvm = builder.finalize().expect("finalize");
    let directives = igvm.directives();

    let area_idx = directives
        .iter()
        .position(|d| matches!(d, IgvmDirectiveHeader::ParameterArea { .. }));
    let insert_idx = directives
        .iter()
        .position(|d| matches!(d, IgvmDirectiveHeader::ParameterInsert(_)));
    assert!(area_idx.unwrap() < insert_idx.unwrap());
}

/// Firmware at 4G boundary: base = 4GB - firmware_size.
#[test]
fn firmware_4g_placed_at_correct_address() {
    let fw = vec![0xCCu8; 8192];
    let mut builder = Builder::new();
    builder.add_snp_platform();
    builder.add_firmware_4g(&fw);

    let gpas = page_gpas(&builder);
    let expected_base = (1u64 << 32) - 8192;
    assert_eq!(gpas[0], expected_base);
    assert_eq!(gpas[1], expected_base + 4096);
}

/// 1M region maps the tail of firmware ending at 1MB.
/// Large firmware (>128KB) maps only last 128KB; small firmware maps entirely.
#[test]
fn firmware_1m_mapping() {
    // Large firmware: only last 128KB mapped
    let large = vec![0xBBu8; 256 * 1024];
    let mut builder = Builder::new();
    builder.add_snp_platform();
    builder.add_firmware_1m(&large);

    let gpas = page_gpas(&builder);
    assert_eq!(gpas[0], (1u64 << 20) - (128 * 1024));
    assert_eq!(gpas.len(), 128 * 1024 / 4096);
    assert_eq!(*gpas.last().unwrap(), (1u64 << 20) - 4096);

    // Small firmware: entire firmware mapped
    let small = vec![0xAAu8; 64 * 1024];
    let mut builder2 = Builder::new();
    builder2.add_snp_platform();
    builder2.add_firmware_1m(&small);

    let gpas2 = page_gpas(&builder2);
    assert_eq!(gpas2[0], (1u64 << 20) - (64 * 1024));
    assert_eq!(gpas2.len(), 64 * 1024 / 4096);
}

/// Data larger than 4K is split into consecutive pages.
#[test]
fn add_data_pages_splits_into_4k_pages() {
    let mut builder = Builder::new();
    builder.add_snp_platform();
    builder.add_data_pages(0x5000, &vec![0u8; 10000]);

    let gpas = page_gpas(&builder);
    assert_eq!(gpas.len(), 3, "10000 bytes = 3 pages");
    assert_eq!(gpas, vec![0x5000, 0x6000, 0x7000]);
}

/// remove_page_data_in_range removes only overlapping PageData.
#[test]
fn remove_page_data_in_range() {
    let mut builder = Builder::new();
    builder.add_snp_platform();
    builder.add_data_pages(0x1000, &[0u8; 4096]);
    builder.add_data_pages(0x2000, &[0u8; 4096]);
    builder.add_data_pages(0x3000, &[0u8; 4096]);

    builder.remove_page_data_in_range(0x2000, 4096);

    let gpas = page_gpas(&builder);
    assert_eq!(gpas, vec![0x1000, 0x3000]);
}

/// VMSA GPA is always 0xFFFFFFFFF000 regardless of input.
#[test]
fn snp_vmsa_gpa() {
    let mut builder = Builder::new();
    builder.add_snp_platform();
    builder.add_snp_vmsa_context(&real_mode_regs_at(0xFFFFFFF0), false, 0);

    let igvm = builder.finalize().expect("finalize");
    let vmsa_gpa = igvm.directives().iter().find_map(|d| {
        if let IgvmDirectiveHeader::SnpVpContext { gpa, .. } = d {
            Some(*gpa)
        } else {
            None
        }
    });
    assert_eq!(vmsa_gpa, Some(0xFFFFFFFFF000));
}

/// UEFI vars are placed immediately before firmware in the 4G region.
#[test]
fn uefivars_placed_before_firmware_at_4g() {
    let fw = vec![0u8; 4 * 1024 * 1024];
    let vars = vec![0u8; 256 * 1024];
    let mut builder = Builder::new();
    builder.add_snp_platform();
    builder.add_firmware_4g(&fw);
    builder.add_uefivars(&vars, fw.len());

    let gpas = page_gpas(&builder);
    let fw_base = (1u64 << 32) - fw.len() as u64;
    let vars_base = (1u64 << 32) - vars.len() as u64 - fw.len() as u64;

    assert!(gpas.contains(&fw_base));
    assert!(gpas.contains(&vars_base));
    assert!(vars_base < fw_base);
}
