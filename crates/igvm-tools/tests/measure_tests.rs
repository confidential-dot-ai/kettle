use igvm_tools::measure;
use igvm_tools::x86regs::real_mode_regs_at;

/// Helper: create an SNP platform header with compat mask 1.
fn snp_platforms() -> Vec<igvm::IgvmPlatformHeader> {
    vec![igvm::IgvmPlatformHeader::SupportedPlatform(
        igvm_defs::IGVM_VHS_SUPPORTED_PLATFORM {
            compatibility_mask: 1,
            highest_vtl: 0,
            platform_type: igvm_defs::IgvmPlatformType::SEV_SNP,
            platform_version: 1,
            shared_gpa_boundary: 0,
        },
    )]
}

fn revision() -> igvm::IgvmRevision {
    igvm::IgvmRevision::V2 {
        arch: igvm::Arch::X64,
        page_size: igvm_defs::PAGE_SIZE_4K.try_into().unwrap(),
    }
}

/// Same input always produces the same digest.
#[test]
fn single_page_deterministic_digest() {
    let directives = vec![igvm::IgvmDirectiveHeader::PageData {
        gpa: 0x1000,
        compatibility_mask: 1,
        flags: igvm_defs::IgvmPageDataFlags::new(),
        data_type: igvm_defs::IgvmPageDataType::NORMAL,
        data: vec![0xAAu8; 4096],
    }];

    let igvm = igvm::IgvmFile::new(revision(), snp_platforms(), vec![], directives).unwrap();
    let r1 = measure::measure_snp(&igvm, false).unwrap();
    let r2 = measure::measure_snp(&igvm, false).unwrap();

    assert_eq!(r1.page_count, 1);
    assert_ne!(r1.launch_digest, [0u8; 48], "digest must not be zeros");
    assert_eq!(r1.launch_digest, r2.launch_digest, "must be deterministic");
}

/// Different page content produces a different digest.
#[test]
fn different_data_different_digest() {
    let make = |byte: u8| {
        let directives = vec![igvm::IgvmDirectiveHeader::PageData {
            gpa: 0x1000,
            compatibility_mask: 1,
            flags: igvm_defs::IgvmPageDataFlags::new(),
            data_type: igvm_defs::IgvmPageDataType::NORMAL,
            data: vec![byte; 4096],
        }];
        igvm::IgvmFile::new(revision(), snp_platforms(), vec![], directives).unwrap()
    };

    let r1 = measure::measure_snp(&make(0x00), false).unwrap();
    let r2 = measure::measure_snp(&make(0xFF), false).unwrap();
    assert_ne!(r1.launch_digest, r2.launch_digest);
}

/// SNP spec: unmeasured pages still update the running digest.
#[test]
fn unmeasured_pages_affect_digest() {
    let normal_only = vec![igvm::IgvmDirectiveHeader::PageData {
        gpa: 0x1000,
        compatibility_mask: 1,
        flags: igvm_defs::IgvmPageDataFlags::new(),
        data_type: igvm_defs::IgvmPageDataType::NORMAL,
        data: vec![0u8; 4096],
    }];

    let with_unmeasured = vec![
        igvm::IgvmDirectiveHeader::PageData {
            gpa: 0x1000,
            compatibility_mask: 1,
            flags: igvm_defs::IgvmPageDataFlags::new(),
            data_type: igvm_defs::IgvmPageDataType::NORMAL,
            data: vec![0u8; 4096],
        },
        igvm::IgvmDirectiveHeader::PageData {
            gpa: 0x2000,
            compatibility_mask: 1,
            flags: igvm_defs::IgvmPageDataFlags::new().with_unmeasured(true),
            data_type: igvm_defs::IgvmPageDataType::NORMAL,
            data: vec![],
        },
    ];

    let igvm1 = igvm::IgvmFile::new(revision(), snp_platforms(), vec![], normal_only).unwrap();
    let igvm2 = igvm::IgvmFile::new(revision(), snp_platforms(), vec![], with_unmeasured).unwrap();

    let r1 = measure::measure_snp(&igvm1, false).unwrap();
    let r2 = measure::measure_snp(&igvm2, false).unwrap();

    assert_eq!(r1.page_count, 1);
    assert_eq!(r2.page_count, 2);
    assert_ne!(r1.launch_digest, r2.launch_digest);
}

/// VMSA pages (measured during LAUNCH_FINISH) must affect the digest.
#[test]
fn vmsa_measurement_affects_digest() {
    use igvm::snp_defs::SevFeatures;
    use igvm_tools::x86regs::vmsa_context;

    let page_only = vec![igvm::IgvmDirectiveHeader::PageData {
        gpa: 0x1000,
        compatibility_mask: 1,
        flags: igvm_defs::IgvmPageDataFlags::new(),
        data_type: igvm_defs::IgvmPageDataType::NORMAL,
        data: vec![0u8; 4096],
    }];

    let regs = real_mode_regs_at(0xFFFFFFF0);
    let vmsa = vmsa_context(&regs, SevFeatures::new().with_snp(true));
    let with_vmsa = vec![
        igvm::IgvmDirectiveHeader::PageData {
            gpa: 0x1000,
            compatibility_mask: 1,
            flags: igvm_defs::IgvmPageDataFlags::new(),
            data_type: igvm_defs::IgvmPageDataType::NORMAL,
            data: vec![0u8; 4096],
        },
        igvm::IgvmDirectiveHeader::SnpVpContext {
            gpa: 0xFFFFFFFFF000,
            compatibility_mask: 1,
            vp_index: 0,
            vmsa: Box::new(vmsa),
        },
    ];

    let igvm1 = igvm::IgvmFile::new(revision(), snp_platforms(), vec![], page_only).unwrap();
    let igvm2 = igvm::IgvmFile::new(revision(), snp_platforms(), vec![], with_vmsa).unwrap();

    let r1 = measure::measure_snp(&igvm1, false).unwrap();
    let r2 = measure::measure_snp(&igvm2, false).unwrap();

    assert_eq!(r1.vmsa_count, 0);
    assert_eq!(r2.vmsa_count, 1);
    assert_ne!(r1.launch_digest, r2.launch_digest);
}

/// ParameterInsert pages are measured immediately (QEMU-specific behavior).
#[test]
fn parameter_insert_measured() {
    let page_only = vec![igvm::IgvmDirectiveHeader::PageData {
        gpa: 0x1000,
        compatibility_mask: 1,
        flags: igvm_defs::IgvmPageDataFlags::new(),
        data_type: igvm_defs::IgvmPageDataType::NORMAL,
        data: vec![0u8; 4096],
    }];

    let with_param = vec![
        igvm::IgvmDirectiveHeader::ParameterArea {
            parameter_area_index: 0,
            number_of_bytes: 4096,
            initial_data: Vec::new(),
        },
        igvm::IgvmDirectiveHeader::PageData {
            gpa: 0x1000,
            compatibility_mask: 1,
            flags: igvm_defs::IgvmPageDataFlags::new(),
            data_type: igvm_defs::IgvmPageDataType::NORMAL,
            data: vec![0u8; 4096],
        },
        igvm::IgvmDirectiveHeader::ParameterInsert(igvm_defs::IGVM_VHS_PARAMETER_INSERT {
            parameter_area_index: 0,
            gpa: 0x80000,
            compatibility_mask: 1,
        }),
    ];

    let igvm1 = igvm::IgvmFile::new(revision(), snp_platforms(), vec![], page_only).unwrap();
    let igvm2 = igvm::IgvmFile::new(revision(), snp_platforms(), vec![], with_param).unwrap();

    let r1 = measure::measure_snp(&igvm1, false).unwrap();
    let r2 = measure::measure_snp(&igvm2, false).unwrap();

    assert_eq!(r1.page_count, 1);
    assert_eq!(r2.page_count, 2);
    assert_ne!(r1.launch_digest, r2.launch_digest);
}

/// No SNP platform → error (don't silently produce a bogus digest).
#[test]
fn no_snp_platform_returns_error() {
    let platforms = vec![igvm::IgvmPlatformHeader::SupportedPlatform(
        igvm_defs::IGVM_VHS_SUPPORTED_PLATFORM {
            compatibility_mask: 1,
            highest_vtl: 0,
            platform_type: igvm_defs::IgvmPlatformType::NATIVE,
            platform_version: 1,
            shared_gpa_boundary: 0,
        },
    )];

    let directives = vec![igvm::IgvmDirectiveHeader::PageData {
        gpa: 0x1000,
        compatibility_mask: 1,
        flags: igvm_defs::IgvmPageDataFlags::new(),
        data_type: igvm_defs::IgvmPageDataType::NORMAL,
        data: vec![0u8; 4096],
    }];

    let igvm = igvm::IgvmFile::new(revision(), platforms, vec![], directives).unwrap();
    let result = measure::measure_snp(&igvm, false);

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("SEV_SNP"));
}
