use igvm::registers::X86Register;
use igvm::snp_defs::SevFeatures;
use igvm_tools::x86regs::{flat32_mode_regs, real_mode_regs_at, vmsa_context, SegmentAttributes};
use zerocopy::IntoBytes;

/// Real mode at standard reset vector produces CS.base=0xFFFF0000, RIP=0xFFF0.
#[test]
fn real_mode_reset_vector() {
    let regs = real_mode_regs_at(0xFFFFFFF0);
    let rip = regs.iter().find_map(|r| match r {
        X86Register::Rip(v) => Some(*v),
        _ => None,
    });
    let cs_base = regs.iter().find_map(|r| match r {
        X86Register::Cs(seg) => Some(seg.base),
        _ => None,
    });

    assert_eq!(rip, Some(0xFFF0), "RIP = low 16 bits of reset addr");
    assert_eq!(cs_base, Some(0xFFFF0000), "CS.base = high 16 bits << 16");
}

/// Flat32 mode should have PE set in CR0 and CS selector = 0x08.
#[test]
fn flat32_mode_pe_set() {
    let regs = flat32_mode_regs(None);
    let cr0 = regs.iter().find_map(|r| match r {
        X86Register::Cr0(v) => Some(*v),
        _ => None,
    });
    let cs_sel = regs.iter().find_map(|r| match r {
        X86Register::Cs(seg) => Some(seg.selector),
        _ => None,
    });

    assert!(cr0.unwrap() & 1 == 1, "CR0.PE must be set");
    assert_eq!(cs_sel, Some(0x08), "CS selector = 0x08 in flat32");
}

/// SevSelector uses 12-bit attributes: bits [7:0] direct, bits [11:8] from [15:12].
/// Wrong packing = wrong VMSA hash = wrong launch digest.
#[test]
fn vmsa_segment_attribute_packing() {
    let regs = flat32_mode_regs(None);
    let features = SevFeatures::new().with_snp(true);
    let vmsa = vmsa_context(&regs, features);

    let code32_raw: u16 = SegmentAttributes::code32().into();
    let expected_packed = (code32_raw & 0xff) | ((code32_raw & 0xf000) >> 4);
    assert_eq!(vmsa.cs.attrib, expected_packed, "CS attribute packing");

    let data32_raw: u16 = SegmentAttributes::data32().into();
    let expected_data = (data32_raw & 0xff) | ((data32_raw & 0xf000) >> 4);
    assert_eq!(vmsa.ds.attrib, expected_data, "DS attribute packing");
}

/// AMD architectural reset defaults that go into the VMSA.
/// Wrong values = wrong VMSA hash = wrong launch digest.
#[test]
fn vmsa_context_reset_defaults() {
    let regs = real_mode_regs_at(0xFFFFFFF0);
    let features = SevFeatures::new().with_snp(true);
    let vmsa = vmsa_context(&regs, features);

    assert_eq!(vmsa.dr6, 0xffff0ff0, "DR6 reset value");
    assert_eq!(vmsa.dr7, 0x400, "DR7 reset value");
    assert_eq!(vmsa.xcr0, 1, "XCR0 enables x87");
    assert_eq!(vmsa.x87_fcw, 0x37f, "FPU control word reset");
    assert_eq!(vmsa.mxcsr, 0x1f80, "MXCSR reset");
    assert_ne!(vmsa.efer & (1 << 12), 0, "EFER.SVME must be set");
    assert_eq!(vmsa.pat, 0x0007040600070406, "PAT reset default");
    assert!(vmsa.sev_features.snp(), "SNP feature flag");
}

/// VMSA struct must fit within a single page (padded to 4096 during measurement).
#[test]
fn vmsa_fits_in_page() {
    let regs = real_mode_regs_at(0xFFFFFFF0);
    let features = SevFeatures::new().with_snp(true);
    let vmsa = vmsa_context(&regs, features);
    let bytes = vmsa.as_bytes();
    assert!(
        bytes.len() <= 4096,
        "SevVmsa ({} bytes) must fit within a 4K page",
        bytes.len()
    );
}
