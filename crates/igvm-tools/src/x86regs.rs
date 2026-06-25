// This module exists because no crate provides x86 register/VMSA construction
// for IGVM SNP contexts. The igvm crate provides the data types (X86Register,
// SevVmsa) but not the initialization logic for real-mode, protected-mode,
// or AP reset states.
//
// Register values must produce VMSAs that match what QEMU+KVM expect.
// Verified against hardware attestation on EPYC 8224P for both SMP=1 and SMP=2.
//
// Segment attributes must pack correctly for both native context
// (IgvmNativeVpContextX64) and VMSA context (SevVmsa). The attribute format
// differs: native uses raw 16-bit, VMSA drops 4 middle bits.

use bitfield_struct::bitfield;
use igvm::registers::{SegmentRegister, TableRegister, X86Register};
use igvm::snp_defs::{SevFeatures, SevSelector, SevVmsa};
use igvm_defs::IgvmNativeVpContextX64;
use zerocopy::FromZeros;

#[bitfield(u16)]
pub struct SegmentAttributes {
    #[bits(default = true)]
    pub accessed: bool,
    pub rw: bool,
    pub ce: bool,
    pub code: bool,

    #[bits(default = true)]
    pub system: bool,
    #[bits(2)]
    pub dpl: u8,
    pub present: bool,

    #[bits(4)]
    _limit1619: u8,

    pub avl: bool,
    pub long: bool,
    pub db: bool,
    pub granularity: bool,
}

impl SegmentAttributes {
    pub const fn code16() -> Self {
        SegmentAttributes::new()
            .with_rw(true)
            .with_code(true)
            .with_present(true)
    }
    pub const fn data16() -> Self {
        SegmentAttributes::new()
            .with_rw(true)
            .with_code(false)
            .with_present(true)
    }

    pub const fn code32() -> Self {
        SegmentAttributes::new()
            .with_rw(true)
            .with_code(true)
            .with_present(true)
            .with_db(true)
            .with_granularity(true)
    }
    pub const fn data32() -> Self {
        SegmentAttributes::new()
            .with_rw(true)
            .with_code(false)
            .with_present(true)
            .with_db(true)
            .with_granularity(true)
    }

    pub const fn code64() -> Self {
        SegmentAttributes::new()
            .with_code(true)
            .with_present(true)
            .with_long(true)
    }
    pub const fn data64() -> Self {
        SegmentAttributes::new().with_present(true)
    }

    fn system_segment(systype: u16) -> Self {
        SegmentAttributes::from(systype & 0x0f)
            .with_system(false)
            .with_present(true)
    }

    pub fn ldt() -> Self {
        Self::system_segment(0x02)
    }

    pub fn tss16() -> Self {
        Self::system_segment(0x03)
    }

    pub fn tss3264() -> Self {
        Self::system_segment(0x0b)
    }
}

#[bitfield(u64)]
pub struct ControlRegister0 {
    pub pe: bool,
    pub mp: bool,
    pub em: bool,
    pub ts: bool,
    pub et: bool,
    pub ne: bool,

    #[bits(10)]
    _pad0: u16,

    pub wp: bool,
    _pad1: bool,
    pub am: bool,

    #[bits(10)]
    _pad2: u16,

    pub nw: bool,
    pub cd: bool,
    pub pg: bool,

    #[bits(32)]
    _pad3: u32,
}

impl ControlRegister0 {
    pub const fn reset() -> Self {
        ControlRegister0::new()
            .with_et(true)
            .with_nw(true)
            .with_cd(true)
    }

    pub const fn reset_fast() -> Self {
        ControlRegister0::new().with_et(true)
    }
}

#[bitfield(u64)]
pub struct ControlRegister4 {
    pub vme: bool,
    pub pvi: bool,
    pub tsd: bool,
    pub de: bool,
    pub pse: bool,
    pub pae: bool,
    pub mce: bool,
    pub pge: bool,
    pub pce: bool,
    pub osfxsr: bool,
    pub osmmexcept: bool,
    pub unip: bool,
    pub la57: bool,
    pub vmxe: bool,
    pub smxr: bool,
    _pad0: bool,

    pub fsgsbase: bool,
    pub pcide: bool,
    pub osxsave: bool,
    _pad1: bool,

    pub smep: bool,
    pub smap: bool,
    pub pke: bool,
    pub cet: bool,
    pub pks: bool,

    #[bits(39)]
    _pad2: u64,
}

#[bitfield(u64)]
pub struct ExtFeatureEnableReg {
    pub sce: bool,

    #[bits(7)]
    _pad0: u8,

    pub lme: bool,
    _pad1: bool,

    pub lma: bool,
    pub nxe: bool,
    pub svme: bool,
    pub lmsle: bool,
    pub ffxsr: bool,
    pub tce: bool,

    #[bits(48)]
    _pad2: u64,
}

fn common_regs() -> Vec<X86Register> {
    let tab = TableRegister {
        base: 0,
        limit: 0xffff,
    };
    vec![
        // PAT reset default: WB, WT, UC-, UC, WB, WT, UC-, UC (AMD APM Vol 2)
        X86Register::Pat(0x0007040600070406),
        X86Register::Gdtr(tab),
        X86Register::Idtr(tab),
    ]
}

pub fn real_mode_regs_at(reset_addr: u32) -> Vec<X86Register> {
    let cr0 = ControlRegister0::reset_fast().into();
    let code = SegmentRegister {
        base: (reset_addr & 0xffff0000) as u64,
        limit: 0xffff,
        selector: 0xf000,
        attributes: SegmentAttributes::code16().into(),
    };
    let data = SegmentRegister {
        base: 0,
        limit: 0xffff,
        selector: 0,
        attributes: SegmentAttributes::data16().into(),
    };
    let tss = SegmentRegister {
        base: 0,
        limit: 0xffff,
        selector: 0,
        attributes: SegmentAttributes::tss16().into(),
    };
    let mut regs = vec![
        X86Register::Cr0(cr0),
        X86Register::Rip((reset_addr & 0xffff) as u64),
        X86Register::Cs(code),
        X86Register::Ss(data),
        X86Register::Ds(data),
        X86Register::Es(data),
        X86Register::Fs(data),
        X86Register::Gs(data),
        X86Register::Tr(tss),
    ];

    regs.append(&mut common_regs());
    regs
}

pub fn flat32_mode_regs(rip: Option<u64>) -> Vec<X86Register> {
    let cr0 = ControlRegister0::reset_fast()
        .with_pe(true)
        .with_ne(true)
        .into();
    let code = SegmentRegister {
        base: 0,
        limit: 0xffffffff,
        selector: 0x08,
        attributes: SegmentAttributes::code32().into(),
    };
    let data = SegmentRegister {
        base: 0,
        limit: 0xffffffff,
        selector: 0x10,
        attributes: SegmentAttributes::data32().into(),
    };
    let tss = SegmentRegister {
        base: 0,
        limit: 0xffff,
        selector: 0,
        attributes: SegmentAttributes::tss3264().into(),
    };
    let mut regs = vec![
        X86Register::Cr0(cr0),
        X86Register::Rip(rip.unwrap_or(0xfffffff0)),
        X86Register::Cs(code),
        X86Register::Ss(data),
        X86Register::Ds(data),
        X86Register::Es(data),
        X86Register::Fs(data),
        X86Register::Gs(data),
        X86Register::Tr(tss),
    ];

    regs.append(&mut common_regs());
    regs
}

pub fn native_context(regs: &[X86Register]) -> IgvmNativeVpContextX64 {
    let mut ctx = IgvmNativeVpContextX64::new_zeroed();

    for r in regs {
        match r {
            X86Register::Rip(rip) => ctx.rip = *rip,
            X86Register::Cr0(cr0) => ctx.cr0 = *cr0,
            X86Register::Gdtr(tab) => {
                ctx.gdtr_base = tab.base;
                ctx.gdtr_limit = tab.limit;
            }
            X86Register::Idtr(tab) => {
                ctx.idtr_base = tab.base;
                ctx.idtr_limit = tab.limit;
            }
            X86Register::Cs(seg) => {
                ctx.code_base = seg.base as u32;
                ctx.code_limit = seg.limit;
                ctx.code_selector = seg.selector;
                ctx.code_attributes = seg.attributes;
            }
            X86Register::Ds(seg) => {
                ctx.data_base = seg.base as u32;
                ctx.data_limit = seg.limit;
                ctx.data_selector = seg.selector;
                ctx.data_attributes = seg.attributes;
            }
            X86Register::Gs(seg) => {
                ctx.gs_base = seg.base;
            }
            X86Register::Ss(_)
            | X86Register::Es(_)
            | X86Register::Fs(_)
            | X86Register::Tr(_)
            | X86Register::Pat(_) => {}
            _ => {
                panic!("native_context: not implemented: {r:?}");
            }
        }
    }

    ctx
}

fn vmsa_segment(seg: &SegmentRegister) -> SevSelector {
    // ALGORITHM: Attribute packing for SevVmsa format.
    // SevSelector uses 12-bit attributes: bits [7:0] direct, bits [11:8] from [15:12].
    // The 4 limit bits [11:8] in the middle of the 16-bit SegmentAttributes are dropped.
    let attrib = (seg.attributes & 0xff) | ((seg.attributes & 0xf000) >> 4);
    SevSelector {
        base: seg.base,
        limit: seg.limit,
        selector: seg.selector,
        attrib,
    }
}

fn vmsa_table(tab: &TableRegister) -> SevSelector {
    SevSelector {
        base: tab.base,
        limit: tab.limit as u32,
        selector: 0,
        attrib: 0,
    }
}

/// Construct an SEV VMSA from a register list and SEV feature flags.
///
/// Sets AMD architectural reset defaults for fields not in `X86Register`:
/// - `dr6 = 0xffff0ff0` — AMD architectural reset value
/// - `dr7 = 0x400` — AMD architectural reset value
/// - `xcr0 = 1` — enables x87 FPU state
/// - `x87_fcw = 0x37f` — FPU control word reset default
/// - `mxcsr = 0x1f80` — SSE control/status reset default
///
/// Also enables SVM in EFER (required for SEV guests).
pub fn vmsa_context(regs: &[X86Register], features: SevFeatures) -> SevVmsa {
    let mut vmsa = SevVmsa::new_zeroed();

    // Reset defaults (AMD APM Vol 2)
    vmsa.dr6 = 0xffff0ff0;
    vmsa.dr7 = 0x400;
    vmsa.xcr0 = 1;
    vmsa.x87_fcw = 0x37f;
    vmsa.mxcsr = 0x1f80;

    vmsa.sev_features = features;

    for r in regs {
        match r {
            X86Register::Rip(rip) => vmsa.rip = *rip,
            X86Register::Cr0(cr0) => vmsa.cr0 = *cr0,
            X86Register::Pat(pat) => vmsa.pat = *pat,
            X86Register::Gdtr(tab) => vmsa.gdtr = vmsa_table(tab),
            X86Register::Idtr(tab) => vmsa.idtr = vmsa_table(tab),
            X86Register::Cs(seg) => vmsa.cs = vmsa_segment(seg),
            X86Register::Ss(seg) => vmsa.ss = vmsa_segment(seg),
            X86Register::Ds(seg) => vmsa.ds = vmsa_segment(seg),
            X86Register::Es(seg) => vmsa.es = vmsa_segment(seg),
            X86Register::Fs(seg) => vmsa.fs = vmsa_segment(seg),
            X86Register::Gs(seg) => vmsa.gs = vmsa_segment(seg),
            X86Register::Tr(seg) => vmsa.tr = vmsa_segment(seg),
            _ => {
                panic!("vmsa_context: not implemented: {r:?}");
            }
        }
    }

    // AMD fixup: enable SVM in EFER
    vmsa.efer |= u64::from(ExtFeatureEnableReg::new().with_svme(true));

    vmsa
}
