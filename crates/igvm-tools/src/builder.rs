// This module exists because building an IGVM file requires precise page placement,
// platform configuration, and directive ordering. No existing crate provides a
// unified build pipeline (wrap + update in one pass). The closest is virt-firmware-rs
// builder.rs which requires a two-step serialize→parse round-trip with igvm-update.
//
// NOTE: This module targets QEMU+KVM. Page ordering and directive layout are
// designed to match QEMU's IGVM loading behavior.
//
// Pages must be sorted by GPA at finalization. QEMU/KVM processes
// directives in file order; GPA ordering determines measurement order.
// SNP special pages (SECRETS, CPUID) must use correct IgvmPageDataType.
// Parameter areas must be placed before ParameterInsert directives.
// Firmware must be mapped at (4GB - firmware_size) for 4G region.
//   For 1M region, the firmware tail (last min(128KB, fw_size) bytes) is mapped
//   ending at 1MB.
// VMSA GPA is always 0xFFFFFFFFF000 for all vCPUs.
// IgvmParamArea GPAs must not get duplicate PageData entries from
// add_ovmf_snp_pages (they're covered by ParameterInsert).

use std::cmp::{min, Ordering};

use igvm::snp_defs::SevFeatures;
use igvm::{
    registers::X86Register, Arch, IgvmDirectiveHeader, IgvmFile, IgvmInitializationHeader,
    IgvmPlatformHeader, IgvmRevision,
};
use igvm_defs::{
    IgvmPageDataFlags, IgvmPageDataType, IgvmPlatformType, SnpPolicy, IGVM_VHS_PARAMETER,
    IGVM_VHS_PARAMETER_INSERT, IGVM_VHS_SUPPORTED_PLATFORM, PAGE_SIZE_4K,
};

use crate::ovmfmeta::{OvmfMeta, OvmfRegionType};
use crate::x86regs::{native_context, vmsa_context};

pub const NATIVE_COMPAT: u32 = 1u32 << 0;
pub const SEV_SNP_COMPAT: u32 = 1u32 << 1;

/// IGVM file builder for constructing confidential VM images.
///
/// Lifecycle: `new()` → `add_*()` calls → `finalize()`.
/// `finalize()` sorts directives by GPA before producing the `IgvmFile`.
pub struct Builder {
    revision: IgvmRevision,
    platforms: Vec<IgvmPlatformHeader>,
    initializations: Vec<IgvmInitializationHeader>,
    directives: Vec<IgvmDirectiveHeader>,
    compatibility_mask_all: u32,
}

impl Builder {
    fn revision() -> IgvmRevision {
        IgvmRevision::V2 {
            arch: Arch::X64,
            page_size: PAGE_SIZE_4K.try_into().expect("PAGE_SIZE_4K fits u32"),
        }
    }

    pub fn new() -> Builder {
        Builder {
            revision: Self::revision(),
            platforms: Vec::new(),
            initializations: Vec::new(),
            directives: Vec::new(),
            compatibility_mask_all: 0,
        }
    }

    // --- Platform configuration ---

    /// Add a NATIVE (non-SNP) platform. Uses VTL 2 and platform_version 1,
    /// which are standard defaults for QEMU+KVM.
    pub fn add_native_platform(&mut self) -> &mut Builder {
        let native = IgvmPlatformHeader::SupportedPlatform(IGVM_VHS_SUPPORTED_PLATFORM {
            compatibility_mask: NATIVE_COMPAT,
            highest_vtl: 2,
            platform_type: IgvmPlatformType::NATIVE,
            platform_version: 1,
            shared_gpa_boundary: 0,
        });
        self.compatibility_mask_all |= NATIVE_COMPAT;
        self.platforms.push(native);
        self
    }

    /// Add an SEV-SNP platform. Uses VTL 2 and platform_version 1,
    /// which are standard defaults for QEMU+KVM.
    pub fn add_snp_platform(&mut self) -> &mut Builder {
        let snp = IgvmPlatformHeader::SupportedPlatform(IGVM_VHS_SUPPORTED_PLATFORM {
            compatibility_mask: SEV_SNP_COMPAT,
            highest_vtl: 2,
            platform_type: IgvmPlatformType::SEV_SNP,
            platform_version: 1,
            shared_gpa_boundary: 0,
        });
        self.compatibility_mask_all |= SEV_SNP_COMPAT;
        self.platforms.push(snp);
        self
    }

    // --- CPU context ---

    pub fn add_native_context(&mut self, regs: &[X86Register]) -> &mut Builder {
        let native = native_context(regs);
        let ctx = IgvmDirectiveHeader::X64NativeVpContext {
            compatibility_mask: NATIVE_COMPAT,
            vp_index: 0,
            context: Box::new(native),
        };
        self.directives.push(ctx);
        self
    }

    pub fn add_snp_vmsa_context(
        &mut self,
        regs: &[X86Register],
        debug: bool,
        vp_index: u16,
    ) -> &mut Builder {
        let features = SevFeatures::new().with_snp(true).with_debug_swap(debug);
        let vmsa = vmsa_context(regs, features);
        let gpa = 0xFFFFFFFFF000;
        let ctx = IgvmDirectiveHeader::SnpVpContext {
            gpa,
            compatibility_mask: SEV_SNP_COMPAT,
            vp_index,
            vmsa: Box::new(vmsa),
        };
        self.directives.push(ctx);
        self
    }

    pub fn add_snp_policy(&mut self, snp_policy: Option<SnpPolicy>) -> &mut Builder {
        let default_policy = SnpPolicy::new().with_reserved_must_be_one(1).with_smt(1);
        let policy = IgvmInitializationHeader::GuestPolicy {
            policy: snp_policy.unwrap_or(default_policy).into(),
            compatibility_mask: SEV_SNP_COMPAT,
        };
        self.initializations.push(policy);
        self
    }

    // --- Page directives ---

    pub fn add_empty_pages(
        &mut self,
        base: usize,
        size: usize,
        compatibility_mask: u32,
        data_type: IgvmPageDataType,
    ) -> &mut Builder {
        let psize = PAGE_SIZE_4K as usize;
        let pages = size.div_ceil(psize);
        for pg in 0..pages {
            let start = pg * psize;
            let page = IgvmDirectiveHeader::PageData {
                gpa: (base + start) as u64,
                compatibility_mask,
                flags: IgvmPageDataFlags::new(),
                data_type,
                data: vec![],
            };
            self.directives.push(page);
        }
        self
    }

    pub fn add_empty_normal_pages(&mut self, base: usize, size: usize) -> &mut Builder {
        self.add_empty_pages(
            base,
            size,
            self.compatibility_mask_all,
            IgvmPageDataType::NORMAL,
        )
    }

    pub fn add_ovmf_snp_pages(&mut self, ovmfmeta: &OvmfMeta) -> &mut Builder {
        // Collect IgvmParamArea GPAs — these are covered by ParameterInsert
        // directives and must not get duplicate PageData entries.
        let mut param_gpas: Vec<(usize, usize)> = Vec::new();
        for r in &ovmfmeta.regions {
            if r.etype == OvmfRegionType::IgvmParamArea {
                param_gpas.push((r.memory.0, r.memory.1));
            }
        }

        for r in &ovmfmeta.regions {
            let itype = match r.etype {
                OvmfRegionType::SevMemory
                | OvmfRegionType::SevSvsmCca
                | OvmfRegionType::SevHashes => Some(IgvmPageDataType::NORMAL),
                OvmfRegionType::SevSecrets => Some(IgvmPageDataType::SECRETS),
                OvmfRegionType::SevCpuid => Some(IgvmPageDataType::CPUID_DATA),
                _ => None,
            };
            if let Some(t) = itype {
                let psize = PAGE_SIZE_4K as usize;
                let pages = r.memory.1.div_ceil(psize);
                for pg in 0..pages {
                    let gpa = r.memory.0 + pg * psize;
                    let overlaps = param_gpas
                        .iter()
                        .any(|&(base, size)| gpa >= base && gpa < base + size);
                    if !overlaps {
                        self.add_empty_pages(gpa, psize, SEV_SNP_COMPAT, t);
                    }
                }
            }
        }
        self
    }

    // --- IGVM parameters ---

    pub fn add_igvm_param_area(&mut self, index: u32, bytes: u64) {
        self.directives.push(IgvmDirectiveHeader::ParameterArea {
            parameter_area_index: index,
            number_of_bytes: bytes,
            initial_data: Vec::new(),
        });
    }

    fn add_igvm_param<P>(&mut self, mkdirective: P, index: u32, offset: u32)
    where
        P: FnOnce(IGVM_VHS_PARAMETER) -> IgvmDirectiveHeader,
    {
        let param = IGVM_VHS_PARAMETER {
            parameter_area_index: index,
            byte_offset: offset,
        };
        self.directives.push(mkdirective(param));
    }

    pub fn add_igvm_param_memmap(&mut self, index: u32, offset: u32) {
        self.add_igvm_param(IgvmDirectiveHeader::MemoryMap, index, offset);
    }

    pub fn add_igvm_param_vpcount(&mut self, index: u32, offset: u32) {
        self.add_igvm_param(IgvmDirectiveHeader::VpCount, index, offset);
    }

    pub fn add_igvm_param_insert(&mut self, index: u32, gpa: u64) {
        self.directives.push(IgvmDirectiveHeader::ParameterInsert(
            IGVM_VHS_PARAMETER_INSERT {
                parameter_area_index: index,
                gpa,
                compatibility_mask: self.compatibility_mask_all,
            },
        ));
    }

    pub fn add_ovmf_igvm_params(&mut self, ovmfmeta: &OvmfMeta) -> &mut Builder {
        let Some(area) = &ovmfmeta
            .regions
            .iter()
            .find(|r| r.etype == OvmfRegionType::IgvmParamArea)
        else {
            return self;
        };

        self.add_igvm_param_area(0, area.memory.1 as u64);
        for r in &ovmfmeta.regions {
            match r.etype {
                OvmfRegionType::IgvmParamMemoryMap => {
                    self.add_igvm_param_memmap(0, r.memory.0 as u32);
                }
                OvmfRegionType::IgvmParamVpCount => {
                    self.add_igvm_param_vpcount(0, r.memory.0 as u32);
                }
                _ => {}
            }
        }
        self.add_igvm_param_insert(0, area.memory.0 as u64);

        self
    }

    // --- Data pages ---

    pub fn add_data_pages_flags(
        &mut self,
        base: usize,
        data: &[u8],
        flags: IgvmPageDataFlags,
    ) -> &mut Builder {
        let psize = PAGE_SIZE_4K as usize;
        let pages = data.len().div_ceil(psize);
        for pg in 0..pages {
            let start = pg * psize;
            let end = min(start + psize, data.len());
            let page = IgvmDirectiveHeader::PageData {
                gpa: (base + start) as u64,
                compatibility_mask: self.compatibility_mask_all,
                flags,
                data_type: IgvmPageDataType::NORMAL,
                data: data[start..end].to_vec(),
            };
            self.directives.push(page);
        }
        self
    }

    pub fn add_data_pages(&mut self, base: usize, data: &[u8]) -> &mut Builder {
        self.add_data_pages_flags(base, data, IgvmPageDataFlags::new())
    }

    pub fn add_data_pages_unmeasured(&mut self, base: usize, data: &[u8]) -> &mut Builder {
        self.add_data_pages_flags(base, data, IgvmPageDataFlags::new().with_unmeasured(true))
    }

    pub fn remove_page_data_in_range(&mut self, base: usize, size: usize) -> &mut Builder {
        let psize = PAGE_SIZE_4K as usize;
        self.directives.retain(|d| {
            if let IgvmDirectiveHeader::PageData { gpa, .. } = d {
                let page_gpa = *gpa as usize;
                if page_gpa >= base && page_gpa < base + size.max(psize) {
                    return false;
                }
            }
            true
        });
        self
    }

    // --- Firmware loading ---

    pub fn add_firmware_4g(&mut self, firmware: &[u8]) -> &mut Builder {
        let fwbase = (1u64 << 32) as usize - firmware.len();
        self.add_data_pages(fwbase, firmware)
    }

    pub fn add_firmware_1m(&mut self, firmware: &[u8]) -> &mut Builder {
        let lowsize = min(128 * 1024, firmware.len());
        let lowbase = (1u64 << 20) as usize - lowsize;
        let offset = firmware.len() - lowsize;
        self.add_data_pages(lowbase, &firmware[offset..])
    }

    pub fn add_uefivars(&mut self, uefivars: &[u8], fwsize: usize) -> &mut Builder {
        let varsbase = (1u64 << 32) as usize - uefivars.len() - fwsize;
        self.add_data_pages(varsbase, uefivars)
    }

    // --- Finalization ---

    // Non-PageData directives sort as GPA 0, placing them before all page data.
    // Rust's sort_by is stable, so non-PageData directives preserve insertion order
    // among themselves. This matches the expected directive order for QEMU+KVM.
    fn sort_pages(a: &IgvmDirectiveHeader, b: &IgvmDirectiveHeader) -> Ordering {
        let a_gpa = if let IgvmDirectiveHeader::PageData { gpa, .. } = a {
            gpa
        } else {
            &0
        };
        let b_gpa = if let IgvmDirectiveHeader::PageData { gpa, .. } = b {
            gpa
        } else {
            &0
        };
        a_gpa.cmp(b_gpa)
    }

    pub fn finalize(&self) -> Result<IgvmFile, igvm::Error> {
        let mut directives = self.directives.clone();
        directives.sort_by(Self::sort_pages);
        IgvmFile::new(
            self.revision,
            self.platforms.clone(),
            self.initializations.clone(),
            directives,
        )
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}
