// This module exists because OVMF firmware embeds metadata (region descriptors,
// reset addresses, parameter areas) in a GUID-tagged binary format at the tail
// of the firmware image. No existing crate parses this. The format is defined by
// OvmfPkg/ResetVector/Ia32/AmdSev.asm in the edk2 source tree.
//
// Parsed regions must exactly match the firmware's embedded metadata.
// An incorrect base/size causes pages to be placed at wrong GPAs, producing a
// wrong launch digest. Verified against multiple OVMF builds.
//
// sev_reset_addr must be extracted from OVMF_META_SEV_RESET if present.
// This is the AP startup vector required for SMP > 1.

use std::fmt;
use std::mem::size_of;
use uguid::{guid, Guid};
use zerocopy::byteorder::little_endian::U16;
use zerocopy::{FromBytes, Unalign};

/// OVMF metadata list header GUID.
pub const OVMF_META_LIST: Guid = guid!("96b582de-1fb2-45f7-baea-a366c55a082d");
/// SEV-ES reset address block GUID.
pub const OVMF_META_SEV_RESET: Guid = guid!("00f771de-1a7e-4fcb-890e-68c77e2fb44e");
/// SEV secret page region GUID.
pub const OVMF_META_SEV_SECRET: Guid = guid!("4c2eb361-7d9b-4cc3-8081-127c90d3d294");
/// SEV launch digest hashes region GUID.
pub const OVMF_META_SEV_HASHES: Guid = guid!("7255371f-3a3b-4b04-927b-1da6efa8d454");
/// SEV region list GUID (contains SNP special page descriptors).
pub const OVMF_META_SEV_LIST: Guid = guid!("dc886566-984a-4798-a75e-5585a7bf67cc");
/// IGVM parameter area list GUID (contains param area, memory map, VP count regions).
pub const OVMF_META_IGVM_PARAM: Guid = guid!("784fa70e-3176-4677-8a20-04b68699e374");

#[repr(C, packed)]
#[derive(Debug, FromBytes)]
struct OvmfMetaBlock {
    size: Unalign<U16>,
    guid: [u8; 16],
}

#[repr(C, packed)]
#[derive(Debug, FromBytes)]
struct OvmfMetaListHead {
    magic: u32,
    length: u32,
    version: u32,
    entries: u32,
}

#[repr(C, packed)]
#[derive(Debug, FromBytes)]
struct OvmfMetaSevIgvmEntry {
    base: u32,
    size: u32,
    kind: u32,
}

#[derive(Debug, Eq, PartialEq)]
pub enum OvmfRegionType {
    Undefined,

    SevMemory,
    SevSecrets,
    SevCpuid,
    SevSvsmCca,
    SevHashes,

    IgvmParamArea,
    IgvmParamMemoryMap,
    IgvmParamVpCount,
    IgvmHobArea,
}

impl OvmfRegionType {
    pub fn new_sev(t: u32) -> OvmfRegionType {
        match t {
            0x01 => OvmfRegionType::SevMemory,
            0x02 => OvmfRegionType::SevSecrets,
            0x03 => OvmfRegionType::SevCpuid,
            0x04 => OvmfRegionType::SevSvsmCca,
            0x10 => OvmfRegionType::SevHashes,
            _ => OvmfRegionType::Undefined,
        }
    }

    pub fn new_igvm(t: u32) -> OvmfRegionType {
        match t {
            0x100 => OvmfRegionType::IgvmParamArea,
            0x101 => OvmfRegionType::IgvmParamMemoryMap,
            0x102 => OvmfRegionType::IgvmParamVpCount,
            0x200 => OvmfRegionType::IgvmHobArea,
            _ => OvmfRegionType::Undefined,
        }
    }
}

#[derive(Debug)]
pub struct OvmfRegion {
    pub memory: (usize, usize),
    pub etype: OvmfRegionType,
}

impl OvmfRegion {
    fn new_sev(entry: &OvmfMetaSevIgvmEntry) -> OvmfRegion {
        OvmfRegion {
            memory: (entry.base as usize, entry.size as usize),
            etype: OvmfRegionType::new_sev(entry.kind),
        }
    }

    fn new_igvm(entry: &OvmfMetaSevIgvmEntry) -> OvmfRegion {
        OvmfRegion {
            memory: (entry.base as usize, entry.size as usize),
            etype: OvmfRegionType::new_igvm(entry.kind),
        }
    }
}

impl fmt::Display for OvmfRegion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "0x{:08x} +0x{:x}  {:?}",
            self.memory.0, self.memory.1, self.etype
        )
    }
}

pub struct OvmfMeta<'f> {
    firmware: &'f [u8],
    pub regions: Vec<OvmfRegion>,
    pub sev_reset_addr: Option<u32>,
}

impl OvmfMeta<'_> {
    fn meta_blk(blob: &[u8]) -> Option<(Guid, &[u8], &[u8])> {
        let (data, meta) = OvmfMetaBlock::read_from_suffix(blob).ok()?;
        let size: u16 = meta.size.get().into();
        let dsize = (size as usize).checked_sub(size_of::<OvmfMetaBlock>())?;
        let start = data.len().checked_sub(dsize)?;
        let (other, blk) = data.split_at_checked(start)?;
        Some((Guid::from_bytes(meta.guid), blk, other))
    }

    fn parse_blk(&mut self, guid: Guid, blk: &[u8]) -> Option<()> {
        match guid {
            OVMF_META_SEV_RESET => {
                let (addr, _) = u32::read_from_prefix(blk).ok()?;
                self.sev_reset_addr = Some(addr);
            }
            OVMF_META_SEV_SECRET | OVMF_META_SEV_HASHES => {
                // Parsed but not stored separately — these appear in SEV_LIST regions.
            }
            OVMF_META_SEV_LIST => {
                let (listbase, _) = u32::read_from_prefix(blk).ok()?;
                let start = self.firmware.len().checked_sub(listbase as usize)?;
                let sev = self.firmware.get(start..)?;
                let (head, mut items) = OvmfMetaListHead::read_from_prefix(sev).ok()?;
                for _ in 0..head.entries {
                    let (e, r) = OvmfMetaSevIgvmEntry::read_from_prefix(items).ok()?;
                    if e.size != 0 {
                        self.regions.push(OvmfRegion::new_sev(&e));
                    }
                    items = r;
                }
            }
            OVMF_META_IGVM_PARAM => {
                let (listbase, _) = u32::read_from_prefix(blk).ok()?;
                let start = self.firmware.len().checked_sub(listbase as usize)?;
                let param = self.firmware.get(start..)?;
                let (head, mut items) = OvmfMetaListHead::read_from_prefix(param).ok()?;
                for _ in 0..head.entries {
                    let (e, r) = OvmfMetaSevIgvmEntry::read_from_prefix(items).ok()?;
                    if e.size != 0 {
                        self.regions.push(OvmfRegion::new_igvm(&e));
                    }
                    items = r;
                }
            }
            _ => {}
        }
        Some(())
    }

    pub fn new(firmware: &[u8]) -> Option<OvmfMeta<'_>> {
        let mut ovmfmeta = OvmfMeta {
            firmware,
            regions: Vec::new(),
            sev_reset_addr: None,
        };

        let s = firmware.len().checked_sub(0x20)?;
        let f = firmware.get(..s)?;
        let (g, mut m1, _) = Self::meta_blk(f)?;

        if g == OVMF_META_LIST {
            loop {
                let Some((g, b, m2)) = Self::meta_blk(m1) else {
                    break;
                };
                ovmfmeta.parse_blk(g, b);
                m1 = m2;
            }
        }

        Some(ovmfmeta)
    }

    pub fn print(&self) {
        eprintln!("OVMF regions:");
        for r in &self.regions {
            eprintln!("  {r}");
        }
        if let Some(addr) = self.sev_reset_addr {
            eprintln!("  SEV reset addr: 0x{addr:08x}");
        }
    }
}
