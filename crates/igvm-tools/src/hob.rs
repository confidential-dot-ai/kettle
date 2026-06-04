// This module exists because OVMF firmware discovers kernel/shim/cert data
// through EFI Hand-Off Blocks (HOBs) placed in a designated memory area.
// No existing crate outside virtfw-libefi provides these structures, and
// depending on that crate brings ~5 transitive deps we don't need.
//
// EfiIgvmDataHob must be exactly 0x30 (48) bytes, repr(C), matching
// the structure OVMF firmware parses in EfiIgvmDataHobGuid handler.
// GUID bytes must match 3dd177ff-b632-4e25-bef3-065063d55fc4 exactly.
// HOB list must end with 8-byte end-of-list marker (type=0xFFFF, len=8).
// Blob addresses must be 4K-page-aligned and sequential from base.

use std::mem::size_of;

use uguid::{guid, Guid};
use zerocopy::{FromBytes, Immutable, IntoBytes};

const PAGE_SIZE_4K: usize = 4096;

const EFI_HOB_TYPE_GUID_EXTENSION: u16 = 0x0004;
const EFI_HOB_TYPE_END_OF_HOB_LIST: u16 = 0xFFFF;

pub const EFI_IGVM_DATA_HOB_GUID: Guid = guid!("3dd177ff-b632-4e25-bef3-065063d55fc4");

// --- Binary structures (must match OVMF's parsing exactly) ---

#[repr(C)]
#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable)]
struct EfiHobHeader {
    hob_type: u16,
    hob_length: u16,
    _reserved: u32,
}

impl EfiHobHeader {
    fn new(hob_type: u16, hob_length: u16) -> Self {
        Self {
            hob_type,
            hob_length,
            _reserved: 0,
        }
    }

    fn end_of_list() -> Self {
        Self::new(EFI_HOB_TYPE_END_OF_HOB_LIST, size_of::<Self>() as u16)
    }
}

/// 16-byte raw GUID in EFI wire format (first 3 fields LE, last 8 bytes as-is).
/// uguid::Guid::to_bytes() produces exactly this layout.
#[repr(C)]
#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable)]
struct RawGuid {
    bytes: [u8; 16],
}

impl From<Guid> for RawGuid {
    fn from(guid: Guid) -> Self {
        Self {
            bytes: guid.to_bytes(),
        }
    }
}

/// HOB entry describing a data blob placed in guest memory.
/// OVMF reads these to locate kernel, shim, and secure boot cert data.
#[repr(C)]
#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable)]
struct EfiIgvmDataHob {
    hdr: EfiHobHeader,
    guid_ext: RawGuid,
    address: u64,
    length: u64,
    data_type: u32,
    data_flags: u32,
}

// Compile-time check: OVMF expects exactly 0x30 bytes.
const _: () = assert!(size_of::<EfiIgvmDataHob>() == 0x30);

impl EfiIgvmDataHob {
    fn new(address: usize, length: usize, data_type: IgvmDataType) -> Self {
        Self {
            hdr: EfiHobHeader::new(
                EFI_HOB_TYPE_GUID_EXTENSION,
                size_of::<EfiIgvmDataHob>() as u16,
            ),
            guid_ext: EFI_IGVM_DATA_HOB_GUID.into(),
            address: address as u64,
            length: length as u64,
            data_type: data_type as u32,
            data_flags: 0,
        }
    }
}

// --- Public API ---

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum IgvmDataType {
    Pk = 0x100,
    Kek = 0x101,
    Db = 0x102,
    Dbx = 0x103,
    Shim = 0x200,
    Kernel = 0x201,
}

struct IgvmDataEntry<'b> {
    hob: EfiIgvmDataHob,
    addr: usize,
    blob: &'b [u8],
    measured: bool,
}

/// Manages a list of data blobs (kernel, shim, certs) to be placed in guest memory
/// and described via HOB entries for OVMF to discover.
pub struct IgvmDataList<'b> {
    base: usize,
    data: Vec<IgvmDataEntry<'b>>,
}

impl<'b> IgvmDataList<'b> {
    /// Create a new list. `base` is the starting GPA for blob placement (typically 0x20000000).
    pub fn new(base: usize) -> Self {
        Self {
            base,
            data: Vec::new(),
        }
    }

    /// Add a data blob. Address is auto-assigned sequentially, 4K-aligned.
    pub fn add(&mut self, blob: &'b [u8], data_type: IgvmDataType, measured: bool) {
        let hob = EfiIgvmDataHob::new(self.base, blob.len(), data_type);
        let addr = self.base;
        self.data.push(IgvmDataEntry {
            hob,
            addr,
            blob,
            measured,
        });
        self.base += blob.len().next_multiple_of(PAGE_SIZE_4K);
    }

    /// Serialize all HOB entries + end-of-list marker into a byte vector.
    /// This blob goes into the OVMF HOB area.
    pub fn hobs(&self) -> Vec<u8> {
        let mut blob = Vec::new();
        for d in &self.data {
            blob.extend_from_slice(d.hob.as_bytes());
        }
        blob.extend_from_slice(EfiHobHeader::end_of_list().as_bytes());
        blob
    }

    /// Return (address, data) pairs filtered by measured/unmeasured.
    /// Measured blobs → add_data_pages (included in SNP digest).
    /// Unmeasured blobs → add_data_pages_unmeasured.
    pub fn blobs(&self, measured: bool) -> Vec<(usize, &'b [u8])> {
        self.data
            .iter()
            .filter(|d| d.measured == measured)
            .map(|d| (d.addr, d.blob))
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn entry_count(&self) -> usize {
        self.data.len()
    }
}
