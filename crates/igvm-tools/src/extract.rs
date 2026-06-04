//! Recover the kernel (UKI) command line embedded in an IGVM file.
//!
//! The launch-measured "kernel" blob in a QEMU+KVM IGVM is a UKI (a PE/COFF
//! image bundling kernel + initrd + cmdline). This module locates that blob via
//! the IGVM HOB list, reassembles it from the measured page data, and reads the
//! `.cmdline` PE section — the boot command line that, for steep images, carries
//! `roothash=`.

use std::collections::BTreeMap;

use igvm::{IgvmDirectiveHeader, IgvmFile};

const PAGE_SIZE: u64 = 4096;

/// Read a little-endian u32 at `off`, or `None` if out of range.
fn u32_at(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

/// Parse a PE/COFF image and return the contents of its `.cmdline` section as a
/// trimmed UTF-8 string. Errors if the image is not PE or has no `.cmdline`.
pub fn parse_pe_cmdline(image: &[u8]) -> Result<String, String> {
    if image.len() < 0x40 || &image[0..2] != b"MZ" {
        return Err("kernel blob is not a PE image (no MZ header)".into());
    }
    let pe_off = u32_at(image, 0x3c).ok_or("truncated DOS header")? as usize;
    if image.get(pe_off..pe_off + 4) != Some(b"PE\0\0") {
        return Err("kernel blob is not a PE image (no PE signature)".into());
    }
    let coff = pe_off + 4;
    let num_sections = image
        .get(coff + 2..coff + 4)
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
        .ok_or("truncated COFF header")? as usize;
    let opt_size = image
        .get(coff + 16..coff + 18)
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
        .ok_or("truncated COFF header")? as usize;
    let mut sec = coff + 20 + opt_size;
    for _ in 0..num_sections {
        let name = image.get(sec..sec + 8).ok_or("truncated section table")?;
        if name == b".cmdline" {
            let size = u32_at(image, sec + 16).ok_or("truncated section header")? as usize;
            let ptr = u32_at(image, sec + 20).ok_or("truncated section header")? as usize;
            let raw = image
                .get(ptr..ptr + size)
                .ok_or("`.cmdline` section out of bounds")?;
            let text = raw.split(|&b| b == 0).next().unwrap_or(raw);
            return Ok(String::from_utf8_lossy(text).trim().to_string());
        }
        sec += 40;
    }
    Err("kernel UKI has no `.cmdline` section".into())
}

/// data_type value for the kernel blob in an EfiIgvmDataHob (see `hob::IgvmDataType::Kernel`).
const HOB_DATA_TYPE_KERNEL: u32 = 0x201;

/// Build a gpa→page map of every measured `PageData` page in the IGVM.
fn page_map(igvm: &IgvmFile) -> BTreeMap<u64, Vec<u8>> {
    let mut map = BTreeMap::new();
    for d in igvm.directives() {
        if let IgvmDirectiveHeader::PageData { gpa, data, .. } = d {
            if !data.is_empty() {
                let mut page = vec![0u8; PAGE_SIZE as usize];
                let n = data.len().min(PAGE_SIZE as usize);
                page[..n].copy_from_slice(&data[..n]);
                map.insert(*gpa, page);
            }
        }
    }
    map
}

/// Group the page map into contiguous (gpa-stepped) byte runs: (start_gpa, bytes).
fn contiguous_runs(pages: &BTreeMap<u64, Vec<u8>>) -> Vec<(u64, Vec<u8>)> {
    let mut runs: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut cur_start: Option<u64> = None;
    let mut cur_next = 0u64;
    let mut cur: Vec<u8> = Vec::new();
    for (&gpa, page) in pages {
        match cur_start {
            Some(_) if gpa == cur_next => {}
            _ => {
                if let Some(start) = cur_start {
                    runs.push((start, std::mem::take(&mut cur)));
                }
                cur_start = Some(gpa);
            }
        }
        cur.extend_from_slice(page);
        cur_next = gpa + PAGE_SIZE;
    }
    if let Some(start) = cur_start {
        runs.push((start, cur));
    }
    runs
}

/// Find the kernel blob's (guest address, length) by scanning the measured page
/// data for EfiIgvmDataHob entries (matched by the 16-byte HOB GUID) and picking
/// the one whose data_type is Kernel.
pub fn find_kernel_blob(pages: &BTreeMap<u64, Vec<u8>>) -> Result<(u64, u64), String> {
    let guid = crate::hob::EFI_IGVM_DATA_HOB_GUID.to_bytes();
    for (_start, bytes) in contiguous_runs(pages) {
        let mut i = 0usize;
        while i + 0x30 <= bytes.len() {
            // GUID sits at offset 8 within the 0x30-byte struct.
            if i >= 8 && bytes[i..i + 16] == guid {
                let base = i - 8;
                let data_type = u32_at(&bytes, base + 0x28).unwrap_or(0);
                if data_type == HOB_DATA_TYPE_KERNEL {
                    let address = u64::from_le_bytes(bytes[base + 0x18..base + 0x20].try_into().unwrap());
                    let length = u64::from_le_bytes(bytes[base + 0x20..base + 0x28].try_into().unwrap());
                    return Ok((address, length));
                }
            }
            i += 1;
        }
    }
    Err("no kernel HOB found in IGVM".into())
}

/// Reassemble `length` bytes starting at guest address `addr` from the page map.
///
/// `addr`/`length` come from an on-disk HOB entry, so a malformed IGVM must
/// produce an error here, never a panic or a giant allocation.
pub fn reassemble(pages: &BTreeMap<u64, Vec<u8>>, addr: u64, length: u64) -> Result<Vec<u8>, String> {
    // The blob cannot be larger than everything we measured; reject absurd
    // HOB lengths before allocating or iterating.
    let available = (pages.len() as u64) * PAGE_SIZE;
    if length > available {
        return Err(format!(
            "kernel blob length {length} exceeds available measured page bytes {available}"
        ));
    }
    let length = length as usize;
    let mut gpa = addr & !(PAGE_SIZE - 1);
    let skip = (addr - gpa) as usize;
    let needed = length
        .checked_add(skip)
        .ok_or("kernel blob address + length overflows")?;
    let mut out = Vec::with_capacity(needed);
    while out.len() < needed {
        let page = pages
            .get(&gpa)
            .ok_or_else(|| format!("missing page at gpa {gpa:#x} while reassembling kernel"))?;
        out.extend_from_slice(page);
        gpa = gpa
            .checked_add(PAGE_SIZE)
            .ok_or("guest address overflows while reassembling kernel")?;
    }
    Ok(out[skip..skip + length].to_vec())
}

/// Recover the kernel UKI command line from an IGVM file: locate the kernel
/// blob via the HOB list, reassemble it, and read its `.cmdline` PE section.
pub fn kernel_cmdline(igvm: &IgvmFile) -> Result<String, String> {
    let pages = page_map(igvm);
    let (addr, len) = find_kernel_blob(&pages)?;
    let uki = reassemble(&pages, addr, len)?;
    parse_pe_cmdline(&uki)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal PE32+ image with a single `.cmdline` section whose
    /// contents are `body`. Only the fields our parser reads are filled in.
    fn synthetic_uki(body: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 0x400];
        buf[0] = b'M';
        buf[1] = b'Z';
        let pe_off = 0x80usize;
        buf[0x3c..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
        buf[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        // COFF header: NumberOfSections @ +6 (u16), SizeOfOptionalHeader @ +20 (u16)
        let coff = pe_off + 4;
        buf[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // 1 section
        let opt_size = 0xf0u16;
        buf[coff + 16..coff + 18].copy_from_slice(&opt_size.to_le_bytes());
        // Section table starts after optional header
        let sec = coff + 20 + opt_size as usize;
        buf[sec..sec + 8].copy_from_slice(b".cmdline");
        let raw_ptr = 0x300u32;
        buf[sec + 16..sec + 20].copy_from_slice(&(body.len() as u32).to_le_bytes()); // SizeOfRawData
        buf[sec + 20..sec + 24].copy_from_slice(&raw_ptr.to_le_bytes()); // PointerToRawData
        buf[raw_ptr as usize..raw_ptr as usize + body.len()].copy_from_slice(body);
        buf
    }

    #[test]
    fn parse_pe_cmdline_reads_section() {
        let uki = synthetic_uki(b"roothash=deadbeef console=hvc0\0\0");
        let cmdline = parse_pe_cmdline(&uki).expect("cmdline");
        assert_eq!(cmdline, "roothash=deadbeef console=hvc0");
    }

    #[test]
    fn parse_pe_cmdline_missing_section() {
        let mut uki = synthetic_uki(b"x");
        // Rename the section so it is not found.
        let pe_off = 0x80;
        let sec = pe_off + 4 + 20 + 0xf0;
        uki[sec..sec + 8].copy_from_slice(b".text\0\0\0");
        assert!(parse_pe_cmdline(&uki).is_err());
    }

    use crate::hob::EFI_IGVM_DATA_HOB_GUID;

    /// One 0x30-byte EfiIgvmDataHob: header(8) + guid(16) + address(8) +
    /// length(8) + data_type(4) + flags(4).
    fn hob_entry(address: u64, length: u64, data_type: u32) -> Vec<u8> {
        let mut e = vec![0u8; 0x30];
        e[0..2].copy_from_slice(&0x0004u16.to_le_bytes()); // GUID_EXTENSION
        e[2..4].copy_from_slice(&0x30u16.to_le_bytes());
        e[8..24].copy_from_slice(&EFI_IGVM_DATA_HOB_GUID.to_bytes());
        e[24..32].copy_from_slice(&address.to_le_bytes());
        e[32..40].copy_from_slice(&length.to_le_bytes());
        e[40..44].copy_from_slice(&data_type.to_le_bytes());
        e
    }

    #[test]
    fn find_kernel_blob_locates_kernel() {
        // HOB area at gpa 0 holds a shim entry then a kernel entry.
        let mut hob_page = vec![0u8; 4096];
        let shim = hob_entry(0x40000000, 10, 0x202);
        let kernel = hob_entry(0x20000000, 7, 0x201);
        hob_page[0..0x30].copy_from_slice(&shim);
        hob_page[0x30..0x60].copy_from_slice(&kernel);

        let mut pages: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        pages.insert(0, hob_page);
        // kernel bytes at gpa 0x20000000
        let mut kpage = vec![0u8; 4096];
        kpage[..7].copy_from_slice(b"ABCDEFG");
        pages.insert(0x20000000, kpage);

        let (addr, len) = find_kernel_blob(&pages).expect("kernel hob");
        assert_eq!((addr, len), (0x20000000, 7));
        let bytes = reassemble(&pages, addr, len).expect("kernel bytes");
        assert_eq!(&bytes, b"ABCDEFG");
    }

    #[test]
    fn reassemble_rejects_absurd_length() {
        // A malformed HOB length far larger than the measured pages must error,
        // not panic or attempt a huge allocation.
        let mut pages: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        pages.insert(0x20000000, vec![0u8; 4096]);
        assert!(reassemble(&pages, 0x20000000, u64::MAX).is_err());
    }

    #[test]
    #[ignore = "requires local steep build at /home/ubuntu/steep/output/base"]
    fn kernel_cmdline_from_real_igvm() {
        let bytes = std::fs::read("/home/ubuntu/steep/output/base/guest.igvm").unwrap();
        let igvm = igvm::IgvmFile::new_from_binary(&bytes, None).unwrap();
        let cmdline = kernel_cmdline(&igvm).unwrap();
        assert!(
            cmdline.contains("roothash=695be9124b1f2043c8ea1e248a98792cf003002b95610061d5b27de0c77ea741"),
            "cmdline was: {cmdline}"
        );
    }
}
