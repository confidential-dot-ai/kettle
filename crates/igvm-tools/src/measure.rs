// This module exists because no crate computes SNP LAUNCH_DIGEST from an IgvmFile.
// The algorithm is defined in AMD SEV-SNP ABI Specification §7.3 (PAGE_INFO hashing).
// We must exactly replicate QEMU+KVM's measurement behavior including page batching
// and VMSA override timing.
//
// NOTE: This module is QEMU+KVM-specific. The batch flushing logic, page ordering
// assumptions, ParameterInsert timing, and VMSA overrides all match QEMU+KVM's
// implementation. A different VMM (e.g. cloud-hypervisor, Firecracker) may process
// IGVM directives differently and produce a different launch digest.
//
// PAGE_INFO structure is exactly 0x70 bytes with fields at fixed offsets.
// CONTENTS = SHA384(padded_page_data) for NORMAL/VMSA, zeros for others.
// ALL page types (including UNMEASURED) extend the running digest.
//   "UNMEASURED" means the page contents hash is zeros, but the page's GPA and
//   type still contribute to the final digest.
// VMSA pages are measured AFTER all PageData (simulating LAUNCH_FINISH).
// ParameterInsert pages are measured IMMEDIATELY without flushing pending batch.
//   This means ParameterInsert pages can interleave with PageData pages in
//   measurement order, matching QEMU's directive-order processing.
// Batch breaks occur on type change, data presence change, GPA discontinuity,
//   or non-consecutive directive index.
// KVM VMSA overrides (CR4=0x40, RFLAGS=0x02) are always applied.

use std::collections::HashMap;

use igvm::{IgvmDirectiveHeader, IgvmFile, IgvmPlatformHeader};
use igvm_defs::{IgvmPageDataFlags, IgvmPageDataType, IgvmPlatformType};
use sha2::{Digest, Sha384};
use zerocopy::IntoBytes;

use crate::hypervisor;

const SNP_PAGE_TYPE_NORMAL: u8 = 0x01;
const SNP_PAGE_TYPE_VMSA: u8 = 0x02;
const SNP_PAGE_TYPE_UNMEASURED: u8 = 0x04;
const SNP_PAGE_TYPE_SECRETS: u8 = 0x05;
const SNP_PAGE_TYPE_CPUID: u8 = 0x06;

const PAGE_SIZE: usize = 4096;
const VMSA_GPA: u64 = 0xFFFF_FFFF_F000;

#[derive(Debug)]
pub struct MeasureResult {
    pub launch_digest: [u8; 48],
    pub page_count: u64,
    pub vmsa_count: u32,
}

/// Build the 0x70-byte PAGE_INFO structure and hash it to produce the new digest.
///
/// ALGORITHM: SHA384 over fixed-layout PAGE_INFO, O(1) per page. This is the
/// core of SNP's measured launch — each page extends the running digest exactly
/// like a hash chain. No alternative algorithm exists; this is the hardware spec.
fn update_page_info(
    digest_cur: &[u8; 48],
    contents: &[u8; 48],
    page_type: u8,
    gpa: u64,
) -> [u8; 48] {
    let mut page_info = [0u8; 0x70];

    page_info[0x00..0x30].copy_from_slice(digest_cur);
    page_info[0x30..0x60].copy_from_slice(contents);
    page_info[0x60..0x62].copy_from_slice(&0x0070u16.to_le_bytes());
    page_info[0x62] = page_type;
    page_info[0x68..0x70].copy_from_slice(&gpa.to_le_bytes());

    Sha384::digest(page_info).into()
}

/// Classify a PageData directive into (snp_page_type, contents_hash, has_data).
fn classify_page_data(
    data_type: IgvmPageDataType,
    flags: &IgvmPageDataFlags,
    data: &[u8],
) -> (u8, [u8; 48], bool) {
    let zeros48 = [0u8; 48];
    match data_type {
        IgvmPageDataType::SECRETS => (SNP_PAGE_TYPE_SECRETS, zeros48, false),
        IgvmPageDataType::CPUID_DATA | IgvmPageDataType::CPUID_XF => {
            (SNP_PAGE_TYPE_CPUID, zeros48, false)
        }
        _ => {
            if flags.unmeasured() {
                (SNP_PAGE_TYPE_UNMEASURED, zeros48, false)
            } else {
                let mut padded = vec![0u8; PAGE_SIZE];
                if !data.is_empty() {
                    let copy_len = data.len().min(PAGE_SIZE);
                    padded[..copy_len].copy_from_slice(&data[..copy_len]);
                }
                let hash: [u8; 48] = Sha384::digest(&padded).into();
                (SNP_PAGE_TYPE_NORMAL, hash, !data.is_empty())
            }
        }
    }
}

struct PendingPage {
    gpa: u64,
    page_type: u8,
    contents: [u8; 48],
}

fn page_type_name(t: u8) -> &'static str {
    match t {
        SNP_PAGE_TYPE_NORMAL => "NORMAL",
        SNP_PAGE_TYPE_UNMEASURED => "UNMEASURED",
        SNP_PAGE_TYPE_SECRETS => "SECRETS",
        SNP_PAGE_TYPE_CPUID => "CPUID",
        _ => "???",
    }
}

fn flush_batch(
    ld: &mut [u8; 48],
    batch: &mut Vec<PendingPage>,
    page_count: &mut u64,
    verbose: bool,
) {
    for page in batch.iter() {
        if verbose {
            eprintln!(
                "  measure  gpa=0x{:08x}  type={:<12}  contents={}  [batch-flush]",
                page.gpa,
                page_type_name(page.page_type),
                hex::encode(page.contents)
            );
        }
        *ld = update_page_info(ld, &page.contents, page.page_type, page.gpa);
        *page_count += 1;
    }
    batch.clear();
}

/// Measure collected VMSA pages — KVM does this during LAUNCH_FINISH.
fn measure_vmsa_pages(
    ld: &mut [u8; 48],
    vmsa_pages: &[(u64, Vec<u8>)],
    page_count: &mut u64,
    verbose: bool,
) {
    for (gpa, vmsa_page) in vmsa_pages {
        let vmsa_hash: [u8; 48] = Sha384::digest(vmsa_page).into();
        if verbose {
            eprintln!(
                "  VMSA     gpa=0x{:012x}  (igvm_gpa=0x{:012x})  hash={}",
                VMSA_GPA,
                gpa,
                hex::encode(vmsa_hash)
            );
        }
        *ld = update_page_info(ld, &vmsa_hash, SNP_PAGE_TYPE_VMSA, VMSA_GPA);
        *page_count += 1;
    }
}

fn find_snp_compat(igvm: &IgvmFile) -> Result<u32, String> {
    igvm.platforms()
        .iter()
        .find_map(|p| match p {
            IgvmPlatformHeader::SupportedPlatform(plat)
                if plat.platform_type == IgvmPlatformType::SEV_SNP =>
            {
                Some(plat.compatibility_mask)
            }
            _ => None,
        })
        .ok_or_else(|| "No SEV_SNP platform found in IGVM file".to_string())
}

fn collect_param_areas(igvm: &IgvmFile) -> HashMap<u32, u64> {
    let mut areas = HashMap::new();
    for directive in igvm.directives() {
        if let IgvmDirectiveHeader::ParameterArea {
            number_of_bytes,
            parameter_area_index,
            ..
        } = directive
        {
            areas.insert(*parameter_area_index, *number_of_bytes);
        }
    }
    areas
}

/// Compute the SNP LAUNCH_DIGEST for an IGVM file.
///
/// This replicates QEMU+KVM's exact measurement behavior:
/// 1. PageData pages are batched by contiguity/type and flushed together
/// 2. ParameterInsert pages are measured immediately (without flushing pending batch),
///    so they can interleave with PageData pages in measurement order
/// 3. VMSA pages are measured last (during simulated LAUNCH_FINISH)
/// 4. KVM VMSA overrides (CR4=0x40, RFLAGS=0x02) are always applied
///
/// The resulting digest matches the hardware attestation report when the guest
/// runs on QEMU+KVM. Other VMMs may produce different digests.
pub fn measure_snp(igvm: &IgvmFile, verbose: bool) -> Result<MeasureResult, String> {
    let snp_compat = find_snp_compat(igvm)?;

    if verbose {
        eprintln!("SNP compatibility mask: 0x{snp_compat:x}");
    }

    let param_areas = collect_param_areas(igvm);
    let zeros48 = [0u8; 48];

    let mut ld = [0u8; 48];
    let mut page_count = 0u64;
    let mut vmsa_pages: Vec<(u64, Vec<u8>)> = Vec::new();

    // QEMU batches contiguous PageData pages and measures them together.
    // Non-PageData directives are measured immediately.
    // We must replicate this behavior to match hardware.
    let mut pending_batch: Vec<PendingPage> = Vec::new();
    let mut prev_page_gpa: Option<u64> = None;
    let mut prev_page_type: Option<u8> = None;
    let mut prev_page_has_data: Option<bool> = None;
    let mut last_page_directive_idx: Option<usize> = None;

    for (dir_idx, directive) in igvm.directives().iter().enumerate() {
        match directive {
            IgvmDirectiveHeader::PageData {
                gpa,
                compatibility_mask,
                flags,
                data_type,
                data,
            } => {
                if compatibility_mask & snp_compat == 0 {
                    continue;
                }

                let (page_type, contents, has_data) = classify_page_data(*data_type, flags, data);

                // Check if this page breaks the current batch.
                let should_flush =
                    if let (Some(prev_gpa), Some(prev_type), Some(prev_has), Some(last_idx)) = (
                        prev_page_gpa,
                        prev_page_type,
                        prev_page_has_data,
                        last_page_directive_idx,
                    ) {
                        page_type != prev_type
                            || has_data != prev_has
                            || *gpa != prev_gpa + PAGE_SIZE as u64
                            || dir_idx != last_idx + 1
                    } else {
                        false
                    };

                if should_flush && !pending_batch.is_empty() {
                    flush_batch(&mut ld, &mut pending_batch, &mut page_count, verbose);
                }

                pending_batch.push(PendingPage {
                    gpa: *gpa,
                    page_type,
                    contents,
                });
                prev_page_gpa = Some(*gpa);
                prev_page_type = Some(page_type);
                prev_page_has_data = Some(has_data);
                last_page_directive_idx = Some(dir_idx);
            }

            IgvmDirectiveHeader::SnpVpContext {
                gpa,
                compatibility_mask,
                vmsa,
                ..
            } => {
                if compatibility_mask & snp_compat == 0 {
                    continue;
                }

                let mut vmsa_page = vec![0u8; PAGE_SIZE];
                let vmsa_bytes = vmsa.as_bytes();
                let copy_len = vmsa_bytes.len().min(PAGE_SIZE);
                vmsa_page[..copy_len].copy_from_slice(&vmsa_bytes[..copy_len]);

                hypervisor::apply_kvm_vmsa_overrides(&mut vmsa_page);
                vmsa_pages.push((*gpa, vmsa_page));
            }

            IgvmDirectiveHeader::ParameterInsert(insert) => {
                if insert.compatibility_mask & snp_compat == 0 {
                    continue;
                }

                let area_size = param_areas
                    .get(&insert.parameter_area_index)
                    .copied()
                    .ok_or_else(|| {
                        format!(
                            "ParameterInsert references unknown area {}",
                            insert.parameter_area_index
                        )
                    })?;

                // ParameterInsert is measured IMMEDIATELY without flushing
                // the pending PageData batch. This is QEMU's behavior.
                let num_pages = (area_size as usize).div_ceil(PAGE_SIZE);
                for pg in 0..num_pages {
                    let page_gpa = insert.gpa + (pg as u64 * PAGE_SIZE as u64);
                    if verbose {
                        eprintln!(
                            "  measure  gpa=0x{:08x}  type=UNMEASURED    contents={}  [param-insert]",
                            page_gpa,
                            hex::encode(zeros48)
                        );
                    }
                    ld = update_page_info(&ld, &zeros48, SNP_PAGE_TYPE_UNMEASURED, page_gpa);
                    page_count += 1;
                }
            }

            _ => {}
        }
    }

    // Flush any remaining batch
    if !pending_batch.is_empty() {
        flush_batch(&mut ld, &mut pending_batch, &mut page_count, verbose);
    }

    if verbose {
        eprintln!("Pages measured (before VMSA): {page_count}");
        eprintln!("Digest before VMSA: {}", hex::encode(ld));
    }

    // Measure VMSA pages — KVM does this during LAUNCH_FINISH
    let vmsa_count = vmsa_pages.len() as u32;
    measure_vmsa_pages(&mut ld, &vmsa_pages, &mut page_count, verbose);

    if verbose {
        eprintln!("Total pages measured: {page_count}");
    }

    Ok(MeasureResult {
        launch_digest: ld,
        page_count,
        vmsa_count,
    })
}
