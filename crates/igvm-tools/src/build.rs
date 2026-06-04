//! High-level API for building IGVM files.
//!
//! This module provides a single `build()` function that takes a configuration
//! struct and returns serialized IGVM bytes plus measurement results. It wraps
//! the lower-level `Builder` and `measure` APIs.

use crate::builder::Builder;
use crate::hob::{IgvmDataList, IgvmDataType};
use crate::measure::{self, MeasureResult};
use crate::ovmfmeta::{OvmfMeta, OvmfRegionType};
use crate::x86regs::{flat32_mode_regs, real_mode_regs_at};

/// Platform type for IGVM construction.
#[derive(Clone, Debug)]
pub enum Platform {
    Snp,
    Native,
    SnpNative,
}

/// Boot mode for initial vCPU state.
#[derive(Clone, Debug)]
pub enum BootMode {
    Real16,
    Flat32,
}

/// Configuration for building an IGVM image.
pub struct BuildConfig<'a> {
    /// OVMF firmware image bytes.
    pub firmware: &'a [u8],
    /// UEFI variable store (optional).
    pub vars: Option<&'a [u8]>,
    /// Kernel EFI binary / UKI (optional).
    pub kernel: Option<&'a [u8]>,
    /// Shim EFI binary (optional).
    pub shim: Option<&'a [u8]>,
    /// Secure boot PK certificate (optional).
    pub pk: Option<&'a [u8]>,
    /// Secure boot KEK certificate (optional).
    pub kek: Option<&'a [u8]>,
    /// Secure boot db certificate (optional).
    pub db: Option<&'a [u8]>,
    /// Secure boot dbx revocation list (optional).
    pub dbx: Option<&'a [u8]>,
    /// Platform type.
    pub platform: Platform,
    /// Boot mode.
    pub boot_mode: BootMode,
    /// Number of vCPUs.
    pub smp: u32,
    /// Print verbose measurement output to stderr.
    pub verbose: bool,
}

/// Result of building an IGVM image.
pub struct BuildResult {
    /// Serialized IGVM binary, ready to write to a file.
    pub igvm_bytes: Vec<u8>,
    /// SNP measurement result (launch digest, page/vmsa counts).
    pub measurement: MeasureResult,
}

struct HobInputs<'a> {
    kernel: Option<&'a [u8]>,
    shim: Option<&'a [u8]>,
    pk: Option<&'a [u8]>,
    kek: Option<&'a [u8]>,
    db: Option<&'a [u8]>,
    dbx: Option<&'a [u8]>,
}

impl HobInputs<'_> {
    fn has_data(&self) -> bool {
        self.kernel.is_some()
            || self.shim.is_some()
            || self.pk.is_some()
            || self.kek.is_some()
            || self.db.is_some()
            || self.dbx.is_some()
    }
}

fn add_hob_data(
    builder: &mut Builder,
    ovmfmeta: &Option<OvmfMeta>,
    inputs: &HobInputs,
) -> Result<(), String> {
    if !inputs.has_data() {
        return Ok(());
    }

    let hobarea = ovmfmeta
        .as_ref()
        .and_then(|m| {
            m.regions
                .iter()
                .find(|r| r.etype == OvmfRegionType::IgvmHobArea)
        })
        .ok_or("OVMF firmware has no IgvmHobArea region (needed for kernel/shim/cert injection)")?;

    let mut hoblist = IgvmDataList::new(0x20000000); // start at 512 MB

    if let Some(blob) = inputs.pk {
        hoblist.add(blob, IgvmDataType::Pk, true);
    }
    if let Some(blob) = inputs.kek {
        hoblist.add(blob, IgvmDataType::Kek, true);
    }
    if let Some(blob) = inputs.db {
        hoblist.add(blob, IgvmDataType::Db, true);
    }
    if let Some(blob) = inputs.dbx {
        hoblist.add(blob, IgvmDataType::Dbx, true);
    }
    if let Some(blob) = inputs.shim {
        hoblist.add(blob, IgvmDataType::Shim, false);
    }
    if let Some(blob) = inputs.kernel {
        hoblist.add(blob, IgvmDataType::Kernel, true);
    }

    let hobs_blob = hoblist.hobs();
    builder.remove_page_data_in_range(hobarea.memory.0, hobarea.memory.1);
    builder.add_data_pages(hobarea.memory.0, &hobs_blob);

    for (addr, blob) in hoblist.blobs(true) {
        builder.remove_page_data_in_range(addr, blob.len());
        builder.add_data_pages(addr, blob);
    }
    for (addr, blob) in hoblist.blobs(false) {
        builder.remove_page_data_in_range(addr, blob.len());
        builder.add_data_pages_unmeasured(addr, blob);
    }

    Ok(())
}

/// Build an IGVM image from the given configuration.
///
/// Returns the serialized IGVM bytes and SNP measurement result.
/// The measurement matches hardware attestation when the guest runs on QEMU+KVM.
pub fn build(config: &BuildConfig) -> Result<BuildResult, String> {
    let ovmfmeta = OvmfMeta::new(config.firmware);

    let mut builder = Builder::new();
    let use_snp = matches!(config.platform, Platform::Snp | Platform::SnpNative);
    let use_native = matches!(config.platform, Platform::Native | Platform::SnpNative);

    if use_native {
        builder.add_native_platform();
        if matches!(config.boot_mode, BootMode::Flat32) {
            builder.add_native_context(&flat32_mode_regs(None));
        }
    }

    if use_snp {
        builder.add_snp_platform();

        let bsp_regs = match config.boot_mode {
            BootMode::Flat32 => flat32_mode_regs(None),
            BootMode::Real16 => real_mode_regs_at(0xFFFFFFF0),
        };
        builder.add_snp_vmsa_context(&bsp_regs, false, 0);

        if config.smp > 1 {
            let ap_reset_addr = ovmfmeta.as_ref().and_then(|m| m.sev_reset_addr).ok_or(
                "OVMF firmware does not contain SEV-ES reset address (needed for --smp > 1)",
            )?;
            let ap_regs = real_mode_regs_at(ap_reset_addr);
            for vp in 1..config.smp {
                let vp_index = u16::try_from(vp).map_err(|_| "vCPU index exceeds u16 range")?;
                builder.add_snp_vmsa_context(&ap_regs, false, vp_index);
            }
        }

        if let Some(ref meta) = ovmfmeta {
            builder.add_ovmf_snp_pages(meta);
        }
        builder.add_snp_policy(None);
    }

    if let Some(ref meta) = ovmfmeta {
        builder.add_ovmf_igvm_params(meta);
    }

    if matches!(config.boot_mode, BootMode::Real16) {
        builder.add_firmware_1m(config.firmware);
    }
    builder.add_firmware_4g(config.firmware);

    if let Some(vars) = config.vars {
        builder.add_uefivars(vars, config.firmware.len());
    }

    let hob_inputs = HobInputs {
        kernel: config.kernel,
        shim: config.shim,
        pk: config.pk,
        kek: config.kek,
        db: config.db,
        dbx: config.dbx,
    };
    add_hob_data(&mut builder, &ovmfmeta, &hob_inputs)?;

    let igvm = builder
        .finalize()
        .map_err(|e| format!("finalize igvm: {e}"))?;

    let measurement = measure::measure_snp(&igvm, config.verbose)?;

    let mut igvm_bytes = Vec::new();
    igvm.serialize(&mut igvm_bytes)
        .map_err(|e| format!("serialize igvm: {e}"))?;

    Ok(BuildResult {
        igvm_bytes,
        measurement,
    })
}
