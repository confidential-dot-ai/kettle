//! IGVM construction and measurement library for AMD SEV-SNP confidential VMs.
//!
//! Provides building (`builder`), measurement (`measure`), and supporting modules
//! for creating IGVM files compatible with QEMU+KVM. The computed launch digest
//! matches hardware attestation when the guest runs on QEMU+KVM.
//!
//! # Quick start
//!
//! Use [`build()`] for a high-level API that takes firmware bytes and returns
//! serialized IGVM + measurement. For fine-grained control, use [`builder::Builder`]
//! and [`measure::measure_snp()`] directly.

pub mod build;
pub mod builder;
pub mod hob;
pub mod hypervisor;
pub mod manifest;
pub mod measure;
pub mod ovmfmeta;
pub mod x86regs;

// Re-export the high-level API at the crate root.
pub use build::{build, BootMode, BuildConfig, BuildResult, Platform};
