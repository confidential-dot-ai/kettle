// This module exists because KVM modifies VMSA fields during vCPU initialization
// before SNP measurement. Without these overrides, computed launch digest won't
// match hardware when running on QEMU+KVM (the only supported VMM for this tool).
//
// VMSA bytes at offsets 0x148 (CR4) and 0x170 (RFLAGS) must match
// what KVM's sev_es_sync_vmsa() produces. Verified against Linux 6.x kernel source
// and hardware attestation reports on EPYC 8224P (Siena).

/// Apply KVM-specific VMSA overrides.
///
/// KVM's `sev_es_sync_vmsa()` sets CR4 and RFLAGS to non-zero defaults
/// during vCPU initialization. The SNP hardware measures the KVM-modified
/// VMSA, not the raw IGVM VMSA, so we must apply these before measurement.
///
/// Reference: Linux arch/x86/kvm/svm/sev.c
/// Offsets per AMD APM Vol 2, Table B-4 (VMSA layout): CR4 at 0x148, RFLAGS at 0x170.
pub fn apply_kvm_vmsa_overrides(vmsa: &mut [u8]) {
    // CR4 = 0x40 (MCE bit) — set by KVM during vCPU init
    vmsa[0x148] = 0x40;
    // RFLAGS = 0x02 (reserved bit, always set) — set by KVM during vCPU init
    vmsa[0x170] = 0x02;
}
