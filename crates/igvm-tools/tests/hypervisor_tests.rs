use igvm_tools::hypervisor;

/// KVM sets CR4=0x40 at offset 0x148 and RFLAGS=0x02 at offset 0x170.
/// Wrong offsets = wrong VMSA hash = wrong launch digest.
#[test]
fn kvm_overrides_correct_offsets() {
    let mut vmsa = vec![0u8; 4096];
    hypervisor::apply_kvm_vmsa_overrides(&mut vmsa);

    assert_eq!(vmsa[0x148], 0x40, "CR4 must be MCE bit (0x40)");
    assert_eq!(vmsa[0x170], 0x02, "RFLAGS must be 0x02 (reserved bit)");

    // All other bytes must remain zero
    for (i, &b) in vmsa.iter().enumerate() {
        if i != 0x148 && i != 0x170 {
            assert_eq!(b, 0, "byte at offset 0x{i:x} should be untouched");
        }
    }
}
