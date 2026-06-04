# igvm-tools

Build and measure IGVM files for AMD SEV-SNP confidential VMs running on **QEMU+KVM**.


## QEMU+KVM only

This tool is designed exclusively for QEMU+KVM. The IGVM construction, page ordering, measurement algorithm (batch flushing behavior), and VMSA overrides all replicate QEMU+KVM's specific implementation. The computed launch digest matches hardware attestation reports **only** when the guest runs on QEMU+KVM.

Other VMMs (cloud-hypervisor, Firecracker, Hyper-V) process IGVM directives differently and will produce different launch digests.

### Roadmap

- **Additional VMMs** — support for cloud-hypervisor and other IGVM-capable VMMs is planned.
- **Intel TDX** — TDX uses a fundamentally different measurement model (MRTD via `TDH.MR.EXTEND`) and is not yet supported. TDX support is planned for a future release.

## Install

```bash
git clone https://github.com/lunal-dev/igvm-tools.git
cargo install --path .
```

## OVMF firmware

igvm-tools requires a patched OVMF firmware with IGVM metadata support (parameter areas, HOB regions, SEV-ES reset vector). The standard `OvmfPkg/AmdSev/AmdSevX64.dsc` target **does not work** with IGVM under SEV-SNP (fails with 0x404 page-not-validated errors).

Use our patched edk2 fork:

```bash
git clone https://github.com/lunal-dev/edk2.git
cd edk2
git checkout OvmfPkg-PlatformPei-skip-pvalidate-igvm-pages
git submodule update --init
source edksetup.sh
build -a X64 -t GCC5 -p OvmfPkg/OvmfPkgX64.dsc -b RELEASE -DSMM_REQUIRE=FALSE
# Output: Build/OvmfX64/RELEASE_GCC5/FV/OVMF.fd
```

The patch adds IGVM-aware PVALIDATE handling so OVMF skips re-validation of pages already validated by the PSP during IGVM launch.

## Usage

### Build an IGVM file

```bash
# Firmware only (minimal SNP guest)
igvm-tools build \
    --firmware OVMF.fd \
    --output firmware.igvm

# Firmware + UKI kernel (kernel measured in launch digest)
igvm-tools build \
    --firmware OVMF.fd \
    --kernel my-uki.efi \
    --output uki.igvm

# Multi-vCPU build
igvm-tools build \
    --firmware OVMF.fd \
    --kernel my-uki.efi \
    --smp 4 \
    --output smp4.igvm
```

The SNP launch digest is printed to **stdout** (for piping) and build details go to stderr.

### Measure an existing IGVM file

```bash
igvm-tools measure my-guest.igvm
```

This parses the IGVM file and computes the SNP launch digest without building anything.

### Options

| Flag                | Default  | Description                                       |
| ------------------- | -------- | ------------------------------------------------- |
| `--firmware FILE`   | required | OVMF firmware image                               |
| `--kernel FILE`     | —        | Kernel/UKI EFI binary (measured in digest)        |
| `--shim FILE`       | —        | Shim EFI binary (unmeasured, verified at runtime) |
| `--vars FILE`       | —        | UEFI variable store                               |
| `--pk FILE`         | —        | Secure boot PK certificate (.auth)                |
| `--kek FILE`        | —        | Secure boot KEK certificate (.auth)               |
| `--db FILE`         | —        | Secure boot db certificate (.auth)                |
| `--dbx FILE`        | —        | Secure boot dbx revocation list (.auth)           |
| `--platform`        | `snp`    | `snp`, `native`, or `snp+native`                  |
| `--boot-mode`       | `real16` | `real16` or `flat32`                              |
| `--smp N`           | `1`      | Number of vCPUs                                   |
| `-o, --output FILE` | required | Output IGVM file                                  |
| `--manifest FILE`   | —        | Output JSON manifest with digest and input hashes |
| `--meta`            | —        | Print OVMF metadata regions                       |
| `-v, --verbose`     | —        | Print per-page measurement trace                  |

### JSON manifest

When `--manifest` is specified, a JSON file is written containing:

```json
{
  "version": 1,
  "igvm_file": "output.igvm",
  "igvm_sha256": "...",
  "measurement": {
    "snp_launch_digest": "...",
    "algorithm": "sha384",
    "page_count": 5598,
    "vmsa_count": 1
  },
  "config": {
    "platform": "snp",
    "boot_mode": "real16",
    "smp": 1
  },
  "inputs": {
    "firmware": { "path": "OVMF.fd", "sha256": "..." },
    "kernel": { "path": "my-uki.efi", "sha256": "..." }
  },
  "generated_at": "2026-03-11T01:20:00Z"
}
```

## Running with QEMU

```bash
# Build the IGVM
igvm-tools build \
    --firmware OVMF.fd \
    --kernel my-uki.efi \
    --output guest.igvm

# Launch with QEMU (requires SEV-SNP capable host + KVM)
qemu-system-x86_64 \
    -enable-kvm -cpu EPYC-Genoa \
    -object igvm-cfg,id=igvm0,file=guest.igvm \
    -machine q35,confidential-guest-support=sev0,igvm-cfg=igvm0,memory-backend=ram1,kernel-irqchip=split \
    -object memory-backend-memfd,id=ram1,size=4G,share=true \
    -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1 \
    -smp 1 -nographic -no-reboot
```

The guest's hardware attestation report will contain a launch digest matching the value printed by `igvm-tools build`.

## Verifying attestation

```bash
# Get the expected digest
DIGEST=$(igvm-tools measure guest.igvm)

# Inside the guest, read the attestation report and compare
# the measurement field at offset 0x90 (48 bytes, SHA-384)
```

The digest is deterministic: same inputs always produce the same digest, regardless of when or where the build runs. Changing the kernel, firmware, vCPU count, or secure boot certs produces a different digest.
## Examples

```bash
# Build an IGVM from firmware
./examples/build.sh --firmware OVMF.fd -o guest.igvm

# Build with a kernel and 2 vCPUs
./examples/build.sh --firmware OVMF.fd --kernel my-uki.efi --smp 2 -o guest.igvm

# Measure an existing IGVM file
./examples/measure.sh guest.igvm
```

## Testing

```bash
cargo test
```

## License

Apache 2.0
