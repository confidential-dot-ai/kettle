# Examples

Prebuilt OVMF firmware and a UKI are included in `prebuilt/` so you can build and measure IGVM files without any extra setup.

## Quick start

```bash
cargo build --release

# Build an IGVM (prints the expected SNP launch digest)
./examples/build.sh -o guest.igvm

# Build with SMP 2
./examples/build.sh --smp 2 -o guest-smp2.igvm

# Measure an existing IGVM
./examples/measure.sh guest.igvm
```

## What's in `prebuilt/`

### `OVMF.fd` (4 MB)

Patched OVMF firmware built from our [edk2 fork](https://github.com/lunal-dev/edk2)

The patch adds IGVM-aware PVALIDATE handling — when booting via IGVM, pages loaded through `SNP_LAUNCH_UPDATE` are already validated by the PSP. Without the patch, OVMF re-validates these pages and the guest silently terminates.

**How it was built:**

```bash
# Prerequisites (Ubuntu/Debian)
sudo apt install build-essential nasm iasl uuid-dev python3

git clone https://github.com/lunal-dev/edk2.git
cd edk2
git checkout OvmfPkg-PlatformPei-skip-pvalidate-igvm-pages
git submodule update --init    # ~2 GB, takes 5-10 min

source edksetup.sh
build -a X64 -t GCC5 -p OvmfPkg/OvmfPkgX64.dsc -b RELEASE -DSMM_REQUIRE=FALSE
# Output: Build/OvmfX64/RELEASE_GCC5/FV/OVMF.fd
```

> **Do NOT use `OvmfPkg/AmdSev/AmdSevX64.dsc`** — it fails with `0x404` page-not-validated errors under IGVM+SNP.

### `uki.efi` (20 MB)

Unified Kernel Image containing:
- Linux 6.17.0-14-generic (Ubuntu 25.10)
- Minimal initramfs with BusyBox, `sev-guest.ko`, `ccp.ko`, and `attestation-cli`
- Command line: `console=ttyS0 earlyprintk=serial`

**How it was built:**

```bash
# Prerequisites
sudo apt install systemd-ukify systemd-boot-efi

ukify build \
    --linux /boot/vmlinuz-6.17.0-14-generic \
    --initrd initramfs.cpio.gz \
    --cmdline "console=ttyS0 earlyprintk=serial" \
    --stub /usr/lib/systemd/boot/efi/linuxx64.efi.stub \
    --output uki.efi
```

## Booting with QEMU

IGVM support requires building QEMU from source (not in any stable release yet):

```bash
git clone https://github.com/qemu/qemu.git && cd qemu
./configure --target-list=x86_64-softmmu --enable-igvm --enable-slirp
make -j$(nproc) && sudo make install
```

Then boot:

```bash
qemu-system-x86_64 \
    -enable-kvm -cpu EPYC-Genoa \
    -machine q35,confidential-guest-support=sev0,igvm-cfg=igvm0,memory-backend=ram1,kernel-irqchip=split \
    -object igvm-cfg,id=igvm0,file=guest.igvm \
    -object memory-backend-memfd,id=ram1,size=4G,share=true \
    -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1 \
    -smp 1 -nographic -nodefaults -serial stdio -no-reboot
```
