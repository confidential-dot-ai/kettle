---
name: kettle
description: |
  Build, publish, run, and verify measured CVM (confidential VM) guest images with
  kettle and kettle-orchestrator. Covers the full guest-image pipeline: reproducible
  StageX builds of the kettle/kettle-server binaries, mkosi-based image builds that
  emit disk.raw + guest.igvm + OVMF.fd + uki.efi + dm-verity roothash, IGVM launch
  measurement, OCI artifact distribution via oras/GHCR, booting AMD SEV-SNP guests
  under QEMU+KVM, and end-to-end attested-build verification (SLSA provenance +
  hardware evidence).

  Trigger this skill whenever the task involves: CVM guest images, IGVM files or
  launch measurements, UKI (unified kernel images), dm-verity roothash binding,
  SEV-SNP guests under QEMU, OCI image artifacts for confidential VMs, measured
  boot chains, launching or orchestrating confidential VMs, kettle / kettle-server /
  kettle-orchestrator / igvm-tools commands, or verifying attested builds against
  the exact VM image that produced them.
---

# Kettle: measured CVM guest images, built and run

## Overview

Kettle (github.com/confidential-dot-ai/kettle) creates **attested builds**: build
artifacts accompanied by SLSA v1.2 provenance and hardware-signed evidence proving
the build ran inside a confidential VM. To make that proof meaningful, the CVM
itself must be reproducible and measurable — so the project also ships the tooling
to **build the CVM guest image** (disk, firmware, unified kernel image, IGVM) and
**run it** on AMD SEV-SNP hardware via `kettle-orchestrator`.

Use this skill when you need to:

- Build or rebuild the kettle CVM guest image (IGVM + UKI + dm-verity disk).
- Publish or pull the image as an OCI artifact with `oras`.
- Launch SEV-SNP guests from an image directory, one-off or pooled.
- Verify that a build's attestation matches an exact IGVM and disk image.
- Reason about the measured boot chain and what changes its measurement.

## How it works

The guest image is a directory of five artifacts that together define one
measurable boot configuration:

```
target/image/
├── disk.raw            # GPT disk: read-only rootfs + root-verity hash partition
├── guest-smp10.igvm    # IGVM: OVMF + UKI + vCPU state, pre-measured for SEV-SNP
├── OVMF.fd             # UEFI firmware (also embedded in the IGVM)
├── uki.efi             # Unified kernel image: kernel + initrd + cmdline
├── roothash            # dm-verity root hash of the rootfs (64 hex chars)
├── manifest.json       # version-2 image manifest (smp, memory, paths)
└── ghcr-manifest.json  # exact OCI manifest bytes from the last oras push
```

The measured boot chain, from hardware up:

1. **IGVM** describes the guest's initial memory: OVMF firmware, the UKI, and
   initial vCPU state. QEMU loads it via `-object igvm-cfg`; the AMD-SP measures
   every page into the **SNP launch digest** that later appears in attestation
   reports. The digest depends on vCPU count, so IGVMs are per-`smp`
   (hence `guest-smp10.igvm`).
2. **UKI** bundles kernel + initrd + kernel cmdline into one signed-measurable
   EFI binary. The cmdline pins the **dm-verity roothash**, so the measured IGVM
   transitively commits to the exact root filesystem.
3. **disk.raw** carries the read-only rootfs plus a GPT `root-verity` partition
   (built by confidential-os-builder with mkosi/systemd-repart) holding the
   kernel refuses any rootfs block that doesn't hash to the pinned roothash.
4. A writable **scratch disk** (ext4, `LABEL=scratch`) is created fresh per
   launch for build workspaces — nothing persists across boots, and nothing
   writable is part of the measurement.

Because every layer is committed into the launch digest, `kettle verify` can walk
the chain backwards: attested launch digest → IGVM file → roothash in the UKI
cmdline → roothash stored in disk.raw.

**Distribution** is a plain OCI artifact. `oras push` uploads each file as a
layer (media type `application/vnd.oci.image.layer.v1.tar`, titled by filename)
under artifact type `application/vnd.steep.base.v1`, e.g.:

```json
{
  "artifactType": "application/vnd.steep.base.v1",
  "layers": [
    {"annotations": {"org.opencontainers.image.title": "disk.raw"}, "size": 1768337408},
    {"annotations": {"org.opencontainers.image.title": "guest-smp10.igvm"}},
    {"annotations": {"org.opencontainers.image.title": "manifest.json"}},
    {"annotations": {"org.opencontainers.image.title": "OVMF.fd"}},
    {"annotations": {"org.opencontainers.image.title": "roothash"}},
    {"annotations": {"org.opencontainers.image.title": "uki.efi"}}
  ],
  "annotations": {
    "org.opencontainers.image.source": "https://github.com/confidential-dot-ai/kettle",
    "org.opencontainers.image.url": "https://ghcr.io/confidential-dot-ai/kettle-build"
  }
}
```

The pull reference is digest-pinned: sha256 of the exported manifest bytes equals
the registry's manifest digest, so consumers can pin
`ghcr.io/confidential-dot-ai/kettle-build@sha256:<digest>` and know exactly which
image (and therefore which launch measurement) they will boot.

**Runtime**: `kettle-orchestrator` loads an image directory, boots a pool of
SEV-SNP CVMs under QEMU+KVM, forwards each guest's `kettle-server` (port 8080)
to a host port, and exposes an HTTP build API. Clients POST a repo, stream
build events over SSE, download the result archive, and verify it offline.

## Quick agent flow

1. **Discover before running.** Check the CLI surface first: `kettle --help`,
   `kettle-orchestrator --help`, `igvm-tools --help`, or read `src/main.rs` /
   `src/config.rs` in the repos. Never guess flags.
2. **Build binaries reproducibly**: `bin/build-reproducible` (StageX Docker,
   static musl `kettle` + `kettle-server`).
3. **Build the image**: `bin/image-build` cleanly restages measured inputs and
   writes all artifacts to `target/image/`.
4. **Publish**: `bin/image-push` (oras → GHCR, digest self-check included).
5. **Run**: `sudo kettle-orchestrator <IMAGE_DIR>` on an SEV-SNP host, or
   `kettle-orchestrator <IMAGE_DIR> --exec` to boot a single interactive CVM.
6. **Build through it**: `bin/remote-build <REPO_URL> <REF>` or curl the HTTP API.
7. **Verify**: `kettle verify <build-dir> --nonce <hex> --igvm guest.igvm --image disk.raw`.
8. **After any image change**, rebuild and publish, then update every
   digest-pinned OCI reference and expected launch-measurement reference in the
   same rollout.

## Critical guidelines

- **Never invent CLI flags.** Every command here was read from source; tools
  evolve, so confirm against `--help` or the clap arg structs (`src/main.rs`,
  `src/commands/*.rs`, orchestrator `src/config.rs`) before running anything
  destructive or long-running. A mistyped flag fails fast, but a *plausible*
  wrong flag (e.g. an invented `--memory` on the orchestrator) wastes an entire
  image build-boot cycle before you notice.
- **Confidentiality only exists on real AMD SEV-SNP hardware.** QEMU without
  `sev-snp-guest` support, or a run without `--features attest`, exercises
  mechanics only — memory is not encrypted, no launch digest is produced, and
  `evidence.json` is never written. Never substitute such a run and report that
  confidentiality or attestation "was tested". If SNP hardware is unavailable,
  say so explicitly and stop at the non-confidential boundary.
- **The measurement is the contract.** Any change to the kernel, initrd, kernel
  cmdline, OVMF, vCPU count (`smp`), or root filesystem—including files under
  `image/mkosi.extra`—changes the SNP launch digest. Attestation verifiers pin
  that digest, so rebuild and republish the image, then update the digest-pinned
  OCI reference and expected launch-measurement references in lockstep.
  Otherwise verification (including `kettle verify --igvm`) fails, or worse,
  keeps passing against a stale image. Treat the rollout as one atomic operation.
- **Pin by digest, not by tag.** `:latest` on GHCR can move; the launch digest
  cannot. The orchestrator's `GET /config` returns the digest-pinned reference
  it booted from — use that, or compute `sha256(ghcr-manifest.json)` yourself.
- **One variant per manifest.** The orchestrator refuses manifests with zero or
  multiple `variants` on purpose: each variant has its own smp-dependent IGVM
  measurement, and silently picking one would break the verifier's expectation
  of which digest to trust.

## Core workflows

### Build the binaries (reproducible)

`bin/build-reproducible` builds byte-for-byte reproducible, statically linked
musl binaries inside StageX Docker images (see `Dockerfile`):

```bash
cd kettle
bin/build-reproducible        # -> target/reproducible/{kettle,kettle-server}
```

Under the hood this is a `docker build` with `SOURCE_DATE_EPOCH` pinned to the
last commit time and `--features cli,attest,server`, exporting the `artifact`
stage. For a quick non-reproducible dev build:

```bash
cargo build --features cli --bin kettle
# attestation support needs the TPM stack:
apt-get install -y libtss2-dev
cargo build --features cli,attest --bin kettle
cargo build --features cli,attest,server --bin kettle-server
```

### Build the guest image

```bash
cd kettle
bin/image-build          # reuses the reproducible server and download cache
bin/image-build --force  # rebuilds the server before composing the image
CONFOS=/path/to/confidential-os-builder/bin/confos bin/image-build
```

What the script does (read `bin/image-build` for the full picture):

- Recreates the internal `target/steep` staging tree on every run, so a deleted
  input cannot survive into a later measured image. The reproducible server and
  download cache live outside that tree and may be reused.
- Stages the reproducible `kettle-server` at `/usr/local/bin` and copies the
  version-controlled static configuration from `image/mkosi.extra`. These files
  become part of the dm-verity root and therefore the launch measurement.
- Stages installer inputs on the host so chroot setup consumes them locally:
  the Nix tarball and sha256-pinned Intel SGX DCAP debs.
- Creates the `kettle` user and the `kettle` and `sev-guest` groups in the
  image-building chroot. If any name already exists, the build fails rather
  than inheriting an unexpected UID, GID, or membership.
- Bakes in the `/dev/sev-guest` udev rule and enables `kettle-server` with a
  measured systemd preset. First boot no longer needs cloud-init to write a
  unit, rule, or enablement symlink under read-only `/etc`.
- Declares `nix` as Kettle's only addition to confidential-os-builder's base
  writable-state set. The resulting `/nix` overlay preserves the measured Nix
  installation as its lower layer while allowing runtime store/database writes.
- Invokes **confidential-os-builder** through `CONFOS`, which defaults to
  `$HOME/confidential-os-builder/bin/confos`. Set `CONFOS` to select another
  reviewed checkout explicitly. The final builder command is equivalent to:

```bash
CONFOS=~/confidential-os-builder/bin/confos
"$CONFOS" build target/image \
  --smp 10 --memory 20G \
  --extra  target/steep/mkosi.extra \
  --package git,curl,ca-certificates,build-essential,cargo,... \
  --script target/steep/install-nix.sh.chroot
```

The result in `target/image/` includes IGVM launch measurements, so this
directory is both bootable and verifiable. Changes to any staged binary,
package, account, unit, rule, preset, or state declaration require rebuilding
and republishing the image, then updating the digest-pinned OCI reference and
all expected launch-measurement references in the same deployment change.

### Publish and pull the OCI artifact

```bash
cd kettle
bin/image-push
# equivalent to:
cd target/image
oras push "ghcr.io/confidential-dot-ai/kettle-build:latest" ./* \
  --annotation "org.opencontainers.image.source=https://github.com/confidential-dot-ai/kettle" \
  --artifact-type application/vnd.steep.base.v1 \
  --export-manifest ghcr-manifest.json
```

The script then asserts `sha256(ghcr-manifest.json)` resolves on the registry —
catching digest divergence at deploy time instead of as a later verify failure.
Consumers pull the whole image (layers land as their annotated filenames):

```bash
oras pull "ghcr.io/confidential-dot-ai/kettle-build@sha256:<digest>"
```

### Run the orchestrator (pooled CVMs)

Requires root (KVM + SNP device access) and a QEMU that supports `igvm-cfg` and
`sev-snp-guest` objects:

```bash
sudo kettle-orchestrator /usr/share/kettle/image \
  --qemu-binary /usr/share/kettle/qemu-system-x86_64 \
  --port 8000 --slots 4 --scratch-size 30G --console
```

Each slot boots the image with (see orchestrator `src/qemu.rs`):

```bash
qemu-system-x86_64 -enable-kvm -cpu EPYC-Genoa \
  -machine q35,confidential-guest-support=sev0,igvm-cfg=igvm0,memory-backend=ram1,kernel-irqchip=split \
  -object igvm-cfg,id=igvm0,file=guest.igvm \
  -object memory-backend-memfd,id=ram1,size=20G,share=true \
  -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1 \
  -drive file=disk.raw,format=raw,if=virtio,readonly=on \
  -drive file=scratch-slot-0.raw,format=raw,if=virtio \
  -smp 10 -m 20G \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:23000-:8080 ...
```

Note the root disk is `readonly=on` — integrity comes from dm-verity, freshness
from the per-launch scratch disk.

### Boot a single CVM interactively

`--exec` prints the exact QEMU invocation for slot 0, creates the scratch disk,
then execs QEMU in place of the orchestrator (console + QEMU monitor muxed on
stdio; toggle with `Ctrl-a c`):

```bash
sudo kettle-orchestrator target/image --exec
```

This is the fastest way to debug boot problems: you see OVMF/UKI/kernel output
directly and can copy-paste the printed command line.

### Drive a remote attested build

```bash
ORCHESTRATOR_URL=http://127.0.0.1:8000 \
  bin/remote-build https://github.com/burntsushi/ripgrep master
```

Or hit the HTTP API directly (same routes on orchestrator and in-guest
`kettle-server`, which listens on `KETTLE_PORT`, default 8080):

```bash
NONCE="$(openssl rand -hex 16)"
curl -fsS -X POST -H 'content-type: application/json' \
  -d "{\"nonce\":\"$NONCE\",\"repo_url\":\"https://github.com/user/proj\",\"repo_ref\":\"main\"}" \
  http://127.0.0.1:8000/build            # -> {"job_id": ...}
curl -sN  http://127.0.0.1:8000/build/$JOB_ID/events   # SSE stream until "complete"
curl -fsS http://127.0.0.1:8000/build/$JOB_ID/result -o result.tar.gz
curl -fsS http://127.0.0.1:8000/config   # digest-pinned image reference booted
```

### Verify the full chain

```bash
tar xzf result.tar.gz -C build-dir
kettle verify build-dir --nonce "$NONCE"                 # provenance + evidence + nonce
kettle verify build-dir --igvm guest.igvm --image disk.raw
```

- `--igvm <FILE>` recomputes the IGVM's SNP launch digest and requires it to
  match the attested launch measurement — proving the build ran in a CVM booted
  from exactly this IGVM.
- `--image <FILE>` (requires `--igvm`) reads the dm-verity roothash stored in
  the disk's `root-verity` GPT partition and requires it to match the roothash
  committed inside the IGVM — binding the IGVM to a specific root filesystem.
- `--nonce <hex>` (max 16 bytes) proves freshness: pass the same nonce you sent
  to `POST /build` / `kettle attest --nonce`.

### Work with IGVM files directly

The `igvm-tools` crate (in `crates/igvm-tools`) ships a CLI targeting QEMU+KVM
specifically — its measurement matches hardware attestation only on QEMU+KVM:

```bash
igvm-tools build --firmware OVMF.fd --kernel uki.efi \
  --platform snp --smp 10 --output guest-smp10.igvm --manifest igvm-manifest.json
igvm-tools measure guest-smp10.igvm --verbose   # prints the SNP launch digest
```

## Configuration reference

### kettle CLI

```
kettle build  <PATH>                          # SLSA provenance + build + checksums (any machine)
kettle attest <PATH> [--nonce <hex>]          # build + hardware-signed evidence.json (TEE only)
kettle verify <PATH> [--nonce <hex>] [--igvm <FILE>] [--image <FILE>]
```

Cargo features: `cli` (binary metadata), `attest` (TEE attestation; needs
libtss2), `server` (HTTP build server). `kettle attest` without the `attest`
feature fails with an explicit "rebuild with --features attest" error rather
than silently degrading — preserve that behavior in any wrapper you write.

### kettle-orchestrator flags (defaults from `src/config.rs`)

| Flag | Default | Meaning |
|------|---------|---------|
| `IMAGE_DIR` | required | dir with disk.raw, guest.igvm, manifest.json |
| `--port` | 8000 | HTTP API port |
| `--slots` | 4 | concurrent CVMs |
| `--hostfwd-base` | 23000 | host port for slot 0 (slot N = base+N → guest 8080) |
| `--qemu-binary` | `qemu-system-x86_64` | must support igvm-cfg + sev-snp-guest |
| `--scratch-size` | 30G | per-CVM ephemeral ext4 `LABEL=scratch` disk |
| `--build-timeout-secs` | 1800 | per-job build timeout |
| `--boot-timeout-secs` | 30 | CVM boot deadline |
| `--result-ttl-secs` | 1800 | how long results are downloadable |
| `--frontend-dir` | embedded | serve UI from disk instead of embedded assets |
| `--exec` | off | print + exec one slot's QEMU command, then exit |
| `--console` | off | stream guest console to build clients as events |

### Image manifest (`manifest.json`, version 2)

The orchestrator accepts exactly this shape — version 2, platform `snp`,
exactly one variant (each variant's IGVM measurement depends on its `smp`):

```json
{
  "version": 2,
  "build":    { "memory": "20G", "platform": "snp" },
  "outputs":  { "disk_image": { "path": "disk.raw" } },
  "variants": [ { "smp": 10, "igvm": { "path": "guest-smp10.igvm" } } ]
}
```

`memory` must be digits plus optional K/M/G/T suffix. Paths are reduced to
basenames and resolved inside `IMAGE_DIR`.

## Troubleshooting

- **"kettle-orchestrator requires root (rerun with sudo)"** — pooled mode needs
  root for KVM/SNP; only `--exec` skips the check path shown first.
- **"manifest version N is unsupported"** — the orchestrator only reads
  version 2 manifests; rebuild with the current Kettle image tooling instead
  of hand-editing the version field (older shapes are structurally different).
- **"manifest declares platform=...; only \"snp\" is supported"** — the runtime
  is SEV-SNP-only by design; there is no non-confidential fallback to enable.
- **"manifest has N variants; exactly one is required"** — split multi-variant
  images into one directory per variant; see Critical guidelines for why.
- **QEMU rejects `igvm-cfg` / `sev-snp-guest`** — your QEMU lacks IGVM/SNP
  support. Point `--qemu-binary` at a build that has it (deployments ship a
  wrapper that also fixes `LD_LIBRARY_PATH`).
- **Boot hangs or times out (default 30s)** — rerun with `--exec` to watch the
  console. dm-verity mismatches (disk.raw and IGVM from different builds) fail
  here: the kernel rejects the rootfs whose hash doesn't match the pinned
  roothash. Always ship disk.raw and the IGVM from the same `image-build` run.
- **`result.tar.gz` has `provenance.json` but no `evidence.json`** — the guest
  server was built without `--features attest` or is not running on genuine TEE
  hardware. This is a non-confidential run; do not verify or claim attestation.
- **`kettle verify --igvm` mismatch** — the booted IGVM differs from the one on
  hand (wrong smp variant, stale image, or a re-measured rebuild). Compare
  `igvm-tools measure <file>` output with the attested launch digest printed in
  the failure, and check `GET /config` for the digest-pinned image actually
  booted.
- **`kettle verify` is slow in debug builds** — SNP measurement runs two
  SHA-384 hashes per guest page; the repo pins `opt-level = 3` for the sha2
  crate even in dev profiles, so use the repo's own Cargo profile or a release
  build.

## Additional resources

- Repo: https://github.com/confidential-dot-ai/kettle (docs/1-attested-builds.md
  through docs/4-threat-model.md cover the design, provenance standards, and
  threat model)
- Published images: https://ghcr.io/confidential-dot-ai/kettle-build
- Key source files when in doubt: `src/main.rs` (CLI), `src/commands/{attest,verify}.rs`
  (flags and verification steps), `src/verity.rs` (roothash extraction),
  `crates/igvm-tools` (IGVM build/measure), orchestrator `src/config.rs` (flags),
  `src/qemu.rs` (exact QEMU invocation), `src/manifest.rs` (image manifest schema)
- IGVM spec: https://github.com/microsoft/igvm
