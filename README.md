<h1 align="center">
  <img src="docs/kettle.png" width="220px" height="220px" alt="kettle">
</h1>

# Kettle, for attested builds

Kettle builds and verifies **attested builds**, packages that include cryptographically signed SLSA provenance certifying the source, tools, and machine used to create the build.

**Get just the good parts of reproducible builds: the security and assurance of signed and provable inputs, without the misery of constantly repairing your build system.**

## Why attested builds?

Attested builds allow anyone to verify the exact inputs that produced any binary output, by adding cryptographic signatures showing exactly what source code, dependencies, and toolchains were used.

Kettle uses TEEs (Trusted Execution Environments) to sign builds using hardware attestation. Hardware attestations are verified against certificates published by the hardware manufacturer, cryptographically linking binaries to their exact source code.

### Use cases for attested builds

Kettle's attested builds provide a solution to almost every scenario where binaries need a verification trail directly back to the source code and tools that created them. This is just a few examples of problems Kettle can solve:

- A customer deploying your service wants to know it’s running the code you claim, built from the source they audited.
- A compliance team wants evidence that a binary was built with specific dependency versions, not newer ones with unknown changes.
- A security auditor wants to verify that the toolchain used to compile a release matches the one specified in your security documentation.
- A regulated enterprise wants proof that sensitive data will be processed only by code that passed their review, not by a modified version.
- A package consumer wants to ensure that the binary they downloaded corresponds to the source code and dependencies they reviewed, not a tampered version.

For a full tour of Kettle's design, architecture, and security guarantees, read our guide to attested builds.

1. [What are Attested Builds?](/docs/1-attested-builds.md)
2. [How Attested Builds Work](/docs/2-how-it-works.md)
3. [Provenance and Standards](/docs/3-provenance-standards.md)
4. [Threat Model and Security Boundaries](/docs/4-threat-model.md)

## Why attest with Kettle?

Most build systems can't provide hardware-secured build machines. Kettle ensures your build was created and signed inside a confidential virtual machine, with memory and compute secured even against a malicious hypervisor. In contrast, if you use GitHub's [artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations), you are forced to simply take GitHub's word that their cloud VMs didn't tamper with your build.

Using Kettle to build and attest inside a TEE gives you hardware-based cryptographic assertion, dramatically reducing the number of parties you are forced to trust. You only need to trust the hardware manufacturer and the physical custodians of your build machines. No need to trust the sysadmins with root on the bare metal, or the authors of the hypervisor that creates and manages your build VMs, or the developers maintaining the image your code will run on. The code that runs in your TEE is signed by the hardware, so you can be sure what ran, and encrypted so even the hypervisor can't read the memory of your job as it runs.

## Installing Kettle

Kettle is available from GitHub Releases or from source via Cargo, the Rust build tool.

### From GitHub Releases

```bash
curl -LO https://github.com/lunal-dev/kettle/releases/latest/download/kettle-installer.sh
# don't forget to read the source before you run random scripts from the internet :)
bash kettle-installer.sh
```

### From source

To install Kettle, first [install Rust](https://rustup.rs), and then use Cargo to build and install:

```bash
cargo install --git https://github.com/lunal-dev/kettle
```

If you are running inside a TEE, you will need to install OS packages for attestation, and then enable the `attest` feature flag. Here's an example for Ubuntu Linux:

```bash
apt-get install -y libtss2-dev
cargo install --features attest --git https://github.com/lunal-dev/kettle
```

### Reproducible build

Every release of Kettle includes a full reproducible binary, with support for attestation, built inside a fully reproducible environment in Docker. Download and use the fully reproducible binary by running:

```bash
curl -LO https://github.com/lunal-dev/kettle/releases/latest/download/kettle-reproducible-x86_64-unknown-linux-gnu.tar.xz
tar xfvj kettle-reproducible-x86_64-unknown-linux-gnu.tar.xz 
chmod +x kettle
./kettle attest
```

## Using Kettle

### Build anywhere

Run `kettle build` to do all the steps except the hardware cryptography: generate a SLSA-compliant `provenance.json` file, build the project, and checksum the binaries. Use this command to test your build process even if you aren't inside a TEE.

![`kettle build` will generate the provenance, build the project, and checksum the binaries](/docs/build.png)

Today, Kettle supports building and attesting Rust and Nix projects. It's easy to add additional toolchains, and we plan to add first-party support for Python and Go soon.

This example will check out the `ripgrep` search tool, build a binary, and generate a provenance file:

```bash
git clone https://github.com/burntsushi/ripgrep
kettle build ripgrep
```

After Kettle finishes running, look for the provenance and binaries are available inside the `kettle-build` directory.

### Attest from a TEE

Run `kettle attest` to run a build, record the VM firmware and OS image, then apply a hardware signature to everything to create an `evidence.json` file.

![`kettle attest` will build if needed, then create hardware-signed evidence containing the checksum of the provenance file and confidential VM launch mearusements](/docs/attest.png)

While running inside a TEE, this will check out, build, and attest the `ripgrep` search tool:

```bash
git clone https://github.com/burntsushi/ripgrep
kettle attest ripgrep
```

After Kettle finishes running, the provenance, attestation, and binaries are available inside the `kettle-build` directory.

### Verify anywhere

Run `kettle verify` to cryptographically verify your binaries. Kettle will read the `evidence.json`, verify the signature using hardware vendor public keys, and then validate the signed `provenance.json` and use it to confirm the checksum of your binary.

![verify the hardware-signed evidence, which provides the checksums for the provenance and binary, which you can use to prove which source code, dependencies, and toolchain were used](/docs/verify.png)

Verify the attested build created above like this:

```bash
kettle verify ripgrep/kettle-build
```

Two optional flags tie the attestation to the exact VM image that produced it:

- `--igvm <FILE>` — verify that the attested launch measurement matches this IGVM
  file's launch digest, proving the build ran in a confidential VM booted from
  exactly this IGVM.
- `--image <FILE>` — verify that the dm-verity roothash committed inside the IGVM
  matches the roothash stored in this disk image (`disk.raw`), binding the
  verified IGVM to a specific root filesystem. Requires `--igvm`.

```bash
kettle verify ripgrep/kettle-build --igvm guest.igvm --image disk.raw
```

## Supported toolchains

Today, Kettle supports building, attesting, and verifying software packaged with:

- Cargo, for programs written in Rust
- pnpm, for programs written in JavaScript and TypeScript
- nix, for programs written in any language

Planned toolchain support includes:

- uv, for programs written in Python
- go, for programs written in Go

## Development

Use `cargo nextest run` to run the tests for any platform.

In a TEE, use `cargo nextest run --ignored all` to run the full integration tests that checkout Rust and Nix projects, build them, attest them, and verify them.

Run `bin/build-reproducible` to use Docker images provided by the StageX project to build a byte-for-byte reproducible build of Kettle into `./target/reproducible/kettle`.
