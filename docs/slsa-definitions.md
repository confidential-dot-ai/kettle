# SLSA buildType definitions for attested builds

Each attested build produced by [Kettle](https://github.com/confidential-dot-ai/kettle) includes a `provenance.json` file at `kettle-build/provenance.json`. The provenance file is an [in-toto Statement](https://in-toto.io/Statement/v1) carrying a [SLSA v1.2 build provenance predicate](https://slsa.dev/spec/v1.2/build-provenance), and contains a list of the source code and tools that were used to create the build. This document is linked from the `buildType` parameter in that file, and describes how the fields in that file correspond to the attested build that was created.

The file is serialized as pretty-printed JSON with keys in a fixed order. The exact formatting is important because the SHA-256 checksum of the file is included in the cryptographic attestion produced by the TEE where the build ran. Re-ordering keys or changing whitespace will cause `kettle verify` to fail.

## Build type

Every attested build uses the same `buildType`: `https://confidential.ai/attested-builds/v1`. The toolchain is auto-detected from the project's lockfile, and is identified in the provenance by the set of keys in `internalParameters.toolchain` (see below).

The `buildType` version pins the schema of `externalParameters` and `internalParameters` **and** each toolchain's input Merkle tree leaf ordering (see [`byproducts`](#rundetailsbyproducts)). Any change to either requires bumping the `/v1` suffix.

## Build steps

Given a provenance file, the build steps used to produce the artifacts were:

1. Cloning `predicate.buildDefinition.externalParameters.source.uri` and checking out `source.digest.gitCommit`.
2. Verifying the toolchain's lockfile (see the table above) hashes to `internalParameters.lockfileHash`.
3. Installing the toolchain versions recorded in `internalParameters.toolchain`.
4. Running `externalParameters.buildCommand` from the repository root.
5. Gathering the produced `artifacts/` and recording them in `subject`.

## `_type` and `predicateType`

```json
"_type": "https://in-toto.io/Statement/v1",
"predicateType": "https://slsa.dev/provenance/v1"
```

These values are the same for all builds. The file itself matches in-toto Statement v1, and the predicate matches the [SLSA v1.2 specification](https://slsa.dev/spec/v1.2/build-provenance). The `predicateType` value is `https://slsa.dev/provenance/v1` for all 1.x versions of SLSA. When this was written, SLSA v1.2 was the latest version.

## `subject`

One entry per output artifact, with the artifact's file name and a dictionary of one or more digests of the file's bytes. The algorithm used to create the digest is provided as the key, and the digest itself is the value.

```json
"subject": [
  {
    "digest": {
      "sha256": "bdd19eb82593e5c956660470e3f0aa29c79d8929db55bcdff31230d836c31f2a"
    },
    "name": "rg"
  }
]
```

What counts as an artifact depends on the toolchain:

- **cargo**: executable files found in `target/release` (extension-less or `.exe`; intermediate outputs such as `.d`, `.rlib`, `.so`, and dotfiles are excluded).
- **nix**: the store paths printed by `nix build --print-out-paths`.
- **pnpm**: the full `dist/` directory, archived as a single `dist.tar.gz`.

## `predicate.buildDefinition`

### `buildDefinition.buildType`

Always `https://confidential.ai/attested-builds/v1` (see [Build type](#build-type)). The toolchain driver that ran the build is identified by the set of keys in `internalParameters.toolchain`, which determines which per-toolchain schema the rest of `buildDefinition` follows.

### `buildDefinition.externalParameters`

The user-controlled inputs to the build: which source to build, and the command used to build it.

```json
"externalParameters": {
  "buildCommand": "cargo build --locked --release",
  "source": {
    "digest": {
      "gitCommit": "4519153e5e461527f4bca45b042fff45c4ec6fb9",
      "gitTree": "0e1c3a9e3e85a65799d9dbf15aa4743ad18cbc3f"
    },
    "uri": "https://github.com/burntsushi/ripgrep"
  }
}
```

- `buildCommand` — the exact command the driver executed, as a string. This is fixed per toolchain (see table above); users cannot inject arbitrary flags.
- `source.uri` — the URL of the `origin` remote of the built repository (`git remote get-url origin`; empty string if the repository has no remote).
- `source.digest.gitCommit` — `git rev-parse HEAD` at build time.
- `source.digest.gitTree` — `git rev-parse HEAD^{tree}` at build time. Recording the tree hash in addition to the commit lets verifiers confirm the source contents independently of commit metadata.

### `buildDefinition.internalParameters`

A record of the tooling used to create the build. Common to all build types:

```json
"internalParameters": {
  "lockfileHash": {
    "sha256": "8aee2707b876453e57e5b89846ab5b33d429a4e0d1f5a95f7c8622db130cf59f"
  },
  "toolchain": { ... }
}
```

- `lockfileHash` — hex-encoded SHA-256 of the raw bytes of the toolchain's lockfile (`Cargo.lock`, `flake.lock`, or `pnpm-lock.yaml`).
- `toolchain` — the version string and hex-encoded SHA-256 of the binary for every tool involved in the build, always including `kettle` itself (kettle hashes its own executable). The set of keys identifies the toolchain:
  - cargo builds: `cargo`, `rustc`, `kettle`
  - nix builds: `nix`, `kettle`
  - pnpm builds: `pnpm`, `node`, `kettle`

For example, here is a toolchain section from a Rust project build:

```json
"toolchain": {
  "cargo": {
    "digest": {
      "sha256": "6bbe4f5601b419b69ec2001b5e64c997770f620e1493ad7007b78e505457796f"
    },
    "version": "cargo 1.93.1 (083ac5135 2025-12-15)"
  },
  "rustc": {
    "digest": {
      "sha256": "bd1875234c27f9f0c9f9c700ade69f7e83d25e368f38407d32b4b0e2cbc2426d"
    },
    "version": "rustc 1.93.1 (01f6ddf75 2026-02-11)"
  },
  "kettle": {
    "digest": {
      "sha256": "2e8e398fce4dfb04f1dad4555908b48c08909a3a2dcb026d8a82874556e942ff"
    },
    "version": "1.0.0"
  }
}
```

Nix builds add two more fields:

```json
"internalParameters": {
  "evaluation": {
    "derivationCount": 2,
    "fetchCount": 296
  },
  "flakeInputs": [
    {
      "name": "fenix",
      "narHash": "sha256-f09fAifGPEuRrz1DFY910jexq0DaBuQBbq7WcxQIUgs="
    }
  ],
  ...
}
```

- `evaluation.derivationCount` — number of derivations in the evaluated build graph.
- `evaluation.fetchCount` — number of fixed-output (fetch) derivations in that graph.
- `flakeInputs` — the `narHash` of each input recorded in `flake.lock` (omitted when the flake has no inputs).

### `buildDefinition.resolvedDependencies`

Every external artifact fetched to perform the build, each with a [Package URL](https://github.com/package-url/purl-spec)-style `uri` and a content digest. Entries are sorted by `uri`. The format is per-toolchain:

**cargo** — one entry per package in `Cargo.lock` (excluding workspace members, which are covered by git):

```json
{
  "digest": {
    "sha256": "8e60d3430d3a69478ad0993f19238d2df97c507009a52b3c10addcd7f6bcb916"
  },
  "name": "aho-corasick",
  "uri": "pkg:cargo/aho-corasick@1.1.3?checksum=sha256:8e60d3430d3a69478ad0993f19238d2df97c507009a52b3c10addcd7f6bcb916"
}
```

- Registry dependencies use the `Cargo.lock` checksum as a `sha256` digest, with uri `pkg:cargo/{name}@{version}?checksum=sha256:{checksum}`.
- Git dependencies use a `gitCommit` digest, with uri `pkg:cargo/{name}@{version}?vcs_url=git+{url}@{commit}` (URL percent-encoded).
- Path dependencies outside the workspace are resolved to the git commit of their containing repository, with uri `pkg:cargo/{name}@{version}?vcs_url=git+file:{relative-path}@{commit}`; this requires that repository's working tree to be clean.

**nix** — one entry per fixed-output derivation (fetch) in the evaluated build graph:

```json
{
  "annotations": {
    "drvPath": "wjsx1al69h2n4jnklbn252m6xxv0h8bi-0001-Add-prototype-to-function-definitions.patch.drv",
    "outputHashMode": "flat"
  },
  "digest": {
    "sha256": "X2Vv6VVM3KjmBHo2ukVWe5YTVXRmqe//Kw2kr73OpZs="
  },
  "name": "0001-Add-prototype-to-function-definitions.patch",
  "uri": "pkg:nix-fetch/0001-Add-prototype-to-function-definitions.patch?hash=sha256:X2Vv6VVM3KjmBHo2ukVWe5YTVXRmqe//Kw2kr73OpZs="
}
```

The digest is the derivation's expected output hash exactly as nix records it (base64, unlike the hex digests elsewhere in the file). `annotations` carries nix-specific detail: the derivation path, the output hash mode (`flat` or `recursive`), and the fetch `url`/`urls` when the derivation declares them.

**pnpm** — one entry per package in `pnpm-lock.yaml`:

```json
{
  "digest": {
    "sha512": "sha512-...base64..."
  },
  "name": "aho-corasick",
  "uri": "pkg:npm/aho-corasick@1.1.3?checksum=sha512-...base64..."
}
```

The digest is the package's `integrity` value (SRI, typically SHA-512) from the lockfile, with uri `pkg:npm/{name}@{version}?checksum={integrity}`. Packages resolved from a GitHub commit tarball instead record the `codeload.github.com` tarball URL as the `uri`, with the commit (the URL's last path segment) as the digest value.

## `predicate.runDetails`

### `runDetails.builder.id`

```json
"builder": {
  "id": "https://lunal.dev/kettle-tee/v1"
}
```

Identifies the kettle TEE build platform. Per SLSA, this URI represents the transitive closure of the trusted build platform; the accompanying TEE attestation is what makes this claim verifiable rather than merely asserted.

### `runDetails.metadata`

```json
"metadata": {
  "invocationId": "build-20260520-215052-17223ff8",
  "startedOn": "2026-05-20T21:50:52.083557+00:00",
  "finishedOn": "2026-05-20T21:50:56.455535+00:00"
}
```

- `invocationId` — `build-{YYYYMMDD-HHMMSS}-{suffix}`, where the suffix is 8 random hex characters, unique per build invocation.
- `startedOn` — UTC RFC 3339 timestamp with microsecond precision, captured immediately before the build command runs.
- `finishedOn` — same format, captured after artifact collection completes. `null` if the build did not finish.

### `runDetails.byproducts`

A single byproduct: the root of a Merkle tree over all build inputs.

```json
"byproducts": [
  {
    "digest": {
      "sha256": "5deb8d3000e179a407d8627b2d4a201f0fb81bb11f1bcd9dff7b42180e029805"
    },
    "name": "input_merkle_root"
  }
]
```

Each leaf is the SHA-256 of an input entry string; the tree is a standard binary SHA-256 Merkle tree and the root is hex-encoded. This single value commits to the entire input set, so two builds with the same Merkle root consumed identical inputs.

The leaf ordering is a frozen contract for each toolchain — changing it requires a new `buildType` version:

- **cargo**: git commit, git tree, rustc hash, rustc version, cargo hash, cargo version, lockfile hash, then each resolved dependency `uri` in sorted order.
- **nix**: git commit, git tree, lockfile hash, then `fetch:{name}:{algo}:{hash}` for each fetch, then nix hash, nix version.
- **pnpm**: git commit, git tree, node hash, node version, pnpm hash, pnpm version, lockfile hash, then each resolved dependency `uri` in sorted order.

## Complete example

A cargo build of ripgrep (dependency list truncated):

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://confidential.ai/attested-builds/v1",
      "externalParameters": {
        "buildCommand": "cargo build --locked --release",
        "source": {
          "digest": {
            "gitCommit": "4519153e5e461527f4bca45b042fff45c4ec6fb9",
            "gitTree": "0e1c3a9e3e85a65799d9dbf15aa4743ad18cbc3f"
          },
          "uri": "https://github.com/burntsushi/ripgrep"
        }
      },
      "internalParameters": {
        "lockfileHash": {
          "sha256": "8aee2707b876453e57e5b89846ab5b33d429a4e0d1f5a95f7c8622db130cf59f"
        },
        "toolchain": {
          "cargo": {
            "digest": {
              "sha256": "6bbe4f5601b419b69ec2001b5e64c997770f620e1493ad7007b78e505457796f"
            },
            "version": "cargo 1.93.1 (083ac5135 2025-12-15)"
          },
          "rustc": {
            "digest": {
              "sha256": "bd1875234c27f9f0c9f9c700ade69f7e83d25e368f38407d32b4b0e2cbc2426d"
            },
            "version": "rustc 1.93.1 (01f6ddf75 2026-02-11)"
          },
          "kettle": {
            "digest": {
              "sha256": "2e8e398fce4dfb04f1dad4555908b48c08909a3a2dcb026d8a82874556e942ff"
            },
            "version": "1.0.0"
          }
        }
      },
      "resolvedDependencies": [
        {
          "digest": {
            "sha256": "8e60d3430d3a69478ad0993f19238d2df97c507009a52b3c10addcd7f6bcb916"
          },
          "name": "aho-corasick",
          "uri": "pkg:cargo/aho-corasick@1.1.3?checksum=sha256:8e60d3430d3a69478ad0993f19238d2df97c507009a52b3c10addcd7f6bcb916"
        }
      ]
    },
    "runDetails": {
      "builder": {
        "id": "https://lunal.dev/kettle-tee/v1"
      },
      "byproducts": [
        {
          "digest": {
            "sha256": "5deb8d3000e179a407d8627b2d4a201f0fb81bb11f1bcd9dff7b42180e029805"
          },
          "name": "input_merkle_root"
        }
      ],
      "metadata": {
        "invocationId": "build-20260520-215052-17223ff8",
        "startedOn": "2026-05-20T21:50:52.083557+00:00",
        "finishedOn": "2026-05-20T21:50:56.455535+00:00"
      }
    }
  },
  "predicateType": "https://slsa.dev/provenance/v1",
  "subject": [
    {
      "digest": {
        "sha256": "bdd19eb82593e5c956660470e3f0aa29c79d8929db55bcdff31230d836c31f2a"
      },
      "name": "rg"
    }
  ]
}
```
