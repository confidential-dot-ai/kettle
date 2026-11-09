#!/usr/bin/env bash
# TDX evidence payload: run kettle's TEE-gated suite inside an Intel TD.
#
# confidential-ci's tdx-evidence lane boots a per-job TD from the pinned
# confidential-os general-purpose image, clones this repo at the dispatched ref
# and runs this script as root over SSH. The cvm-e2e payload contract applies:
# `@@PAYLOAD_OK@@` on the last line is the gate, `@@...@@` lines are progress,
# The TD is 8 vCPU / 16Gi with a scratch disk.
set -euo pipefail
cd "$(dirname "$0")/.."

step() { echo "@@$1@@"; }

[ "$(id -u)" -eq 0 ] || { echo "must run as root (id -u = $(id -u))"; exit 1; }

step REPORT_INTERFACE
[ -e /dev/tdx_guest ] || [ -d /sys/kernel/config/tsm/report ] \
  || { echo "TDX report interface missing: /dev/tdx_guest absent and configfs-tsm not mounted"; exit 1; }

step DEPS
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  git curl ca-certificates build-essential pkg-config libtss2-dev
curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 10 --max-time 300 \
  --retry 3 --retry-all-errors https://sh.rustup.rs \
  | sh -s -- -y --profile minimal --default-toolchain stable --no-modify-path
# shellcheck source=/dev/null
. "$HOME/.cargo/env"
curl -fsSL --connect-timeout 10 --max-time 120 --retry 3 --retry-all-errors \
  https://get.nexte.st/0.9/linux | tar -xz -C /usr/local/bin cargo-nextest
cargo-nextest --version

# Suite and filter as the SNP leg runs them: stored_roothash_from_real_disk reads
# a disk image at a developer's path, cli_attest_alejandra clones and builds an
# out-of-tree project.
step TEST
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0
export CARGO_BUILD_JOBS=4   # 16Gi guest: about 4Gi per concurrent rustc
TEST_THREADS=4              # 8 vCPU: half the cores, leaving the rest to builds the tests spawn
select=(--features attest --run-ignored all
  -E 'not (test(stored_roothash_from_real_disk) | test(cli_attest_alejandra))')
selected=$(cargo nextest list "${select[@]}" --message-format oneline)
[ -n "$selected" ] || { echo "filter selects no tests"; exit 1; }
echo "$selected"
cargo nextest run "${select[@]}" --test-threads "$TEST_THREADS" --no-fail-fast

echo "@@PAYLOAD_OK@@"
