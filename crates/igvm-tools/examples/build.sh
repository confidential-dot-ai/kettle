#!/usr/bin/env bash
# Build an IGVM file using prebuilt OVMF + UKI.
#
# Usage:
#   ./examples/build.sh                    # SMP 1
#   ./examples/build.sh --smp 2            # SMP 2
#   ./examples/build.sh -o my-guest.igvm   # custom output path
#
# Uses prebuilt/OVMF.fd and prebuilt/uki.efi by default.
# See examples/README.md for how these were generated.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FIRMWARE="${FIRMWARE:-$SCRIPT_DIR/prebuilt/OVMF.fd}"
KERNEL="${KERNEL:-$SCRIPT_DIR/prebuilt/uki.efi}"

if [ ! -f "$FIRMWARE" ]; then
    echo "ERROR: OVMF not found: $FIRMWARE" >&2
    echo "See examples/README.md for how to build it." >&2
    exit 1
fi

if [ ! -f "$KERNEL" ]; then
    echo "ERROR: UKI not found: $KERNEL" >&2
    echo "See examples/README.md for how to build it." >&2
    exit 1
fi

exec igvm-tools build --firmware "$FIRMWARE" --kernel "$KERNEL" "$@"
