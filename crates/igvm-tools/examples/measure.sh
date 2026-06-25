#!/usr/bin/env bash
# Measure an IGVM file and print the expected SNP launch digest.
#
# Usage:
#   ./examples/measure.sh guest.igvm
#   ./examples/measure.sh -v guest.igvm   # verbose per-page trace

set -euo pipefail
exec igvm-tools measure "$@"
