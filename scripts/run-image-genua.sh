#!/usr/bin/env bash
# Build cloud-hypervisor and boot a genua product image with it.
#
# Usage: ./run-image-genua.sh [--release] <image.qcow2>
#
# Builds cloud-hypervisor (debug unless --release is given), downloads
# the EDK2 UEFI firmware (CLOUDHV.fd, see docs/uefi.md) next to this
# script if missing, and boots the image through that firmware. Cloud
# Hypervisor has no legacy BIOS and cannot direct-kernel-boot an
# OpenBSD-based image, so the disk can only boot via UEFI.
#
# stdout is the interactive guest serial port (COM1). The VMM logs at
# debug level to cloud-hypervisor.log. The terminal is in raw mode, so
# Ctrl-C is forwarded to the guest and does NOT stop the VM. To stop
# the VM, run the ch-remote command printed at startup from a second
# terminal.
set -euo pipefail

DIR=$(dirname "$(readlink -f "$0")")

PROFILE=debug
CARGO_FLAG=
IMG=
while [ $# -gt 0 ]; do
    case $1 in
        # -h prints the header comment above
        -h|--help) sed -n "2,/^set / s/^#[ ]\{0,1\}//p" "$0"; exit 0 ;;
        --release) PROFILE=release CARGO_FLAG=--release ;;
        -*) echo "unknown option: $1" >&2; exit 1 ;;
        *) IMG=$1 ;;
    esac
    shift
done
[ -n "$IMG" ] || { echo "Usage: ${0##*/} [--release] <image.qcow2>" >&2; exit 1; }

cargo build $CARGO_FLAG --manifest-path "$DIR/../Cargo.toml"

# Same pinned firmware build as the integration tests (test-util.sh).
FW=$DIR/CLOUDHV.fd
[ -f "$FW" ] || curl -fL -o "$FW" \
    "https://github.com/cloud-hypervisor/edk2/releases/download/ch-1e1b96f126/CLOUDHV.fd"

API_SOCK=$DIR/ch.sock
rm -f "$API_SOCK"

# A killed VMM leaves the terminal in raw mode, so restore it on exit.
STTY_SAVE=$(stty -g 2>/dev/null || true)
trap '[ -z "$STTY_SAVE" ] || stty "$STTY_SAVE"' EXIT

echo "To stop the VM, run from another terminal:" >&2
echo "  $DIR/../target/$PROFILE/ch-remote --api-socket $API_SOCK shutdown-vmm" >&2

"$DIR/../target/$PROFILE/cloud-hypervisor" \
    --api-socket "$API_SOCK" \
    --firmware "$FW" \
    --disk path="$IMG" \
    --cpus boot=1 \
    --memory size=4G \
    --serial tty \
    --console off \
    -vv \
    --log-file "$DIR/cloud-hypervisor.log"
