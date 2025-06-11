#!/usr/bin/env bash

set -euo pipefail

# The MAC address must be attached to the macvtap and be used inside the guest
mac="c2:67:4f:53:29:cb"
# Host network adapter to bridge the guest onto
host_net="wlp1s0"

# Delete in case a previous run failed.
sudo ip link delete macvtap0 || true

# Create the macvtap0 as a new virtual MAC associated with the host network
sudo ip link add link "$host_net" name macvtap0 type macvtap
sudo ip link set macvtap0 address "$mac" up
sudo ip link show macvtap0

# A new character device is created for this interface
tapindex=$(< /sys/class/net/macvtap0/ifindex)
tapdevice="/dev/tap$tapindex"

# Ensure that we can access this device
sudo chown "$UID:$UID" "$tapdevice"

rm -f /tmp/chv1.sock
cargo run --bin cloud-hypervisor -- \
        --api-socket /tmp/chv1.sock \
        --kernel /etc/bootitems/linux/kernel_minimal/stable.vmlinux \
        --initramfs /etc/bootitems/linux/initrd_minimal/default \
        --cmdline "console=ttyS0" \
        --disk path=nixos-livemig-vm--base-image-backup.raw \
        --cpus boot=4 \
        --memory size=1024M \
        --console off \
        --serial tty \
        --net id=net1,fd=44,mac=$mac 44<>$"$tapdevice"

# Close FD on exit
exec 44>&-
sudo ip link delete macvtap0
