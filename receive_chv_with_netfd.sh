#!/usr/bin/env bash

set -euo pipefail

# activate job control
set -m

# The MAC address must be attached to the macvtap and be used inside the guest
mac="c2:67:4f:53:29:cc"
# Host network adapter to bridge the guest onto
host_net="wlp1s0"

# Delete in case a previous run failed.
sudo ip link delete macvtap1 || true

# Create the macvtap0 as a new virtual MAC associated with the host network
sudo ip link add link "$host_net" name macvtap1 type macvtap
sudo ip link set macvtap1 address "$mac" up
sudo ip link show macvtap1

# A new character device is created for this interface
tapindex=$(< /sys/class/net/macvtap1/ifindex)
tapdevice="/dev/tap$tapindex"

# Ensure that we can access this device
sudo chown "$UID:$UID" "$tapdevice"

# Open as FD 42
exec 42<>"$tapdevice"

rm -f /tmp/chv2.sock
cargo run --bin cloud-hypervisor -- --api-socket /tmp/chv2.sock

# Close FD on exit
exec 42>&-
sudo ip link delete macvtap1
