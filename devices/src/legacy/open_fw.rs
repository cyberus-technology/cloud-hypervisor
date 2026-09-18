// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! This is a collection of interfaces that can be used for interacting with Open Firmware
//! data types.

use std::fmt::{Display, Formatter, Result as FmtResult};

use pci::PciBdf;
use thiserror::Error;
use vm_virtio::VirtioDeviceType;

#[cfg(target_arch = "x86_64")]
/// QEMU bootorder paths and OVMF's parser use `/pci@i0cf8` for the PCI root associated with I/O
/// port 0xcf8. QEMU uses `scsi` in the Open Firmware paths for its virtio-blk devices. While we do
/// not configure our blk devices as SCSI, we reuse the same path to stay compatible. See:
/// https://github.com/tianocore/edk2/blob/2816ff0ab0d6505bf580aa8eec02cc2b89f04230/OvmfPkg/Library/QemuBootOrderLib/QemuBootOrderLib.c#L909
const OPENFW_DEVICE_PATH_VIRTIO_DISK_PREFIX: &str = "/pci@i0cf8/scsi@";
#[cfg(target_arch = "x86_64")]
/// OVMF/QEMU uses target = 0 and LUN (Logical Unit Number) = 0 to represent a single virtio-blk
/// device.
const OPENFW_DEVICE_PATH_VIRTIO_DISK_SUFFIX: &str = "/disk@0,0";

#[derive(Debug, Error)]
pub enum OpenFwDevicePathError {
    /// Device is not attached to a bus.
    #[error("Can't create an Open Firmware device path from a device not attached to a bus")]
    NoBusDevice,
    /// Device is not bootable.
    #[error("Can't create an Open Firmware device path for a non-bootable device")]
    DeviceNotBootable,
    /// Device is not a PCI device.
    #[error("Currently only PCI devices are supported")]
    NoPciDevice,
    /// Device is not connected to the first PCI bus on the first segment.
    #[error(
        "Device must be connected to the PCI root bus (segment 0, bus 0) but found segment {segment_id}, bus {bus_id}"
    )]
    DeviceNotConnectedToRootBus { segment_id: u16, bus_id: u8 },
    /// PCI device without a configured BDF.
    #[error("Found a PCI device without BDF set")]
    PciDeviceWithoutBdf,
}

#[derive(Debug)]
/// Struct for creating Open Firmware device path strings.
///
/// This struct contains methods to create a Open Firmware device path from a device's bus address
/// and its device type in the form of `"/pci@i0cf8/<bustype>@<address>/<device_type>@0.0"`.
pub struct OpenFwDevicePath(String);

impl OpenFwDevicePath {
    #[cfg(target_arch = "x86_64")]
    /// Creates an Open Firmware device path for the given device type and PCI BDF.
    pub fn from_bdf_and_device(
        bdf: PciBdf,
        device_type: VirtioDeviceType,
    ) -> Result<Self, OpenFwDevicePathError> {
        // CHV currently rejects device path generation for devices outside PCI segment 0. This is
        // required with the current OVMF integration: while CHV exposes each PCI segment as a
        // separate PCI domain/root complex, OVMF only creates boot-time PCI root-bridge support for
        // segment 0.[0] The flat PCI topology of CHV additionally only supports bus ID 0.
        // [0] https://github.com/tianocore/edk2/blob/58a00ddd494845143667da0d807fa517bc5447b1/OvmfPkg/Library/PciHostBridgeUtilityLib/PciHostBridgeUtilityLib.c#L136
        if bdf.segment() != 0 || bdf.bus() != 0 {
            return Err(OpenFwDevicePathError::DeviceNotConnectedToRootBus {
                segment_id: bdf.segment(),
                bus_id: bdf.bus(),
            });
        }
        match device_type {
            VirtioDeviceType::Block => Ok(Self(format!(
                "{OPENFW_DEVICE_PATH_VIRTIO_DISK_PREFIX}{:x}{OPENFW_DEVICE_PATH_VIRTIO_DISK_SUFFIX}",
                bdf.device()
            ))),
            _ => Err(OpenFwDevicePathError::DeviceNotBootable),
        }
    }
}

impl Display for OpenFwDevicePath {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn openfw_device_path() {
        use crate::legacy::open_fw::OpenFwDevicePath;

        let expected_open_fw_path = "/pci@i0cf8/scsi@3/disk@0,0".to_owned();

        let bdf = PciBdf::new(0, 0, 3, 0);

        let open_fw_path =
            OpenFwDevicePath::from_bdf_and_device(bdf, vm_virtio::VirtioDeviceType::Block).unwrap();
        assert_eq!(open_fw_path.to_string(), expected_open_fw_path);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn openfw_device_path_invalid_bdf() {
        let invalid_segment = 1_u16;
        let invalid_bus = 1_u8;

        let bdf = PciBdf::new(0, invalid_bus, 3, 0);
        let e = OpenFwDevicePath::from_bdf_and_device(bdf, vm_virtio::VirtioDeviceType::Block)
            .unwrap_err();
        assert!(
            matches!(e, OpenFwDevicePathError::DeviceNotConnectedToRootBus{segment_id: segment, bus_id: bus} if segment == 0 && bus == invalid_bus)
        );
        let bdf = PciBdf::new(invalid_segment, invalid_bus, 3, 0);
        let e = OpenFwDevicePath::from_bdf_and_device(bdf, vm_virtio::VirtioDeviceType::Block)
            .unwrap_err();
        assert!(
            matches!(e, OpenFwDevicePathError::DeviceNotConnectedToRootBus{segment_id: segment, bus_id: bus} if segment == invalid_segment && bus == invalid_bus)
        );
        let bdf = PciBdf::new(invalid_segment, 0, 3, 0);
        let e = OpenFwDevicePath::from_bdf_and_device(bdf, vm_virtio::VirtioDeviceType::Block)
            .unwrap_err();
        assert!(
            matches!(e, OpenFwDevicePathError::DeviceNotConnectedToRootBus{segment_id: segment, bus_id: bus} if segment == invalid_segment && bus == 0)
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn openfw_device_path_unsupported_device_type() {
        let bdf = PciBdf::new(0, 0, 3, 0);

        let e = OpenFwDevicePath::from_bdf_and_device(bdf, vm_virtio::VirtioDeviceType::Console)
            .unwrap_err();
        assert!(matches!(e, OpenFwDevicePathError::DeviceNotBootable));
    }
}
