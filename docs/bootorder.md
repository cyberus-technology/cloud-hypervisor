# Boot Order Hints
Cloud Hypervisor allows users to provide boot-order hints to the
firmware with the `bootindex` option for disk devices. It exposes these
hints through the QEMU-compatible [`fw_cfg` device](./fw_cfg.md), as an
item named `bootorder` in the fw_cfg file directory.

The firmware must support QEMU fw_cfg and interpret its `bootorder`
item. When a disk specifies `bootindex` and no fw_cfg configuration was
provided, Cloud Hypervisor implicitly adds an fw_cfg device with its
default configuration.

Boot-order hints are currently supported only on x86_64 builds with the
`fw_cfg` feature and only for devices on PCI segment 0. Lower indices
result in higher precedence and each index has to be unique.