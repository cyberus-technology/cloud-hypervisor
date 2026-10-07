// Copyright 2025 Google LLC.
//
// SPDX-License-Identifier: Apache-2.0
//

//! Cloud Hypervisor implementation of QEMU's fw_cfg spec
//! https://www.qemu.org/docs/master/specs/fw_cfg.html
//! Linux kernel fw_cfg driver header
//! https://github.com/torvalds/linux/blob/master/include/uapi/linux/qemu_fw_cfg.h
//! Uploading files to the guest via fw_cfg is supported for all kernels 4.6+ w/ CONFIG_FW_CFG_SYSFS enabled
//! https://cateee.net/lkddb/web-lkddb/FW_CFG_SYSFS.html
//! No kernel requirement if above functionality is not required,
//! only firmware must implement mechanism to interact with this fw_cfg device
use std::fs::File;
use std::io::{Error as IoError, ErrorKind, Read, Result};
use std::mem::offset_of;
use std::os::unix::fs::FileExt;
use std::sync::{Arc, Barrier};

use acpi_tables::rsdp::Rsdp;
use arch::RegionType;
#[cfg(target_arch = "aarch64")]
use arch::aarch64::layout::{
    MEM_32BIT_DEVICES_START, MEM_32BIT_RESERVED_START, RAM_64BIT_START, RAM_START as HIGH_RAM_START,
};
#[cfg(target_arch = "x86_64")]
use arch::layout::{
    EBDA_START, HIGH_RAM_START, MEM_32BIT_DEVICES_SIZE, MEM_32BIT_DEVICES_START,
    MEM_32BIT_RESERVED_START, PCI_MMCONFIG_SIZE, PCI_MMCONFIG_START, RAM_64BIT_START,
};
use bitfield_struct::bitfield;
#[cfg(target_arch = "x86_64")]
use linux_loader::bootparam::boot_params;
#[cfg(target_arch = "aarch64")]
use linux_loader::loader::pe::arm64_image_header as boot_params;
use log::{debug, error};
use thiserror::Error;
use vm_device::BusDevice;
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{
    ByteValued, Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap,
};
use vmm_sys_util::sock_ctrl_msg::IntoIovec;
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes};

#[cfg(target_arch = "x86_64")]
// https://github.com/project-oak/oak/tree/main/stage0_bin#memory-layout
const STAGE0_START_ADDRESS: GuestAddress = GuestAddress(0xfffe_0000);
#[cfg(target_arch = "x86_64")]
const STAGE0_SIZE: usize = 0x2_0000;
const E820_RAM: u32 = 1;
const E820_RESERVED: u32 = 2;

#[cfg(target_arch = "x86_64")]
const PORT_FW_CFG_SELECTOR_OFFSET: u64 = 0x0;
#[cfg(target_arch = "x86_64")]
const PORT_FW_CFG_DATA_OFFSET: u64 = 0x1;
#[cfg(target_arch = "x86_64")]
const PORT_FW_CFG_DMA_HI_OFFSET: u64 = 0x4;
#[cfg(target_arch = "x86_64")]
const PORT_FW_CFG_DMA_LO_OFFSET: u64 = 0x8;
#[cfg(target_arch = "x86_64")]
pub const PORT_FW_CFG_BASE: u64 = 0x510;
#[cfg(target_arch = "x86_64")]
pub const PORT_FW_CFG_WIDTH: u64 = 0xc;
#[cfg(target_arch = "aarch64")]
const PORT_FW_CFG_SELECTOR_OFFSET: u64 = 0x8;
#[cfg(target_arch = "aarch64")]
const PORT_FW_CFG_DATA_OFFSET: u64 = 0x0;
#[cfg(target_arch = "aarch64")]
const PORT_FW_CFG_DMA_HI_OFFSET: u64 = 0x10;
#[cfg(target_arch = "aarch64")]
const PORT_FW_CFG_DMA_LO_OFFSET: u64 = 0x14;
#[cfg(target_arch = "aarch64")]
pub const PORT_FW_CFG_BASE: u64 = 0x9030000;
#[cfg(target_arch = "aarch64")]
pub const PORT_FW_CFG_WIDTH: u64 = 0x10;

const FW_CFG_SIGNATURE: u16 = 0x00;
const FW_CFG_ID: u16 = 0x01;
const FW_CFG_KERNEL_SIZE: u16 = 0x08;
const FW_CFG_INITRD_SIZE: u16 = 0x0b;
const FW_CFG_KERNEL_DATA: u16 = 0x11;
const FW_CFG_INITRD_DATA: u16 = 0x12;
const FW_CFG_CMDLINE_SIZE: u16 = 0x14;
const FW_CFG_CMDLINE_DATA: u16 = 0x15;
const FW_CFG_SETUP_SIZE: u16 = 0x17;
const FW_CFG_SETUP_DATA: u16 = 0x18;
const FW_CFG_FILE_DIR: u16 = 0x19;
const FW_CFG_KNOWN_ITEMS: usize = 0x20;

pub const FW_CFG_FILE_FIRST: u16 = 0x20;
pub const FW_CFG_DMA_SIGNATURE_CONTENT: [u8; 8] = *b"QEMU CFG";
pub const FW_CFG_SIGNATURE_CONTENT: [u8; 4] = *b"QEMU";
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/qemu_fw_cfg.h
pub const FW_CFG_ACPI_ID: &str = "QEMU0002";
// Reserved (must be enabled)
const FW_CFG_F_RESERVED: u8 = 1 << 0;
const FW_CFG_F_DMA: u8 = 1 << 1;
// We disable the broken DMA interface while the rework is in progress.
// See https://github.com/cobaltcore-dev/cobaltcore/issues/647.
pub const FW_CFG_FEATURE: [u8; 4] = [FW_CFG_F_RESERVED, 0, 0, 0];

const COMMAND_ALLOCATE: u32 = 0x1;
const COMMAND_ADD_POINTER: u32 = 0x2;
const COMMAND_ADD_CHECKSUM: u32 = 0x3;

const ALLOC_ZONE_HIGH: u8 = 0x1;
const ALLOC_ZONE_FSEG: u8 = 0x2;

const FW_CFG_FILENAME_TABLE_LOADER: &str = "etc/table-loader";
const FW_CFG_FILENAME_RSDP: &str = "acpi/rsdp";
const FW_CFG_FILENAME_ACPI_TABLES: &str = "acpi/tables";

#[derive(Debug)]
pub enum FwCfgContent {
    Bytes(Vec<u8>),
    Slice(&'static [u8]),
    File(u64, File),
    U64(u64),
    U32(u32),
    U16(u16),
}

struct FwCfgContentAccess<'a> {
    content: &'a FwCfgContent,
    offset: u32,
}

impl Read for FwCfgContentAccess<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self.content {
            FwCfgContent::File(offset, f) => {
                f.read_exact_at(buf, offset + self.offset as u64)?;
                Ok(buf.len())
            }
            FwCfgContent::Bytes(b) => match b.get(self.offset as usize..) {
                Some(mut s) => s.read(buf),
                None => Err(ErrorKind::UnexpectedEof)?,
            },
            FwCfgContent::Slice(b) => match b.get(self.offset as usize..) {
                Some(mut s) => s.read(buf),
                None => Err(ErrorKind::UnexpectedEof)?,
            },
            FwCfgContent::U64(n) => match n.to_le_bytes().get(self.offset as usize..) {
                Some(mut s) => s.read(buf),
                None => Err(ErrorKind::UnexpectedEof)?,
            },
            FwCfgContent::U32(n) => match n.to_le_bytes().get(self.offset as usize..) {
                Some(mut s) => s.read(buf),
                None => Err(ErrorKind::UnexpectedEof)?,
            },
            FwCfgContent::U16(n) => match n.to_le_bytes().get(self.offset as usize..) {
                Some(mut s) => s.read(buf),
                None => Err(ErrorKind::UnexpectedEof)?,
            },
        }
    }
}

impl Default for FwCfgContent {
    fn default() -> Self {
        FwCfgContent::Slice(&[])
    }
}

impl FwCfgContent {
    fn size(&self) -> Result<u32> {
        let ret = match self {
            FwCfgContent::Bytes(v) => v.len(),
            FwCfgContent::File(offset, f) => (f.metadata()?.len().checked_sub(*offset))
                .ok_or::<IoError>(ErrorKind::UnexpectedEof.into())?
                as usize,
            FwCfgContent::Slice(s) => s.len(),
            FwCfgContent::U64(n) => size_of_val(n),
            FwCfgContent::U32(n) => size_of_val(n),
            FwCfgContent::U16(n) => size_of_val(n),
        };
        u32::try_from(ret).map_err(|_| ErrorKind::InvalidInput.into())
    }
    fn access(&self, offset: u32) -> FwCfgContentAccess<'_> {
        FwCfgContentAccess {
            content: self,
            offset,
        }
    }
}

#[derive(Debug, Default)]
pub struct FwCfgItem {
    pub name: String,
    pub content: FwCfgContent,
}

// ARM MMIO transport needs a rework.
// Find more details here: https://github.com/cobaltcore-dev/cobaltcore/issues/650
#[cfg(all(feature = "fw_cfg", target_arch = "aarch64"))]
compile_error!(
    "fw_cfg is not supported on aarch64: the MMIO transport is incomplete and defective."
);
/// https://www.qemu.org/docs/master/specs/fw_cfg.html
#[derive(Debug)]
pub struct FwCfg {
    selector: u16,
    data_offset: u32,
    dma_address: u64,
    items: Vec<FwCfgItem>,                           // 0x20 and above
    known_items: [FwCfgContent; FW_CFG_KNOWN_ITEMS], // 0x0 to 0x19
    memory: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>>,
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes)]
struct FwCfgDmaAccess {
    control_be: u32,
    length_be: u32,
    address_be: u64,
}

// https://github.com/torvalds/linux/blob/master/include/uapi/linux/qemu_fw_cfg.h#L67
#[bitfield(u32)]
struct AccessControl {
    // FW_CFG_DMA_CTL_ERROR = 0x01
    error: bool,
    // FW_CFG_DMA_CTL_READ = 0x02
    read: bool,
    #[bits(1)]
    _unused2: u8,
    // FW_CFG_DMA_CTL_SKIP = 0x04
    skip: bool,
    #[bits(3)]
    _unused3: u8,
    // FW_CFG_DMA_CTL_ERROR = 0x08
    select: bool,
    #[bits(7)]
    _unused4: u8,
    // FW_CFG_DMA_CTL_WRITE = 0x10
    write: bool,
    #[bits(16)]
    _unused: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes)]
struct FwCfgFilesHeader {
    count_be: u32,
}

pub const FILE_NAME_SIZE: usize = 56;

pub fn create_file_name(name: &str) -> [u8; FILE_NAME_SIZE] {
    let mut c_name = [0u8; FILE_NAME_SIZE];
    let c_len = std::cmp::min(FILE_NAME_SIZE - 1, name.len());
    c_name[0..c_len].copy_from_slice(&name.as_bytes()[0..c_len]);
    c_name
}

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Debug, IntoBytes, FromBytes, Clone, Copy)]
struct BootE820Entry {
    addr: u64,
    size: u64,
    type_: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes)]
struct FwCfgFile {
    size_be: u32,
    select_be: u16,
    _reserved: u16,
    name: [u8; FILE_NAME_SIZE],
}

#[repr(C, align(4))]
#[derive(Debug, IntoBytes, Immutable)]
struct Allocate {
    command: u32,
    file: [u8; FILE_NAME_SIZE],
    align: u32,
    zone: u8,
    _pad: [u8; 63],
}

#[repr(C, align(4))]
#[derive(Debug, IntoBytes, Immutable)]
struct AddPointer {
    command: u32,
    dst: [u8; FILE_NAME_SIZE],
    src: [u8; FILE_NAME_SIZE],
    offset: u32,
    size: u8,
    _pad: [u8; 7],
}

#[repr(C, align(4))]
#[derive(Debug, IntoBytes, Immutable)]
struct AddChecksum {
    command: u32,
    file: [u8; FILE_NAME_SIZE],
    offset: u32,
    start: u32,
    len: u32,
    _pad: [u8; 56],
}

fn create_intra_pointer(name: &str, offset: usize, size: u8) -> AddPointer {
    AddPointer {
        command: COMMAND_ADD_POINTER,
        dst: create_file_name(name),
        src: create_file_name(name),
        offset: offset as u32,
        size,
        _pad: [0; 7],
    }
}

fn create_acpi_table_checksum(offset: usize, len: usize) -> AddChecksum {
    AddChecksum {
        command: COMMAND_ADD_CHECKSUM,
        file: create_file_name(FW_CFG_FILENAME_ACPI_TABLES),
        offset: (offset + offset_of!(AcpiTableHeader, checksum)) as u32,
        start: offset as u32,
        len: len as u32,
        _pad: [0; 56],
    }
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, IntoBytes)]
struct AcpiTableHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    asl_compiler_id: [u8; 4],
    asl_compiler_revision: u32,
}

struct AcpiTable {
    rsdp: Rsdp,
    tables: Vec<u8>,
    table_pointers: Vec<usize>,
    table_checksums: Vec<(usize, usize)>,
}

impl AcpiTable {
    fn pointers(&self) -> &[usize] {
        &self.table_pointers
    }

    fn checksums(&self) -> &[(usize, usize)] {
        &self.table_checksums
    }

    fn take(self) -> (Rsdp, Vec<u8>) {
        (self.rsdp, self.tables)
    }
}

// Creates fw_cfg items used by firmware to load and verify Acpi tables
// https://github.com/qemu/qemu/blob/master/hw/acpi/bios-linker-loader.c
fn create_acpi_loader(acpi_table: AcpiTable) -> [FwCfgItem; 3] {
    let mut table_loader_bytes: Vec<u8> = Vec::new();
    let allocate_rsdp = Allocate {
        command: COMMAND_ALLOCATE,
        file: create_file_name(FW_CFG_FILENAME_RSDP),
        align: 4,
        zone: ALLOC_ZONE_FSEG,
        _pad: [0; 63],
    };
    table_loader_bytes.extend(allocate_rsdp.as_bytes());

    let allocate_tables = Allocate {
        command: COMMAND_ALLOCATE,
        file: create_file_name(FW_CFG_FILENAME_ACPI_TABLES),
        align: 4,
        zone: ALLOC_ZONE_HIGH,
        _pad: [0; 63],
    };
    table_loader_bytes.extend(allocate_tables.as_bytes());

    for pointer_offset in acpi_table.pointers().iter() {
        let pointer = create_intra_pointer(FW_CFG_FILENAME_ACPI_TABLES, *pointer_offset, 8);
        table_loader_bytes.extend(pointer.as_bytes());
    }
    for (offset, len) in acpi_table.checksums().iter() {
        let checksum = create_acpi_table_checksum(*offset, *len);
        table_loader_bytes.extend(checksum.as_bytes());
    }
    let pointer_rsdp_to_xsdt = AddPointer {
        command: COMMAND_ADD_POINTER,
        dst: create_file_name(FW_CFG_FILENAME_RSDP),
        src: create_file_name(FW_CFG_FILENAME_ACPI_TABLES),
        offset: offset_of!(Rsdp, xsdt_addr) as u32,
        size: 8,
        _pad: [0; 7],
    };
    table_loader_bytes.extend(pointer_rsdp_to_xsdt.as_bytes());
    let checksum_rsdp = AddChecksum {
        command: COMMAND_ADD_CHECKSUM,
        file: create_file_name(FW_CFG_FILENAME_RSDP),
        offset: offset_of!(Rsdp, checksum) as u32,
        start: 0,
        len: offset_of!(Rsdp, length) as u32,
        _pad: [0; 56],
    };
    let checksum_rsdp_ext = AddChecksum {
        command: COMMAND_ADD_CHECKSUM,
        file: create_file_name(FW_CFG_FILENAME_RSDP),
        offset: offset_of!(Rsdp, extended_checksum) as u32,
        start: 0,
        len: size_of::<Rsdp>() as u32,
        _pad: [0; 56],
    };
    table_loader_bytes.extend(checksum_rsdp.as_bytes());
    table_loader_bytes.extend(checksum_rsdp_ext.as_bytes());

    let table_loader = FwCfgItem {
        name: FW_CFG_FILENAME_TABLE_LOADER.to_owned(),
        content: FwCfgContent::Bytes(table_loader_bytes),
    };
    let (rsdp, tables) = acpi_table.take();
    let acpi_rsdp = FwCfgItem {
        name: FW_CFG_FILENAME_RSDP.to_owned(),
        content: FwCfgContent::Bytes(rsdp.as_bytes().to_owned()),
    };
    let apci_tables = FwCfgItem {
        name: FW_CFG_FILENAME_ACPI_TABLES.to_owned(),
        content: FwCfgContent::Bytes(tables),
    };
    [table_loader, acpi_rsdp, apci_tables]
}

#[derive(Error, Debug)]
pub enum FwCfgContentAccessError {
    /// Failed to access the data source that is backing the FwCfg item.
    #[error("Reading the source failed")]
    ReadError,
    /// FwCfg doesn't hold an item that can be referenced by the given selector.
    #[error("There is no item accessible through the selector {0}")]
    IllegalSelector(u16),
    /// The item accessed is too large and it's size cannot be represented by a 32-bit unsigned
    /// integer.
    #[error("The accessed item is too large")]
    TooLarge,
    /// The cursor for this item pointed behind its EOF, which means the
    /// file was shrunk after the last access.
    #[error("The cursor was behind the EOF of an item")]
    UnexpectedEof,
    /// Accessing a file backed item failed.
    #[error("The file backed item could not be accessed")]
    FileAccessFailed(#[source] IoError),
}

type FwCfgContentAccessResult<T> = std::result::Result<T, FwCfgContentAccessError>;

impl FwCfg {
    pub fn new(memory: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>>) -> FwCfg {
        const DEFAULT_ITEM: FwCfgContent = FwCfgContent::Slice(&[]);
        let mut known_items = [DEFAULT_ITEM; FW_CFG_KNOWN_ITEMS];
        known_items[FW_CFG_SIGNATURE as usize] = FwCfgContent::Slice(&FW_CFG_SIGNATURE_CONTENT);
        known_items[FW_CFG_ID as usize] = FwCfgContent::Slice(&FW_CFG_FEATURE);
        let file_buf = Vec::from(FwCfgFilesHeader { count_be: 0 }.as_mut_bytes());
        known_items[FW_CFG_FILE_DIR as usize] = FwCfgContent::Bytes(file_buf);

        FwCfg {
            selector: 0,
            data_offset: 0,
            dma_address: 0,
            items: vec![],
            known_items,
            memory,
        }
    }

    pub fn populate_fw_cfg(
        &mut self,
        mem_size: Option<usize>,
        kernel: Option<File>,
        initramfs: Option<File>,
        cmdline: Option<std::ffi::CString>,
        fw_cfg_item_list: Option<Vec<FwCfgItem>>,
        #[cfg(target_arch = "x86_64")] kvm_sev_snp_enabled: bool,
    ) -> Result<()> {
        if let Some(mem_size) = mem_size {
            self.add_e820(mem_size)?;
        }
        if let Some(kernel) = kernel {
            self.add_kernel_data(
                &kernel,
                #[cfg(target_arch = "x86_64")]
                kvm_sev_snp_enabled,
            )?;
        }
        if let Some(cmdline) = cmdline {
            self.add_kernel_cmdline(cmdline);
        }
        if let Some(initramfs) = initramfs {
            self.add_initramfs_data(&initramfs)?;
        }
        if let Some(fw_cfg_item_list) = fw_cfg_item_list {
            for item in fw_cfg_item_list {
                self.add_item(item)?;
            }
        }
        Ok(())
    }

    pub fn add_e820(&mut self, mem_size: usize) -> Result<()> {
        #[cfg(target_arch = "x86_64")]
        let mut mem_regions = vec![
            (GuestAddress(0), EBDA_START.0 as usize, RegionType::Ram),
            (
                MEM_32BIT_DEVICES_START,
                MEM_32BIT_DEVICES_SIZE as usize,
                RegionType::Reserved,
            ),
            (
                PCI_MMCONFIG_START,
                PCI_MMCONFIG_SIZE as usize,
                RegionType::Reserved,
            ),
            (STAGE0_START_ADDRESS, STAGE0_SIZE, RegionType::Reserved),
        ];
        #[cfg(target_arch = "aarch64")]
        let mut mem_regions = arch::aarch64::arch_memory_regions();
        if mem_size < MEM_32BIT_DEVICES_START.0 as usize {
            mem_regions.push((
                HIGH_RAM_START,
                mem_size - HIGH_RAM_START.0 as usize,
                RegionType::Ram,
            ));
        } else {
            mem_regions.push((
                HIGH_RAM_START,
                MEM_32BIT_RESERVED_START.0 as usize - HIGH_RAM_START.0 as usize,
                RegionType::Ram,
            ));
            mem_regions.push((
                RAM_64BIT_START,
                mem_size - (MEM_32BIT_DEVICES_START.0 as usize),
                RegionType::Ram,
            ));
        }
        let mut bytes = vec![];
        for (addr, size, region) in mem_regions.iter() {
            let type_ = match region {
                RegionType::Ram => E820_RAM,
                RegionType::Reserved => E820_RESERVED,
                RegionType::SubRegion => continue,
            };
            let mut entry = BootE820Entry {
                addr: addr.0,
                size: *size as u64,
                type_,
            };
            bytes.extend_from_slice(entry.as_mut_bytes());
        }
        let item = FwCfgItem {
            name: "etc/e820".to_owned(),
            content: FwCfgContent::Bytes(bytes),
        };
        self.add_item(item)
    }

    fn file_dir_mut(&mut self) -> &mut Vec<u8> {
        let FwCfgContent::Bytes(file_buf) = &mut self.known_items[FW_CFG_FILE_DIR as usize] else {
            unreachable!("fw_cfg: selector {FW_CFG_FILE_DIR:#x} should be FwCfgContent::Byte!")
        };
        file_buf
    }

    fn update_count(&mut self) {
        let mut header = FwCfgFilesHeader {
            count_be: (self.items.len() as u32).to_be(),
        };
        self.file_dir_mut()[0..4].copy_from_slice(header.as_mut_bytes());
    }

    pub fn add_item(&mut self, item: FwCfgItem) -> Result<()> {
        let index = self.items.len();
        let c_name = create_file_name(&item.name);
        let size = item.content.size()?;
        let mut cfg_file = FwCfgFile {
            size_be: size.to_be(),
            select_be: (FW_CFG_FILE_FIRST + index as u16).to_be(),
            _reserved: 0,
            name: c_name,
        };
        self.file_dir_mut()
            .extend_from_slice(cfg_file.as_mut_bytes());
        self.items.push(item);
        self.update_count();
        Ok(())
    }

    /// Retrieves the [`FwCfgContent`] corresponding to the selector currently set in the internal
    /// selector buffer.
    fn get_selected_content(&self) -> FwCfgContentAccessResult<&FwCfgContent> {
        if let Some(known_item) = self.known_items.get(usize::from(self.selector)) {
            Ok(known_item)
        } else if let Some(item) = self
            .items
            .get(usize::from(self.selector - FW_CFG_FILE_FIRST))
        {
            Ok(&item.content)
        } else {
            Err(FwCfgContentAccessError::IllegalSelector(self.selector))
        }
    }

    fn dma_read_content(
        &self,
        content: &FwCfgContent,
        offset: u32,
        len: u32,
        address: u64,
    ) -> Result<u32> {
        let content_size = content.size()?.saturating_sub(offset);
        let op_size = std::cmp::min(content_size, len);
        let mut access = content.access(offset);
        let mut buf = vec![0u8; op_size as usize];
        access.read_exact(buf.as_mut_bytes())?;
        let r = self
            .memory
            .memory()
            .write(buf.as_bytes(), GuestAddress(address));
        match r {
            Err(e) => {
                error!("fw_cfg: dma read error: {e:x?}");
                Err(ErrorKind::InvalidInput.into())
            }
            Ok(size) => Ok(size as u32),
        }
    }

    fn dma_read(&mut self, selector: u16, len: u32, address: u64) -> Result<()> {
        let op_size = if let Some(content) = self.known_items.get(selector as usize) {
            self.dma_read_content(content, self.data_offset, len, address)
        } else if let Some(item) = self.items.get((selector - FW_CFG_FILE_FIRST) as usize) {
            self.dma_read_content(&item.content, self.data_offset, len, address)
        } else {
            error!("fw_cfg: selector {selector:#x} does not exist.");
            Err(ErrorKind::NotFound.into())
        }?;
        self.data_offset += op_size;
        Ok(())
    }

    fn do_dma(&mut self) {
        // If the DMA bit is not set, then DMA is a no-op like Write from the traditional interface.
        if (FW_CFG_FEATURE[0] & FW_CFG_F_DMA) == 0 {
            return;
        }

        let dma_address = self.dma_address;
        let mut access = FwCfgDmaAccess::new_zeroed();
        let dma_access = match self
            .memory
            .memory()
            .read(access.as_mut_bytes(), GuestAddress(dma_address))
        {
            Ok(_) => access,
            Err(e) => {
                error!("fw_cfg: invalid address of dma access {dma_address:#x}: {e:?}");
                return;
            }
        };
        let control = AccessControl(u32::from_be(dma_access.control_be));
        if control.select() {
            self.selector = control.select() as u16;
        }
        let len = u32::from_be(dma_access.length_be);
        let addr = u64::from_be(dma_access.address_be);
        let ret = if control.read() {
            self.dma_read(self.selector, len, addr)
        } else if control.write() {
            Err(ErrorKind::InvalidInput.into())
        } else if control.skip() {
            self.data_offset += len;
            Ok(())
        } else {
            Err(ErrorKind::InvalidData.into())
        };
        let mut access_resp = AccessControl(0);
        if let Err(e) = ret {
            error!("fw_cfg: dma operation {dma_access:x?}: {e:x?}");
            access_resp.set_error(true);
        }
        if let Err(e) = self.memory.memory().write(
            &access_resp.0.to_be_bytes(),
            GuestAddress(dma_address + core::mem::offset_of!(FwCfgDmaAccess, control_be) as u64),
        ) {
            error!("fw_cfg: finishing dma: {e:?}");
        }
    }

    pub fn add_kernel_data(
        &mut self,
        file: &File,
        #[cfg(target_arch = "x86_64")] kvm_sev_snp_enabled: bool,
    ) -> Result<()> {
        let mut buffer = vec![0u8; size_of::<boot_params>()];
        file.read_exact_at(&mut buffer, 0)?;
        let bp = boot_params::from_mut_slice(&mut buffer).unwrap();
        #[cfg(target_arch = "x86_64")]
        {
            // For SEV-SNP guests on KVM, don't modify the kernel header so the
            // bytes sent via fw_cfg match what the VMM hashes for the launch digest.
            // The guest firmware handles these fields itself.
            if !kvm_sev_snp_enabled {
                if bp.hdr.setup_sects == 0 {
                    bp.hdr.setup_sects = 4;
                }
                bp.hdr.type_of_loader = 0xff;
            }
        }
        #[cfg(target_arch = "aarch64")]
        let kernel_start = bp.text_offset;
        #[cfg(target_arch = "x86_64")]
        let kernel_start = {
            let sects = if bp.hdr.setup_sects == 0 {
                4
            } else {
                bp.hdr.setup_sects
            };
            (sects as usize + 1) * 512
        };

        #[cfg(target_arch = "x86_64")]
        if kernel_start <= buffer.len() {
            buffer.truncate(kernel_start);
        } else {
            buffer.resize(kernel_start, 0);
            file.read_exact_at(
                &mut buffer[size_of::<boot_params>()..],
                size_of::<boot_params>() as u64,
            )?;
        }

        self.known_items[FW_CFG_SETUP_SIZE as usize] = FwCfgContent::U32(buffer.len() as u32);
        self.known_items[FW_CFG_SETUP_DATA as usize] = FwCfgContent::Bytes(buffer);
        self.known_items[FW_CFG_KERNEL_SIZE as usize] =
            FwCfgContent::U32(file.metadata()?.len() as u32 - kernel_start as u32);
        self.known_items[FW_CFG_KERNEL_DATA as usize] =
            FwCfgContent::File(kernel_start as u64, file.try_clone()?);
        Ok(())
    }

    pub fn add_kernel_cmdline(&mut self, s: std::ffi::CString) {
        let bytes = s.into_bytes_with_nul();
        self.known_items[FW_CFG_CMDLINE_SIZE as usize] = FwCfgContent::U32(bytes.len() as u32);
        self.known_items[FW_CFG_CMDLINE_DATA as usize] = FwCfgContent::Bytes(bytes);
    }

    pub fn add_acpi(
        &mut self,
        rsdp: Rsdp,
        tables: Vec<u8>,
        table_checksums: Vec<(usize, usize)>,
        table_pointers: Vec<usize>,
    ) -> Result<()> {
        let acpi_table = AcpiTable {
            rsdp,
            tables,
            table_checksums,
            table_pointers,
        };
        let [table_loader, acpi_rsdp, apci_tables] = create_acpi_loader(acpi_table);
        self.add_item(table_loader)?;
        self.add_item(acpi_rsdp)?;
        self.add_item(apci_tables)
    }

    pub fn add_initramfs_data(&mut self, file: &File) -> Result<()> {
        let initramfs_size = file.metadata()?.len();
        self.known_items[FW_CFG_INITRD_SIZE as usize] = FwCfgContent::U32(initramfs_size as _);
        self.known_items[FW_CFG_INITRD_DATA as usize] = FwCfgContent::File(0, file.try_clone()?);
        Ok(())
    }

    /// Reads the data [`FwCfgContent`] of item currently selected through the internal selector
    /// buffer to an externally provided buffer.
    ///
    /// On success, returns the number of bytes written to the buffer. This can be fewer bytes than
    /// the buffer length, if the items content shorter than the buffer. If the buffer is shorter
    /// than the item's content, then more than one reads is necessary to retrieve all data.
    ///
    /// Either accumulate the number of bytes returned through all calls to this function or use the
    /// internal buffer for offset and the items size to determine if the all bytes were read.
    ///
    /// Errors if access to a file backed item fails ([`FwCfgContentAccessError::ReadError`]) or if
    /// the size of the item exceeds u32::MAX ([`FwCfgContentAccessError::TooLarge]).
    fn read_content(&mut self, data: &mut [u8]) -> FwCfgContentAccessResult<u32> {
        let content_size = self.get_selected_content()?.size().map_err(|e| match e {
            e if e.kind() == ErrorKind::UnexpectedEof => FwCfgContentAccessError::UnexpectedEof,
            e if e.kind() == ErrorKind::InvalidInput => FwCfgContentAccessError::TooLarge,
            e => FwCfgContentAccessError::FileAccessFailed(e),
        })?;

        let remaining_content_bytes = content_size.saturating_sub(self.data_offset);
        let content_bytes_to_copy = u32::min(remaining_content_bytes, data.len() as u32);
        let planned_end = self.data_offset + content_bytes_to_copy;
        let read_size = self
            .get_selected_content()?
            .access(self.data_offset)
            .read(data[..content_bytes_to_copy as usize].as_mut_bytes())
            .map_err(|_| FwCfgContentAccessError::ReadError)?;

        // Only relevant for file backed items. These can change between
        // access so the data used to calculate can be stale. We cannot fix this.
        if read_size != content_bytes_to_copy as usize {
            return Err(FwCfgContentAccessError::ReadError);
        }

        self.data_offset = planned_end;

        Ok(content_bytes_to_copy)
    }

    /// Reads data from this [`FwCfg`]'s item selected through the internal selector buffer and
    /// writes it's data to the provided buffer.
    ///
    /// If less bytes were read from the item than the buffer can hold, remaining bytes of the
    /// buffer will be filled with zeros (0x0).
    fn read_data(&mut self, data: &mut [u8]) {
        if let Ok(read_len) = self.read_content(data) {
            data[read_len as usize..].fill(0x0);
        } else {
            data.fill(0x0);
        }
    }
}

impl BusDevice for FwCfg {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        let mut qemu_mapped_offsets = (PORT_FW_CFG_SELECTOR_OFFSET..PORT_FW_CFG_DATA_OFFSET + 1)
            .chain(PORT_FW_CFG_DMA_HI_OFFSET..PORT_FW_CFG_DMA_LO_OFFSET + 4);
        match (offset, data.len()) {
            (PORT_FW_CFG_SELECTOR_OFFSET, 1) => {
                // Selector register is actually defined write-only. QEMU’s combined PIO region
                // treats a 1-byte read at this offset as a data read. Bypass to mimic QEMU quirk.
                self.read_data(data);
            }
            // TODO(fw_cfg): For now we need to allow arbitrary length reads from DATA because we
            // cannot distinguish between on one multi byte long read and multiple single-byte
            // reads. There is an open issue in kvm-ioctls:
            // https://github.com/rust-vmm/kvm/issues/371 Once this is solved, we should only
            // support one-byte-length reads.
            (PORT_FW_CFG_DATA_OFFSET, _) => self.read_data(data),
            (PORT_FW_CFG_DMA_HI_OFFSET, 4) => {
                let addr = self.dma_address;
                let addr_hi = (addr >> 32) as u32;
                data.copy_from_slice(&addr_hi.to_be_bytes());
            }
            (PORT_FW_CFG_DMA_LO_OFFSET, 4) => {
                let addr = self.dma_address;
                let addr_lo = (addr & 0xffff_ffff) as u32;
                data.copy_from_slice(&addr_lo.to_be_bytes());
            }
            (offset, _) if qemu_mapped_offsets.any(|mapped_offset| mapped_offset == offset) => {
                // We read from a port that should actually be mapped to fw_cfg. Note that QEMU
                // doesn't map the entire range but leaves a hole at 0x512 and 0x513. We mimic this
                // by doing a no-op below for this range.
                debug!(
                    "fw_cfg: Unsupported {:#x}-byte read from address: base={:#x} + offset={:#x}.",
                    data.len(),
                    PORT_FW_CFG_BASE,
                    offset
                );

                data.fill(0x0);
            }
            (offset, _) => {
                // We read from a port that shouldn't be mapped to fw_cfg and do nothing but warn.
                debug!(
                    "fw_cfg: read to unmapped address: base={PORT_FW_CFG_BASE:#x} + offset={offset:#x}. Read length: {}. This is a wrong mapping and a bug!",
                    data.len()
                );
            }
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        let size = data.size();
        match (offset, size) {
            (PORT_FW_CFG_SELECTOR_OFFSET, 2) => {
                let mut buf = [0u8; 2];
                buf[..size].copy_from_slice(&data[..size]);
                #[cfg(target_arch = "x86_64")]
                let val = u16::from_le_bytes(buf);
                #[cfg(target_arch = "aarch64")]
                let val = u16::from_be_bytes(buf);
                self.selector = val;
                self.data_offset = 0;
            }
            (PORT_FW_CFG_DATA_OFFSET, 1) => error!("fw_cfg: data register is read-only."),
            (PORT_FW_CFG_DMA_HI_OFFSET, 4) => {
                let mut buf = [0u8; 4];
                buf[..size].copy_from_slice(&data[..size]);
                let val = u32::from_be_bytes(buf);
                self.dma_address &= 0xffff_ffff;
                self.dma_address |= (val as u64) << 32;
            }
            (PORT_FW_CFG_DMA_LO_OFFSET, 4) => {
                let mut buf = [0u8; 4];
                buf[..size].copy_from_slice(&data[..size]);
                let val = u32::from_be_bytes(buf);
                self.dma_address &= !0xffff_ffff;
                self.dma_address |= val as u64;
                self.do_dma();
            }
            _ => {
                debug!(
                    "fw_cfg: write to unmapped address: base={PORT_FW_CFG_BASE:#x} + offset={offset:#x}. Write length: {size}. This is a wrong mapping and a bug!"
                );
            }
        }
        None
    }
}

#[cfg(test)]
mod unit_tests {
    use std::ffi::CString;
    use std::io::Write;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    #[test]
    fn test_signature() {
        let gm = GuestMemoryAtomic::new(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM_64BIT_START.0 as usize)]).unwrap(),
        );

        let mut fw_cfg = FwCfg::new(gm);

        let mut data = vec![0u8];

        let mut sig_iter = FW_CFG_SIGNATURE_CONTENT.into_iter();
        fw_cfg.write(0, PORT_FW_CFG_SELECTOR_OFFSET, &[FW_CFG_SIGNATURE as u8, 0]);
        loop {
            if let Some(char) = sig_iter.next() {
                fw_cfg.read(0, PORT_FW_CFG_DATA_OFFSET, &mut data);
                assert_eq!(data[0], char);
            } else {
                return;
            }
        }
    }

    #[test]
    fn test_kernel_cmdline() {
        let gm = GuestMemoryAtomic::new(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM_64BIT_START.0 as usize)]).unwrap(),
        );

        let mut fw_cfg = FwCfg::new(gm);

        let cmdline = *b"cmdline\0";

        fw_cfg.add_kernel_cmdline(CString::from_vec_with_nul(cmdline.to_vec()).unwrap());

        let mut data = vec![0u8];

        let mut cmdline_iter = cmdline.into_iter();
        fw_cfg.write(
            0,
            PORT_FW_CFG_SELECTOR_OFFSET,
            &[FW_CFG_CMDLINE_DATA as u8, 0],
        );
        loop {
            if let Some(char) = cmdline_iter.next() {
                fw_cfg.read(0, PORT_FW_CFG_DATA_OFFSET, &mut data);
                assert_eq!(data[0], char);
            } else {
                return;
            }
        }
    }

    #[test]
    fn test_initram_fs() {
        let gm = GuestMemoryAtomic::new(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM_64BIT_START.0 as usize)]).unwrap(),
        );

        let mut fw_cfg = FwCfg::new(gm);

        let temp = TempFile::new().unwrap();
        let mut temp_file = temp.as_file();

        let initram_content = b"this is the initramfs";
        let written = temp_file.write(initram_content);
        assert_eq!(written.unwrap(), 21);
        let _ = fw_cfg.add_initramfs_data(temp_file);

        let mut data = vec![0u8];

        let mut initram_iter = (*initram_content).into_iter();
        fw_cfg.write(
            0,
            PORT_FW_CFG_SELECTOR_OFFSET,
            &[FW_CFG_INITRD_DATA as u8, 0],
        );
        loop {
            if let Some(char) = initram_iter.next() {
                fw_cfg.read(0, PORT_FW_CFG_DATA_OFFSET, &mut data);
                assert_eq!(data[0], char);
            } else {
                return;
            }
        }
    }

    #[test]
    fn test_string_item() {
        let gm = GuestMemoryAtomic::new(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM_64BIT_START.0 as usize)]).unwrap(),
        );

        let mut fw_cfg = FwCfg::new(gm);

        // Simulate OVMF X-PciMmio64Mb string item for GPU CC passthrough
        let item = FwCfgItem {
            name: "opt/ovmf/X-PciMmio64Mb".to_owned(),
            content: FwCfgContent::Bytes("262144".as_bytes().to_vec()),
        };
        fw_cfg.add_item(item).unwrap();

        let expected = b"262144";
        let mut data = vec![0u8];

        // Select the first file item (FW_CFG_FILE_FIRST = 0x20)
        fw_cfg.write(
            0,
            PORT_FW_CFG_SELECTOR_OFFSET,
            &[FW_CFG_FILE_FIRST as u8, 0],
        );
        for &byte in expected.iter() {
            fw_cfg.read(0, PORT_FW_CFG_DATA_OFFSET, &mut data);
            assert_eq!(data[0], byte);
        }
    }

    #[test]
    fn test_dma() {
        let code = [
            0xba, 0xf8, 0x03, 0x00, 0xd8, 0x04, b'0', 0xee, 0xb0, b'\n', 0xee, 0xf4,
        ];

        let content = FwCfgContent::Bytes(code.to_vec());

        let mem_size = 0x1000;
        let load_addr = GuestAddress(0x1000);
        let mem: GuestMemoryMmap<AtomicBitmap> =
            GuestMemoryMmap::from_ranges(&[(load_addr, mem_size)]).unwrap();

        // Note: In firmware we would just allocate FwCfgDmaAccess struct
        // and use address of struct (&) as dma address
        let mut access_control = AccessControl(0);
        // bit 1 = read access
        access_control.set_read(true);
        // length of data to access
        let length_be = (code.len() as u32).to_be();
        // guest address for data
        let code_address = 0x1900_u64;
        let address_be = code_address.to_be();
        let mut access = FwCfgDmaAccess {
            control_be: access_control.0.to_be(), // bit(1) = read bit
            length_be,
            address_be,
        };
        // access address is where to put the code
        let access_address = GuestAddress(load_addr.0);
        let address_bytes = access_address.0.to_be_bytes();
        let dma_lo: [u8; 4] = address_bytes[0..4].try_into().unwrap();
        let dma_hi: [u8; 4] = address_bytes[4..8].try_into().unwrap();

        // writing the FwCfgDmaAccess to mem (this would just be self.dma_access.as_ref() in guest)
        let _ = mem.write(access.as_mut_bytes(), access_address);
        let mem_m = GuestMemoryAtomic::new(mem.clone());
        let mut fw_cfg = FwCfg::new(mem_m);
        let cfg_item = FwCfgItem {
            name: "code".to_string(),
            content,
        };
        let _ = fw_cfg.add_item(cfg_item);

        let mut data = [0u8; 12];

        let _ = mem.read(&mut data, GuestAddress(code_address));
        assert_ne!(data, code);

        fw_cfg.write(
            0,
            PORT_FW_CFG_SELECTOR_OFFSET,
            &[FW_CFG_FILE_FIRST as u8, 0],
        );
        fw_cfg.write(0, PORT_FW_CFG_DMA_LO_OFFSET, &dma_lo);
        fw_cfg.write(0, PORT_FW_CFG_DMA_HI_OFFSET, &dma_hi);
        let _ = mem.read(&mut data, GuestAddress(code_address));

        // Assert that the DMA path is currently deactivated.
        assert_eq!(data, [0u8; 12]);
        assert_eq!(fw_cfg.data_offset, 0);
    }

    #[test]
    fn test_register_allow_arbitrary_length_reads_from_data() {
        let mut fw_cfg = FwCfg::new(GuestMemoryAtomic::new(GuestMemoryMmap::new()));
        fw_cfg.write(0, PORT_FW_CFG_SELECTOR_OFFSET, &[FW_CFG_SIGNATURE as u8, 0]);

        // Two-byte reads are served.
        let mut buff = [0xEF; 2];
        fw_cfg.read(0, PORT_FW_CFG_DATA_OFFSET, &mut buff);
        assert_eq!(buff, *b"QE");
        assert_eq!(fw_cfg.data_offset, 2);
        // Four-byte reads are served.
        let mut buff = [0xEF; 4];
        fw_cfg.write(0, PORT_FW_CFG_SELECTOR_OFFSET, &[FW_CFG_SIGNATURE as u8, 0]);
        fw_cfg.read(0, PORT_FW_CFG_DATA_OFFSET, &mut buff);
        assert_eq!(buff, *b"QEMU");
        assert_eq!(fw_cfg.data_offset, 4);
        // Eight-byte reads are served.
        let mut buff = [0xEF; 8];
        fw_cfg.write(0, PORT_FW_CFG_SELECTOR_OFFSET, &[FW_CFG_SIGNATURE as u8, 0]);
        fw_cfg.read(0, PORT_FW_CFG_DATA_OFFSET, &mut buff);
        assert_eq!(buff, *b"QEMU\0\0\0\0");
        assert_eq!(fw_cfg.data_offset, 4);
    }

    #[test]
    fn test_register_invalid_ports_leaves_buffer_untouched() {
        // We should not answer reads from unknown ports.
        let mut fw_cfg = FwCfg::new(GuestMemoryAtomic::new(GuestMemoryMmap::new()));
        fw_cfg.write(0, PORT_FW_CFG_SELECTOR_OFFSET, &[FW_CFG_SIGNATURE as u8, 0]);
        // Single-byte reads from forbidden ports should be a no-op. Test the address succeeding the
        // mapped range of 0xC addresses.
        let mut buff = [0xCD; 1];
        fw_cfg.read(0, PORT_FW_CFG_DMA_LO_OFFSET + 4, &mut buff);
        assert_eq!(fw_cfg.data_offset, 0);
        assert_eq!(buff, [0xCD; 1]);
        // Test that reads to addresses in the hole of the mapping are no-ops too.
        let mut buff = [0xCD; 1];
        fw_cfg.read(0, PORT_FW_CFG_DATA_OFFSET + 1, &mut buff);
        assert_eq!(fw_cfg.data_offset, 0);
        assert_eq!(buff, [0xCD; 1]);
        let mut buff = [0xCD; 1];
        fw_cfg.read(0, PORT_FW_CFG_DATA_OFFSET + 2, &mut buff);
        assert_eq!(fw_cfg.data_offset, 0);
        assert_eq!(buff, [0xCD; 1]);
    }

    #[test]
    fn test_register_qemu_selector_read_quirk() {
        // While defined as write-only, QEMU uses a port-mapping that leaves the select register
        // readable. For full compatibility we also allow reading from the selector register as a
        // quirk.
        let mut fw_cfg = FwCfg::new(GuestMemoryAtomic::new(GuestMemoryMmap::new()));
        fw_cfg.write(0, PORT_FW_CFG_SELECTOR_OFFSET, &[FW_CFG_SIGNATURE as u8, 0]);
        // One-byte read returns actual data.
        let mut buff = [0xEF; 1];
        fw_cfg.read(0, PORT_FW_CFG_SELECTOR_OFFSET, &mut buff);
        assert_eq!(fw_cfg.data_offset, 1);
        assert_eq!(buff, [b'Q']);
        // Forbidden access zeros buffer similar to data register access. Offset isn't moved.
        let mut buff = [0xEF; 2];
        fw_cfg.read(0, PORT_FW_CFG_SELECTOR_OFFSET, &mut buff);
        assert_eq!(fw_cfg.data_offset, 1);
        assert_eq!(buff, [0x0; 2]);
    }

    #[test]
    fn test_register_reads_past_eof_return_zero() {
        let mut fw_cfg = FwCfg::new(GuestMemoryAtomic::new(GuestMemoryMmap::new()));
        fw_cfg.write(0, PORT_FW_CFG_SELECTOR_OFFSET, &[FW_CFG_SIGNATURE as u8, 0]);
        let mut buff = [0xEF; 8];
        let max_offset = FW_CFG_SIGNATURE_CONTENT.len() as u32;
        for (offset, byte) in buff.iter_mut().enumerate() {
            fw_cfg.read(0, PORT_FW_CFG_DATA_OFFSET, byte.as_mut_bytes());
            let expected_offset = if (offset as u32 + 1) < max_offset {
                offset as u32 + 1
            } else {
                max_offset
            };
            assert_eq!(fw_cfg.data_offset, expected_offset);
        }
        assert_eq!(buff[..4], FW_CFG_SIGNATURE_CONTENT);
        assert_eq!(buff[4..], [0; 4]);
    }

    #[test]
    fn test_register_reads_with_invalid_selector() {
        const SELECTOR_INITIALIZED_WITH_DEFAULT: u16 = 0x08;
        let mut fw_cfg = FwCfg::new(GuestMemoryAtomic::new(GuestMemoryMmap::new()));
        fw_cfg.known_items[SELECTOR_INITIALIZED_WITH_DEFAULT as usize] = FwCfgContent::Slice(&[]);
        fw_cfg.write(0, PORT_FW_CFG_SELECTOR_OFFSET, &[0xFF, 0]);
        let mut buff = [0xEF_u8; 8];
        for byte in buff.iter_mut() {
            fw_cfg.read(0, PORT_FW_CFG_DATA_OFFSET, byte.as_mut_bytes());
            assert_eq!(fw_cfg.data_offset, 0);
        }
        assert_eq!(buff, [0; 8]);

        fw_cfg.write(
            0,
            PORT_FW_CFG_SELECTOR_OFFSET,
            &SELECTOR_INITIALIZED_WITH_DEFAULT.to_le_bytes(),
        );
        let mut buff = [0xEF_u8; 8];
        for byte in buff.iter_mut() {
            fw_cfg.read(0, PORT_FW_CFG_DATA_OFFSET, byte.as_mut_bytes());
            assert_eq!(fw_cfg.data_offset, 0);
        }
        assert_eq!(buff, [0; 8]);
    }

    #[test]
    fn test_register_writing_select_resets_internal_cursor() {
        let mut fw_cfg = FwCfg::new(GuestMemoryAtomic::new(GuestMemoryMmap::new()));
        let payload_bytes = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let content = FwCfgContent::Bytes(payload_bytes.to_vec());
        let cfg_item = FwCfgItem {
            name: "payload".to_string(),
            content,
        };
        fw_cfg.add_item(cfg_item).unwrap();

        // Read the same bytes twice, demonstrating that we can reset the cursor by selecting a new item.
        for _ in 0..2 {
            fw_cfg.write(
                0,
                PORT_FW_CFG_SELECTOR_OFFSET,
                &FW_CFG_FILE_FIRST.to_le_bytes(),
            );
            assert_eq!(fw_cfg.data_offset, 0);
            let mut buffer = [0xEF_u8; 6];
            const MAX_INDEX: usize = 4;
            for (index, byte) in buffer.iter_mut().enumerate().take(MAX_INDEX) {
                fw_cfg.read(0, PORT_FW_CFG_DATA_OFFSET, byte.as_mut_bytes());
                assert_eq!(fw_cfg.data_offset as usize, index + 1);
            }
            assert_eq!(buffer[..MAX_INDEX], payload_bytes[..MAX_INDEX]);
            assert_eq!(buffer[MAX_INDEX..], [0xEF; 2]);
            assert_eq!(fw_cfg.data_offset, MAX_INDEX as u32);
        }
    }
}
