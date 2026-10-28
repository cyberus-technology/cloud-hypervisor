// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! Intel TDX (Trust Domain Extensions) commands for a TD (Trust Domain), one
//! per `KVM_MEMORY_ENCRYPT_OP` sub-ioctl, as documented in
//! <https://docs.kernel.org/virt/kvm/x86/intel-tdx.html>.

use std::{array, io};

use igvm_defs::PAGE_SIZE_4K;
use kvm_bindings::{
    KVM_MAX_CPUID_ENTRIES, KVM_TDX_MEASURE_MEMORY_REGION, TdxCapabilities, TdxInitVm, kvm_tdx_cmd,
    kvm_tdx_cmd_id_KVM_TDX_CAPABILITIES, kvm_tdx_cmd_id_KVM_TDX_FINALIZE_VM,
    kvm_tdx_cmd_id_KVM_TDX_INIT_MEM_REGION, kvm_tdx_cmd_id_KVM_TDX_INIT_VCPU,
    kvm_tdx_cmd_id_KVM_TDX_INIT_VM, kvm_tdx_init_mem_region,
};
use kvm_ioctls::{VcpuFd, VmFd};
use log::error;

use super::{KvmVcpu, KvmVm};
use crate::arch::x86::CpuIdEntry;
use crate::cpu;
use crate::vm::{self, TdxInitVmParams};

/// Issues one TDX sub-ioctl, retrying the errnos below and logging the TDX
/// module status from `hw_error`.
///
/// Three errnos are retried. EINTR arrives when a signal interrupts the ioctl,
/// EAGAIN when a SEAMCALL cannot get entropy and EBUSY when the TDX module
/// reports itself busy. EBUSY is not retried for KVM_TDX_INIT_VM, which reports
/// it when a vCPU already exists.
///
/// # Safety
///
/// `cmd.data` must be valid for the command in `cmd.id`. It is either an
/// immediate value, or a pointer to a value that stays valid and unaliased
/// for the whole call.
unsafe fn tdx_cmd(fd: &impl TdxEncryptOp, cmd: &mut kvm_tdx_cmd) -> io::Result<()> {
    // A SEAMCALL returning TDX_RND_NO_ENTROPY gets ten tries in the kernel.
    // A hundred ioctl retries outlast that, so a dry RNG still errors out.
    const MAX_RETRIES: u32 = 100;
    let mut retries_left = MAX_RETRIES;

    let err = loop {
        // KVM rejects a request that carries a nonzero hw_error.
        cmd.hw_error = 0;

        // SAFETY: the caller guarantees `cmd` is valid for this ioctl.
        let errno = match unsafe { fd.encrypt_op_tdx(cmd) } {
            Ok(()) => return Ok(()),
            Err(err) => err.errno(),
        };

        let retry = match errno {
            libc::EINTR | libc::EAGAIN => true,
            // INIT_VM reports EBUSY when a vCPU already exists.
            libc::EBUSY => cmd.id != kvm_tdx_cmd_id_KVM_TDX_INIT_VM,
            _ => false,
        };
        if !retry {
            break io::Error::from_raw_os_error(errno);
        }

        if retries_left == 0 {
            break io::Error::other(format!(
                "Gave up after {MAX_RETRIES} retries, last errno {errno}"
            ));
        }

        retries_left -= 1;
    };

    error!(
        "KVM TDX command {} failed: {err}, hw_error: {:#x}",
        cmd.id, cmd.hw_error
    );
    Err(err)
}

/// `KVM_MEMORY_ENCRYPT_OP`, which TDX issues on both the VM and the vCPU fd.
trait TdxEncryptOp {
    /// # Safety
    ///
    /// `cmd.data` must be an immediate or a valid, unaliased pointer for the
    /// call.
    unsafe fn encrypt_op_tdx(&self, cmd: &mut kvm_tdx_cmd) -> Result<(), kvm_ioctls::Error>;
}

impl TdxEncryptOp for VmFd {
    unsafe fn encrypt_op_tdx(&self, cmd: &mut kvm_tdx_cmd) -> Result<(), kvm_ioctls::Error> {
        // SAFETY: the caller guarantees `cmd` is valid for this ioctl.
        unsafe { VmFd::encrypt_op_tdx(self, cmd) }
    }
}

impl TdxEncryptOp for VcpuFd {
    unsafe fn encrypt_op_tdx(&self, cmd: &mut kvm_tdx_cmd) -> Result<(), kvm_ioctls::Error> {
        // SAFETY: the caller guarantees `cmd` is valid for this ioctl.
        unsafe { VcpuFd::encrypt_op_tdx(self, cmd) }
    }
}

/// Splits a SHA-384 digest into the six `u64`s the uapi takes. Only their byte
/// representation matters, because the kernel copies it verbatim.
fn digest(bytes: &[u8; 48]) -> [u64; 6] {
    array::from_fn(|word_index| {
        let start = word_index * 8;
        let mut word = [0; 8];
        word.copy_from_slice(&bytes[start..start + 8]);
        u64::from_le_bytes(word)
    })
}

impl KvmVm {
    /// [`vm::Vm::tdx_capabilities()`] via `KVM_TDX_CAPABILITIES`.
    pub fn tdx_capabilities(&self) -> vm::Result<vm::TdxCapabilities> {
        let mut caps = TdxCapabilities::new(KVM_MAX_CPUID_ENTRIES).map_err(|e| {
            vm::HypervisorVmError::TdxCapabilities(io::Error::other(format!(
                "Failed to allocate TDX capabilities: {e}"
            )))
        })?;
        let mut cmd = kvm_tdx_cmd {
            id: kvm_tdx_cmd_id_KVM_TDX_CAPABILITIES,
            data: caps.as_mut_fam_struct_ptr() as u64,
            ..Default::default()
        };

        // SAFETY: `data` points to `caps`, valid and unaliased for the call.
        unsafe { tdx_cmd(self.fd.as_ref(), &mut cmd) }
            .map_err(vm::HypervisorVmError::TdxCapabilities)?;

        let cpuid = caps
            .as_slice()
            .iter()
            .map(|e| CpuIdEntry::from(*e))
            .collect();
        let caps = caps.as_fam_struct_ref();

        Ok(vm::TdxCapabilities {
            supported_attrs: caps.supported_attrs,
            supported_xfam: caps.supported_xfam,
            cpuid,
        })
    }
    /// [`vm::Vm::tdx_init()`] via `KVM_TDX_INIT_VM`.
    pub fn tdx_init(&self, params: &TdxInitVmParams) -> vm::Result<()> {
        let cpuid: Vec<_> = params.cpuid.iter().map(|e| (*e).into()).collect();
        let mut init = TdxInitVm::from_entries(&cpuid).map_err(|e| {
            vm::HypervisorVmError::InitializeTdx(io::Error::other(format!(
                "Failed to allocate TDX init parameters: {e}"
            )))
        })?;

        // SAFETY: only the scalar fields before `cpuid` are written. The FAM
        // length is `cpuid.nent`, set by `from_entries()` to the allocated
        // entry count, and it stays untouched here.
        let tdx = unsafe { init.as_mut_fam_struct() };
        tdx.attributes = params.attributes;
        tdx.xfam = params.xfam;
        tdx.mrconfigid = digest(&params.mrconfigid);
        tdx.mrowner = digest(&params.mrowner);
        tdx.mrownerconfig = digest(&params.mrownerconfig);

        let mut cmd = kvm_tdx_cmd {
            id: kvm_tdx_cmd_id_KVM_TDX_INIT_VM,
            data: init.as_mut_fam_struct_ptr() as u64,
            ..Default::default()
        };

        // SAFETY: `data` points to `init`, valid and unaliased for the call.
        unsafe { tdx_cmd(self.fd.as_ref(), &mut cmd) }.map_err(vm::HypervisorVmError::InitializeTdx)
    }

    /// [`vm::Vm::tdx_finalize()`] via `KVM_TDX_FINALIZE_VM`.
    pub fn tdx_finalize(&self) -> vm::Result<()> {
        let mut cmd = kvm_tdx_cmd {
            id: kvm_tdx_cmd_id_KVM_TDX_FINALIZE_VM,
            ..Default::default()
        };

        // SAFETY: `data` is zero, which is what this command requires.
        unsafe { tdx_cmd(self.fd.as_ref(), &mut cmd) }.map_err(vm::HypervisorVmError::FinalizeTdx)
    }
}

impl KvmVcpu {
    /// [`cpu::Vcpu::tdx_init()`] via `KVM_TDX_INIT_VCPU`.
    pub fn tdx_init(&self, initial_rcx: u64) -> cpu::Result<()> {
        let mut cmd = kvm_tdx_cmd {
            id: kvm_tdx_cmd_id_KVM_TDX_INIT_VCPU,
            data: initial_rcx,
            ..Default::default()
        };

        // SAFETY: `data` is an immediate value, not a pointer.
        unsafe { tdx_cmd(&self.fd, &mut cmd) }.map_err(cpu::HypervisorCpuError::InitializeTdx)
    }

    /// [`cpu::Vcpu::tdx_init_memory_region()`] via `KVM_TDX_INIT_MEM_REGION`.
    pub fn tdx_init_memory_region(
        &self,
        source: u64,
        gpa: u64,
        nr_pages: u64,
        measure: bool,
    ) -> cpu::Result<()> {
        // The kernel only reports EINVAL for these, which does not say which
        // value is wrong.
        if !source.is_multiple_of(PAGE_SIZE_4K)
            || !gpa.is_multiple_of(PAGE_SIZE_4K)
            || nr_pages == 0
        {
            return Err(cpu::HypervisorCpuError::InitMemRegionTdx(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Source 0x{source:x} and GPA 0x{gpa:x} must be page \
                     aligned, nr_pages {nr_pages} must be non-zero"
                ),
            )));
        }

        // The kernel advances the source address, GPA and page count and
        // copies the remaining request back through this pointer.
        let mut region = kvm_tdx_init_mem_region {
            source_addr: source,
            gpa,
            nr_pages,
        };
        let mut cmd = kvm_tdx_cmd {
            id: kvm_tdx_cmd_id_KVM_TDX_INIT_MEM_REGION,
            flags: if measure {
                KVM_TDX_MEASURE_MEMORY_REGION
            } else {
                0
            },
            data: (&raw mut region) as u64,
            ..Default::default()
        };

        // SAFETY: `data` points to `region`, valid and unaliased for the call.
        unsafe { tdx_cmd(&self.fd, &mut cmd) }.map_err(cpu::HypervisorCpuError::InitMemRegionTdx)
    }
}
