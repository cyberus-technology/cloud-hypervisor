use hypervisor::arch::x86::CpuIdEntry;

use super::{CpuIdEntryRegister, CpuidReg};

pub(super) struct CascadeLakeServerV1CpuIdFeatures {
    edx_1: CpuIdEntryRegister<1, 0, { CpuidReg::EDX as u8 }>,
    ecx_1: CpuIdEntryRegister<1, 0, { CpuidReg::ECX as u8 }>,
    edx_8000_0001h: CpuIdEntryRegister<0x8000_0001, 0, { CpuidReg::EDX as u8 }>,
    ecx_8000_0001h: CpuIdEntryRegister<0x8000_0001, 0, { CpuidReg::ECX as u8 }>,
    ebx_7_0: CpuIdEntryRegister<7, 0, { CpuidReg::EBX as u8 }>,
    ecx_7_0: CpuIdEntryRegister<7, 0, { CpuidReg::ECX as u8 }>,
    edx_7_0: CpuIdEntryRegister<7, 0, { CpuidReg::EDX as u8 }>,
    eax_0dh: CpuIdEntryRegister<0xd, 1, { CpuidReg::EAX as u8 }>,
}

impl CascadeLakeServerV1CpuIdFeatures {
    pub(super) fn new() -> Self {
        use CpuIdEntryRegister as FF;
        Self {
            edx_1: FF::VME
                | FF::SSE2
                | FF::SSE
                | FF::FXSR
                | FF::MMX
                | FF::CLFLUSH
                | FF::PSE36
                | FF::PAT
                | FF::CMOV
                | FF::MCA
                | FF::PGE
                | FF::MTRR
                | FF::SEP
                | FF::APIC
                | FF::CX8
                | FF::MCE
                | FF::PAE
                | FF::MSR
                | FF::TSC
                | FF::PSE
                | FF::DE
                | FF::FPU,

            ecx_1: FF::AVX
                | FF::XSAVE
                | FF::AES
                | FF::POPCNT
                | FF::X2APIC
                | FF::SSE4_2
                | FF::SSE4_1
                | FF::CX16
                | FF::SSSE3
                | FF::PCLMULQDQ
                | FF::SSE3
                | FF::TSC_DEADLINE
                | FF::FMA
                | FF::MOVBE
                | FF::PCID
                | FF::F16C
                | FF::RDRAND,

            edx_8000_0001h: FF::LM | FF::PDPE1GB | FF::RDTSCP | FF::NX | FF::SYSCALL,
            ecx_8000_0001h: FF::ABM | FF::LAHF_LM | FF::PREFETCH_3DNOW,
            ebx_7_0: FF::FSGSBASE
                | FF::BMI1
                | FF::HLE
                | FF::AVX2
                | FF::SMEP
                | FF::BMI2
                | FF::ERMS
                | FF::INVPCID
                | FF::RTM
                | FF::RDSEED
                | FF::ADX
                | FF::SMAP
                | FF::CLWB
                | FF::AVX512F
                | FF::AVX512DQ
                | FF::AVX512BW
                | FF::AVX512CD
                | FF::AVX512VL
                | FF::CLFLUSHOPT,
            ecx_7_0: FF::PKU | FF::AVX512VNNI,
            edx_7_0: FF::SPEC_CTRL | FF::SSBD,
            eax_0dh: FF::XSAVEOPT | FF::XSAVEC | FF::XGETBV1,
        }
    }

    /// Restricts the given entries by performing bitwise intersections of registers
    /// per set of matching parameters.
    pub(super) fn restrict(self, cpuid: &mut [CpuIdEntry]) {
        // NOTE: This might get a bit repetetive when we get more structs in this module.
        // Might be worth introducing a proc macro for this at some point...
        let Self {
            edx_1,
            ecx_1,
            edx_8000_0001h,
            ecx_8000_0001h,
            ebx_7_0,
            ecx_7_0,
            edx_7_0,
            eax_0dh,
        } = self;
        edx_1.intersect_matching(cpuid);
        ecx_1.intersect_matching(cpuid);
        edx_8000_0001h.intersect_matching(cpuid);
        ecx_8000_0001h.intersect_matching(cpuid);
        ebx_7_0.intersect_matching(cpuid);
        ecx_7_0.intersect_matching(cpuid);
        edx_7_0.intersect_matching(cpuid);
        eax_0dh.intersect_matching(cpuid);
    }
}
