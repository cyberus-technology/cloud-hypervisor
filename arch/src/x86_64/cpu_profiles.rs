use hypervisor::arch::x86::CpuIdEntry;

use super::{CpuIdFeatureFlags, CpuidReg};

pub(super) struct CascadeLakeServerV1CpuIdFeatures {
    edx_1: CpuIdFeatureFlags<1, 0, { CpuidReg::EDX as u8 }>,
    ecx_1: CpuIdFeatureFlags<1, 0, { CpuidReg::ECX as u8 }>,
    edx_8000_0001h: CpuIdFeatureFlags<0x8000_0001, 0, { CpuidReg::EDX as u8 }>,
    ecx_8000_0001h: CpuIdFeatureFlags<0x8000_0001, 0, { CpuidReg::ECX as u8 }>,
    ebx_7_0: CpuIdFeatureFlags<7, 0, { CpuidReg::EBX as u8 }>,
    ecx_7_0: CpuIdFeatureFlags<7, 0, { CpuidReg::ECX as u8 }>,
    edx_7_0: CpuIdFeatureFlags<7, 0, { CpuidReg::EDX as u8 }>,
    eax_0dh: CpuIdFeatureFlags<0xd, 1, { CpuidReg::EAX as u8 }>,
}

impl CascadeLakeServerV1CpuIdFeatures {
    pub(super) fn new() -> Self {
        use CpuIdFeatureFlags as FF;
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

    pub(super) const fn into_cpuid_entries(self) -> [CpuIdEntry; 4] {
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
        [
            edx_1.join(ecx_1),
            edx_8000_0001h.join(ecx_8000_0001h),
            ebx_7_0.join_three(ecx_7_0, edx_7_0),
            eax_0dh.into_entry(),
        ]
    }
}
