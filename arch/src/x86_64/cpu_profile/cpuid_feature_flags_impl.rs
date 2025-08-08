use crate::x86_64::cpuid_feature_flags::{CpuIdEntryRegister, CpuIdFeatureFlags};

impl CpuIdFeatureFlags {
    pub const fn intel_cascadelake_v1() -> Self {
        use CpuIdEntryRegister as FF;

        Self {
            edx_1: FF::VME
                .or(FF::SSE2)
                .or(FF::SSE)
                .or(FF::FXSR)
                .or(FF::MMX)
                .or(FF::CLFLUSH)
                .or(FF::PSE36)
                .or(FF::PAT)
                .or(FF::CMOV)
                .or(FF::MCA)
                .or(FF::PGE)
                .or(FF::MTRR)
                .or(FF::SEP)
                .or(FF::APIC)
                .or(FF::CX8)
                .or(FF::MCE)
                .or(FF::PAE)
                .or(FF::MSR)
                .or(FF::TSC)
                .or(FF::PSE)
                .or(FF::DE)
                .or(FF::FPU),

            ecx_1: FF::AVX
                .or(FF::XSAVE)
                .or(FF::AES)
                .or(FF::POPCNT)
                .or(FF::X2APIC)
                .or(FF::SSE4_2)
                .or(FF::SSE4_1)
                .or(FF::CX16)
                .or(FF::SSSE3)
                .or(FF::PCLMULQDQ)
                .or(FF::SSE3)
                .or(FF::TSC_DEADLINE)
                .or(FF::FMA)
                .or(FF::MOVBE)
                .or(FF::PCID)
                .or(FF::F16C)
                .or(FF::RDRAND),

            edx_8000_0001h: FF::LM
                .or(FF::PDPE1GB)
                .or(FF::RDTSCP)
                .or(FF::NX)
                .or(FF::SYSCALL),
            ecx_8000_0001h: FF::ABM.or(FF::LAHF_LM).or(FF::PREFETCH_3DNOW),
            ebx_7_0: FF::FSGSBASE
                .or(FF::BMI1)
                .or(FF::HLE)
                .or(FF::AVX2)
                .or(FF::SMEP)
                .or(FF::BMI2)
                .or(FF::ERMS)
                .or(FF::INVPCID)
                .or(FF::RTM)
                .or(FF::RDSEED)
                .or(FF::ADX)
                .or(FF::SMAP)
                .or(FF::CLWB)
                .or(FF::AVX512F)
                .or(FF::AVX512DQ)
                .or(FF::AVX512BW)
                .or(FF::AVX512CD)
                .or(FF::AVX512VL)
                .or(FF::CLFLUSHOPT),
            ecx_7_0: FF::PKU.or(FF::AVX512VNNI),
            edx_7_0: FF::SPEC_CTRL.or(FF::SSBD),
            eax_0dh_1: FF::XSAVEOPT.or(FF::XSAVEC).or(FF::XGETBV1),
            eax_7_1: FF::NULL,
            ecx_7_1: FF::NULL,
            edx_7_1: FF::NULL,
            edx_7_2: FF::NULL,
            ecx_14h: FF::NULL,
            ecx_24h_1: FF::NULL,
            edx_8000_0007h: FF::NULL,
            ebx_8000_0008h: FF::NULL,
            edx_8000_000ah: FF::NULL,
            eax_8000_0021h: FF::NULL,
        }
    }
}
