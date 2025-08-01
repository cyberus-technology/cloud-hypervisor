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
    pub(super) const fn new() -> Self {
        use CpuIdFeatureFlags as FF;
        // Placing this in a const block ensures compile time evaluation and we get isntant feedback
        // (even from the LSP) if the lists contain arguments that are not defined for the given
        // function, index, register triple via `crate::x86_64::impl_cpuid_feature_flags!`
        const {
            Self {
                edx_1: FF::<1, 0, { CpuidReg::EDX as u8 }>::from_names(&[
                    "vme", "sse2", "sse", "fxsr", "mmx", "clflush", "pse36", "pat", "cmov", "mca",
                    "pge", "mtrr", "sep", "apic", "cx8", "mce", "pae", "msr", "tsc", "pse", "de",
                    "fpu",
                ]),

                ecx_1: FF::<1, 0, { CpuidReg::ECX as u8 }>::from_names(&[
                    "avx",
                    "xsave",
                    "aes",
                    "popcnt",
                    "x2apic",
                    "sse4.2",
                    "sse4.1",
                    "cx16",
                    "ssse3",
                    "pclmulqdq",
                    "pni",
                    "tsc-deadline",
                    "fma",
                    "movbe",
                    "pcid",
                    "f16c",
                    "rdrand",
                ]),

                edx_8000_0001h: FF::<0x8000_0001, 0, { CpuidReg::EDX as u8 }>::from_names(&[
                    "lm", "pdpe1gb", "rdtscp", "nx", "syscall",
                ]),
                ecx_8000_0001h: FF::<0x8000_0001, 0, { CpuidReg::ECX as u8 }>::from_names(&[
                    "abm",
                    "lahf-lm",
                    "3dnowprefetch",
                ]),
                ebx_7_0: FF::<7, 0, { CpuidReg::EBX as u8 }>::from_names(&[
                    "fsgsbase",
                    "bmi1",
                    "hle",
                    "avx2",
                    "smep",
                    "bmi2",
                    "erms",
                    "invpcid",
                    "rtm",
                    "rdseed",
                    "adx",
                    "smap",
                    "clwb",
                    "avx512f",
                    "avx512dq",
                    "avx512bw",
                    "avx512cd",
                    "avx512vl",
                    "clflushopt",
                ]),
                ecx_7_0: FF::<7, 0, { CpuidReg::ECX as u8 }>::from_names(&["pku", "avx512vnni"]),
                edx_7_0: FF::<7, 0, { CpuidReg::EDX as u8 }>::from_names(&["spec-ctrl", "ssbd"]),
                eax_0dh: FF::<0xd, 1, { CpuidReg::EAX as u8 }>::from_names(&[
                    "xsaveopt", "xsavec", "xgetbv1",
                ]),
            }
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
