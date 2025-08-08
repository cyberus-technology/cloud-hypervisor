use hypervisor::arch::x86::{CpuIdEntry, CPUID_FLAG_VALID_INDEX};

use super::CpuidReg;

/// A bitset of CPUID feature flags for a given leaf, sub-leaf and register triple
/// (or function, index, register in KVM terms).
pub struct CpuIdEntryRegister<const FUNCTION: u32, const INDEX: u32, const REG: u8>(u32);

impl<const FUNCTION: u32, const INDEX: u32, const REG: u8>
    CpuIdEntryRegister<FUNCTION, INDEX, REG>
{
    pub const NULL: Self = Self(0);
    // Workaround until we can use BitOr in const contexts
    pub const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
    /// Represents this [`CpuIdEntryRegister`] as a bitset in terms of a [`u32`].
    ///
    /// The returned representation does not track the metadata consisting of
    /// the function/leaf, index/subleaf and register name.
    pub const fn into_raw(&self) -> u32 {
        self.0
    }
    fn intersect_matching(&self, cpuid: &mut [CpuIdEntry]) {
        let mut found_matching = false;
        for entry in cpuid.iter_mut().filter(|entry| {
            entry.function == FUNCTION
                && entry.index == INDEX
                // We only care about the cpuid entries with a valid index flag in KVM terms.
                // TODO: Is this indeed the case?
                && entry.flags == CPUID_FLAG_VALID_INDEX
        }) {
            found_matching = true;
            let mut updated = 0;
            if REG == { CpuidReg::EAX as u8 } {
                entry.eax &= self.0;
                updated = entry.eax;
            } else if REG == { CpuidReg::EBX as u8 } {
                entry.ebx &= self.0;
                updated = entry.ebx;
            } else if REG == { CpuidReg::ECX as u8 } {
                entry.ecx &= self.0;
                updated = entry.ecx;
            } else if REG == { CpuidReg::EDX as u8 } {
                entry.edx &= self.0;
                updated = entry.edx;
            } else {
                // Unfortunately we cannot use enums as const generic parameters yet, hence we check for this
                // here.
                error!("BUG: CpuIdFeatureFlags constructed with invalid register value");
            }
            // The job is done, but also check if the updated register contains all set feature flags,
            // if not report them.
            let mut missing_bits = updated ^ self.0;
            if missing_bits != 0 {
                // iterate over the missing bits and log a warning
                let mut bit_positions = Vec::new();
                while missing_bits != 0 {
                    let idx = missing_bits.trailing_zeros() as usize;
                    bit_positions.push(u8::try_from(idx).expect(
                        "idx is at most 32 hence it can be represented as a u8 without problems",
                    ));
                    let least_significant_bit = missing_bits & missing_bits.wrapping_neg();
                    missing_bits ^= least_significant_bit;
                }
                // TODO: Use a proper register name rather than REG and consider returning this as an error instead of logging here
                log::warn!(
                    "the given cpuid entry identified by: \n
                 function = 0x{:08x} \
                 index = 0x{:08x} \
                 flags =  0x{:08x} \
                 does not have the following bits set: {:?} in the register {:?}
                 even though the specified restriction permits it.
                ",
                    entry.function,
                    entry.index,
                    entry.flags,
                    bit_positions,
                    REG
                );
            }
        }
        if (!found_matching) && (self.0 != 0) {
            // TODO: Better log or return an error here
            log::warn!("no entry matched");
        }
    }
}

/// Reduces boilerplate when implementing CpuIdFeatureFlag constants.
/// One passes in a parameterized CpuIdFeatureFlags together with
/// a name per bit in the 32bit bitset.
///
/// For lower order bits that should not have any associated constant, appearing
/// before a higher order bit that needs a constant, you can simply place a "NULL"
/// in its place.
macro_rules! cpuid_flag_constants {
    /* NOTE: We allow dead code within this macro as we may want to use certain
     unused constants in the feature when introducing more cpu profiles.
     The alternative would be to fill the macro invocations with more "NULL"
     entries.
    */
    //============ Possible starting points ===========//
    ($t:ty, $name:ident) => {
        impl $t {
            #[allow(dead_code)]
            pub const $name: Self = Self(1);
        }
    };
    ($t:ty, "NULL", $($tail:tt)*) => {
        impl $t {
            cpuid_flag_constants!(1, $($tail)*);
        }
    };
    ($t:ty, $name:ident, $($tail:tt)*) => {
        impl $t {
            #[allow(dead_code)]
            pub const $name: Self = Self(1);
            cpuid_flag_constants!(1, $($tail)*);
        }
    };

    //============ Possible most deeply nested macro invocation ===========//
    ($i:expr, $name:ident $(,)*) => {
        #[allow(dead_code)]
        pub const $name: Self = Self(1 << $i);
    };

    ($i:expr, "NULL" $(,)*) => {};

    // ============ Possible continuations that continue the recursion ===== //
    ($i:expr, "NULL", $($tail:tt)+) => {
        cpuid_flag_constants!($i + 1, $($tail)*);
    };
    ($i:expr, $name:ident, $($tail:tt)+) => {
        #[allow(dead_code)]
        pub const $name: Self = Self(1 << $i);
        cpuid_flag_constants!($i + 1, $($tail)*);
    };

}

cpuid_flag_constants!(
    CpuIdEntryRegister<1, 0, { CpuidReg::EDX as u8 }>,
            FPU, VME, DE, PSE,
            TSC, MSR, PAE, MCE,
            CX8, APIC, "NULL", SEP,
            MTRR, PGE, MCA, CMOV,
            PAT, PSE36, PN /* Intel psn */, CLFLUSH /* Intel clfsh */,
            "NULL", DS /* INTEL DTS */, ACPI, MMX,
            FXSR, SSE, SSE2, SS,
            HT /* Intel htt */, TM, IA64, PBE,
);
cpuid_flag_constants!(
    CpuIdEntryRegister<1, 0, { CpuidReg::ECX as u8 }>,
            SSE3 /* Intel PNI,AMD sse3 */, PCLMULQDQ, DTES64, MONITOR,
            DS_CPL, VMX, SMX, EST,
            TM2, SSSE3, CID, "NULL",
            FMA, CX16, XTPR, PDCM,
            "NULL", PCID, DCA, SSE4_1,
            SSE4_2, X2APIC, MOVBE, POPCNT,
            TSC_DEADLINE, AES, XSAVE, "NULL" /* osxsave */,
            AVX, F16C, RDRAND, HYPERVISOR,
);
/*
TODO: The duplicate values only set for AMD are currently ignored (set to "NULL"). We need to
change this when we add the first AMD cpu profile.
*/
cpuid_flag_constants!(
    CpuIdEntryRegister<0x8000_0001, 0, { CpuidReg::EDX as u8}>,
            "NULL" /* AMD_FPU */, "NULL" /* AMD_VME */, "NULL" /* AMD_DE */, "NULL" /* AMD_PSE */,
            "NULL" /* AMD_TSC */, "NULL" /* AMD_MSR */, "NULL" /* AMD_PAE */, "NULL" /* AMD_MCE */,
            "NULL" /* AMD_CX8 */, "NULL" /* AMD_APIC */, "NULL", SYSCALL,
            "NULL" /* AMD_MTRR */, "NULL" /* AMD_PGE */, "NULL" /* AMD_MCA */, "NULL" /* AMD_CMOV */,
            "NULL" /* AMD_PAT */, "NULL" /* AMD_PSE36 */, "NULL", "NULL" /* AMD ECC */,
            NX, "NULL", MMXEXT, "NULL" /* AMD_MMX */,
            "NULL" /* AMD_FXSR */, FXSR_OPT, PDPE1GB, RDTSCP,
            "NULL", LM, EXT_3DNOW, FIRST_3DNOW,

);
cpuid_flag_constants!(
    CpuIdEntryRegister<0x8000_0001, 0, { CpuidReg::ECX as u8}>,
            LAHF_LM, CMP_LEGACY, SVM, EXTAPIC,
            CR8LEGACY, ABM, SSE4A, MISALIGNSSE,
            PREFETCH_3DNOW, OSVW, IBS, XOP,
            SKINIT, WDT, "NULL", LWP,
            FMA4, TCE, "NULL", NODEID_MSR,
            "NULL", TBM, TOPOEXT, PERFCTR_CORE,
            PERFCTR_NB, "NULL", "NULL", "NULL",
            "NULL", "NULL", "NULL", "NULL",
);
cpuid_flag_constants!(
    CpuIdEntryRegister<7, 0, {CpuidReg::EBX as u8}>,
            FSGSBASE, TSC_ADJUST, SGX, BMI1,
            HLE, AVX2, FDP_EXCPTN_ONLY, SMEP,
            BMI2, ERMS, INVPCID, RTM,
            "NULL", ZERO_FCS_FDS, MPX, "NULL",
            AVX512F, AVX512DQ, RDSEED, ADX,
            SMAP, AVX512IFMA, PCOMMIT, CLFLUSHOPT,
            CLWB, INTEL_PT, AVX512PF, AVX512ER,
            AVX512CD, SHA_NI, AVX512BW, AVX512VL,
);
cpuid_flag_constants!(
    CpuIdEntryRegister<7, 0, {CpuidReg::ECX as u8}>,
            "NULL", AVX512VBMI, UMIP, PKU,
            "NULL" /* ospke */, WAITPKG, AVX512VBMI2, "NULL",
            GFNI, VAES, VPCLMULQDQ, AVX512VNNI,
            AVX512BITALG, "NULL", AVX512_VPOPCNTDQ, "NULL",
            LA57, "NULL", "NULL", "NULL",
            "NULL", "NULL", RDPID, "NULL",
            BUS_LOCK_DETECT, CLDEMOTE, "NULL", MOVDIRI,
            MOVDIR64B, "NULL", SGXLC, PKS,
);

cpuid_flag_constants!(
    CpuIdEntryRegister<7, 0, {CpuidReg::EDX as u8}>,
    "NULL", "NULL", AVX512_4VNNIW, AVX512_4FMAPS,
    FSRM, "NULL", "NULL", "NULL",
    AVX512_VP2INTERSECT, "NULL", MD_CLEAR, "NULL",
    "NULL", "NULL", SERIALIZE, "NULL",
    TSX_LDTRK, "NULL", "NULL" /* pconfig */, ARCH_LBR,
    "NULL", "NULL", AMX_BF16, AVX512_FP16,
    AMX_TILE, AMX_INT8, SPEC_CTRL, STIBP,
    FLUSH_L1D, ARCH_CAPABILITIES, CORE_CAPABILITY, SSBD,
);

cpuid_flag_constants!(
    CpuIdEntryRegister<0xd,1, {CpuidReg::EAX as u8}>,
            XSAVEOPT, XSAVEC, XGETBV1, XSAVES,
            XFD, "NULL", "NULL", "NULL",
            "NULL", "NULL", "NULL", "NULL",
            "NULL", "NULL", "NULL", "NULL",
            "NULL", "NULL", "NULL", "NULL",
            "NULL", "NULL", "NULL", "NULL",
            "NULL", "NULL", "NULL", "NULL",
            "NULL", "NULL", "NULL", "NULL",
);

cpuid_flag_constants!(
    CpuIdEntryRegister<6, 0, {CpuidReg::EAX as u8}>,
            "NULL", "NULL", ARAT, "NULL",
            "NULL", "NULL", "NULL", "NULL",
            "NULL", "NULL", "NULL", "NULL",
            "NULL", "NULL", "NULL", "NULL",
            "NULL", "NULL", "NULL", "NULL",
            "NULL", "NULL", "NULL", "NULL",
            "NULL", "NULL", "NULL", "NULL",
            "NULL", "NULL", "NULL", "NULL",

);

/// A set of CPUID feature flags consisting of the registers for the various leaves describing
/// CPU feature flags.
///
/// # Feature related Registers that are ignored
///
/// - 0x12: SGX capabilities (this is handled separately for now)
/// - 0x19: Intel key locker features (ignored, but why?)
/// - 0x1E, EXC=1: TMUL information (this is handled separately for now)
/// - TODO: 0x8000_0001F: Encrypted Memory Capabilities
/// - 0xC000_0000: Highest Centaur Extended Function (out of scope for now)
/// - 0xC000_0001: Centaur Feature Information (out of scope for now)
/// # Constructors
///
/// This struct has constructors for each of the currently supported CPU profiles.
///
/// For DEVELOPERS: The CPU profile constructors are located in [`crate::x86_64::cpu_profile::cpuid_feature_flags_impl`](crate::x86_64::cpu_profile::cpuid_feature_flags_impl).
pub struct CpuIdFeatureFlags {
    pub edx_1: CpuIdEntryRegister<1, 0, { CpuidReg::EDX as u8 }>,
    pub ecx_1: CpuIdEntryRegister<1, 0, { CpuidReg::ECX as u8 }>,
    pub ebx_7_0: CpuIdEntryRegister<7, 0, { CpuidReg::EBX as u8 }>,
    pub ecx_7_0: CpuIdEntryRegister<7, 0, { CpuidReg::ECX as u8 }>,
    pub edx_7_0: CpuIdEntryRegister<7, 0, { CpuidReg::EDX as u8 }>,
    pub eax_7_1: CpuIdEntryRegister<7, 1, { CpuidReg::EAX as u8 }>,
    pub ecx_7_1: CpuIdEntryRegister<7, 1, { CpuidReg::ECX as u8 }>,
    pub edx_7_1: CpuIdEntryRegister<7, 1, { CpuidReg::EDX as u8 }>,
    pub edx_7_2: CpuIdEntryRegister<7, 2, { CpuidReg::EDX as u8 }>,
    pub eax_0dh_1: CpuIdEntryRegister<0xd, 1, { CpuidReg::EAX as u8 }>,
    pub ecx_14h: CpuIdEntryRegister<0x14, 0, { CpuidReg::ECX as u8 }>,
    pub ecx_24h_1: CpuIdEntryRegister<0x24, 1, { CpuidReg::ECX as u8 }>,
    pub edx_8000_0001h: CpuIdEntryRegister<0x8000_0001, 0, { CpuidReg::EDX as u8 }>,
    pub ecx_8000_0001h: CpuIdEntryRegister<0x8000_0001, 0, { CpuidReg::ECX as u8 }>,
    pub edx_8000_0007h: CpuIdEntryRegister<0x8000_0007, 0, { CpuidReg::EDX as u8 }>,
    pub ebx_8000_0008h: CpuIdEntryRegister<0x8000_0008, 0, { CpuidReg::EBX as u8 }>,
    /// FEAT_SVM in QEMU
    pub edx_8000_000ah: CpuIdEntryRegister<0x8000_000A, 0, { CpuidReg::EDX as u8 }>,
    pub eax_8000_0021h: CpuIdEntryRegister<0x8000_0021, 0, { CpuidReg::EAX as u8 }>,
}

impl CpuIdFeatureFlags {
    pub(in crate::x86_64) fn restrict(&self, cpuid: &mut [CpuIdEntry]) {
        let Self {
            edx_1,
            ecx_1,
            ebx_7_0,
            ecx_7_0,
            edx_7_0,
            eax_7_1,
            ecx_7_1,
            edx_7_1,
            edx_7_2,
            eax_0dh_1,
            ecx_14h,
            ecx_24h_1,
            edx_8000_0001h,
            ecx_8000_0001h,
            edx_8000_0007h,
            ebx_8000_0008h,
            edx_8000_000ah,
            eax_8000_0021h,
        } = self;
        edx_1.intersect_matching(cpuid);
        ecx_1.intersect_matching(cpuid);
        ebx_7_0.intersect_matching(cpuid);
        ecx_7_0.intersect_matching(cpuid);
        edx_7_0.intersect_matching(cpuid);
        eax_7_1.intersect_matching(cpuid);
        ecx_7_1.intersect_matching(cpuid);
        edx_7_1.intersect_matching(cpuid);
        edx_7_2.intersect_matching(cpuid);
        eax_0dh_1.intersect_matching(cpuid);
        ecx_14h.intersect_matching(cpuid);
        ecx_24h_1.intersect_matching(cpuid);
        edx_8000_0001h.intersect_matching(cpuid);
        ecx_8000_0001h.intersect_matching(cpuid);
        edx_8000_0007h.intersect_matching(cpuid);
        ebx_8000_0008h.intersect_matching(cpuid);
        edx_8000_000ah.intersect_matching(cpuid);
        eax_8000_0021h.intersect_matching(cpuid);
    }
}
