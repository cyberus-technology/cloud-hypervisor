use hypervisor::arch::x86::{CpuIdEntry, CPUID_FLAG_VALID_INDEX};

use super::CpuidReg;

/// A bitset of CPUID feature flags for a given leaf, sub-leaf and register triple
/// (or function, index, register in KVM terms).
pub struct CpuIdEntryRegister<const FUNCTION: u32, const INDEX: u32, const REG: u8>(u32);

impl<const FUNCTION: u32, const INDEX: u32, const REG: u8>
    CpuIdEntryRegister<FUNCTION, INDEX, REG>
{
    pub const fn register_name(&self) -> &'static str {
        const {
            if CpuidReg::EAX as u8 == REG {
                "eax"
            } else if CpuidReg::EBX as u8 == REG {
                "ebx"
            } else if CpuidReg::ECX as u8 == REG {
                "ecx"
            } else if CpuidReg::EDX as u8 == REG {
                "edx"
            } else {
                // Note that this block is evaluated at compile time and cannot lead to runtime panics
                panic!("invalid register value");
            }
        }
    }
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
                log::warn!(
                    "the given cpuid entry identified by: \n
                 function = 0x{:08x} \
                 index = 0x{:08x} \
                 flags =  0x{:08x} \
                 does not have the following bits set: {:?} for the {} register
                 even though the specified restriction permits it.
                ",
                    FUNCTION,
                    INDEX,
                    entry.flags,
                    bit_positions,
                    self.register_name()
                );
            }
        }
        if (!found_matching) && (self.0 != 0) {
            log::warn!(
                "no entry matched the function = 0x{:8x}, index = 0x{:08x} parameters",
                FUNCTION,
                INDEX
            );
        }
    }
}

/// Generates multiple constants for [`CpuIdEntryRegister`] without having to repeat the function, index, register parameters every time.
///
/// Also produces decent documentation for each constant including the parameters, the bit position and the wikipedia entry where the meaning of each feature flag for
/// the current (function, index, register) triple can be found.
///
/// Invocations have the following named arguments in the following order:
/// - `wiki`: A string with the link to the wikipedia entry describing the various values in this leaf, subleaf, register triple (or function, index, register in KVM terms).
/// - `function`: The leaf for the CPUID entry (called function in KVM terminology).
/// - `index`: The subleaf for the CPUID entry (called index in KVM terminology).
/// - `register`: The register where the feature bits are located (valid inputs are `eax`, `ebx`, `ecx` and `edx`. These are idents and not string literals).
/// - A list of tuples where the first is the name of the constant and the second is its corresponding bit position.
macro_rules! impl_cpuid_entry_register_constants {
    (wiki = $wiki:literal, function = $function:literal, index = $index:literal, register = $register:ident, [$(($name:ident, $position:literal)),+$(,)*]) => {
        paste::paste! {
            impl CpuIdEntryRegister<$function, $index, {CpuidReg::[<$register:upper>] as u8}> {
                $(
                    #[doc = "Bit `" $position "` in register `" $register "` of CPUID function = `" $function "`, index = `" $index "`."]
                    #[doc = "\n\nSee [this section of the CPUID article in wikipedia]( " $wiki " ) for more information"]
                    pub const $name: Self = Self(1u32 << $position);
                )+
            }
        }
    };
}

impl_cpuid_entry_register_constants!(
    wiki = "https://en.wikipedia.org/wiki/CPUID#EAX=1:_Processor_Info_and_Feature_Bits",
    function = 1,
    index = 0,
    register = edx,
    [
        (FPU, 0),
        (VME, 1),
        (DE, 2),
        (PSE, 3),
        (TSC, 4),
        (MSR, 5),
        (PAE, 6),
        (MCE, 7),
        (CX8, 8),
        (APIC, 9),
        (SEP, 11),
        (MTRR, 12),
        (PGE, 13),
        (MCA, 14),
        (CMOV, 15),
        (PAT, 16),
        (PSE36, 17),
        (PN /* Intel psn */, 18),
        (CLFLUSH /* Intel clfsh */, 19),
        (DS /* INTEL DTS */, 21),
        (ACPI, 22),
        (MMX, 23),
        (FXSR, 24),
        (SSE, 25),
        (SSE2, 26),
        (SS, 27),
        (HT /* Intel htt */, 28),
        (TM, 29),
        (IA64, 30),
        (PBE, 31),
    ]
);

impl_cpuid_entry_register_constants!(
    wiki = "https://en.wikipedia.org/wiki/CPUID#EAX=1:_Processor_Info_and_Feature_Bits",
    function = 1,
    index = 0,
    register = ecx,
    [
        (SSE3 /* Intel PNI and AMD sse3 */, 0),
        (PCLMULQDQ, 1),
        (DTES64, 2),
        (MONITOR, 3),
        (DS_CPL, 4),
        (VMX, 5),
        (SMX, 6),
        (EST, 7),
        (TM2, 8),
        (SSSE3, 9),
        (CID, 10),
        (FMA, 12),
        (CX16, 13),
        (XTPR, 14),
        (PDCM, 15),
        (PCID, 17),
        (DCA, 18),
        (SSE4_1, 19),
        (SSE4_2, 20),
        (X2APIC, 21),
        (MOVBE, 22),
        (POPCNT, 23),
        (TSC_DEADLINE, 24),
        (AES, 25),
        (XSAVE, 26),
        (AVX, 28),
        (F16C, 29),
        (RDRAND, 30),
        (HYPERVISOR, 31),
    ]
);

// We only make the ARAT (always running APIC timer) capability from this leaf ergonomic for now.
impl_cpuid_entry_register_constants!(
    wiki = "https://en.wikipedia.org/wiki/CPUID#EAX=6:_Thermal_and_Power_Management",
    function = 6,
    index = 0,
    register = eax,
    [(ARAT, 2)]
);

impl_cpuid_entry_register_constants!(
    wiki = "https://en.wikipedia.org/wiki/CPUID#EAX=7,_ECX=0:_Extended_Features",
    function = 7,
    index = 0,
    register = ebx,
    [
        (FSGSBASE, 0),
        (TSC_ADJUST, 1),
        (SGX, 2),
        (BMI1, 3),
        (HLE, 4),
        (AVX2, 5),
        (FDP_EXCPTN_ONLY, 6),
        (SMEP, 7),
        (BMI2, 8),
        (ERMS, 9),
        (INVPCID, 10),
        (RTM, 11),
        (ZERO_FCS_FDS, 13),
        (MPX, 14),
        (AVX512F, 16),
        (AVX512DQ, 17),
        (RDSEED, 18),
        (ADX, 19),
        (SMAP, 20),
        (AVX512IFMA, 21),
        (PCOMMIT, 22),
        (CLFLUSHOPT, 23),
        (CLWB, 24),
        (INTEL_PT, 25),
        (AVX512PF, 26),
        (AVX512ER, 27),
        (AVX512CD, 28),
        (SHA_NI, 29),
        (AVX512BW, 30),
        (AVX512VL, 31),
    ]
);

impl_cpuid_entry_register_constants!(
    wiki = "https://en.wikipedia.org/wiki/CPUID#EAX=7,_ECX=0:_Extended_Features",
    function = 7,
    index = 0,
    register = ecx,
    [
        (AVX512VBMI, 1),
        (UMIP, 2),
        (PKU, 3),
        (WAITPKG, 5),
        (AVX512VBMI2, 6),
        (GFNI, 8),
        (VAES, 9),
        (VPCLMULQDQ, 10),
        (AVX512VNNI, 11),
        (AVX512BITALG, 12),
        (AVX512_VPOPCNTDQ, 14),
        (LA57, 16),
        (RDPID, 22),
        (BUS_LOCK_DETECT, 24),
        (CLDEMOTE, 25),
        (MOVDIRI, 27),
        (MOVDIR64B, 28),
        (SGXLC, 30),
        (PKS, 31),
    ]
);

impl_cpuid_entry_register_constants!(
    wiki = "https://en.wikipedia.org/wiki/CPUID#EAX=7,_ECX=0:_Extended_Features",
    function = 7,
    index = 0,
    register = edx,
    [
        (AVX512_4VNNIW, 2),
        (AVX512_4FMAPS, 3),
        (FSRM, 4),
        (AVX512_VP2INTERSECT, 8),
        (MD_CLEAR, 10),
        (SERIALIZE, 14),
        (TSX_LDTRK, 16),
        (ARCH_LBR, 19),
        (AMX_BF16, 22),
        (AVX512_FP16, 23),
        (AMX_TILE, 24),
        (AMX_INT8, 25),
        (SPEC_CTRL, 26),
        (STIBP, 27),
        (FLUSH_L1D, 28),
        (ARCH_CAPABILITIES, 29),
        (CORE_CAPABILITY, 30),
        (SSBD, 31),
    ]
);

impl_cpuid_entry_register_constants!(
    wiki = "https://en.wikipedia.org/wiki/CPUID#EAX=7,_ECX=1:_Extended_Features",
    function = 7,
    index = 1,
    register = ecx,
    [(MSR_IMM, 5)]
);
impl_cpuid_entry_register_constants!(
    wiki = "https://en.wikipedia.org/wiki/CPUID#EAX=7,_ECX=1:_Extended_Features",
    function = 7,
    index = 1,
    register = eax,
    [
        (SHA512, 0),
        (SM3, 1),
        (SM4, 2),
        (AVX_VNNI, 4),
        (AVX512_BF16, 5),
        (CMPCCXADD, 7),
        (FZRM, 10),
        (FSRS, 11),
        (FSRC, 12),
        (FRED, 17),
        (LKGS, 18),
        (WRMSRNS, 19),
        (AMX_FP16, 21),
        (AVX_IFMA, 23),
        (LAM, 26),
    ]
);

impl_cpuid_entry_register_constants!(
    wiki = "https://en.wikipedia.org/wiki/CPUID#EAX=7,_ECX=1:_Extended_Features",
    function = 7,
    index = 1,
    register = edx,
    [
        (AVX_VNNI_INT8, 4),
        (AVX_NE_CONVERT, 5),
        (AMX_COMPLEX, 8),
        (AVX_VNNI_INT16, 10),
        (PREFETCHITI, 14),
        (AVX10, 19),
    ]
);

impl_cpuid_entry_register_constants!(
    wiki = "https://en.wikipedia.org/wiki/CPUID#EAX=7,_ECX=2:_Extended_Features",
    function = 7,
    index = 2,
    register = edx,
    [
        (INTEL_PSFD, 0),
        (IPRED_CTRL, 1),
        (RRSBA_CTRL, 2),
        (DDPD_U, 3),
        (BHI_CTRL, 4),
        (MCDT_NO, 5),
    ]
);
impl_cpuid_entry_register_constants!(
    wiki = "https://en.wikipedia.org/wiki/CPUID#EAX=0Dh:_XSAVE_Features_and_State_Components",
    function = 0xd,
    index = 1,
    register = eax,
    [
        (XSAVEOPT, 0),
        (XSAVEC, 1),
        (XGETBV1, 2),
        (XSAVES, 3),
        (XFD, 4),
    ]
);

impl_cpuid_entry_register_constants!(
    wiki = "https://en.wikipedia.org/wiki/CPUID#EAX=24h,_ECX=1:_Discrete_AVX10_Features",
    function = 0x24,
    index = 1,
    register = ecx,
    [(VPMM, 0), (AVX_10_VNNI_INT, 2)]
);

impl_cpuid_entry_register_constants!(
    wiki = "https://en.wikipedia.org/wiki/CPUID#EAX=8000'0001h:_Extended_Processor_Info_and_Feature_Bits",
    function = 0x8000_0001,
    index = 0,
    register = edx,
    [
        (SYSCALL, 11),
        (NX, 20),
        (MMXEXT, 22),
        (FXSR_OPT, 25),
        (PDPE1GB, 26),
        (RDTSCP, 27),
        (LM, 29),
        (EXT_3DNOW, 30),
        (FIRST_3DNOW, 31),
    ]
);
impl_cpuid_entry_register_constants!(
    wiki = "https://en.wikipedia.org/wiki/CPUID#EAX=8000'0001h:_Extended_Processor_Info_and_Feature_Bits",
    function = 0x8000_0001,
    index = 0,
    register = ecx,
    [
        (LAHF_LM,0),
        (CMP_LEGACY,1),
        (SVM,2),
        (EXTAPIC,3),
        (CR8LEGACY,4),
        (ABM,5),
        (SSE4A,6),
        (MISALIGNSSE,7),
        (PREFETCH_3DNOW,8),
        (OSVW,9),
        (IBS,10),
        (XOP,11),
        (SKINIT,12),
        (WDT,13),
        (LWP,15),
        (FMA4,16),
        (TCE,17),
        (NODEID_MSR,19),
        (TBM,21),
        (TOPOEXT,22),
        (PERFCTR_CORE,23),
        (PERFCTR_NB,24),
    ]
);
impl_cpuid_entry_register_constants!(
    wiki="https://en.wikipedia.org/wiki/CPUID#EAX=8000'0007h:_Processor_Power_Management_Information_and_RAS_Capabilities",
    function = 0x8000_0007,
    index = 0,
    register = edx,
    [(INVTSC, 8)]
);

/// A set of CPUID feature flags consisting of the registers for the various leaves describing
/// CPU feature flags.
///
/// # Feature related Registers that are ignored
///
/// - 0x12: SGX capabilities (this is ignored as CHV has deprecated its support). TODO: Should we include this and set it to `Self::NULL` ?
///
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
