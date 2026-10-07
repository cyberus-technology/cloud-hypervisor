// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//
//! This module contains lists of architectural MSRs (or more accurately MSR register addresses) that
//! are permitted and forbidden for use with CPU profiles.
//!
//! The CPU profile generation tool obtains all MSRS supported by both KVM and the hardware
//! when it runs and uses the permitted list to only record those that are permitted.
//!
//! The list of forbidden architectural MSRs is only used to rule out "false" new MSRs that otherwise
//! would require updating the CPU profile generation tool.

// We occasionally write doc comments for constants that are defined in private modules. This
// is still helpful for developers as the LSP can then provide information about the constants
// directly at the site(s) where they are being used.
#![allow(unused_doc_comments)]

pub(in crate::x86_64) use forbidden_architectural_msrs::FORBIDDEN_IA32_MSR_RANGES;
pub(in crate::x86_64) use permitted_architectural_msrs::PERMITTED_IA32_MSRS;

use crate::x86_64::CpuidReg;
use crate::x86_64::cpuid_definitions::Parameters;
use crate::x86_64::cpuid_definitions::intel::assert_not_denied_cpuid_feature;

mod permitted_architectural_msrs {
    use read_only::READ_ONLY_IA32_MSRS;
    use read_write::READ_WRITE_IA32_MSRS;
    use write_only::WRITE_ONLY_IA32_MSRS;

    use super::{CpuidReg, Parameters};
    use crate::x86_64::msr_definitions::intel::architectural_msrs::assert_not_denied_cpuid_feature;

    mod read_only {
        use super::{CpuidReg, Parameters, assert_not_denied_cpuid_feature};
        /// (R/O)
        const IA32_BARRIER: u32 = 0x2f;
        const _IA32_BARRIER_CPUID_CHECK: () = const {
            assert_not_denied_cpuid_feature::<27>(&Parameters {
                leaf: 0x7,
                sub_leaf: 0..=0,
                register: CpuidReg::EAX,
            });
        };

        /// MTRR Capability (R/O)
        const IA32_MTRRCAP: u32 = 0xfe;

        // TODO: Not sure whether the IA32_FZM_* msrs should be permitted
        const IA32_FZM_DOMAIN_CONFIG: u32 = 0x83;
        const IA32_FZM_RANGE_STARTADDR: u32 = 0x84;
        const IA32_FZM_RANGE_ENDADDR: u32 = 0x85;
        const IA32_FZM_RANGE_WRITESTATUS: u32 = 0x86;
        // NOTE: This is permitted, but will be zeroed out for all non-host CPU profiles.
        const IA32_MCG_CAP: u32 = 0x179;

        /// DCA Capability (R)
        const IA32_PLATFORM_DCA_CAP: u32 = 0x1f8;
        /// If set, CPU supports Prefetch-Hint type
        const IA32_CPU_DCA_CAP: u32 = 0x1f9;

        const _IA32_DCA_CAP_CPUID_CHECK: () = assert_not_denied_cpuid_feature::<18>(&Parameters {
            leaf: 0x1,
            sub_leaf: 0..=0,
            register: CpuidReg::ECX,
        });

        // TODO: Can we rather place this MSR in the deny list?
        const IA32_MCU_STAGING_MBOX_ADDR: u32 = 0x7a5;

        // NOTE: THE X2APIC related MSRs cannot be filtered by KVM, but we include them here anyway for completeness sake.
        const IA32_X2APIC_APICID: u32 = 0x802;
        const IA32_X2APIC_VERSION: u32 = 0x803;
        const IA32_X2APIC_PPR: u32 = 0x80a;
        const IA32_X2APIC_LDR: u32 = 0x80d;
        const IA32_X2APIC_ISR0: u32 = 0x810;
        const IA32_X2APIC_ISR1: u32 = 0x811;
        const IA32_X2APIC_ISR2: u32 = 0x812;

        const IA32_X2APIC_ISR3: u32 = 0x813;
        const IA32_X2APIC_ISR4: u32 = 0x814;
        const IA32_X2APIC_ISR5: u32 = 0x815;
        const IA32_X2APIC_ISR6: u32 = 0x816;
        const IA32_X2APIC_ISR7: u32 = 0x817;
        const IA32_X2APIC_TMR0: u32 = 0x818;
        const IA32_X2APIC_TMR1: u32 = 0x819;
        const IA32_X2APIC_TMR2: u32 = 0x81a;
        const IA32_X2APIC_TMR3: u32 = 0x81b;
        const IA32_X2APIC_TMR4: u32 = 0x81c;
        const IA32_X2APIC_TMR5: u32 = 0x81d;
        const IA32_X2APIC_TMR6: u32 = 0x81e;
        const IA32_X2APIC_TMR7: u32 = 0x81f;
        const IA32_X2APIC_IRR0: u32 = 0x820;
        const IA32_X2APIC_IRR1: u32 = 0x821;
        const IA32_X2APIC_IRR2: u32 = 0x822;
        const IA32_X2APIC_IRR3: u32 = 0x823;
        const IA32_X2APIC_IRR4: u32 = 0x824;
        const IA32_X2APIC_IRR5: u32 = 0x825;
        const IA32_X2APIC_IRR6: u32 = 0x826;
        const IA32_X2APIC_IRR7: u32 = 0x827;
        const IA32_X2APIC_CUR_COUNT: u32 = 0x839;

        pub(super) const READ_ONLY_IA32_MSRS: [u32; 39] = [
            IA32_BARRIER,
            IA32_MTRRCAP,
            IA32_FZM_DOMAIN_CONFIG,
            IA32_FZM_RANGE_STARTADDR,
            IA32_FZM_RANGE_ENDADDR,
            IA32_FZM_RANGE_WRITESTATUS,
            IA32_MCG_CAP,
            IA32_PLATFORM_DCA_CAP,
            IA32_CPU_DCA_CAP,
            IA32_MCU_STAGING_MBOX_ADDR,
            IA32_X2APIC_APICID,
            IA32_X2APIC_VERSION,
            IA32_X2APIC_PPR,
            IA32_X2APIC_LDR,
            IA32_X2APIC_ISR0,
            IA32_X2APIC_ISR1,
            IA32_X2APIC_ISR2,
            IA32_X2APIC_ISR3,
            IA32_X2APIC_ISR4,
            IA32_X2APIC_ISR5,
            IA32_X2APIC_ISR6,
            IA32_X2APIC_ISR7,
            IA32_X2APIC_TMR0,
            IA32_X2APIC_TMR1,
            IA32_X2APIC_TMR2,
            IA32_X2APIC_TMR3,
            IA32_X2APIC_TMR4,
            IA32_X2APIC_TMR5,
            IA32_X2APIC_TMR6,
            IA32_X2APIC_TMR7,
            IA32_X2APIC_IRR0,
            IA32_X2APIC_IRR1,
            IA32_X2APIC_IRR2,
            IA32_X2APIC_IRR3,
            IA32_X2APIC_IRR4,
            IA32_X2APIC_IRR5,
            IA32_X2APIC_IRR6,
            IA32_X2APIC_IRR7,
            IA32_X2APIC_CUR_COUNT,
        ];
    }

    mod read_write {
        use super::{CpuidReg, Parameters, assert_not_denied_cpuid_feature};

        const IA32_TIME_STAMP_COUNTER: u32 = 0x10;

        const IA32_APIC_BASE: u32 = 0x1b;

        const IA32_FEATURE_CONTROL: u32 = 0x3a;

        /// Per Logical Processor TSC Adjust (R/Write to clear)
        const IA32_TSC_ADJUST: u32 = 0x3b;
        const _IA32_TSC_ADJUST_CPUID_CHECK: () =
            assert_not_denied_cpuid_feature::<1>(&Parameters {
                leaf: 0x7,
                sub_leaf: 0..=0,
                register: CpuidReg::EBX,
            });

        const IA32_SPEC_CTRL: u32 = 0x48;
        const _IA32_SPECT_CTRL_CPUID_CHECK: () =
            assert_not_denied_cpuid_feature::<26>(&Parameters {
                leaf: 0x7,
                sub_leaf: 0..=0,
                register: CpuidReg::EDX,
            });

        const IA32_MCU_OPT_CTRL: u32 = 0x123;
        const _IA32_MCU_OPT_CTRL_CPUID_CHECK: () =
            assert_not_denied_cpuid_feature::<9>(&Parameters {
                leaf: 0x7,
                sub_leaf: (0..=0),
                register: CpuidReg::EDX,
            });

        /// SYSENTER_CS_MSR
        const IA32_SYSENTER_CS: u32 = 0x174;

        /// SYSENTER_ESP_MSR
        const IA32_SYSENTER_ESP: u32 = 0x175;

        /// SYSENTER_ESP_MSR
        const IA32_SYSENTER_EIP: u32 = 0x176;

        // Technically permitted (as users will expect it given that MCA is available via CPUID),
        // but probably not very useful since IA32_MCG_CAP will be zeroed out for all non-host
        // CPU profiles
        const IA32_MCG_STATUS: u32 = 0x17a;

        // TODO: Does it really make sense to permit this MSR?
        const IA32_SMM_MONITOR_CTL: u32 = 0x9b;
        const _IA32_SMM_MONITOR_CTL_CPUID_CHECK: () =
            assert_not_denied_cpuid_feature::<5>(&Parameters {
                leaf: 0x1,
                sub_leaf: 0..=0,
                register: CpuidReg::ECX,
            });

        /// Enable Misc. Processr Features
        const IA32_MISC_ENABLE: u32 = 0x1a0;

        const IA32_XFD: u32 = 0x1c4;
        const IA32_XFD_ERR: u32 = 0x1c5;

        const IA32_DCA_0_CAP: u32 = 0x1fa;

        const _IA32_DCA_0_CAP_CPUID_CHECK: () =
            assert_not_denied_cpuid_feature::<18>(&Parameters {
                leaf: 0x1,
                sub_leaf: 0..=0,
                register: CpuidReg::ECX,
            });

        const IA32_MTRR_PHYSBASE0: u32 = 0x200;
        const IA32_MTRR_PHYSMASK0: u32 = 0x201;
        const IA32_MTRR_PHYSBASE1: u32 = 0x202;
        const IA32_MTRR_PHYSMASK1: u32 = 0x203;
        const IA32_MTRR_PHYSBASE2: u32 = 0x204;
        const IA32_MTRR_PHYSMASK2: u32 = 0x205;
        const IA32_MTRR_PHYSBASE3: u32 = 0x206;
        const IA32_MTRR_PHYSMASK3: u32 = 0x207;
        const IA32_MTRR_PHYSBASE4: u32 = 0x208;
        const IA32_MTRR_PHYSMASK4: u32 = 0x209;
        const IA32_MTRR_PHYSBASE5: u32 = 0x20a;
        const IA32_MTRR_PHYSMASK5: u32 = 0x20b;
        const IA32_MTRR_PHYSBASE6: u32 = 0x20c;
        const IA32_MTRR_PHYSMASK6: u32 = 0x20d;
        const IA32_MTRR_PHYSBASE7: u32 = 0x20e;
        const IA32_MTRR_PHYSMASK7: u32 = 0x20f;
        const IA32_MTRR_PHYSBASE8: u32 = 0x210;
        const IA32_MTRR_PHYSMASK8: u32 = 0x211;
        const IA32_MTRR_PHYSBASE9: u32 = 0x212;
        const IA32_MTRR_PHYSMASK9: u32 = 0x213;

        const IA32_MTRR_FIX64K_00000: u32 = 0x250;
        const IA32_MTRR_FIX16K_80000: u32 = 0x258;
        const IA32_MTRR_FIX16K_A0000: u32 = 0x259;
        const IA32_MTRR_FIX4K_C0000: u32 = 0x268;
        const IA32_MTRR_FIX4K_C8000: u32 = 0x269;
        const IA32_MTRR_FIX4K_D0000: u32 = 0x26a;
        const IA32_MTRR_FIX4K_D8000: u32 = 0x26b;
        const IA32_MTRR_FIX4K_E0000: u32 = 0x26c;
        const IA32_MTRR_FIX4K_E8000: u32 = 0x26d;
        const IA32_MTRR_FIX4K_F0000: u32 = 0x26e;
        const IA32_MTRR_FIX4K_F8000: u32 = 0x26f;

        const _IA32_MTRR_FIX_I_X_CPUID_CHECK: () =
            assert_not_denied_cpuid_feature::<12>(&Parameters {
                leaf: 0x1,
                sub_leaf: 0..=0,
                register: CpuidReg::EDX,
            });

        const IA32_PAT: u32 = 0x277;
        const _IA32_PAT_CPUID_CHECK: () = assert_not_denied_cpuid_feature::<16>(&Parameters {
            leaf: 0x1,
            sub_leaf: 0..=0,
            register: CpuidReg::EDX,
        });

        const IA32_MTRR_DEF_TYPE: u32 = 0x2ff;

        // Error reporting banks. KVM always reports 32
        // of them by default.
        // TODO: Consider conditionally compiling this based
        // on whether we are using KVM
        const IA32_MC0_CTL: u32 = 0x400;
        const IA32_MC0_STATUS: u32 = 0x401;
        const IA32_MC0_ADDR: u32 = 0x402;
        const IA32_MC0_MISC: u32 = 0x403;
        const IA32_MC1_CTL: u32 = 0x404;
        const IA32_MC1_STATUS: u32 = 0x405;
        const IA32_MC1_ADDR: u32 = 0x406;

        const IA32_MC1_MISC: u32 = 0x407;
        const IA32_MC2_CTL: u32 = 0x408;
        const IA32_MC2_STATUS: u32 = 0x409;
        const IA32_MC2_ADDR: u32 = 0x40a;
        const IA32_MC2_MISC: u32 = 0x40b;
        const IA32_MC3_CTL: u32 = 0x40c;
        const IA32_MC3_STATUS: u32 = 0x40d;
        const IA32_MC3_ADDR1: u32 = 0x40e;
        const IA32_MC3_MISC: u32 = 0x40f;
        const IA32_MC4_CTL: u32 = 0x410;
        const IA32_MC4_STATUS: u32 = 0x411;
        const IA32_MC4_ADDR: u32 = 0x412;
        const IA32_MC4_MISC: u32 = 0x413;
        const IA32_MC5_CTL: u32 = 0x414;
        const IA32_MC5_STATUS: u32 = 0x415;
        const IA32_MC5_ADDR: u32 = 0x416;
        const IA32_MC5_MISC: u32 = 0x417;
        const IA32_MC6_CTL: u32 = 0x418;

        const IA32_MC6_STATUS: u32 = 0x419;
        const IA32_MC6_ADDR1: u32 = 0x41a;
        const IA32_MC6_MISC: u32 = 0x41b;
        const IA32_MC7_CTL: u32 = 0x41c;
        const IA32_MC7_STATUS: u32 = 0x41d;
        const IA32_MC7_ADDR: u32 = 0x41e;
        const IA32_MC7_MISC: u32 = 0x41f;
        const IA32_MC8_CTL: u32 = 0x420;
        const IA32_MC8_STATUS: u32 = 0x421;
        const IA32_MC8_ADDR: u32 = 0x422;
        const IA32_MC8_MISC: u32 = 0x423;
        const IA32_MC9_CTL: u32 = 0x424;
        const IA32_MC9_STATUS: u32 = 0x425;
        const IA32_MC9_ADDR: u32 = 0x426;
        const IA32_MC9_MISC: u32 = 0x427;
        const IA32_MC10_CTL: u32 = 0x428;
        const IA32_MC10_STATUS: u32 = 0x429;
        const IA32_MC10_ADDR: u32 = 0x42a;
        const IA32_MC10_MISC: u32 = 0x42b;

        const IA32_MC11_CTL: u32 = 0x42c;
        const IA32_MC11_STATUS: u32 = 0x42d;
        const IA32_MC11_ADDR: u32 = 0x42e;
        const IA32_MC11_MISC: u32 = 0x42f;
        const IA32_MC12_CTL: u32 = 0x430;
        const IA32_MC12_STATUS: u32 = 0x431;
        const IA32_MC12_ADDR: u32 = 0x432;
        const IA32_MC12_MISC: u32 = 0x433;
        const IA32_MC13_CTL: u32 = 0x434;
        const IA32_MC13_STATUS: u32 = 0x435;
        const IA32_MC13_ADDR: u32 = 0x436;
        const IA32_MC13_MISC: u32 = 0x437;
        const IA32_MC14_CTL: u32 = 0x438;
        const IA32_MC14_STATUS: u32 = 0x439;
        const IA32_MC14_ADDR: u32 = 0x43a;
        const IA32_MC14_MISC: u32 = 0x43b;
        const IA32_MC15_CTL: u32 = 0x43c;
        const IA32_MC15_STATUS: u32 = 0x43d;

        const IA32_MC15_ADDR: u32 = 0x43e;
        const IA32_MC15_MISC: u32 = 0x43f;
        const IA32_MC16_CTL: u32 = 0x440;
        const IA32_MC16_STATUS: u32 = 0x441;
        const IA32_MC16_ADDR: u32 = 0x442;
        const IA32_MC16_MISC: u32 = 0x443;
        const IA32_MC17_CTL: u32 = 0x444;
        const IA32_MC17_STATUS: u32 = 0x445;
        const IA32_MC17_ADDR: u32 = 0x446;
        const IA32_MC17_MISC: u32 = 0x447;
        const IA32_MC18_CTL: u32 = 0x448;
        const IA32_MC18_STATUS: u32 = 0x449;
        const IA32_MC18_ADDR: u32 = 0x44a;
        const IA32_MC18_MISC: u32 = 0x44b;
        const IA32_MC19_CTL: u32 = 0x44c;
        const IA32_MC19_STATUS: u32 = 0x44d;
        const IA32_MC19_ADDR: u32 = 0x44e;
        const IA32_MC19_MISC: u32 = 0x44f;
        const IA32_MC20_CTL: u32 = 0x450;

        const IA32_MC20_STATUS: u32 = 0x451;
        const IA32_MC20_ADDR: u32 = 0x452;
        const IA32_MC20_MISC: u32 = 0x453;
        const IA32_MC21_CTL: u32 = 0x454;
        const IA32_MC21_STATUS: u32 = 0x455;
        const IA32_MC21_ADDR: u32 = 0x456;
        const IA32_MC21_MISC: u32 = 0x457;
        const IA32_MC22_CTL: u32 = 0x458;
        const IA32_MC22_STATUS: u32 = 0x459;
        const IA32_MC22_ADDR: u32 = 0x45a;
        const IA32_MC22_MISC: u32 = 0x45b;
        const IA32_MC23_CTL: u32 = 0x45c;
        const IA32_MC23_STATUS: u32 = 0x45d;
        const IA32_MC23_ADDR: u32 = 0x45e;
        const IA32_MC23_MISC: u32 = 0x45f;
        const IA32_MC24_CTL: u32 = 0x460;
        const IA32_MC24_STATUS: u32 = 0x461;
        const IA32_MC24_ADDR: u32 = 0x462;

        const IA32_MC24_MISC: u32 = 0x463;
        const IA32_MC25_CTL: u32 = 0x464;
        const IA32_MC25_STATUS: u32 = 0x465;
        const IA32_MC25_ADDR: u32 = 0x466;
        const IA32_MC25_MISC: u32 = 0x467;
        const IA32_MC26_CTL: u32 = 0x468;
        const IA32_MC26_STATUS: u32 = 0x469;
        const IA32_MC26_ADDR: u32 = 0x46a;
        const IA32_MC26_MISC: u32 = 0x46b;
        const IA32_MC27_CTL: u32 = 0x46c;
        const IA32_MC27_STATUS: u32 = 0x46d;
        const IA32_MC27_ADDR: u32 = 0x46e;
        const IA32_MC27_MISC: u32 = 0x46f;
        const IA32_MC28_CTL: u32 = 0x470;
        const IA32_MC28_STATUS: u32 = 0x471;
        const IA32_MC28_ADDR: u32 = 0x472;
        const IA32_MC28_MISC: u32 = 0x473;
        const IA32_MC29_CTL: u32 = 0x474;
        const IA32_MC29_STATUS: u32 = 0x475;

        const IA32_MC29_ADDR: u32 = 0x476;
        const IA32_MC29_MISC: u32 = 0x477;
        const IA32_MC30_CTL: u32 = 0x478;
        const IA32_MC30_STATUS: u32 = 0x479;
        const IA32_MC30_ADDR: u32 = 0x47a;
        const IA32_MC30_MISC: u32 = 0x47b;
        const IA32_MC31_CTL: u32 = 0x47c;
        const IA32_MC31_STATUS: u32 = 0x47d;
        const IA32_MC31_ADDR: u32 = 0x47e;
        const IA32_MC31_MISC: u32 = 0x47f;

        const IA32_U_CET: u32 = 0x6a0;
        const IA32_S_CET: u32 = 0x6a2;

        const IA32_TSC_DEADLINE: u32 = 0x6e0;
        const _IA32_TSC_DEADLINE_CPUID_CHECK: () =
            assert_not_denied_cpuid_feature::<24>(&Parameters {
                leaf: 0x1,
                sub_leaf: 0..=0,
                register: CpuidReg::ECX,
            });

        // NOTE: THE X2APIC related MSRs cannot be filtered by KVM, but we include them here anyway for completeness sake.
        const IA32_X2APIC_TPR: u32 = 0x808;
        const IA32_X2APIC_SIVR: u32 = 0x80f;

        const IA32_X2APIC_ESR: u32 = 0x828;
        const IA32_X2APIC_LVT_CMCI: u32 = 0x82f;
        const IA32_X2APIC_ICR: u32 = 0x830;
        const IA32_X2APIC_LVT_TIMER: u32 = 0x832;
        const IA32_X2APIC_LVT_THERMAL: u32 = 0x833;
        const IA32_X2APIC_LVT_PMI: u32 = 0x834;
        const IA32_X2APIC_LVT_LINT0: u32 = 0x835;

        const IA32_X2APIC_LVT_LINT1: u32 = 0x836;
        const IA32_X2APIC_LVT_ERROR: u32 = 0x837;
        const IA32_X2APIC_INIT_COUNT: u32 = 0x838;
        const IA32_X2APIC_DIV_CONF: u32 = 0x83e;

        const IA32_XSS: u32 = 0xda0;
        const _IA32_XSS_CPUID_CHECK: () = assert_not_denied_cpuid_feature::<3>(&Parameters {
            leaf: 0xd,
            sub_leaf: 1..=1,
            register: CpuidReg::EAX,
        });

        /// Extended Feature Enable
        const IA32_EFER: u32 = 0xc0000080;

        const IA32_STAR: u32 = 0xc000_0081;
        const IA32_LSTAR: u32 = 0xc000_0082;
        const IA32_CSTAR: u32 = 0xc000_0083;
        const IA32_FMASK: u32 = 0xc000_0084;
        const IA32_FS_BASE: u32 = 0xc000_0100;
        const IA32_GS_BASE: u32 = 0xc000_0101;
        const IA32_KERNEL_GS_BASE: u32 = 0xc000_0102;
        const _IA32_EFER_UPTO_IA32_KERNEL_GS_BASE_CPUID_CHECK: () =
            assert_not_denied_cpuid_feature::<29>(&Parameters {
                leaf: 0x80000001,
                sub_leaf: 0..=0,
                register: CpuidReg::EDX,
            });

        const IA32_TSC_AUX: u32 = 0xc000_0103;
        // NOTE That either the following has to pass, or the same test with 0x80000001.EDX[27]
        const _IA32_TSC_AUX_CPUID_CHECK: () = assert_not_denied_cpuid_feature::<22>(&Parameters {
            leaf: 0x7,
            sub_leaf: 0..=0,
            register: CpuidReg::ECX,
        });

        pub(super) const READ_WRITE_IA32_MSRS: [u32; 202] = [
            IA32_TIME_STAMP_COUNTER,
            IA32_APIC_BASE,
            IA32_FEATURE_CONTROL,
            IA32_TSC_ADJUST,
            IA32_SPEC_CTRL,
            IA32_MCU_OPT_CTRL,
            IA32_SYSENTER_CS,
            IA32_SYSENTER_ESP,
            IA32_SYSENTER_EIP,
            IA32_MCG_STATUS,
            IA32_SMM_MONITOR_CTL,
            IA32_MISC_ENABLE,
            IA32_XFD,
            IA32_XFD_ERR,
            IA32_DCA_0_CAP,
            IA32_MTRR_PHYSBASE0,
            IA32_MTRR_PHYSMASK0,
            IA32_MTRR_PHYSBASE1,
            IA32_MTRR_PHYSMASK1,
            IA32_MTRR_PHYSBASE2,
            IA32_MTRR_PHYSMASK2,
            IA32_MTRR_PHYSBASE3,
            IA32_MTRR_PHYSMASK3,
            IA32_MTRR_PHYSBASE4,
            IA32_MTRR_PHYSMASK4,
            IA32_MTRR_PHYSBASE5,
            IA32_MTRR_PHYSMASK5,
            IA32_MTRR_PHYSBASE6,
            IA32_MTRR_PHYSMASK6,
            IA32_MTRR_PHYSBASE7,
            IA32_MTRR_PHYSMASK7,
            IA32_MTRR_PHYSBASE8,
            IA32_MTRR_PHYSMASK8,
            IA32_MTRR_PHYSBASE9,
            IA32_MTRR_PHYSMASK9,
            IA32_MTRR_FIX64K_00000,
            IA32_MTRR_FIX16K_80000,
            IA32_MTRR_FIX16K_A0000,
            IA32_MTRR_FIX4K_C0000,
            IA32_MTRR_FIX4K_C8000,
            IA32_MTRR_FIX4K_D0000,
            IA32_MTRR_FIX4K_D8000,
            IA32_MTRR_FIX4K_E0000,
            IA32_MTRR_FIX4K_E8000,
            IA32_MTRR_FIX4K_F0000,
            IA32_MTRR_FIX4K_F8000,
            IA32_PAT,
            IA32_MTRR_DEF_TYPE,
            IA32_MC0_CTL,
            IA32_MC0_STATUS,
            IA32_MC0_ADDR,
            IA32_MC0_MISC,
            IA32_MC1_CTL,
            IA32_MC1_STATUS,
            IA32_MC1_ADDR,
            IA32_MC1_MISC,
            IA32_MC2_CTL,
            IA32_MC2_STATUS,
            IA32_MC2_ADDR,
            IA32_MC2_MISC,
            IA32_MC3_CTL,
            IA32_MC3_STATUS,
            IA32_MC3_ADDR1,
            IA32_MC3_MISC,
            IA32_MC4_CTL,
            IA32_MC4_STATUS,
            IA32_MC4_ADDR,
            IA32_MC4_MISC,
            IA32_MC5_CTL,
            IA32_MC5_STATUS,
            IA32_MC5_ADDR,
            IA32_MC5_MISC,
            IA32_MC6_CTL,
            IA32_MC6_STATUS,
            IA32_MC6_ADDR1,
            IA32_MC6_MISC,
            IA32_MC7_CTL,
            IA32_MC7_STATUS,
            IA32_MC7_ADDR,
            IA32_MC7_MISC,
            IA32_MC8_CTL,
            IA32_MC8_STATUS,
            IA32_MC8_ADDR,
            IA32_MC8_MISC,
            IA32_MC9_CTL,
            IA32_MC9_STATUS,
            IA32_MC9_ADDR,
            IA32_MC9_MISC,
            IA32_MC10_CTL,
            IA32_MC10_STATUS,
            IA32_MC10_ADDR,
            IA32_MC10_MISC,
            IA32_MC11_CTL,
            IA32_MC11_STATUS,
            IA32_MC11_ADDR,
            IA32_MC11_MISC,
            IA32_MC12_CTL,
            IA32_MC12_STATUS,
            IA32_MC12_ADDR,
            IA32_MC12_MISC,
            IA32_MC13_CTL,
            IA32_MC13_STATUS,
            IA32_MC13_ADDR,
            IA32_MC13_MISC,
            IA32_MC14_CTL,
            IA32_MC14_STATUS,
            IA32_MC14_ADDR,
            IA32_MC14_MISC,
            IA32_MC15_CTL,
            IA32_MC15_STATUS,
            IA32_MC15_ADDR,
            IA32_MC15_MISC,
            IA32_MC16_CTL,
            IA32_MC16_STATUS,
            IA32_MC16_ADDR,
            IA32_MC16_MISC,
            IA32_MC17_CTL,
            IA32_MC17_STATUS,
            IA32_MC17_ADDR,
            IA32_MC17_MISC,
            IA32_MC18_CTL,
            IA32_MC18_STATUS,
            IA32_MC18_ADDR,
            IA32_MC18_MISC,
            IA32_MC19_CTL,
            IA32_MC19_STATUS,
            IA32_MC19_ADDR,
            IA32_MC19_MISC,
            IA32_MC20_CTL,
            IA32_MC20_STATUS,
            IA32_MC20_ADDR,
            IA32_MC20_MISC,
            IA32_MC21_CTL,
            IA32_MC21_STATUS,
            IA32_MC21_ADDR,
            IA32_MC21_MISC,
            IA32_MC22_CTL,
            IA32_MC22_STATUS,
            IA32_MC22_ADDR,
            IA32_MC22_MISC,
            IA32_MC23_CTL,
            IA32_MC23_STATUS,
            IA32_MC23_ADDR,
            IA32_MC23_MISC,
            IA32_MC24_CTL,
            IA32_MC24_STATUS,
            IA32_MC24_ADDR,
            IA32_MC24_MISC,
            IA32_MC25_CTL,
            IA32_MC25_STATUS,
            IA32_MC25_ADDR,
            IA32_MC25_MISC,
            IA32_MC26_CTL,
            IA32_MC26_STATUS,
            IA32_MC26_ADDR,
            IA32_MC26_MISC,
            IA32_MC27_CTL,
            IA32_MC27_STATUS,
            IA32_MC27_ADDR,
            IA32_MC27_MISC,
            IA32_MC28_CTL,
            IA32_MC28_STATUS,
            IA32_MC28_ADDR,
            IA32_MC28_MISC,
            IA32_MC29_CTL,
            IA32_MC29_STATUS,
            IA32_MC29_ADDR,
            IA32_MC29_MISC,
            IA32_MC30_CTL,
            IA32_MC30_STATUS,
            IA32_MC30_ADDR,
            IA32_MC30_MISC,
            IA32_MC31_CTL,
            IA32_MC31_STATUS,
            IA32_MC31_ADDR,
            IA32_MC31_MISC,
            IA32_U_CET,
            IA32_S_CET,
            IA32_TSC_DEADLINE,
            IA32_X2APIC_TPR,
            IA32_X2APIC_SIVR,
            IA32_X2APIC_ESR,
            IA32_X2APIC_LVT_CMCI,
            IA32_X2APIC_ICR,
            IA32_X2APIC_LVT_TIMER,
            IA32_X2APIC_LVT_THERMAL,
            IA32_X2APIC_LVT_PMI,
            IA32_X2APIC_LVT_LINT0,
            IA32_X2APIC_LVT_LINT1,
            IA32_X2APIC_LVT_ERROR,
            IA32_X2APIC_INIT_COUNT,
            IA32_X2APIC_DIV_CONF,
            IA32_XSS,
            IA32_EFER,
            IA32_STAR,
            IA32_LSTAR,
            IA32_CSTAR,
            IA32_FMASK,
            IA32_FS_BASE,
            IA32_GS_BASE,
            IA32_KERNEL_GS_BASE,
            IA32_TSC_AUX,
        ];
    }

    mod write_only {
        use super::{CpuidReg, Parameters, assert_not_denied_cpuid_feature};

        /// Prediction Command (WO)
        const IA32_PRED_CMD: u32 = 0x49;
        const _IA32_PRED_CMD_CPUID_CHECK: () = assert_not_denied_cpuid_feature::<26>(&Parameters {
            leaf: 0x7,
            sub_leaf: 0..=0,
            register: CpuidReg::EDX,
        });

        /// Flush Command (WO)
        const IA32_FLUSH_CMD: u32 = 0x10b;

        // TODO: Should probably use inherit policy here
        const _IA32_FLUSH_CMD_CPUID_CHECK: () =
            assert_not_denied_cpuid_feature::<28>(&Parameters {
                leaf: 0x7,
                sub_leaf: 0..=0,
                register: CpuidReg::EDX,
            });

        // X2apic related MSRS cannot be filtered by KVM, but we include it here anyway for completeness sake
        const IA32_X2APIC_EOI: u32 = 0x80b;

        const IA32_X2APIC_SELF_IPI: u32 = 0x83f;

        pub(super) const WRITE_ONLY_IA32_MSRS: [u32; 4] = [
            IA32_PRED_CMD,
            IA32_FLUSH_CMD,
            IA32_X2APIC_EOI,
            IA32_X2APIC_SELF_IPI,
        ];
    }

    /// A list of permitted Intel IA32 MSRs that are not considered MSR-based feature indices
    /// by KVM.
    ///
    /// The MSRs listed here can be studied further in Table 2.2 in Section 2.1 of the Intel SDM
    /// Vol. 4 from October 2025
    pub(in crate::x86_64) const PERMITTED_IA32_MSRS: [u32; 245] = const {
        let mut permitted = [0u32; 245];
        let read_only_len = READ_ONLY_IA32_MSRS.len();
        let write_only_len = WRITE_ONLY_IA32_MSRS.len();
        let read_write_len = READ_WRITE_IA32_MSRS.len();
        assert!(permitted.len() == (read_only_len + write_only_len + read_write_len));
        let mut idx = 0;
        // Insert read only msrs
        {
            let mut i = 0;
            while i < read_only_len {
                permitted[idx + i] = READ_ONLY_IA32_MSRS[i];
                i += 1;
            }
            idx += read_only_len;
        }
        // Insert write only msrs
        {
            let mut i = 0;
            while i < write_only_len {
                permitted[idx + i] = WRITE_ONLY_IA32_MSRS[i];
                i += 1;
            }
            idx += write_only_len;
        }
        // Insert read & write msrs
        {
            let mut i = 0;
            while i < read_write_len {
                permitted[idx + i] = READ_WRITE_IA32_MSRS[i];
                i += 1;
            }
        }
        permitted
    };
}

mod forbidden_architectural_msrs {
    const IA32_P5_MC_ADDR: (u32, u32) = (0x0, 0x0);
    const IA32_P5_MC_TYPE: (u32, u32) = (0x1, 0x1);

    const IA32_MONITOR_FILTER_SIZE: (u32, u32) = (0x6, 0x6);
    // TODO: Not sure about this one
    const IA32_PLATFORM_ID: (u32, u32) = (0x17, 0x17);

    /// Only available is CPUID 0x7.0x1.EBX[0] = 1, but this is always 0 for non-host CPU profiles
    const IA32_PPIN_CTL: (u32, u32) = (0x4e, 0x4e);

    /// Only available is CPUID 0x7.0x1.EBX[0] = 1, but this is always 0 for non-host CPU profiles
    const IA32_PPIN: (u32, u32) = (0x4f, 0x4f);

    /// Used for microcode updates. Should not be available for guests.
    const IA32_BIOS_UPDT_TRIG: (u32, u32) = (0x79, 0x79);

    /// Currently only related to Secure enclaves/Keylocker which is not available for non-host CPU profiles
    const IA32_FEATURE_ACTIVATION: (u32, u32) = (0x7a, 0x7a);

    /// Related to microcode updates
    const IA32_MCU_ENUMERATION: (u32, u32) = (0x7b, 0x7b);

    const IA32_MCU_STATUS: (u32, u32) = (0x7c, 0x7c);

    // TODO: Not sure what this does and whether it should be enabled
    const IA32_FZM_RANGE_INDEX: (u32, u32) = (0x82, 0x82);

    /// Related to total memory encryption
    ///
    const IA32_MKTME_KEYID_PARTITIONING: (u32, u32) = (0x87, 0x87);

    const IA32_SGXLEPUBKEYHASH0: (u32, u32) = (0x8c, 0x8c);

    const IA32_SGXLEPUBKEYHASH1: (u32, u32) = (0x8d, 0x8d);

    const IA32_SGXLEPUBKEYHASH2: (u32, u32) = (0x8e, 0x8e);

    const IA32_SGXLEPUBKEYHASH3: (u32, u32) = (0x8f, 0x8f);

    const IA32_SGXLEPUBKEYHASH4: (u32, u32) = (0x90, 0x90);

    const IA32_SGXLEPUBKEYHASH5: (u32, u32) = (0x91, 0x91);

    // TODO: Check this
    const IA32_SMBASE: (u32, u32) = (0x9e, 0x9e);

    const IA32_MISC_PACKAGE_CTLS: (u32, u32) = (0xbc, 0xbc);

    /// xAPIC Disable Status
    // TODO: Also check consistency with IA32_ARCH_CAPABILITIES[21]
    const IA32_XAPIC_DISABLE_STATUS: (u32, u32) = (0xbd, 0xbd);

    const IA32_SMRR_PHYS_BASE_MASK: (u32, u32) = (0x1f2, 0x1f3);

    /// Overclocking Status (R/O)
    // TODO: Also check consistency with IA32_ARCH_CAPABILITIES[23]
    const IA32_OVERCLOCKING_STATUS: (u32, u32) = (0x195, 0x195);

    /// Clock Modulation Control
    /// This is disabled via CPUID for non-host CPU profiles
    const IA32_CLOCK_MODULATION: (u32, u32) = (0x19a, 0x19a);

    // IA32_PLI_SSP is disabled via CPUID for non-host profiles
    const IA32_PLI_SSP: (u32, u32) = (0x6a4, 0x6a7);

    // This is disabled via CPUID for non-host profiles
    const IA32_INTERRUPT_SSP_TABLE_ADDR: (u32, u32) = (0x6a8, 0x6a8);

    const IA32_PECI_HWP_REQUEST_INFO: (u32, u32) = (0x775, 0x775);
    const IA32_PMC0: (u32, u32) = (0xc1, 0xc1);
    const IA32_PMC1: (u32, u32) = (0xc2, 0xc2);
    const IA32_PMC2: (u32, u32) = (0xc3, 0xc3);
    const IA32_PMC3: (u32, u32) = (0xc4, 0xc4);
    const IA32_PMC4: (u32, u32) = (0xc5, 0xc5);
    const IA32_PMC5: (u32, u32) = (0xc6, 0xc6);
    const IA32_PMC6: (u32, u32) = (0xc7, 0xc7);
    const IA32_PMC7: (u32, u32) = (0xc8, 0xc8);
    const IA32_PMC8: (u32, u32) = (0xc9, 0xc9);
    const IA32_PMC9: (u32, u32) = (0xca, 0xca);

    const IA32_CORE_CAPABILITIES: (u32, u32) = (0xcf, 0xcf);

    // TODO: Do we really want to forbid this MSR?
    const IA32_UMWAIT_CONTROL: (u32, u32) = (0xe1, 0xe1);

    // Disabled by CPUID for non-host CPU profiles
    const IA32_MPERF: (u32, u32) = (0xe7, 0xe7);

    const IA32_APERF: (u32, u32) = (0xe8, 0xe8);

    const IA32_TSX_FORCE_ABORT: (u32, u32) = (0x10f, 0x10f);

    // Disabled via static IA32_ARCH_CAPABILITIES bit for non-host CPU profiles
    const IA32_TSX_CTRL: (u32, u32) = (0x122, 0x122);

    // NOTE: IA32_MCU_OPT_CTRL must necessarily be available, due to
    // what we set in CPUID for some CPU profiles (inherit policy)

    const IA32_MCG_CTL: (u32, u32) = (0x17b, 0x17b);

    // TODO: 0x180- 0x185 is reserved, we should not list these MSRS at all

    /// Disabled via CPUID for all non-host CPU profiles
    const IA32_PERFEVTSEL0: (u32, u32) = (0x186, 0x186);
    const IA32_PERFEVTSEL1: (u32, u32) = (0x187, 0x187);
    const IA32_PERFEVTSEL2: (u32, u32) = (0x188, 0x188);
    const IA32_PERFEVTSEL3: (u32, u32) = (0x189, 0x189);
    const IA32_PERFEVTSEL4: (u32, u32) = (0x18a, 0x18a);
    const IA32_PERFEVTSEL5: (u32, u32) = (0x18b, 0x18b);
    const IA32_PERFEVTSEL6: (u32, u32) = (0x18c, 0x18c);
    const IA32_PERFEVTSEL7: (u32, u32) = (0x18d, 0x18d);
    const IA32_PERFEVTSEL8: (u32, u32) = (0x18e, 0x18e);
    const IA32_PERFEVTSEL9: (u32, u32) = (0x18f, 0x18f);

    // TODO: 0x18a - 0x194 is reserved and should not be included in any list

    // TODO: 0x196, 197 is reserved and should not be included in any list
    //

    const IA32_PERF_STATUS: (u32, u32) = (0x198, 0x198);

    const IA32_PERF_CTL: (u32, u32) = (0x199, 0x199);

    // Disabled via CPUID for non-host profiles
    const IA32_THERM_INTERRUPT: (u32, u32) = (0x19b, 0x19b);

    // Disabled via CPUID for non-host profiles
    const IA32_THERM_STATUS: (u32, u32) = (0x19c, 0x19c);

    // Disabled via CPUID for non-host profiles
    const IA32_ENERGY_PERF_BIAS: (u32, u32) = (0x1b0, 0x1b0);

    // Disabled via CPUID for non-host profiles
    const IA32_PACKAGE_THERM_STATUS: (u32, u32) = (0x1b1, 0x1b1);

    // Disabled via CPUID for non-host profiles
    const IA32_PACKAGE_THERM_INTERRUPT: (u32, u32) = (0x1b2, 0x1b2);

    const IA32_DEBUGCTL: (u32, u32) = (0x1d9, 0x1d9);

    const IA32_LER_FROM_IP: (u32, u32) = (0x1dd, 0x1dd);

    const IA32_LER_TO_IP: (u32, u32) = (0x1de, 0x1de);

    const IA32_LER_INFO: (u32, u32) = (0x1e0, 0x1e0);

    const IA32_MC_I_CTL2: (u32, u32) = (0x280, 0x29f);

    // Disabled via CPUID for non-host profiles
    const IA32_INTEGRITY_STATUS: (u32, u32) = (0x2dc, 0x2dc);

    const IA32_FIXED_CTRI: (u32, u32) = (0x309, 0x30f);

    // IA32_PERF_CAPABILITIES is an MSR-based feature thus not listed here

    // Disabled via CPUID for non-host profiles
    const IA32_FIXED_CTR_CTRL: (u32, u32) = (0x38d, 0x38d);

    // Disabled via CPUID for non-host profiles
    const IA32_PERF_GLOBAL_STATUS: (u32, u32) = (0x38e, 0x38e);

    // Disabled via CPUID for non-host profiles
    const IA32_PERF_GLOBAL_CTRL: (u32, u32) = (0x38f, 0x38f);

    // Disabled via CPUID for non-host profiles
    const IA32_PERF_GLOBAL_STATUS_RESET: (u32, u32) = (0x390, 0x390);

    // Disabled via CPUID for non-host profiles
    const IA32_PERF_GLOBAL_STATUS_SET: (u32, u32) = (0x391, 0x391);

    // Disabled via CPUID for non-host profiles
    const IA32_PERF_GLOBAL_INUSE: (u32, u32) = (0x392, 0x392);

    // TODO: Not sure about this one, but seems to be related to performance monitoring which
    // should be disabled for non-host CPU profiles.
    const IA32_PEBS_ENABLE: (u32, u32) = (0x3f1, 0x3f1);

    const IA32_A_PMC0: (u32, u32) = (0x4c1, 0x4c1);
    const IA32_A_PMC1: (u32, u32) = (0x4c2, 0x4c2);
    const IA32_A_PMC2: (u32, u32) = (0x4c3, 0x4c3);
    const IA32_A_PMC3: (u32, u32) = (0x4c4, 0x4c4);
    const IA32_A_PMC4: (u32, u32) = (0x4c5, 0x4c5);
    const IA32_A_PMC5: (u32, u32) = (0x4c6, 0x4c6);
    const IA32_A_PMC6: (u32, u32) = (0x4c7, 0x4c7);
    const IA32_A_PMC7: (u32, u32) = (0x4c8, 0x4c8);
    const IA32_A_PMC8: (u32, u32) = (0x4c9, 0x4c9);
    const IA32_A_PMC9: (u32, u32) = (0x4ca, 0x4ca);

    const IA32_MCG_EXT_CTL: (u32, u32) = (0x4d0, 0x4d0);

    // SGX is disabled via CPUID for non-host CPU profiles
    const IA32_SGX_SVN_STATUS: (u32, u32) = (0x500, 0x500);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_RTIT_OUTPUT_BASE: (u32, u32) = (0x560, 0x560);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_RTIT_OUTPUT_MASK_PTRS: (u32, u32) = (0x561, 0x561);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_RTIT_CTL: (u32, u32) = (0x570, 0x570);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_RTIT_STATUS: (u32, u32) = (0x571, 0x571);

    // Disabled via CPU profiles
    const IA32_RTIT_CR3_MATCH: (u32, u32) = (0x572, 0x572);

    const IA32_RTIT_ADDR0_A: (u32, u32) = (0x580, 0x580);
    const IA32_RTIT_ADDR0_B: (u32, u32) = (0x581, 0x581);
    const IA32_RTIT_ADDR1_A: (u32, u32) = (0x582, 0x582);
    const IA32_RTIT_ADDR1_B: (u32, u32) = (0x583, 0x583);
    const IA32_RTIT_ADDR2_A: (u32, u32) = (0x584, 0x584);
    const IA32_RTIT_ADDR2_B: (u32, u32) = (0x585, 0x585);
    const IA32_RTIT_ADDR3_A: (u32, u32) = (0x586, 0x586);
    const IA32_RTIT_ADDR3_B: (u32, u32) = (0x587, 0x587);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_DS_AREA: (u32, u32) = (0x600, 0x600);

    // TODO: IA32_TSC_DEADLINE should be available because the TSC_DEADLINE CPUID bit
    // is set by CHV unconditionally. The availability of this MSR probably needs to be
    // handled by CHV itself and not the CPU profiles

    // Disabled via CPUID for non-host CPU profiles
    const IA32_PKRS: (u32, u32) = (0x6e1, 0x6e1);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_PM_ENABLE: (u32, u32) = (0x770, 0x770);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_HWP_CAPABILITIES: (u32, u32) = (0x771, 0x771);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_HWP_REQUEST_PKG: (u32, u32) = (0x772, 0x772);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_HWP_INTERRUPT: (u32, u32) = (0x773, 0x773);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_HWP_REQUEST: (u32, u32) = (0x774, 0x774);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_HWP_CTL: (u32, u32) = (0x776, 0x776);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_HWP_STATUS: (u32, u32) = (0x777, 0x777);

    const IA32_MCU_EXT_SERVICE: (u32, u32) = (0x7a3, 0x7a3);

    const IA32_MCU_ROLLBACK_MIN_ID: (u32, u32) = (0x7a4, 0x7a4);

    // TODO: Not sure about IA32_MCU_STAGING_MBOX_ADDR

    const IA32_ROLLBACK_SIGN_ID_0: (u32, u32) = (0x7b0, 0x7b0);
    const IA32_ROLLBACK_SIGN_ID_1: (u32, u32) = (0x7b1, 0x7b1);
    const IA32_ROLLBACK_SIGN_ID_2: (u32, u32) = (0x7b2, 0x7b2);
    const IA32_ROLLBACK_SIGN_ID_3: (u32, u32) = (0x7b3, 0x7b3);
    const IA32_ROLLBACK_SIGN_ID_4: (u32, u32) = (0x7b4, 0x7b4);
    const IA32_ROLLBACK_SIGN_ID_5: (u32, u32) = (0x7b5, 0x7b5);
    const IA32_ROLLBACK_SIGN_ID_6: (u32, u32) = (0x7b6, 0x7b6);
    const IA32_ROLLBACK_SIGN_ID_7: (u32, u32) = (0x7b7, 0x7b7);
    const IA32_ROLLBACK_SIGN_ID_8: (u32, u32) = (0x7b8, 0x7b8);
    const IA32_ROLLBACK_SIGN_ID_9: (u32, u32) = (0x7b9, 0x7b9);
    const IA32_ROLLBACK_SIGN_ID_10: (u32, u32) = (0x7ba, 0x7ba);
    const IA32_ROLLBACK_SIGN_ID_11: (u32, u32) = (0x7bb, 0x7bb);
    const IA32_ROLLBACK_SIGN_ID_12: (u32, u32) = (0x7bc, 0x7bc);
    const IA32_ROLLBACK_SIGN_ID_13: (u32, u32) = (0x7bd, 0x7bd);
    const IA32_ROLLBACK_SIGN_ID_14: (u32, u32) = (0x7be, 0x7be);
    const IA32_ROLLBACK_SIGN_ID_15: (u32, u32) = (0x7bf, 0x7bf);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_TME_CAPABILITY: (u32, u32) = (0x981, 0x981);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_TME_ACTIVATE: (u32, u32) = (0x982, 0x982);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_TME_EXCLUDE_MASK: (u32, u32) = (0x983, 0x983);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_TME_EXCLUDE_BASE: (u32, u32) = (0x984, 0x984);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_UINTR_RR: (u32, u32) = (0x985, 0x985);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_UINTR_HANDLER: (u32, u32) = (0x986, 0x986);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_UINTR_STACKADJUST: (u32, u32) = (0x987, 0x987);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_UINTR_MISC: (u32, u32) = (0x988, 0x988);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_UINTR_PD: (u32, u32) = (0x989, 0x989);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_UINTR_TT: (u32, u32) = (0x98a, 0x98a);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_COPY_STATUS: (u32, u32) = (0x990, 0x990);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_IWKEYBACKUP_STATUS: (u32, u32) = (0x991, 0x991);

    const IA32_TME_CLEAR_SAVED_KEY: (u32, u32) = (0x9fb, 0x9fb);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_DEBUG_INTERFACE: (u32, u32) = (0xc80, 0xc80);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_L3_QOS_CFG: (u32, u32) = (0xc81, 0xc81);

    // Disabled via CPUID
    const IA32_L2_QOS_CFG: (u32, u32) = (0xc82, 0xc82);

    // Disabled via CPUID
    const IA32_L3_IO_QOS_CFG: (u32, u32) = (0xc83, 0xc83);

    const IA32_RESOURCE_PRIORITY: (u32, u32) = (0xc88, 0xc88);
    const IA32_RESOURCE_PRIORITY_PKG: (u32, u32) = (0xc89, 0xc89);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_QM_EVTSEL: (u32, u32) = (0xc8d, 0xc8d);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_QM_CTR: (u32, u32) = (0xc8e, 0xc8e);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_PQR_ASSOC: (u32, u32) = (0xc8f, 0xc8f);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_L3_MASK_0: (u32, u32) = (0xc90, 0xc90);

    const IA32_L3_MASK_N: (u32, u32) = (0xc91, 0xd8f);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_L2_MASK_0: (u32, u32) = (0xd10, 0xd10);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_L2_MASK_N: (u32, u32) = (0xd11, 0xd4f);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_L2_QOS_EXT_BW_THRTL_I: (u32, u32) = (0xd50, 0xd5e);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_BNDCFGS: (u32, u32) = (0xd90, 0xd90);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_COPY_LOCAL_TO_PLATFORM: (u32, u32) = (0xd91, 0xd91);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_COPY_PLATFORM_TO_LOCAL: (u32, u32) = (0xd92, 0xd92);

    const IA32_PASID: (u32, u32) = (0xd93, 0xd93);
    // Disabled via CPUID for non-host CPU profiles
    const IA32_PKG_HDC_CTL: (u32, u32) = (0xdb0, 0xdb0);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_PM_CTL1: (u32, u32) = (0xdb1, 0xdb1);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_THREAD_STALL: (u32, u32) = (0xdb2, 0xdb2);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_QOS_CORE_BW_THRTL_0: (u32, u32) = (0xe00, 0xe00);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_QOS_CORE_BW_THRTL_1: (u32, u32) = (0xe01, 0xe01);

    // Note that we have CPUID 0x7.EDX.[19] = 0 (ARCH_LBR)
    const IA32_LBR_X_INFO: (u32, u32) = (0x1200, 0x121f);

    // TDX related.
    const IA32_SEAMRR_BASE: (u32, u32) = (0x1400, 0x1400);

    // TDX related.
    const IA32_SEAMRR_MASK: (u32, u32) = (0x1401, 0x1401);

    // Disabled via ARCH_CAPABILITIES for non-host CPU profiles
    // TODO: Check that deny policy is compatible with
    // the policy for IA32_ARCH_COMPATIBILITY[9]
    const IA32_MCU_CONTROL: (u32, u32) = (0x1406, 1406);

    const IA32_LBR_CTL: (u32, u32) = (0x14ce, 0x14ce);

    const IA32_LBR_DEPTH: (u32, u32) = (0x14cf, 0x14cf);

    const IA32_LBR_X_FROM_IP: (u32, u32) = (0x1500, 0x151f);

    const IA32_LBR_X_TO_IP: (u32, u32) = (0x1600, 0x161f);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_HW_FEEDBACK_PTR: (u32, u32) = (0x17d0, 0x17d0);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_HW_FEEDBACK_CONFIG: (u32, u32) = (0x17d1, 0x17d1);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_HW_FEEDBACK_THREAD_CHAR: (u32, u32) = (0x17d2, 0x17d2);

    const IA32_HW_FEEDBACK_THREAD_CONFIG: (u32, u32) = (0x17d4, 0x17d4);

    const IA32_HRESET_ENABLE: (u32, u32) = (0x17da, 0x17da);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP0_CTR: (u32, u32) = (0x1900, 0x1900);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP0_CFG_A: (u32, u32) = (0x1901, 0x1901);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP0_CFG_C: (u32, u32) = (0x1903, 0x1903);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP1_CTR: (u32, u32) = (0x1904, 0x1904);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP1_CFG_A: (u32, u32) = (0x1905, 0x1905);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP1_CFG_C: (u32, u32) = (0x1907, 0x1907);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP2_CTR: (u32, u32) = (0x1908, 0x1908);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP2_CFG_A: (u32, u32) = (0x1909, 0x1909);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP2_CFG_B: (u32, u32) = (0x190a, 0x190a);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP2_CFG_C: (u32, u32) = (0x190b, 0x190b);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP3_CTR: (u32, u32) = (0x190c, 0x190c);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP3_CFG_A: (u32, u32) = (0x190d, 0x190d);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP3_CFG_B: (u32, u32) = (0x190e, 0x190e);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP3_CFG_C: (u32, u32) = (0x190f, 0x190f);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP4_CTR: (u32, u32) = (0x1910, 0x1910);
    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP4_CFG_A: (u32, u32) = (0x1911, 0x1911);
    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP4_CFG_B: (u32, u32) = (0x1912, 0x1912);
    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP4_CFG_C: (u32, u32) = (0x1913, 0x1913);
    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP5_CTR: (u32, u32) = (0x1914, 0x1914);
    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP5_CFG_A: (u32, u32) = (0x1915, 0x1915);
    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP5_CFG_B: (u32, u32) = (0x1916, 0x1916);
    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP5_CFG_C: (u32, u32) = (0x1917, 0x1917);
    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP6_CTR: (u32, u32) = (0x1918, 0x1918);
    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP6_CFG_A: (u32, u32) = (0x1919, 0x1919);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP6_CFG_B: (u32, u32) = (0x191a, 0x191a);
    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP6_CFG_C: (u32, u32) = (0x191b, 0x191b);
    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP7_CTR: (u32, u32) = (0x191c, 0x191c);
    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP7_CFG_A: (u32, u32) = (0x191d, 0x191d);
    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP7_CFG_B: (u32, u32) = (0x191e, 0x191e);
    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP7_CFG_C: (u32, u32) = (0x191f, 0x191f);
    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP8_CTR: (u32, u32) = (0x1920, 0x1920);
    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP8_CFG_A: (u32, u32) = (0x1921, 0x1921);
    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP9_CTR: (u32, u32) = (0x1924, 0x1924);
    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_GP9_CFG_A: (u32, u32) = (0x1925, 0x1925);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_FX0_CTR: (u32, u32) = (0x1980, 0x1980);

    const IA32_PMC_FX0_CFG_B: (u32, u32) = (0x1982, 0x1982);
    const IA32_PMC_FX0_CFG_C: (u32, u32) = (0x1983, 0x1983);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_FX1_CTR: (u32, u32) = (0x1984, 0x1984);
    const IA32_PMC_FX1_CFG_B: (u32, u32) = (0x1986, 0x1986);
    const IA32_PMC_FX1_CFG_C: (u32, u32) = (0x1987, 0x1987);
    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_FX2_CTR: (u32, u32) = (0x1988, 0x1988);

    const IA32_PMC_FX2_CFG_C: (u32, u32) = (0x198b, 0x198b);
    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_FX3_CTR: (u32, u32) = (0x198c, 0x198c);
    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_FX4_CTR: (u32, u32) = (0x1990, 0x1990);
    const IA32_PMC_FX4_CFG_C: (u32, u32) = (0x1993, 0x1993);
    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_FX5_CTR: (u32, u32) = (0x1994, 0x1994);
    const IA32_PMC_FX5_CFG_C: (u32, u32) = (0x1997, 0x1997);

    // Disabled via CPUID for non-host CPU profiles
    const IA32_PMC_FX6_CTR: (u32, u32) = (0x1998, 0x1998);
    const IA32_PMC_FX6_CFG_C: (u32, u32) = (0x199b, 0x199b);

    // TODO: Check against IA32_ARCH_CAPABILITIES[12]
    const IA32_UARCH_MISC_CTL: (u32, u32) = (0x1b01, 0x1b01);
    /// A list of ARCHITECTURAL MSR register addresses that are forbidden for all non-host CPU profiles and also not
    /// considered MSR-based FEATURE indices by KVM.
    pub(in crate::x86_64) const FORBIDDEN_IA32_MSR_RANGES: [(u32, u32); 226] = [
        IA32_P5_MC_ADDR,
        IA32_P5_MC_TYPE,
        // TODO: Not sure about IA32_P5_MC_ADDR & IA32_P5_MC_TYPE
        IA32_MONITOR_FILTER_SIZE,
        // TODO: Not sure about this one
        IA32_PLATFORM_ID,
        /// Only available is CPUID 0x7.0x1.EBX[0] = 1, but this is always 0 for non-host CPU profiles
        IA32_PPIN_CTL,
        /// Only available is CPUID 0x7.0x1.EBX[0] = 1, but this is always 0 for non-host CPU profiles
        IA32_PPIN,
        /// Used for microcode updates. Should not be available for guests.
        IA32_BIOS_UPDT_TRIG,
        /// Currently only related to Secure enclaves/Keylocker which is not available for non-host CPU profiles
        IA32_FEATURE_ACTIVATION,
        IA32_FZM_RANGE_INDEX,
        IA32_SMRR_PHYS_BASE_MASK,
        IA32_PECI_HWP_REQUEST_INFO,
        /// Related to microcode updates
        IA32_MCU_ENUMERATION,
        IA32_MCU_STATUS,
        /// Related to total memory encryption
        IA32_MKTME_KEYID_PARTITIONING,
        // TODO: Not sure what to do about IA32_BIOS_SIGN_ID (note that it is also a MSR-based feature according to KVM)
        IA32_SGXLEPUBKEYHASH0,
        IA32_SGXLEPUBKEYHASH1,
        IA32_SGXLEPUBKEYHASH2,
        IA32_SGXLEPUBKEYHASH3,
        IA32_SGXLEPUBKEYHASH4,
        IA32_SGXLEPUBKEYHASH5,
        // TODO: Check this
        IA32_SMBASE,
        IA32_MISC_PACKAGE_CTLS,
        IA32_XAPIC_DISABLE_STATUS,
        IA32_OVERCLOCKING_STATUS,
        IA32_PMC0,
        IA32_PMC1,
        IA32_PMC2,
        IA32_PMC3,
        IA32_PMC4,
        IA32_PMC5,
        IA32_PMC6,
        IA32_PMC7,
        IA32_PMC8,
        IA32_PMC9,
        IA32_CORE_CAPABILITIES,
        IA32_UMWAIT_CONTROL,
        IA32_CLOCK_MODULATION,
        IA32_PLI_SSP,
        IA32_INTERRUPT_SSP_TABLE_ADDR,
        // Disabled by CPUID for non-host CPU profiles
        IA32_MPERF,
        IA32_APERF,
        IA32_TSX_FORCE_ABORT,
        // Disabled via static IA32_ARCH_CAPABILITIES bit for non-host CPU profiles
        IA32_TSX_CTRL,
        // NOTE: IA32_MCU_OPT_CTRL must necessarily be available, due to
        // what we set in CPUID for some CPU profiles (inherit policy)

        // TODO: Don't know about IA32_SYSENTER_CS, IA32_SYSENTER_ESP,
        // IA32_SYSENTER_EIP
        //
        IA32_MCG_CTL,
        // TODO: 0x180- 0x185 is reserved, we should not list these MSRS at all
        /// Disabled via CPUID for all non-host CPU profiles
        IA32_PERFEVTSEL0,
        IA32_PERFEVTSEL1,
        IA32_PERFEVTSEL2,
        IA32_PERFEVTSEL3,
        IA32_PERFEVTSEL4,
        IA32_PERFEVTSEL5,
        IA32_PERFEVTSEL6,
        IA32_PERFEVTSEL7,
        IA32_PERFEVTSEL8,
        IA32_PERFEVTSEL9,
        // TODO: 0x18a - 0x194 is reserved and should not be included in any list

        // TODO: 0x196, 197 is reserved and should not be included in any list
        //
        IA32_PERF_STATUS,
        IA32_PERF_CTL,
        // Disabled via CPUID for non-host profiles
        IA32_THERM_INTERRUPT,
        // Disabled via CPUID for non-host profiles
        IA32_THERM_STATUS,
        // TODO: Consider disabling IA32_MISC_ENABLE

        // Disabled via CPUID for non-host profiles
        IA32_ENERGY_PERF_BIAS,
        // Disabled via CPUID for non-host profiles
        IA32_PACKAGE_THERM_STATUS,
        // Disabled via CPUID for non-host profiles
        IA32_PACKAGE_THERM_INTERRUPT,
        IA32_DEBUGCTL,
        IA32_LER_FROM_IP,
        IA32_LER_TO_IP,
        IA32_LER_INFO,
        // TODO: Not sure about IA32_SMRR_PHYSBASE & IA32_SMRR_PHYSMASK
        IA32_MC_I_CTL2,
        // Disabled via CPUID for non-host profiles
        IA32_INTEGRITY_STATUS,
        IA32_FIXED_CTRI,
        // IA32_PERF_CAPABILITIES is an MSR-based feature thus not listed here

        // Disabled via CPUID for non-host profiles
        IA32_FIXED_CTR_CTRL,
        // Disabled via CPUID for non-host profiles
        IA32_PERF_GLOBAL_STATUS,
        // Disabled via CPUID for non-host profiles
        IA32_PERF_GLOBAL_CTRL,
        // Disabled via CPUID for non-host profiles
        IA32_PERF_GLOBAL_STATUS_RESET,
        // Disabled via CPUID for non-host profiles
        IA32_PERF_GLOBAL_STATUS_SET,
        // Disabled via CPUID for non-host profiles
        IA32_PERF_GLOBAL_INUSE,
        // TODO: Not sure about this one, but seems to be related to performance monitoring which
        // should be disabled for non-host CPU profiles.
        IA32_PEBS_ENABLE,
        IA32_A_PMC0,
        IA32_A_PMC1,
        IA32_A_PMC2,
        IA32_A_PMC3,
        IA32_A_PMC4,
        IA32_A_PMC5,
        IA32_A_PMC6,
        IA32_A_PMC7,
        IA32_A_PMC8,
        IA32_A_PMC9,
        IA32_MCG_EXT_CTL,
        // SGX is disabled via CPUID for non-host CPU profiles
        IA32_SGX_SVN_STATUS,
        // Disabled via CPUID for non-host CPU profiles
        IA32_RTIT_OUTPUT_BASE,
        // Disabled via CPUID for non-host CPU profiles
        IA32_RTIT_OUTPUT_MASK_PTRS,
        // Disabled via CPUID for non-host CPU profiles
        IA32_RTIT_CTL,
        // Disabled via CPUID for non-host CPU profiles
        IA32_RTIT_STATUS,
        // Disabled via CPU profiles
        IA32_RTIT_CR3_MATCH,
        IA32_RTIT_ADDR0_A,
        IA32_RTIT_ADDR0_B,
        IA32_RTIT_ADDR1_A,
        IA32_RTIT_ADDR1_B,
        IA32_RTIT_ADDR2_A,
        IA32_RTIT_ADDR2_B,
        IA32_RTIT_ADDR3_A,
        IA32_RTIT_ADDR3_B,
        // Disabled via CPUID for non-host CPU profiles
        IA32_DS_AREA,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PKRS,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PM_ENABLE,
        // Disabled via CPUID for non-host CPU profiles
        IA32_HWP_CAPABILITIES,
        // Disabled via CPUID for non-host CPU profiles
        IA32_HWP_REQUEST_PKG,
        // Disabled via CPUID for non-host CPU profiles
        IA32_HWP_INTERRUPT,
        // Disabled via CPUID for non-host CPU profiles
        IA32_HWP_REQUEST,
        // TODO: Can we also deny IA32_PECI_HWP_REQUEST_INFO?

        // Disabled via CPUID for non-host CPU profiles
        IA32_HWP_CTL,
        // Disabled via CPUID for non-host CPU profiles
        IA32_HWP_STATUS,
        // TODO: Currently permitted via IA32_ARCH_CAPABILITIES (bit 22),
        // but that bit should probably have policy Static(0) ?
        IA32_MCU_EXT_SERVICE,
        IA32_MCU_ROLLBACK_MIN_ID,
        // TODO: Not sure about IA32_MCU_STAGING_MBOX_ADDR
        IA32_ROLLBACK_SIGN_ID_0,
        IA32_ROLLBACK_SIGN_ID_1,
        IA32_ROLLBACK_SIGN_ID_2,
        IA32_ROLLBACK_SIGN_ID_3,
        IA32_ROLLBACK_SIGN_ID_4,
        IA32_ROLLBACK_SIGN_ID_5,
        IA32_ROLLBACK_SIGN_ID_6,
        IA32_ROLLBACK_SIGN_ID_7,
        IA32_ROLLBACK_SIGN_ID_8,
        IA32_ROLLBACK_SIGN_ID_9,
        IA32_ROLLBACK_SIGN_ID_10,
        IA32_ROLLBACK_SIGN_ID_11,
        IA32_ROLLBACK_SIGN_ID_12,
        IA32_ROLLBACK_SIGN_ID_13,
        IA32_ROLLBACK_SIGN_ID_14,
        IA32_ROLLBACK_SIGN_ID_15,
        // Disabled via CPUID for non-host CPU profiles
        IA32_TME_CAPABILITY,
        // Disabled via CPUID for non-host CPU profiles
        IA32_TME_ACTIVATE,
        // Disabled via CPUID for non-host CPU profiles
        IA32_TME_EXCLUDE_MASK,
        // Disabled via CPUID for non-host CPU profiles
        IA32_TME_EXCLUDE_BASE,
        // Disabled via CPUID for non-host CPU profiles
        IA32_UINTR_RR,
        // Disabled via CPUID for non-host CPU profiles
        IA32_UINTR_HANDLER,
        // Disabled via CPUID for non-host CPU profiles
        IA32_UINTR_STACKADJUST,
        // Disabled via CPUID for non-host CPU profiles
        IA32_UINTR_MISC,
        // Disabled via CPUID for non-host CPU profiles
        IA32_UINTR_PD,
        // Disabled via CPUID for non-host CPU profiles
        IA32_UINTR_TT,
        // Disabled via CPUID for non-host CPU profiles
        IA32_COPY_STATUS,
        // Disabled via CPUID for non-host CPU profiles
        IA32_IWKEYBACKUP_STATUS,
        IA32_TME_CLEAR_SAVED_KEY,
        // Disabled via CPUID for non-host CPU profiles
        IA32_DEBUG_INTERFACE,
        // Disabled via CPUID for non-host CPU profiles
        IA32_L3_QOS_CFG,
        // Disabled via CPUID
        IA32_L2_QOS_CFG,
        // Disabled via CPUID
        IA32_L3_IO_QOS_CFG,
        IA32_RESOURCE_PRIORITY,
        IA32_RESOURCE_PRIORITY_PKG,
        // Disabled via CPUID for non-host CPU profiles
        IA32_QM_EVTSEL,
        // Disabled via CPUID for non-host CPU profiles
        IA32_QM_CTR,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PQR_ASSOC,
        // Disabled via CPUID for non-host CPU profiles
        IA32_L3_MASK_0,
        IA32_L3_MASK_N,
        // Disabled via CPUID for non-host CPU profiles
        IA32_L2_MASK_0,
        // Disabled via CPUID for non-host CPU profiles
        IA32_L2_MASK_N,
        // Disabled via CPUID for non-host CPU profiles
        IA32_L2_QOS_EXT_BW_THRTL_I,
        // Disabled via CPUID for non-host CPU profiles
        IA32_BNDCFGS,
        // Disabled via CPUID for non-host CPU profiles
        IA32_COPY_LOCAL_TO_PLATFORM,
        // Disabled via CPUID for non-host CPU profiles
        IA32_COPY_PLATFORM_TO_LOCAL,
        IA32_PASID,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PKG_HDC_CTL,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PM_CTL1,
        // Disabled via CPUID for non-host CPU profiles
        IA32_THREAD_STALL,
        // Disabled via CPUID for non-host CPU profiles
        IA32_QOS_CORE_BW_THRTL_0,
        // Disabled via CPUID for non-host CPU profiles
        IA32_QOS_CORE_BW_THRTL_1,
        // TODO: Is it OK to disable this for CPU profiles?
        // Note that we have CPUID 0x7.EDX.[19] = 0 (ARCH_LBR)
        IA32_LBR_X_INFO,
        // TDX related.
        IA32_SEAMRR_BASE,
        // TDX related.
        IA32_SEAMRR_MASK,
        // Disabled via ARCH_CAPABILITIES for non-host CPU profiles
        IA32_MCU_CONTROL,
        IA32_LBR_CTL,
        IA32_LBR_DEPTH,
        IA32_LBR_X_FROM_IP,
        IA32_LBR_X_TO_IP,
        // Disabled via CPUID for non-host CPU profiles
        IA32_HW_FEEDBACK_PTR,
        // Disabled via CPUID for non-host CPU profiles
        IA32_HW_FEEDBACK_CONFIG,
        // Disabled via CPUID for non-host CPU profiles
        IA32_HW_FEEDBACK_THREAD_CHAR,
        IA32_HW_FEEDBACK_THREAD_CONFIG,
        IA32_HRESET_ENABLE,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP0_CTR,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP0_CFG_A,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP0_CFG_C,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP1_CTR,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP1_CFG_A,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP1_CFG_C,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP2_CTR,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP2_CFG_A,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP2_CFG_B,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP2_CFG_C,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP3_CTR,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP3_CFG_A,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP3_CFG_B,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP3_CFG_C,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP4_CTR,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP4_CFG_A,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP4_CFG_B,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP4_CFG_C,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP5_CTR,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP5_CFG_A,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP5_CFG_B,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP5_CFG_C,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP6_CTR,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP6_CFG_A,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP6_CFG_B,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP6_CFG_C,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP7_CTR,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP7_CFG_A,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP7_CFG_B,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP7_CFG_C,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP8_CTR,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP8_CFG_A,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP9_CTR,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_GP9_CFG_A,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_FX0_CTR,
        IA32_PMC_FX0_CFG_B,
        IA32_PMC_FX0_CFG_C,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_FX1_CTR,
        IA32_PMC_FX1_CFG_B,
        IA32_PMC_FX1_CFG_C,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_FX2_CTR,
        IA32_PMC_FX2_CFG_C,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_FX3_CTR,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_FX4_CTR,
        IA32_PMC_FX4_CFG_C,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_FX5_CTR,
        IA32_PMC_FX5_CFG_C,
        // Disabled via CPUID for non-host CPU profiles
        IA32_PMC_FX6_CTR,
        IA32_PMC_FX6_CFG_C,
        IA32_UARCH_MISC_CTL,
    ];
}
