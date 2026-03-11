// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;

use log::{debug, error, warn};

use crate::x86_64::msr_definitions::{
    MsrDefinitions, ProfilePolicy, RegisterAddress, ValueDefinition, ValueDefinitions,
};

impl RegisterAddress {
    pub const IA32_BIOS_SIGN_ID: Self = Self(0x8b);
    pub const IA32_ARCH_CAPABILITIES: Self = Self(0x10a);
    pub const IA32_PERF_CAPABILITIES: Self = Self(0x345);
    pub const IA32_VMX_BASIC: Self = Self(0x480);
    pub const IA32_VMX_PINBASED_CTLS: Self = Self(0x481);
    pub const IA32_VMX_PROCBASED_CTLS: Self = Self(0x482);
    pub const IA32_VMX_EXIT_CTLS: Self = Self(0x483);
    pub const IA32_VMX_ENTRY_CTLS: Self = Self(0x484);
    pub const IA32_VMX_MISC: Self = Self(0x485);
    pub const IA32_VMX_CR0_FIXED0: Self = Self(0x486);
    pub const IA32_VMX_CR0_FIXED1: Self = Self(0x487);
    pub const IA32_VMX_CR4_FIXED0: Self = Self(0x488);
    pub const IA32_VMX_CR4_FIXED1: Self = Self(0x489);
    pub const IA32_VMX_VMCS_ENUM: Self = Self(0x48a);
    pub const IA32_VMX_PROCBASED_CTLS2: Self = Self(0x48b);
    pub const IA32_VMX_EPT_VPID_CAP: Self = Self(0x48c);
    pub const IA32_VMX_TRUE_PINBASED_CTLS: Self = Self(0x48d);
    pub const IA32_VMX_TRUE_PROCBASED_CTLS: Self = Self(0x48e);
    pub const IA32_VMX_TRUE_EXIT_CTLS: Self = Self(0x48f);
    pub const IA32_VMX_TRUE_ENTRY_CTLS: Self = Self(0x490);
    pub const IA32_VMX_VMFUNC: Self = Self(0x491);
    pub const IA32_VMX_PROCBASED_CTLS3: Self = Self(0x492);
    pub const IA32_VMX_EXIT_CTLS2: Self = Self(0x493);

    // =============== Non-architectural MSRs ========

    // KVM + Intel Skylake reports this as an MSR-based feature
    pub const MSR_PLATFORM_INFO: Self = Self(0xce);
}

/// This table contains descriptions of all the MSRs whose register addresses can be contained in
/// the list returned by `KVM_GET_MSR_FEATURE_INDEX_LIST` when executed on an Intel CPU.
///
/// The values described here are based on the Intel 64 and IA-32 Architectures Software Developer's
/// Manual Combined Volumes: 1,2A, 2B, 2C, 2D, 3A, 3B, 3C, 3D, and 4 from October 2025.
///
/// We try to use the same short descriptions as Intel, but in the cases where we could not find an
/// official name for the bit field(s) we invented our own based on the description.
///
/// The descriptions written here are based on those found in the aforementioned manual, but often less
/// detailed. We recommend consulting the official Intel documentation whenever more information
/// is required.
///
///
/// ## Future-proofing
///
/// Future processors and/or KVM versions may of course introduce more MSR-based features than those listed here at this time of writing.
/// In order to make sure that this is taken into account, the CPU profile generation tool will error when this is detected. The person
/// attempting to create a new CPU profile should then update this table accordingly and try again.
pub static INTEL_MSR_FEATURE_DEFINITIONS: MsrDefinitions<24> = const {
    MsrDefinitions([
        (
            RegisterAddress::IA32_BIOS_SIGN_ID,
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "PATCH_SIGN_ID",
                    description: "Any non-zero value is the microcode update signature patch signature ID",
                    bits_range: (32, 63),
                    policy: ProfilePolicy::Passthrough,
                }
            ])
        ),

        (
        RegisterAddress::IA32_ARCH_CAPABILITIES,
        ValueDefinitions::new(&[
            ValueDefinition {
                short: "RDCL_NO",
                description: "The processor is not susceptible to Rogue Data Cache Load (RDCL)",
                bits_range: (0, 0),
                policy: ProfilePolicy::Inherit,
            },
            ValueDefinition {
                short: "IBRS_ALL",
                description: "The processor supports enhanced IBRS",
                bits_range: (1, 1),
                policy: ProfilePolicy::Inherit,
            },
            // Skylake has this bit set, but not Sapphire Rapids
            // TODO: Is Inherit the right policy here? (Will it still be possible to use the Skylake profile on a Sapphire Rapids machine?)
            ValueDefinition {
                short: "RSBA",
                description: "The processor supports RSB Alternate",
                bits_range: (2, 2),
                policy: ProfilePolicy::Inherit,
            },
            ValueDefinition {
                short: "SKIP_L1DFL_VMENTRY",
                description: "A value of 1 indicates the hypervisor need not flush the L1D on VM entry",
                bits_range: (3, 3),
                policy: ProfilePolicy::Inherit,
            },
            ValueDefinition {
                short: "SSB_NO",
                description: "Processor is not susceptible to Speculation Store Bypass",
                bits_range: (4, 4),
                policy: ProfilePolicy::Inherit,
            },
            ValueDefinition {
                short: "MDS_NO",
                description: "Processor is not susceptible to Microarchitectural Data Sampling (MDS)",
                bits_range: (5, 5),
                policy: ProfilePolicy::Inherit,
            },
            ValueDefinition {
                short: "IF_PSCHANGE_MC_NO",
                description: "The processor is not susceptible to a machine check error due to modifying the size of a code page without TLB invalidation",
                bits_range: (6, 6),
                policy: ProfilePolicy::Inherit,
            },
            ValueDefinition {
                short: "TSX_CTRL",
                description: "If 1, indicates presence of IA32_TSX_CTRL MSR",
                bits_range: (7, 7),
                // TSX is riddled with CVEs
                // TODO: Check that this is indeed the right policy
                policy: ProfilePolicy::Static(0),
            },
            ValueDefinition {
                short: "TAA_NO",
                description: "If 1, processor is not affected by TAA",
                bits_range: (8, 8),
                // This is TSX related which we disable anyway
                policy: ProfilePolicy::Static(0),
            },
            ValueDefinition {
                short: "MCU_CONTROL",
                description: "If 1, the processor supports the IA32_MCU_CONTROL MSR",
                bits_range: (9, 9),
                // TODO: Check what the IA32_MCU_CONTROL MSR is
                policy: ProfilePolicy::Static(0),
            },
            ValueDefinition {
                short: "MISC_PACKAGE_CTLS",
                description: "The processor supports IA32_MISC_PACKAGE_CTLS MSR",
                bits_range: (10, 10),
                policy: ProfilePolicy::Static(0),
            },
            ValueDefinition {
                short: "ENERGY_FILTERING_CTL",
                description: "The processor supports setting and reading the IA32_MISC_PACKAGE_CTLS[0] (ENERGY_FILTERING_ENABLE) bit",
                bits_range: (11, 11),
                policy: ProfilePolicy::Static(0),
            },
            ValueDefinition {
                short: "DOITM:",
                description: "If 1, the processor supports Data Operand Independent Timing Mode",
                bits_range: (12, 12),
                policy: ProfilePolicy::Static(0),
            },
            ValueDefinition {
                short: "SBDR_SSDP_NO",
                description: "The processor is not affected by either the Shared Buffers Data Read (SBDR) vulnerability or the Sideband Stale Data Propagator (SSDP)",
                bits_range: (13, 13),
                policy: ProfilePolicy::Inherit,
            },
            ValueDefinition {
                short: "FBSDP_NO",
                description: "The processor is not affected by the Fill Buffer Stale Data Propagator (DBSDP)",
                bits_range: (14, 14),
                policy: ProfilePolicy::Inherit,
            },
            ValueDefinition {
                short: "PSDP_NO",
                description: "The processor is not affected by vulnerabilities involving the Primary Stale Data Propagator (PSDP)",
                bits_range: (15, 15),
                policy: ProfilePolicy::Inherit,
            },
            ValueDefinition {
                short: "MCU_ENUMERATION",
                description: "If 1, the processor supportss the IA32_MCU_ENUMERATION and IA32_MCU_STATUS MSRs",
                bits_range: (16, 16),
                policy: ProfilePolicy::Static(0),
            },
            ValueDefinition {
                short: "FB_CLEAR",
                description: "If 1, the processor supports overwrite of fill buffer values as part of MD_CLEAR operations with the VERW instruction.
                On these processors L1D_FLUSH does not overwrite fill buffer values",
                bits_range: (17, 17),
                policy: ProfilePolicy::Inherit,
            },

            ValueDefinition {
                short: "FB_CLEAR_CTRL",
                description: "If 1, the processor supports the IA32_MCU_OPT_CTRL MSR and allows software to set bit 3 of that MSR (FB_CLEAR_DIS)",
                bits_range: (18, 18),
                policy: ProfilePolicy::Static(0),
            },

            ValueDefinition {
                short: "RRSBA",
                description: "A value of 1 indicates the processor may have the RRSBA alternate prediction behavior, if not disabled by RRSBA_DIS_U or RRSBA_DIS_S",
                bits_range: (19, 19),
                policy: ProfilePolicy::Inherit,
            },

            ValueDefinition {
                short: "BHI_NO",
                description: "A value of 1 indicates BHI_NO branch prediction behavior, regardless of the value of IA32_SPEC_CTRL[BHI_DIS_S] MSR bit",
                bits_range: (20, 20),
                policy: ProfilePolicy::Inherit,
            },

            ValueDefinition {
                short: "XAPIC_DISABLE_STATUS",
                description: "Enumerates that the IA32_XAPIC_DISABLE_STATUS MSR exists, and that bit 0 specifies whether the legacy xAPIC is disabled and APIC state is locked to x2APIC",
                bits_range: (21, 21),
                policy: ProfilePolicy::Static(0),
            },

            ValueDefinition {
                short: "MCU_EXTENDED_SERVICE",
                description: "If 1, the processor supports MCU extended servicing - IA32_MCU_EXT_SERVICE MSR",
                bits_range: (22, 22),
                // TODO: Check
                policy: ProfilePolicy::Static(0),
            },

            ValueDefinition {
                short: "OVERCLOCKING_STATUS",
                description: "If set, the IA32_OVERCLOCKING_STATUS MSR exists",
                bits_range: (23, 23),
                // TODO: Check
                policy: ProfilePolicy::Static(0),
            },

            ValueDefinition {
                short: "PBRSB_NO",
                description: "If 1, the processor is not affected by issues related to Post-Barrier Return Stack Buffer Predictions",
                bits_range: (24, 24),
                policy: ProfilePolicy::Inherit,
            },
            ValueDefinition {
                short: "GDS_CTRL",
                description: "If 1, the processor supports the GDS_MITG_DIS and GDS_MITG_LOCK bits of the IA32_MCU_OPT_CTRL MSR",
                bits_range: (25, 25),
                // TODO: Check
                policy: ProfilePolicy::Inherit,
            },

            ValueDefinition {
                short: "GDS_NO",
                description: "If 1, the processor is not affected by Gather Data Sampling",
                bits_range: (26, 26),
                policy: ProfilePolicy::Inherit,
            },

            ValueDefinition {
                short: "RFDS_NO",
                description: "If 1, processor is not affected by Register File Data Sampling",
                bits_range: (27, 27),
                policy: ProfilePolicy::Inherit,
            },

            ValueDefinition {
                short: "RFDS_CLEAR",
                description: "If 1, when VERW is executed the processor will clear stale data from register files affected by Register File Data Sampling",
                bits_range: (28, 28),
                policy: ProfilePolicy::Inherit,
            },

            ValueDefinition {
                short: "IGN_UMONITOR_SUPPORT",
                description: "If 0, IA32_MCU_OPT_CTRL bit 6 (IGN_UMONITOR) is not supported. If 1, it indicates support of IA32_MCU_OPT_CTRL bit 6 (IGN_UMONITOR)",
                bits_range: (29, 29),
                policy: ProfilePolicy::Static(0),
            },

            ValueDefinition {
                short: "MON_UMON_MITG_SUPPORT",
                description: "If 1, indicates support for IA32_MCU_OPT_CTRL bit 7 (MON_UMON_MITG), otherwise it is not supported",
                bits_range: (30, 30),
                policy: ProfilePolicy::Static(0),
            },

            ValueDefinition {
                short: "PBOPT_SUPPORT",
                description: "If 1, IA32_PBOPT_CTRL bit 0 (Prediction Barrier Option (PBOPT)) is supported, otherwise it is not",
                bits_range: (32, 32),
                policy: ProfilePolicy::Inherit,
            },

            ValueDefinition {
                short: "ITS_NO",
                description: "If 0, the hypervisor indicates that the system is not affected by indirect Target Selection. If 1, then the hypervisor
                indicates that the system may be affected by indirect Target Selection",
                bits_range: (62, 62),
                policy: ProfilePolicy::Passthrough,

            },

        ]),
    ),

    (
            RegisterAddress::IA32_PERF_CAPABILITIES,
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "IA32_PERF_CAPABILITIES",
                    description: "Read Only MSR that enumerates the existence of performance monitoring features",
                    bits_range: (0, 63),
                    // This MSR is only valid if CPUID 0x1.ECX[15] is set, but that bit is always zeroed out for CPU profiles different from host
                    policy: ProfilePolicy::Deny
                }
            ])
        ),

        (
            RegisterAddress::IA32_VMX_BASIC,
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "VMCS_REV_ID",
                    description: "31-bit VMCS revision identifier. Processors that use the same VMCS revision identifier
                    use the same size for VMCS regions",
                    bits_range: (0,31),
                    policy: ProfilePolicy::Inherit
                },

                ValueDefinition {
                    short: "REGION_SIZE",
                    description: "Number of bytes that software should allocate for the VMXON region and any VMCS region. It is a value greater than
                    0 and at most 4096",
                    bits_range: (32, 44),
                    policy: ProfilePolicy::Inherit,
                },

                ValueDefinition {
                    short: "DUAL_MON",
                    description: " If 1, the logical processor supports the dual-monitor treatment of system-management
                    interrupts and system-management mode. See Section 33.15 for details of this treatment",
                    bits_range: (49, 49),
                    // TODO: Should we have Static(0)? here (I think that might be equivalent to what QEMU does)
                    policy: ProfilePolicy::Inherit
                },

                ValueDefinition {
                    short: "MEM_TYPE",
                    description: "The memory type that should be used for the VMCS, for data structures referenced by pointers
                    in the VMCS (I/O bitmaps, virtual-APIC page, MSR areas for VMX transitions), and for the MSEG header",
                    bits_range: (50, 53),
                    policy: ProfilePolicy::Inherit
                },

                ValueDefinition {
                    short: "VM_EXIT_INFO_INS_OUTS",
                    description: " If 1, the processor reports information in the VM-exit instruction-information field on VM exits
                    due to execution of the INS and OUTS instructions.
                    ",
                    bits_range: (54, 54),
                    policy: ProfilePolicy::Inherit
                },

                ValueDefinition {
                    short: "VMX_CTRLS_DEFAULT_MUT",
                    description: "Any VMX controls that default to 1 may be cleared to 0",
                    bits_range: (55,55),
                    policy: ProfilePolicy::Inherit
                },
                ValueDefinition {
                    short: "VM_ENTRY_HARDWARE_EXCEPTIONS",
                    description: "If 1, then software can use VM entry to deliver a hardware exception",
                    bits_range: (56, 56),
                    policy: ProfilePolicy::Inherit
                }
        ])
            ),

            (
              RegisterAddress::IA32_VMX_PINBASED_CTLS,
              ValueDefinitions::new(&[
                  ValueDefinition {
                      short:"ALLOWED_ZERO_EXTERNAL_INTERRUPT_EXITING",
                      description: "See Intel SDM Vol.3C Section 26.6.1 Table 26-5 (Definitions of Pin-Based VM-Execution Controls)",
                      bits_range: (0, 0),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_1_2",
                      description: "VM entry allows control X to be 0 if bit X in this MSR is zero",
                      bits_range: (1, 2),
                      policy: ProfilePolicy::Inherit
                  },
                    ValueDefinition {
                      short:"ALLOWED_ZERO_NMI_EXITING",
                      description: "See Intel SDM Vol.3C Section 26.6.1 Table 26-5 (Definitions of Pin-Based VM-Execution Controls)",
                      bits_range: (3, 3),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_4",
                      description: "VM entry allows control X to be 0 if bit X in this MSR is zero",
                      bits_range: (4, 4),
                      policy: ProfilePolicy::Inherit
                  },
                    ValueDefinition {
                      short:"ALLOWED_ZERO_VIRTUAL_NMIS",
                      description: "See Intel SDM Vol.3C Section 26.6.1 Table 26-5 (Definitions of Pin-Based VM-Execution Controls)",
                      bits_range: (5, 5),
                      policy: ProfilePolicy::Inherit
                  },
                    ValueDefinition {
                      short:"ALLOWED_ZERO_ACTIVATE_VMX_PREEMPTION_TIMER",
                      description: "See Intel SDM Vol.3C Section 26.6.1 Table 26-5 (Definitions of Pin-Based VM-Execution Controls)",
                      bits_range: (6, 6),
                      policy: ProfilePolicy::Inherit
                  },
                    ValueDefinition {
                      short:"ALLOWED_ZERO_PROCESS_POSTED_INTERRUPTS",
                      description: "See Intel SDM Vol.3C Section 26.6.1 Table 26-5 (Definitions of Pin-Based VM-Execution Controls)",
                      bits_range: (7, 7),
                      policy: ProfilePolicy::Inherit
                  },


                  ValueDefinition {
                      short: "ALLOWED_ZERO",
                      description: "VM entry allows control X to be 0 if bit X in this MSR is zero",
                      bits_range: (8, 31),
                      policy: ProfilePolicy::Inherit
                  },

                  ValueDefinition{
                      short:"ALLOWED_ONE_EXTERNAL_INTERRUPT_EXITING", 
                      description: "See Intel SDM Vol.3C Section 26.6.1 Table 26-5 (Definitions of Pin-Based VM-Execution Controls)",
                      bits_range: (32, 32),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ONE_1_2",
                      description: "VM entry allows control X to be 1 if bit X in this MSR is 1",
                      bits_range: (33, 34),
                      policy: ProfilePolicy::Inherit
                  },
                      ValueDefinition{
                      short:"ALLOWED_ONE_NMI_EXITING", 
                      description: "See Intel SDM Vol.3C Section 26.6.1 Table 26-5 (Definitions of Pin-Based VM-Execution Controls)",
                      bits_range: (35, 35),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ONE_4",
                      description: "VM entry allows control X to be 1 if bit X in this MSR is 1",
                      bits_range: (36, 36),
                      policy: ProfilePolicy::Inherit
                  },
                      ValueDefinition{
                      short:"ALLOWED_ONE_VIRTUAL_NMIS", 
                      description: "See Intel SDM Vol.3C Section 26.6.1 Table 26-5 (Definitions of Pin-Based VM-Execution Controls)",
                      bits_range: (37, 37),
                      policy: ProfilePolicy::Inherit
                  },
                      ValueDefinition{
                      short:"ALLOWED_ONE_ACTIVATE_VMX__PREEMPTION_TIMER", 
                      description: "See Intel SDM Vol.3C Section 26.6.1 Table 26-5 (Definitions of Pin-Based VM-Execution Controls)",
                      bits_range: (38, 38),
                      policy: ProfilePolicy::Inherit
                  },
                      ValueDefinition{
                      short:"ALLOWED_ONE_PROCESS_POSTED_INTERRUPTS", 
                      description: "See Intel SDM Vol.3C Section 26.6.1 Table 26-5 (Definitions of Pin-Based VM-Execution Controls)",
                      bits_range: (39, 39),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ONE",
                      description:"VM entry allows control X to be 1 if bit X + 32 in this MSR is 1",
                      bits_range: (40, 63),
                      policy: ProfilePolicy::Inherit
                  }
              ])
            ),

            (
                RegisterAddress::IA32_VMX_PROCBASED_CTLS,
                ValueDefinitions::new(&[
                  ValueDefinition {
                      short: "ALLOWED_ZERO_0_1",
                      description: "Control X is allowed to be 0 if bit X of this MSR is 0",
                      bits_range: (0, 1),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_INTERRUPT_WINDOW_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (2, 2),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_USE_TSC_OFFSETTING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (3, 3),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_4_6",
                      description: "Control X is allowed to be 0 if bit X of this MSR is 0",
                      bits_range: (4, 6),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_HLT_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (7, 7),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_8",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (8, 8),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_INVLPG_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (9, 9),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_MWAIT_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (10, 10),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_RDPMC_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (11, 11),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_RDTSC_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (12, 12),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_13_14",
                      description: "Control X is allowed to be 0 if bit X of this MSR is 0",
                      bits_range: (13, 14),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_CR3_LOAD_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (15, 15),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_CR3_STORE_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (16, 16),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_ACTIVATE_TERTIARY_CONTROLS",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (17, 17),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_18",
                      description: "Control X is allowed to be 0 if bit X of this MSR is 0",
                      bits_range: (18, 18),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_CR8_LOAD_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (19, 19),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_CR8_STORE_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (20, 20),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_USE_TPR_SHADOW",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (21, 21),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_NMI_WINDOW_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (22, 22),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_MOV_DR_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (23, 23),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_UNCONDITIONAL_I/O_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (24, 24),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_USE_I/O_BITMAPS",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (25, 25),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_26",
                      description: "Control X is allowed to be 0 if bit X of this MSR is 0",
                      bits_range: (26, 26),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_MONITOR_TRAP_FLAG",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (27, 27),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_USE_MSR_BITMAPS",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (28, 28),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_MONITOR_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (29, 29),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_PAUSE_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (30, 30),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_ACTIVATE_SECONDARY_CONTROLS",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (31, 31),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short: "ALLOWED_ONE_0_1",
                      description: "Control X is allowed to be 1 if bit 32 + X of this MSR is 1",
                      bits_range: (32, 33),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_INTERRUPT_WINDOW_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (34, 34),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_USE_TSC_OFFSETTING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (35, 35),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short: "ALLOWED_ONE_4_6",
                      description:"VM entry allows control X to be 1 if bit X + 32 in this MSR is 1",
                      bits_range: (36, 38),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_HLT_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (39, 39),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short: "ALLOWED_ONE_8",
                      description:"VM entry allows control X to be 1 if bit X + 32 in this MSR is 1",
                      bits_range: (40, 40),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_INVLPG_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (41, 41),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_MWAIT_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (42, 42),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_RDPMC_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (43, 43),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_RDTSC_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (44, 44),
                      policy: ProfilePolicy::Inherit
                      },

                    ValueDefinition {
                      short: "ALLOWED_ONE_13_14",
                      description:"VM entry allows control X to be 1 if bit X + 32 in this MSR is 1",
                      bits_range: (45, 46),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_CR3_LOAD_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (47, 47),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_CR3_STORE_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (48, 48),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_ACTIVATE_TERTIARY_CONTROLS",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (49, 49),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short: "ALLOWED_ONE_18",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (50, 50),
                      policy: ProfilePolicy::Inherit
                  },

                  ValueDefinition {
                      short:"ALLOWED_ONE_CR8_LOAD_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (51, 51),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_CR8_STORE_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (52, 52),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_USE_TPR_SHADOW",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (53, 53),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_NMI_WINDOW_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (54, 54),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_MOV_DR_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (55, 55),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_UNCONDITIONAL_I/O_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (56, 56),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_USE_I/O_BITMAPS",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (57, 57),
                      policy: ProfilePolicy::Inherit
                      },
                    ValueDefinition {
                      short: "ALLOWED_ONE_26",
                      description: "Control X is allowed to be 1 if bit X of this MSR is 1",
                      bits_range: (58, 58),
                      policy: ProfilePolicy::Inherit
                  },

                  ValueDefinition {
                      short:"ALLOWED_ONE_MONITOR_TRAP_FLAG",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (59, 59),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_USE_MSR_BITMAPS",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (60, 60),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_MONITOR_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (61, 61),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_PAUSE_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (62, 62),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_ACTIVATE_SECONDARY_CONTROLS",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (63, 63),
                      policy: ProfilePolicy::Inherit
                      },

              ])
            ),

            (
                RegisterAddress::IA32_VMX_EXIT_CTLS,
                ValueDefinitions::new(&[
                  ValueDefinition {
                      short: "ALLOWED_ZERO_0_1",
                      description: "Control X is allowed to be 0 if bit X in this MSR is 0",
                      bits_range: (0, 1),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_SAVE_DEBUG_CONTROLS",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (2, 2),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_3_8",
                      description: "Control X is allowed to be 0 if bit X in this MSR is 0",
                      bits_range: (3, 8),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_HOST_ADDRESS_SPACE_SIZE",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (9, 9),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_10_11",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (10, 11),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_IA32_PERF_GLOBAL_CTRL",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (12, 12),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_13_14",
                      description: "Control X is allowed to be 0 if bit X in this MSR is 0",
                      bits_range: (13, 14),
                      policy: ProfilePolicy::Inherit
                   },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_ACKNOWLEDGE_INTERRUPT_O_EXIT",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (15, 15),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_16_17",
                      description: "Control X is allowed to be 0 if bit X in this MSR is 0",
                      bits_range: (16, 17),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_SAVE_IA32_PAT",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (18, 18),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_IA32_PAT",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (19, 19),
                      policy: ProfilePolicy::Inherit
                 },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_SAVE_IA32_EFER",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (20, 20),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_IA32_EFER",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (21, 21),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_SAVE_VMX_PREEMPTION_TIMER_VALUE",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (22, 22),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_CLEAR_IA32_BNDCFGS",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (23, 23),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_CONCEAL_VMX_FROM_PT",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (24, 24),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_CLEAR_IA32_RTIT_CTL",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (25, 25),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_CLEAR_IA32_LBR_CTL",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (26, 26),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_CLEAR_UINV",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (27, 27),
                      policy: ProfilePolicy::Inherit
                },
                // TODO: Also determines whether SSP is loaded on VM exit (do we need that?)
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_CET_STATE",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (28, 28),
                      policy: ProfilePolicy::Static(0)
                },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_PKRS",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (29, 29),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_SAVE_IA32_PERF_GLOBAL_CTL",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (30, 30),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_ACTIVATE_SECONDARY_CONTROLS",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (31, 31),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short: "ALLOWED_ONE_0_1",
                      description: "Control X is allowed to be 1 if bit X in this MSR is 1",
                      bits_range: (32, 33),
                      policy: ProfilePolicy::Inherit
                },

                  ValueDefinition {
                    short:"ALLOWED_ONE_SAVE_DEBUG_CONTROLS",
                    description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                    bits_range: (34, 34),
                    policy: ProfilePolicy::Inherit
                },

                    ValueDefinition {
                      short: "ALLOWED_ONE_3_8",
                      description: "Control X is allowed to be 1 if bit X in this MSR is 1",
                      bits_range: (35, 40),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_HOST_ADDRESS_SPACE_SIZE",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (41, 41),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ONE_10_11",
                      description: "Control X is allowed to be 1 if bit X in this MSR is 1",
                      bits_range: (42, 43),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_IA32_PERF_GLOBAL_CTRL",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (44, 44),
                      policy: ProfilePolicy::Static(0)
                },
                  ValueDefinition {
                      short: "ALLOWED_ONE_13_14",
                      description: "Control X is allowed to be 1 if bit X in this MSR is 1",
                      bits_range: (45, 46),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_ACKNOWLEDGE_INTERRUPT_O_EXIT",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (47, 47),
                      policy: ProfilePolicy::Inherit
                },
                 ValueDefinition {
                      short: "ALLOWED_ONE_16_17",
                      description: "Control X is allowed to be 1 if bit X in this MSR is 1",
                      bits_range: (48, 49),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_SAVE_IA32_PAT",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (50, 50),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_IA32_PAT",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (51, 51),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ONE_SAVE_IA32_EFER",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (52, 52),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_IA32_EFER",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (53, 53),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ONE_SAVE_VMX_PREEMPTION_TIMER_VALUE",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (54, 54),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ONE_CLEAR_IA32_BNDCFGS",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (55, 55),
                      policy: ProfilePolicy::Static(0)
                },
                  ValueDefinition {
                      short:"ALLOWED_ONE_CONCEAL_VMX_FROM_PT",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (56, 56),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ONE_CLEAR_IA32_RTIT_CTL",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (57, 57),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ONE_CLEAR_IA32_LBR_CTL",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (58, 58),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ONE_CLEAR_UINV",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (59, 59),
                      policy: ProfilePolicy::Inherit
                },
                // TODO: Also determines whether SSP is loaded on VM exit (do we need that?)
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_CET_STATE",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (60, 60),
                      policy: ProfilePolicy::Static(0)
                },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_PKRS",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (61, 61),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ONE_SAVE_IA32_PERF_GLOBAL_CTL",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (62, 62),
                      policy: ProfilePolicy::Static(0)
                },
                  ValueDefinition {
                      short:"ALLOWED_ONE_ACTIVATE_SECONDARY_CONTROLS",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (63, 63),
                      policy: ProfilePolicy::Inherit
                },
                ])
            ),
            (
                RegisterAddress::IA32_VMX_ENTRY_CTLS,
                ValueDefinitions::new(&[
                  ValueDefinition {
                      short: "ALLOWED_ZERO_0_1",
                      description: "VM entry allows control X to be 0 if bit X in this MSR is zero",
                      bits_range: (0, 1),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_DEBUG_CONTROLS",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (2, 2),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_3_8",
                      description: "VM entry allows control X to be 0 if bit X in this MSR is zero",
                      bits_range: (3, 8),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_IA_32E_MODE_GUES",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (9, 9),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_ENTRY_TO_SMM",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (10, 10),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_DEACTIVATE_DUAL__MONITOR_TREATMENT",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (11, 11),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_12",
                      description: "VM entry allows control X to be 0 if bit X in this MSR is zero",
                      bits_range: (12, 12),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_IA32_PERF_GLOBAL_CTRL",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (13, 13),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_IA32_PAT",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (14, 14),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_IA32_EFER",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (15, 15),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_IA32_BNDCFGS",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (16, 16),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_CONCEAL_VMX_FROM_PT",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (17, 17),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_IA32_RTIT_CTL",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (18, 18),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_UINV",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (19, 19),
                      policy: ProfilePolicy::Inherit
                  },
                // TODO: Also determines whether SSP is loaded on VM exit (do we need that?)
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_CET_STATE",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (20, 20),
                      policy: ProfilePolicy::Static(0)
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_GUEST_IA32_LBR_CTL",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (21, 21),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_PKRS",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (22, 22),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_23_24",
                      description: "VM entry allows control X to be 0 if bit X in this MSR is zero",
                      bits_range: (23, 24),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_ALLOW_SEAM_GUEST_TELEMETRY",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (25, 25),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_26_31",
                      description: "VM entry allows control X to be 0 if bit X in this MSR is zero",
                      bits_range: (26, 31),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ONE_0_1",
                      description:"VM entry allows control X to be 1 if bit X + 32 in this MSR is 1",
                      bits_range: (32, 33),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_DEBUG_CONTROLS",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (34, 34),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ONE_3_8",
                      description:"VM entry allows control X to be 1 if bit X + 32 in this MSR is 1",
                      bits_range: (35, 40),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_IA_32E_MODE_GUES",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (41, 41),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_ENTRY_TO_SMM",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (42, 42),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_DEACTIVATE_DUAL__MONITOR_TREATMENT",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (43, 43),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ONE_12",
                      description:"VM entry allows control X to be 1 if bit X + 32 in this MSR is 1",
                      bits_range: (44, 44),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_IA32_PERF_GLOBAL_CTRL",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (45, 45),
                      policy: ProfilePolicy::Static(0)
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_IA32_PAT",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (46, 46),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_IA32_EFER",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (47, 47),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_IA32_BNDCFGS",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (48, 48),
                      policy: ProfilePolicy::Static(0)
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_CONCEAL_VMX_FROM_PT",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (49, 49),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_IA32_RTIT_CTL",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (50, 50),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_UINV",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (51, 51),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_CET_STATE",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (52, 52),
                      policy: ProfilePolicy::Static(0)
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_GUEST_IA32_LBR_CTL",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (53, 53),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_PKRS",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (54, 54),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ONE_23_24",
                      description:"VM entry allows control X to be 1 if bit X + 32 in this MSR is 1",
                      bits_range: (55, 56),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_ALLOW_SEAM_GUEST_TELEMETRY",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (57, 57),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ONE_26_31",
                      description:"VM entry allows control X to be 1 if bit X + 32 in this MSR is 1",
                      bits_range: (58, 63),
                      policy: ProfilePolicy::Inherit
                  },
                ])
            ),

            (
                RegisterAddress::IA32_VMX_MISC,
                ValueDefinitions::new(&[
                    ValueDefinition {
                        short: "VMX_PREEMPTION_TSC_REL",
                        description: "specifies the relationship between the rate of the VMX-preemption timer and that of the timestamp counter (TSC)",
                        bits_range: (0, 4),
                        policy: ProfilePolicy::Passthrough
                    },
                    ValueDefinition {
                        short: "IA32_EFER.LMA_STORE",
                        description: "If 1, then VM exits store the value of IA32_EFER.LMA into the IA32-e mode guest VM-entry control",
                        bits_range: (5,5),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "HLT_STATE",
                        description: "Activity state 1 (HLT) is supported",
                        bits_range: (6,6),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "SHUTDOWN_STATE",
                        description: "Activity state 2 (shutdown) is supported",
                        bits_range: (7,7),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "WAIT_FOR_SIPI__STATE",
                        description: "Activity state 3 (wait-for-SIPI) is supported",
                        bits_range: (8,8),
                        policy: ProfilePolicy::Static(0)
                    },
                    ValueDefinition {
                        short: "VMX_INTEL_PT",
                        description: "If 1 then Intel Processor Trace can be used in VMX operation",
                        bits_range: (14,14),
                        policy: ProfilePolicy::Static(0)
                    },
                    ValueDefinition {
                        short: "RDMSR_SMM",
                        description: "If 1 then the RDMSR instruction can be used in system management mode (SMM) to read the IA32_SMBASE MSR",
                        bits_range: (15,15),
                        // TODO: Is this a reasonable policy?
                        policy: ProfilePolicy::Static(0)
                    },
                    ValueDefinition {
                        short: "VMX_NUM_CR3",
                        description: "The number of CR3-target values supported by the processor",
                        bits_range: (16,24),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "MAX_MSR_STORE_LISTS",
                        description: "If N then 512*(N +1) is the recommended maximum number of MSRs to be included each of the VM-exit MSR-store list, VM-exit-MSR-load-list, VM-entry MSR-load list",
                        bits_range: (25, 27),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "SMM_MONITOR_CTL_BIT2",
                        description: "If set then bit 2 of the IA32_SMM_MONITOR_CTL can be set to 1",
                        // TODO: Check policy. Perhaps this should rather be Static(0) ?
                        bits_range: (28, 28),
                        policy: ProfilePolicy::Inherit,
                    },
                    ValueDefinition {
                        short: "VM_WRITE_EXIT_FIELDS",
                        description: "If 1 then software can use VMWRITE to write to any supported field in the VMCS",
                        bits_range: (29,29),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "VM_ENTRY_INJECTION",
                        description: "If 1 then VM entry permits injection of the following: software interrupt, software exception, or privileged software exception with an instruction length of 0",
                        bits_range: (30,30),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "MSEG_REV_ID",
                        description: "MSEG revision identifier used by the processor",
                        bits_range: (32,63),
                        // TODO: Should this be Passthrough?
                        policy: ProfilePolicy::Inherit
                    },
                ])
            ),

            (
                RegisterAddress::IA32_VMX_CR0_FIXED0,
                // NOTE 1: If any entry in IA32_VMX_CR0_FIXED1 has ProfilePolicy::Stattic(0) then the corresponding entry here must also have ProfilePolicy::Static(0)
                //
                // NOTE 2: We use the inherit policy for reserved fields.
                ValueDefinitions::new(&[
                    ValueDefinition {
                        short: "CR0.PE",
                        description: "If 0, then bit 0 (Protection Enable) of CR0 is allowed to be 0. bit 0 of CR0 enables real-address mode when clear.",
                        bits_range: (0, 0),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR0.MP",
                        description: "If 0, then bit 1 (Monitor Coprocessor) of CR0 is allowed to be 0. See Intel SDM Vol. 3A Section 2.5 for more information",
                        bits_range: (1, 1),
                        policy: ProfilePolicy::Inherit
                    },
                    // We expect this to be 0 for all modern processors, but Inherit is fine.
                    ValueDefinition {
                        short: "CR0.EM",
                        description: "If 0, then bit 2 (Emulation) of CR0 is allowed to be 0. See Intel SDM Vol. 3A Section 2.5 for more information",
                        bits_range: (2, 2),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR0.TS",
                        description: "If 0, then bit 3 (Task Switched) of CR0 is allowed to be 0. See Intel SDM Vol. 3A Section 2.5 for more information",
                        bits_range: (3, 3),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR0.ET",
                        description: "If 0, then bit 4 (Extension Type) of CR0 is allowed to be 0. See Intel SDM Vol. 3A Section 2.5 for more information",
                        bits_range: (4, 4),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR0.NE",
                        description: "If 0, then bit 5 (Numeric Error) of CR0 is allowed to be 0. Enables the PC-style x87 FPU error reporting mechanism when clear in CR0.",
                        bits_range: (5, 5),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition {
                        short: "IA32_VMX_CR0_FIXED1_RESERVED_6_15",
                        description: "Reports bits allowed to be 0 in CR0",
                        bits_range: (6, 15),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR0.WP",
                        description: "If 0, then bit 16 (Write protect) of CR0 is allowed to be 0. If this bit is clear in CR0 then supervisor-level procedures are
                        allowed to write into read-only pages",
                        bits_range: (16, 16),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "IA32_VMX_CR0_FIXED1_RESERVED_17_17",
                        description: "Reports bits allowed to be 0 in CR0",
                        bits_range: (17, 17),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR0.AM",
                        description: "If 0, then bit 18 (Alignment Mask) of CR0 is allowed to be 0. If this bit is clear in CR0 then alignment checking is disabled.",
                        bits_range: (18, 18),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "IA32_VMX_CR0_FIXED1_RESERVED_19_28",
                        description: "Reports bits allowed to be 0 in CR0",
                        bits_range: (19, 28),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR0.NW",
                        description: "If 0, then bit 29 (Not Write-through) of CR0 is allowed to be 0. See Intel SDM Vol. 3A Section 2.5 for more information",
                        bits_range: (29, 29),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR0.CD",
                        description: "If 0, then bit 30 (Cache disable) of CR0 is allowed to be  0.  If CR0 bits 30 and 29 are 0 then caching of memory locations
                        for the whole of physical memory in the processor's internal (and external) cache is enabled.",
                        bits_range: (30, 30),
                        policy: ProfilePolicy::Inherit
                    },
                    // TOD0: Disabling paging sounds bad, should we force this to 1?
                    ValueDefinition {
                        short: "CR0.PG",
                        description: "If 0, then bit 31 (Paging) of CR0 is allowed to be 0. If bit 31 of CR0 is cleared then paging is disabled (all linear addresses get treated as physical addresses).",
                        bits_range: (31, 31),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "IA32_VMX_CR0_FIXED1_RESERVED_32_63",
                        description: "Reports bits allowed to be 0 in CR0",
                        bits_range: (32, 63),
                        policy: ProfilePolicy::Inherit
                    },
                ])
            ),

                // NOTE: CR0_FIXED1 cannot be set by KVM, but this is OK, because its value is determined by CPUID anyway
            (
                RegisterAddress::IA32_VMX_CR0_FIXED1,
                ValueDefinitions::new(&[

                    ValueDefinition {
                        short: "CR0.PE",
                        description: "If 1, then bit 0 (Protection Enable) of CR0 is allowed to be 1. bit 0 of CR0 enables protected mode when set",
                        bits_range: (0, 0),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition {
                        short: "CR0.MP",
                        description: "If 1, then bit 1 (Monitor Coprocessor) of CR0 is allowed to be 1. See Intel SDM Vol. 3A Section 2.5 for more information",
                        bits_range: (1, 1),
                        policy: ProfilePolicy::Inherit
                    },
                    // We expect this to be 0 for all modern processors, but Inherit is fine.
                    ValueDefinition {
                        short: "CR0.EM",
                        description: "If 1, then bit 2 (Emulation) of CR0 is allowed to be 1. See Intel SDM Vol. 3A Section 2.5 for more information",
                        bits_range: (2, 2),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR0.TS",
                        description: "If 1, then bit 3 (Task Switched) of CR0 is allowed to be 1. See Intel SDM Vol. 3A Section 2.5 for more information",
                        bits_range: (3, 3),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR0.ET",
                        description: "If 1, then bit 4 (Extension Type) of CR0 is allowed to be 1. See Intel SDM Vol. 3A Section 2.5 for more information",
                        bits_range: (4, 4),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR0.NE",
                        description: "If 1, then bit 5 (Numeric Error) of CR0 is allowed to be 1. This bit enables the native (internal) mechanism for reporting x87 FPU errors when set in CR0.",
                        bits_range: (5, 5),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "IA32_VMX_CR0_FIXED1_RESERVED_6_15",
                        description: "Reports bits allowed to be 1 in CR0",
                        bits_range: (6, 15),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR0.WP",
                        description: "If 1, then bit 16 (Write protect) of CR0 is allowed to be 1. If this bit is set in CR0 then supervisor-level procedures are
                        inhibited from writing into read-only pages",
                        bits_range: (16, 16),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "IA32_VMX_CR0_FIXED1_RESERVED_17_17",
                        description: "Reports bits allowed to be 1 in CR0",
                        bits_range: (17, 17),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR0.AM",
                        description: "If 1, then bit 18 (Alignment Mask) of CR0 is allowed to be 1. If bit 18 of CR0 is set then automatic alignment checking is possible.",
                        bits_range: (18, 18),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "IA32_VMX_CR0_FIXED1_RESERVED_19_28",
                        description: "Reports bits allowed to be 1 in CR0",
                        bits_range: (19, 28),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR0.NW",
                        description: "If 1, then bit 29 (Not Write-through) of CR0 is allowed to be 1. See Intel SDM Vol. 3A Section 2.5 for more information",
                        bits_range: (29, 29),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR0.CD",
                        description: "If 1, then bit 30 (Cache disable) of CR0 is allowed to be 1. If CR0 bit 30 is 1 then caching is restricted",
                        bits_range: (30, 30),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR0.PG",
                        description: "If 1, then bit 31 (Paging) of CR0 is allowed to be 1 which enables paging",
                        bits_range: (31, 31),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "IA32_VMX_CR0_FIXED1_RESERVED_32_63",
                        description: "Reports bits allowed to be 1 in CR0",
                        bits_range: (32, 63),
                        policy: ProfilePolicy::Inherit
                    },
                ])
            ),

            (
                RegisterAddress::IA32_VMX_CR4_FIXED0,
                ValueDefinitions::new(&[
                    ValueDefinition {
                        short: "CR4.VME",
                        description: "If 0, then bit 0 (Virtual-8086 Mode Extension) of CR4 is allowed to be 0. Bit 0 of CR4 disables the interrupt and exception-handling extensions in virtual-8086 mode when clear.",
                        bits_range: (0, 0),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.PVI",
                        description: "If 0, then bit 1 (Protected-Mode Virtual Interrupts) of CR4 is allowed to be 0. Bit 1 of CR4 disables the virtual interrupt flag in protected mode when clear.",
                        bits_range: (1, 1),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.TSD",
                        description: "If 0, then bit 2 (Time Stamp Disable) of CR4 is allowed to be 0. Bit 2 of CR4 allows RDTSC instruction to be executed at any privilege level when clear.",
                        bits_range: (2, 2),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.DE",
                        description: "If 0, then bit 3 (Debugging extensions) of CR4 is allowed to be 0. When Bit 3 of CR4 is clear the processor aliases references to registers DR4 and DR5 for compatibility with legacy software",
                        bits_range: (3, 3),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.PSE",
                        description: "If 0, then bit 4 (Page Size Extensions) of CR4 is allowed to be 0. Bit 4 of CR4 restricts 32-bit paging to pages of 4 KBytes when clear.",
                        bits_range: (4, 4),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.PAE",
                        description: "If 0, then bit 5 (Physical Address Extension) of CR4 is allowed to be 0. Bit 5 of CR4 restricts physical addresses to 32 bits when clear",
                        bits_range: (5, 5),
                        policy: ProfilePolicy::Inherit
                    },
                    // TODO: Perhaps we should force this to 0?
                    ValueDefinition {
                        short: "CR4.MCE",
                        description: "If 0, then bit 6 (Machine-Check Enable) of CR4 is allowed to be 0. Bit 6 of CR4 disables the machine-check exception when clear",
                        bits_range: (6, 6),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.PGE",
                        description: "If 0, then bit 7 (Page Global Enable) of CR4 is allowed to be 0. Bit 7 of CR4 disables the global page feature when clear",
                        bits_range: (7, 7),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.PCE",
                        description: "If 0, then bit 8 (Performance-Monitoring Counter Enable) of CR4 is allowed to be 0. The RDPMC instruction can only be executed at protection level 0 when bit 8 of CR4 is clear",
                        bits_range: (8, 8),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.OSFXSR",
                        description: "If 0, then bit 9 (OS Support for FXSAVE and FXRSTOR) of CR4 is allowed to be 0. See Intel SDM Vol.3A Section 2.5 for more information.",
                        bits_range: (9, 9),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.OSXMMEXCPT",
                        description: "If 0, then bit 10 (OS Support for Unmaksed SIMD Floating-Point Exceptions) of CR4 is allowed to be 0. See Intel SDM Vol.3A Section 2.5 for more information.",
                        bits_range: (10, 10),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.UMIP",
                        description: "If 0, then bit 11 (User-Mode instruction Prevention) of CR4 is allowed to be 0. See Intel SDM Vol.3A Section 2.5 for more information.",
                        bits_range: (11, 11),
                        policy: ProfilePolicy::Inherit
                    },
                    // Maybe this could even be passthrogh? CHV is 64-bit only.
                    ValueDefinition {
                        short: "CR4.LA57",
                        description: "If 0, then bit 12 (57-bit linear addresses) of CR4 is allowed to be 0. See Intel SDM Vol.3A Section 2.5 for more information.",
                        bits_range: (12, 12),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.VMXE",
                        description: "If 0, then bit 13 (VMX-Enable) of CR4 is allowed to be 0. See Intel SDM Vol.3A Section 2.5 for more information.",
                        bits_range: (13, 13),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.SMXE",
                        description: "If 0, then bit 14 (SMX-Enable) of CR4 is allowed to be 0. See Intel SDM Vol.3A Section 2.5 for more information.",
                        bits_range: (14, 14),
                        policy: ProfilePolicy::Static(0)
                    },
                    ValueDefinition {
                        short: "CR4.RESERVED_15",
                        description: "If 0, then bit 15 (RESERVED) of CR4 is allowed to be 0. See Intel SDM Vol.3A Section 2.5 for more information.",
                        bits_range: (15, 15),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.FSGSBASE",
                        description: "If 0, then bit 16 (FSGSBASE-Enable) of CR4 is allowed to be 0. See Intel SDM Vol.3A Section 2.5 for more information",
                        bits_range: (16, 16),
                        policy: ProfilePolicy::Inherit
                    },
                    // Probably irrelevant?
                    ValueDefinition {
                        short: "CR4.PCIDE",
                        description: "If 0, then bit 17 (PCID-Enable) of CR4 is allowed to be 0. See Intel SDM Vol.3A Section 2.5 for more information",
                        bits_range: (17, 17),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.OSXSAVE",
                        description: "If 0, then bit 18 (XSAVE and Processor Extended States-Enable) of CR4 is allowed to be 0. See Intel SDM Vol.3A Section 2.5 for more information",
                        bits_range: (18, 18),
                        policy: ProfilePolicy::Inherit
                    },
                    // CPU Profiles do not support Key locker features for now
                    ValueDefinition {
                        short: "CR4.KL",
                        description: "If 0, then bit 19 (Key-Locker-Enable) of CR4 is allowed to be 0. When bit 19 of CR4 is set, the LOADIWKEY instruction is enabled and CPUID.0x19.EBX[0] is set if support for AES key locker instructions has been activated by system firmware",
                        bits_range: (19, 19),
                        policy: ProfilePolicy::Static(0)
                    },
                    ValueDefinition {
                        short: "CR4.SMEP",
                        description: "If 0, then bit 20 (SMEP-Enable) of CR4 is allowed to be 0. See Intel SDM Vol 3.A Section 2.5 for more information",
                        bits_range: (20, 20),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.SMAP",
                        description: "If 0, then bit 21 (SMAP-Enable) of CR4 is allowed to be 0. See Intel SDM Vol 3.A Section 2.5 for more information",
                        bits_range: (21, 21),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.PKE",
                        description: "If 0, then bit 22 (Enable protection keys for user-mode pages) of CR4 is allowed to be 0. See Intel SDM Vol. 3.A Section 2.5 for more information.",
                        bits_range: (22, 22),
                        policy: ProfilePolicy::Inherit,
                    },
                    ValueDefinition {
                        short: "CR4.CET",
                        description: "If 0, then bit 23 (Control-flow Enforcement Technology) of CR4 is allowed to be 0. See Intel SDM Vol. 3.A Section 2.5 for more information.",
                        bits_range: (23, 23),
                        policy: ProfilePolicy::Static(0)
                    },
                    ValueDefinition {
                        short: "CR4.PKS",
                        description: "If 0, then bit 24 (Enable protection keys for supervisor-mode pages) of CR4 is allowed to be 0. See Intel SDM Vol. 3.A Section 2.5 for more information.",
                        bits_range: (24, 24),
                        policy: ProfilePolicy::Static(0)
                    },
                    ValueDefinition {
                        short: "CR4.UINTR",
                        description: "If 0, then bit 25 (User Interrupts Enable) of CR4 is allowed to be 0. See Intel SDM Vol. 3.A Section 2.5 for more information.",
                        bits_range: (25, 25),
                        policy: ProfilePolicy::Static(0)
                    },
                    ValueDefinition {
                        short: "CR4.RESERVED_26",
                        description: "If 0, then bit 26 (RESERVED) of CR4 is allowed to be 0. See Intel SDM Vol.3.A Section 2.5 for more information.",
                        bits_range: (26, 26),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.LASS",
                        description: "If 0, then bit 27 (User Interrupts Enable) of CR4 is allowed to be 0. See Intel SDM Vol. 3.A Section 2.5 for more information.",
                        bits_range: (27, 27),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.LAM_SUP",
                        description: "If 0, then bit 28 (Supervisor LAM-enable) of CR4 is allowed to be 0. See Intel SDM Vol. 3.A Section 25 for more information.",
                        bits_range: (28, 28),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "IA32_VMX_CR4_FIXED0",
                        description: "Reports bits allowed to be 0 in CR4",
                        bits_range: (29, 63),
                        policy: ProfilePolicy::Inherit
                    }
                ])
            ),

            // NOTE: CR4_FIXED1 cannot be set by KVM, but this is OK, because its value is determined by CPUID anyway
            (
                RegisterAddress::IA32_VMX_CR4_FIXED1,
                ValueDefinitions::new(&[
                    ValueDefinition {
                        short: "CR4.VME",
                        description: "If 1, then bit 1 (Virtual-8086 Mode Extension) of CR4 is allowed to be 1. Bit 0 of CR4 enables the interrupt and exception-handling extensions in virtual-8086 mode when set.",
                        bits_range: (0, 0),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.PVI",
                        description: "If 1, then bit 1 (Protected-Mode Virtual Interrupts) of CR4 is allowed to be 1. Bit 1 of CR4 enables hardware support for a virtual interrupt flag in protected mode when set.",
                        bits_range: (1, 1),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.TSD",
                        description: "If 1, then bit 2 (Time Stamp Disable) of CR4 is allowed to be 1. Bit 2 of CR4 restricts the execution of the RDTS instruction to procedures running at privilege level 0 when set.",
                        bits_range: (2, 2),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.DE",
                        description: "If 1, then bit 3 (Debugging extensions) of CR4 is allowed to be 1. Bit 3 of CR4 make references to debug registers DR4 and DR5 cause an undefined opcode exception when set",
                        bits_range: (3, 3),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.PSE",
                        description: "If 1, then bit 4 (Page Size Extensions) of CR4 is allowed to be 1. Bit 4 of CR4 enables 4-MByte pages with 32-bit paging when set",
                        bits_range: (4, 4),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.PAE",
                        description: "If 1, then bit 5 (Physical Address Extension) of CR4 is allowed to be 1. Bit 5 of CR4 enables paging to produce physical addresses of more than 32 bits when set",
                        bits_range: (5, 5),
                        policy: ProfilePolicy::Inherit
                    },
                    // TODO: Perhaps we should force this to 0?
                    ValueDefinition {
                        short: "CR4.MCE",
                        description: "If 1, then bit 6 (Machine-Check Enable) of CR4 is allowed to be 1. Bit 6 of CR4 enables the machine-check exception when set",
                        bits_range: (6, 6),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.PGE",
                        description: "If 1, then bit 7 (Page Global Enable) of CR4 is allowed to be 1. Bit 7 of CR4 enables the global page feature when set",
                        bits_range: (7, 7),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.PCE",
                        description: "If 1, then bit 8 (Performance-Monitoring Counter Enable) of CR4 is allowed to be 1. The RDPMC instruction can be executed at any protection level when bit 8 of CR4 is set.",
                        bits_range: (8, 8),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.OSFXSR",
                        description: "If 1, then bit 9 (OS Support for FXSAVE and FXRSTOR) of CR4 is allowed to be 1. See Intel SDM Vol.3A Section 2.5 for more information.",
                        bits_range: (9, 9),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.OSXMMEXCPT",
                        description: "If 1, then bit 10 (OS Support for Unmaksed SIMD Floating-Point Exceptions) of CR4 is allowed to be 1. See Intel SDM Vol.3A Section 2.5 for more information.",
                        bits_range: (10, 10),
                        policy: ProfilePolicy::Inherit
                    },
                    // TODO: Is this always 0 for QEMU?
                    ValueDefinition {
                        short: "CR4.UMIP",
                        description: "If 1, then bit 11 (User-Mode instruction Prevention) of CR4 is allowed to be 1. If bit 11 of CR4 is set and CPL > 0 then the SGDT,SIDT,SLDT,SMSW and STR instructions cannot be executed.",
                        bits_range: (11, 11),
                        policy: ProfilePolicy::Inherit
                    },
                    // Maybe this could even be passthrogh? CHV is 64-bit only.
                    ValueDefinition {
                        short: "CR4.LA57",
                        description: "If 1, then bit 12 (57-bit linear addresses) of CR4 is allowed to be 1. See Intel SDM Vol.3A Section 2.5 for more information.",
                        bits_range: (12, 12),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.VMXE",
                        description: "If 1, then bit 13 (VMX-Enable) of CR4 is allowed to be 1. Bit 13 of CR4 enables VMX operation when set.",
                        bits_range: (13, 13),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.SMXE",
                        description: "If 1, then bit 14 (SMX-Enable) of CR4 is allowed to be 1. Bit 14 of CR4 enables SMX operation when set.",
                        bits_range: (14, 14),
                        policy: ProfilePolicy::Static(0)
                    },
                    ValueDefinition {
                        short: "CR4.RESERVED_15",
                        description: "If 1, then bit 15 (RESERVED) of CR4 is allowed to be 1. See Intel SDM Vol.3A Section 2.5 for more information.",
                        bits_range: (15, 15),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.FSGSBASE",
                        description: "If 1, then bit 16 (FSGSBASE-Enable) of CR4 is allowed to be 1. See Intel SDM Vol.3A Section 2.5 for more information",
                        bits_range: (16, 16),
                        policy: ProfilePolicy::Inherit
                    },
                    // Probably irrelevant?
                    ValueDefinition {
                        short: "CR4.PCIDE",
                        description: "If 1, then bit 17 (PCID-Enable) of CR4 is allowed to be 1. Enables process-context identifiers (PCIDs) when bit 17 of CR4 is set. Applies only in IA-32e mode",
                        bits_range: (17, 17),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.OSXSAVE",
                        description: "If 1, then bit 18 (XSAVE and Processor Extended States-Enable) of CR4 is allowed to be 1. See Intel SDM Vol.3A Section 2.5 for more information",
                        bits_range: (18, 18),
                        policy: ProfilePolicy::Inherit
                    },
                    // CPU Profiles do not support Key locker features for now
                    ValueDefinition {
                        short: "CR4.KL",
                        description: "If 1, then bit 19 (Key-Locker-Enable) of CR4 is allowed to be 1. When bit 19 of CR4 is set, the LOADIWKEY instruction is enabled and CPUID.0x19.EBX[0] is set if support for AES key locker instructions has been activated by system firmware",
                        bits_range: (19, 19),
                        policy: ProfilePolicy::Static(0)
                    },
                    ValueDefinition {
                        short: "CR4.SMEP",
                        description: "If 1, then bit 20 (SMEP-Enable) of CR4 is allowed to be 1. Bit 20 of CR4 enables supervisor-mode execution prevention when set",
                        bits_range: (20, 20),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.SMAP",
                        description: "If 1, then bit 21 (SMAP-Enable) of CR4 is allowed to be 1. Bit 21 of CR4 enables supervisor-mode access prevention when set",
                        bits_range: (21, 21),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.PKE",
                        description: "If 1, then bit 22 (Enable protection keys for user-mode pages) of CR4 is allowed to be 1. When bit 22 of CR4 is set, CPUID.0x7.ECX[4] is displayed as 1. See Intel SDM Vol. 3.A Section 2.5 for more information.",
                        bits_range: (22, 22),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.CET",
                        description: "If 1, then bit 23 (Control-flow Enforcement Technology) of CR4 is allowed to be 1. See Intel SDM Vol. 3.A Section 2.5 for more information.",
                        bits_range: (23, 23),
                        policy: ProfilePolicy::Static(0)
                    },
                    ValueDefinition {
                        short: "CR4.PKS",
                        description: "If 1, then bit 24 (Enable protection keys for supervisor-mode pages) of CR4 is allowed to be 1. See Intel SDM Vol. 3.A Section 2.5 for more information.",
                        bits_range: (24, 24),
                        policy: ProfilePolicy::Static(0)
                    },
                    ValueDefinition {
                        short: "CR4.UINTR",
                        description: "If 1, then bit 25 (User Interrupts Enable) of CR4 is allowed to be 1. Bit 25 of CR4 enables user interrupts when set.",
                        bits_range: (25, 25),
                        policy: ProfilePolicy::Static(0)
                    },
                    ValueDefinition {
                        short: "CR4.RESERVED_26",
                        description: "If 1, then bit 26 (RESERVED) of CR4 is allowed to be 1. See Intel SDM Vol.3A Section 2.5 for more information.",
                        bits_range: (26, 26),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.LASS",
                        description: "If 1, then bit 27 (User Interrupts Enable) of CR4 is allowed to be 1. Bit 27 of CR4 enables LASS (Linear-Address-Space Separation) when set.",
                        bits_range: (27, 27),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.LAM_SUP",
                        description: "If 1, then bit 28 (Supervisor LAM-enable) of CR4 is allowed to be 1. Bit 28 of CR4 enables LAM (linear-address masking) for supervisor pointers when set.",
                        bits_range: (28, 28),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "CR4.RESERVED_29_63",
                        description: "Reports bits allowed to be 1 in CR4",
                        bits_range: (29, 63),
                        policy: ProfilePolicy::Inherit
                    }
                ])
            ),

            (
                RegisterAddress::IA32_VMX_VMCS_ENUM,
                ValueDefinitions::new(&[
                    ValueDefinition{
                        short: "MAX_INDEX",
                        description: "highest index value used for any VCMS encoding",
                        bits_range: (1, 9),
                        policy: ProfilePolicy::Inherit
                    }
                ])

            ),

            (
                RegisterAddress::IA32_VMX_PROCBASED_CTLS2,
                ValueDefinitions::new(&[
                    // Intel SDM Vol.3D A.3.3 documents that the ALLOWED_ZERO bits are actually always 0 for this MSR.
                  ValueDefinition {
                      short:"ALLOWED_ZERO_VIRTUALIZE_APIC_ACCESSES",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (0, 0),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_ENABLE_EPT",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (1, 1),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_DESCRIPTOR_TABLE_EXITING",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (2, 2),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_ENABLE_RDTSCP",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (3, 3),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_VIRTUALIZE_X2APIC_MODE",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (4, 4),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_ENABLE_VPID",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (5, 5),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_WBINVD_EXITING",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (6, 6),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_UNRESTRICTED_GUEST",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (7, 7),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_APIC_REGISTER_VIRTUALIZATION",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (8, 8),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_VIRTUAL_INTERRUPT_DELIVERY",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (9, 9),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_PAUSE_LOOP_EXITING",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (10, 10),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_RDRAND_EXITING",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (11, 11),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_ENABLE_INVPCID",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (12, 12),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_ENABLE_VM_FUNCTIONS",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (13, 13),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_VMCS_SHADOWING",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (14, 14),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_ENABLE_ENCLS_EXITING",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (15, 15),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_RDSEED_EXITING",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (16, 16),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_ENABLE_PML",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (17, 17),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_EPT_VIOLATION_#VE",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (18, 18),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_CONCEAL_VMX_FROM_PT",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (19, 19),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_ENABLE_XSAVES/XRSTORS",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (20, 20),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_PASID_TRANSLATION",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (21, 21),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_MODE_BASED_EXECUTE_CONTROL_FOR_EPT",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (22, 22),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_SUB_PAGE_WRITE_PERMISSIONS_FOR_EPT",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (23, 23),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_INTEL_PT_USES_GUEST_PHYSICAL_ADDRESSES",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (24, 24),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_USE_TSC_SCALING",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (25, 25),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_ENABLE_USER_WAIT_AND_PAUSE",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (26, 26),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_ENABLE_PCONFIG",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (27, 27),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_28_29",
                      description: "Control X is allowed to be 0 if bit X of this MSR is 0",
                      bits_range: (28, 29),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_VMM_BUS_LOCK_DETECTION",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (30, 30),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_INSTRUCTION_TIMEOU",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (31, 31),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_VIRTUALIZE_APIC_ACCESSES",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (32, 32),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_ENABLE_EPT",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (33, 33),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_DESCRIPTOR_TABLE_EXITING",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (34, 34),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_ENABLE_RDTSCP",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (35, 35),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_VIRTUALIZE_X2APIC_MODE",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (36, 36),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_ENABLE_VPID",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (37, 37),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_WBINVD_EXITING",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (38, 38),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_UNRESTRICTED_GUEST",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (39, 39),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_APIC_REGISTER_VIRTUALIZATION",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (40, 40),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_VIRTUAL_INTERRUPT_DELIVERY",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (41, 41),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_PAUSE_LOOP_EXITING",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (42, 42),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_RDRAND_EXITING",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (43, 43),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_ENABLE_INVPCID",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (44, 44),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_ENABLE_VM_FUNCTIONS",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (45, 45),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_VMCS_SHADOWING",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (46, 46),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_ENABLE_ENCLS_EXITING",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (47, 47),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_RDSEED_EXITING",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (48, 48),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_ENABLE_PML",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (49, 49),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_EPT_VIOLATION_#VE",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (50, 50),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_CONCEAL_VMX_FROM_PT",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (51, 51),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_ENABLE_XSAVES/XRSTORS",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (52, 52),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_PASID_TRANSLATION",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (53, 53),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_MODE_BASED_EXECUTE_CONTROL_FOR_EPT",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (54, 54),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_SUB_PAGE_WRITE_PERMISSIONS_FOR_EPT",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (55, 55),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_INTEL_PT_USES_GUEST_PHYSICAL_ADDRESSES",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (56, 56),
                      policy: ProfilePolicy::Static(0)
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_USE_TSC_SCALING",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (57, 57),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_ENABLE_USER_WAIT_AND_PAUSE",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (58, 58),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_ENABLE_PCONFIG",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (59, 59),
                      policy: ProfilePolicy::Static(0)
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_28_29",
                      description: "Control X is allowed to be 1 if bit X of this MSR is 1",
                      bits_range: (60, 61),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_VMM_BUS_LOCK_DETECTION",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (62, 62),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_INSTRUCTION_TIMEOUT",
                      description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-7. (Definitions of Secondary Processor-Based VM-Execution Controls)",
                      bits_range: (63, 63),
                      policy: ProfilePolicy::Inherit
                  },
              ])
            ),
            (
                RegisterAddress::IA32_VMX_EPT_VPID_CAP,
                ValueDefinitions::new(&[
                    ValueDefinition{
                        short: "EPT_EXECUTE_ONLY",
                        description: "The processor supports execute-only translations by EPT",
                        bits_range: (0, 0),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "PAGE_WALK_LENGTH_4",
                        description: "Support for Page-walk length of 4",
                        bits_range: (6, 6),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "PAGE_WALK_LENGTH_5",
                        description: "Support for Page-walk length of 5",
                        bits_range: (7, 7),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "EPT_MEM_TYPE_UC",
                        description: "Software can configure the EPT paging structure to memory type to be unreachable (UC)",
                        bits_range: (8, 8),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "EPT_MEM_TYPE_WB",
                        description: "Software can configure the EPT paging structure to memory type to be write-back (WB)",
                        bits_range: (14, 14),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "EPT_PDE_2M",
                        description: "Software can configure the EPT PDE to map a 2-Mbyte page",
                        bits_range: (16, 16),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "EPT_PDPTE_1G",
                        description: "Software can configure the EPT PDPTE to map a 1-Gbyte page",
                        bits_range: (17, 17),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "INVEPT",
                        description: "INVEPT instruction is supported",
                        bits_range: (20, 20),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition {
                        short: "FLAGS_EPT",
                        description: "Accessed and dirty flags for EPT are supported",
                        bits_range: (21, 21),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition {
                        short: "VM_EXIT_VIOLATIONS_INFO",
                        description: "If set, the processors advanced VM-exit information for EPT violations",
                        bits_range: (22, 22),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition {
                        short: "SHADOW_STACK_CTL",
                        description: "Supervisor shadow-stack control is supported",
                        bits_range: (23, 23),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "SINGLE_CONTEXT_INVEPT",
                        description: "The single-context INVEPT type is supported",
                        bits_range: (25, 25),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "ALL_CONTEXT_INVEPT",
                        description: "The all-context INVEPT type is supported",
                        bits_range: (26, 26),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "INVVPID",
                        description: "INVVPID instruction is supported",
                        bits_range: (32, 32),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "INDIVIDUAL_ADDRESS_INVVPID",
                        description: "The individual address INVVPID type is supported",
                        bits_range: (40, 40),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "SINGLE_CONTEXT_INVVPID",
                        description: "The single-context INVVPID type is supported",
                        bits_range: (41, 41),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "ALL_CONTEXT_INVVPID",
                        description: "The all-context INVEPT type is supported",
                        bits_range: (42, 42),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "SINGLE_CONTEXT_RETAINING_GLOBALS_INVVPID",
                        description: "The single-context-retaining-globals INVVPID type is supported",
                        bits_range: (43, 43),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "MAX_HLAT_PREFIX",
                        description: "Enumerates the maximum HLAT prefix size",
                        bits_range: (48, 53),
                        policy: ProfilePolicy::Inherit
                    },
                ])
            ),

            (

                RegisterAddress::IA32_VMX_TRUE_PINBASED_CTLS,
                ValueDefinitions::new(&[
                  ValueDefinition {
                      short:"ALLOWED_ZERO_EXTERNAL_INTERRUPT_EXITING",
                      description: "See Intel SDM Vol.3C Section 26.6.1 Table 26-5 (Definitions of Pin-Based VM-Execution Controls)",
                      bits_range: (0, 0),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_1_2",
                      description: "VM entry allows control X to be 0 if bit X in this MSR is zero",
                      bits_range: (1, 2),
                      policy: ProfilePolicy::Inherit
                  },
                    ValueDefinition {
                      short:"ALLOWED_ZERO_NMI_EXITING",
                      description: "See Intel SDM Vol.3C Section 26.6.1 Table 26-5 (Definitions of Pin-Based VM-Execution Controls)",
                      bits_range: (3, 3),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_4",
                      description: "VM entry allows control X to be 0 if bit X in this MSR is zero",
                      bits_range: (4, 4),
                      policy: ProfilePolicy::Inherit
                  },
                    ValueDefinition {
                      short:"ALLOWED_ZERO_VIRTUAL_NMIS",
                      description: "See Intel SDM Vol.3C Section 26.6.1 Table 26-5 (Definitions of Pin-Based VM-Execution Controls)",
                      bits_range: (5, 5),
                      policy: ProfilePolicy::Inherit
                  },
                    ValueDefinition {
                      short:"ALLOWED_ZERO_ACTIVATE_VMX_PREEMPTION_TIMER",
                      description: "See Intel SDM Vol.3C Section 26.6.1 Table 26-5 (Definitions of Pin-Based VM-Execution Controls)",
                      bits_range: (6, 6),
                      policy: ProfilePolicy::Inherit
                  },
                    ValueDefinition {
                      short:"ALLOWED_ZERO_PROCESS_POSTED_INTERRUPTS",
                      description: "See Intel SDM Vol.3C Section 26.6.1 Table 26-5 (Definitions of Pin-Based VM-Execution Controls)",
                      bits_range: (7, 7),
                      policy: ProfilePolicy::Inherit
                  },


                  ValueDefinition {
                      short: "ALLOWED_ZERO",
                      description: "VM entry allows control X to be 0 if bit X in this MSR is zero",
                      bits_range: (8, 31),
                      policy: ProfilePolicy::Inherit
                  },

                  ValueDefinition{
                      short:"ALLOWED_ONE_EXTERNAL_INTERRUPT_EXITING", 
                      description: "See Intel SDM Vol.3C Section 26.6.1 Table 26-5 (Definitions of Pin-Based VM-Execution Controls)",
                      bits_range: (32, 32),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ONE_1_2",
                      description: "VM entry allows control X to be 1 if bit X in this MSR is 1",
                      bits_range: (33, 34),
                      policy: ProfilePolicy::Inherit
                  },
                      ValueDefinition{
                      short:"ALLOWED_ONE_NMI_EXITING", 
                      description: "See Intel SDM Vol.3C Section 26.6.1 Table 26-5 (Definitions of Pin-Based VM-Execution Controls)",
                      bits_range: (35, 35),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ONE_4",
                      description: "VM entry allows control X to be 1 if bit X in this MSR is 1",
                      bits_range: (36, 36),
                      policy: ProfilePolicy::Inherit
                  },
                      ValueDefinition{
                      short:"ALLOWED_ONE_VIRTUAL_NMIS", 
                      description: "See Intel SDM Vol.3C Section 26.6.1 Table 26-5 (Definitions of Pin-Based VM-Execution Controls)",
                      bits_range: (37, 37),
                      policy: ProfilePolicy::Inherit
                  },
                      ValueDefinition{
                      short:"ALLOWED_ONE_ACTIVATE_VMX__PREEMPTION_TIMER", 
                      description: "See Intel SDM Vol.3C Section 26.6.1 Table 26-5 (Definitions of Pin-Based VM-Execution Controls)",
                      bits_range: (38, 38),
                      policy: ProfilePolicy::Inherit
                  },
                      ValueDefinition{
                      short:"ALLOWED_ONE_PROCESS_POSTED_INTERRUPTS", 
                      description: "See Intel SDM Vol.3C Section 26.6.1 Table 26-5 (Definitions of Pin-Based VM-Execution Controls)",
                      bits_range: (39, 39),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ONE",
                      description:"VM entry allows control X to be 1 if bit X + 32 in this MSR is 1",
                      bits_range: (40, 63),
                      policy: ProfilePolicy::Inherit
                  }
              ])
            ),

            (
                RegisterAddress::IA32_VMX_TRUE_PROCBASED_CTLS,
                ValueDefinitions::new(&[
                  ValueDefinition {
                      short: "ALLOWED_ZERO_0_1",
                      description: "Control X is allowed to be 0 if bit X of this MSR is 0",
                      bits_range: (0, 1),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_INTERRUPT_WINDOW_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (2, 2),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_USE_TSC_OFFSETTING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (3, 3),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_4_6",
                      description: "Control X is allowed to be 0 if bit X of this MSR is 0",
                      bits_range: (4, 6),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_HLT_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (7, 7),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_8",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (8, 8),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_INVLPG_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (9, 9),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_MWAIT_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (10, 10),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_RDPMC_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (11, 11),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_RDTSC_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (12, 12),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_13_14",
                      description: "Control X is allowed to be 0 if bit X of this MSR is 0",
                      bits_range: (13, 14),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_CR3_LOAD_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (15, 15),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_CR3_STORE_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (16, 16),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_ACTIVATE_TERTIARY_CONTROLS",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (17, 17),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_18",
                      description: "Control X is allowed to be 0 if bit X of this MSR is 0",
                      bits_range: (18, 18),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_CR8_LOAD_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (19, 19),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_CR8_STORE_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (20, 20),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_USE_TPR_SHADOW",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (21, 21),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_NMI_WINDOW_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (22, 22),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_MOV_DR_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (23, 23),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_UNCONDITIONAL_I/O_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (24, 24),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_USE_I/O_BITMAPS",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (25, 25),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_26",
                      description: "Control X is allowed to be 0 if bit X of this MSR is 0",
                      bits_range: (26, 26),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_MONITOR_TRAP_FLAG",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (27, 27),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_USE_MSR_BITMAPS",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (28, 28),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_MONITOR_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (29, 29),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_PAUSE_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (30, 30),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_ACTIVATE_SECONDARY_CONTROLS",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (31, 31),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short: "ALLOWED_ONE_0_1",
                      description: "Control X is allowed to be 1 if bit 32 + X of this MSR is 1",
                      bits_range: (32, 33),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_INTERRUPT_WINDOW_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (34, 34),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_USE_TSC_OFFSETTING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (35, 35),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short: "ALLOWED_ONE_4_6",
                      description:"VM entry allows control X to be 1 if bit X + 32 in this MSR is 1",
                      bits_range: (36, 38),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_HLT_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (39, 39),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short: "ALLOWED_ONE_8",
                      description:"VM entry allows control X to be 1 if bit X + 32 in this MSR is 1",
                      bits_range: (40, 40),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_INVLPG_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (41, 41),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_MWAIT_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (42, 42),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_RDPMC_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (43, 43),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_RDTSC_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (44, 44),
                      policy: ProfilePolicy::Inherit
                      },

                    ValueDefinition {
                      short: "ALLOWED_ONE_13_14",
                      description:"VM entry allows control X to be 1 if bit X + 32 in this MSR is 1",
                      bits_range: (45, 46),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_CR3_LOAD_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (47, 47),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_CR3_STORE_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (48, 48),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_ACTIVATE_TERTIARY_CONTROLS",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (49, 49),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short: "ALLOWED_ONE_18",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (50, 50),
                      policy: ProfilePolicy::Inherit
                  },

                  ValueDefinition {
                      short:"ALLOWED_ONE_CR8_LOAD_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (51, 51),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_CR8_STORE_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (52, 52),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_USE_TPR_SHADOW",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (53, 53),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_NMI_WINDOW_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (54, 54),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_MOV_DR_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (55, 55),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_UNCONDITIONAL_I/O_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (56, 56),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_USE_I/O_BITMAPS",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (57, 57),
                      policy: ProfilePolicy::Inherit
                      },
                    ValueDefinition {
                      short: "ALLOWED_ONE_26",
                      description: "Control X is allowed to be 1 if bit X of this MSR is 1",
                      bits_range: (58, 58),
                      policy: ProfilePolicy::Inherit
                  },

                  ValueDefinition {
                      short:"ALLOWED_ONE_MONITOR_TRAP_FLAG",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (59, 59),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_USE_MSR_BITMAPS",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (60, 60),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_MONITOR_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (61, 61),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_PAUSE_EXITING",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (62, 62),
                      policy: ProfilePolicy::Inherit
                      },
                  ValueDefinition {
                      short:"ALLOWED_ONE_ACTIVATE_SECONDARY_CONTROLS",
                      description: "See Intel SDM. Vol.3C Section 26.6.2 Table 26-6 (Definitions of Primary Processor-Based VM-Execution Controls)",
                      bits_range: (63, 63),
                      policy: ProfilePolicy::Inherit
                      },

              ])
            ),

            (
                RegisterAddress::IA32_VMX_TRUE_EXIT_CTLS,
                ValueDefinitions::new(&[
                  ValueDefinition {
                      short: "ALLOWED_ZERO_0_1",
                      description: "Control X is allowed to be 0 if bit X in this MSR is 0",
                      bits_range: (0, 1),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_SAVE_DEBUG_CONTROLS",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (2, 2),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_3_8",
                      description: "Control X is allowed to be 0 if bit X in this MSR is 0",
                      bits_range: (3, 8),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_HOST_ADDRESS_SPACE_SIZE",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (9, 9),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_10_11",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (10, 11),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_IA32_PERF_GLOBAL_CTRL",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (12, 12),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_13_14",
                      description: "Control X is allowed to be 0 if bit X in this MSR is 0",
                      bits_range: (13, 14),
                      policy: ProfilePolicy::Inherit
                   },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_ACKNOWLEDGE_INTERRUPT_O_EXIT",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (15, 15),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_16_17",
                      description: "Control X is allowed to be 0 if bit X in this MSR is 0",
                      bits_range: (16, 17),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_SAVE_IA32_PAT",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (18, 18),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_IA32_PAT",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (19, 19),
                      policy: ProfilePolicy::Inherit
                 },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_SAVE_IA32_EFER",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (20, 20),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_IA32_EFER",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (21, 21),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_SAVE_VMX_PREEMPTION_TIMER_VALUE",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (22, 22),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_CLEAR_IA32_BNDCFGS",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (23, 23),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_CONCEAL_VMX_FROM_PT",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (24, 24),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_CLEAR_IA32_RTIT_CTL",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (25, 25),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_CLEAR_IA32_LBR_CTL",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (26, 26),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_CLEAR_UINV",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (27, 27),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_CET_STATE",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (28, 28),
                      policy: ProfilePolicy::Static(0)
                },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_PKRS",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (29, 29),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_SAVE_IA32_PERF_GLOBAL_CTL",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (30, 30),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_ACTIVATE_SECONDARY_CONTROLS",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (31, 31),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short: "ALLOWED_ONE_0_1",
                      description: "Control X is allowed to be 1 if bit X in this MSR is 1",
                      bits_range: (32, 33),
                      policy: ProfilePolicy::Inherit
                },

                  ValueDefinition {
                    short:"ALLOWED_ONE_SAVE_DEBUG_CONTROLS",
                    description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                    bits_range: (34, 34),
                    policy: ProfilePolicy::Inherit
                },

                    ValueDefinition {
                      short: "ALLOWED_ONE_3_8",
                      description: "Control X is allowed to be 1 if bit X in this MSR is 1",
                      bits_range: (35, 40),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_HOST_ADDRESS_SPACE_SIZE",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (41, 41),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ONE_10_11",
                      description: "Control X is allowed to be 1 if bit X in this MSR is 1",
                      bits_range: (42, 43),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_IA32_PERF_GLOBAL_CTRL",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (44, 44),
                      policy: ProfilePolicy::Static(0)
                },
                  ValueDefinition {
                      short: "ALLOWED_ONE_13_14",
                      description: "Control X is allowed to be 1 if bit X in this MSR is 1",
                      bits_range: (45, 46),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_ACKNOWLEDGE_INTERRUPT_O_EXIT",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (47, 47),
                      policy: ProfilePolicy::Inherit
                },
                 ValueDefinition {
                      short: "ALLOWED_ONE_16_17",
                      description: "Control X is allowed to be 1 if bit X in this MSR is 1",
                      bits_range: (48, 49),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_SAVE_IA32_PAT",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (50, 50),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_IA32_PAT",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (51, 51),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ONE_SAVE_IA32_EFER",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (52, 52),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_IA32_EFER",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (53, 53),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ONE_SAVE_VMX_PREEMPTION_TIMER_VALUE",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (54, 54),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ONE_CLEAR_IA32_BNDCFGS",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (55, 55),
                      policy: ProfilePolicy::Static(0)
                },
                  ValueDefinition {
                      short:"ALLOWED_ONE_CONCEAL_VMX_FROM_PT",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (56, 56),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ONE_CLEAR_IA32_RTIT_CTL",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (57, 57),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ONE_CLEAR_IA32_LBR_CTL",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (58, 58),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ONE_CLEAR_UINV",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (59, 59),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_CET_STATE",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (60, 60),
                      policy: ProfilePolicy::Static(0)
                },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_PKRS",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (61, 61),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ONE_SAVE_IA32_PERF_GLOBAL_CTL",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (62, 62),
                      policy: ProfilePolicy::Static(0)
                },
                  ValueDefinition {
                      short:"ALLOWED_ONE_ACTIVATE_SECONDARY_CONTROLS",
                      description: "See Intel SDM Vol.3C Section 26.7.1 Table 26-14 (Definitions of Primary VM-Exit Controls)",
                      bits_range: (63, 63),
                      policy: ProfilePolicy::Inherit
                },
                ])
            ),

            (
                RegisterAddress::IA32_VMX_TRUE_ENTRY_CTLS,
                ValueDefinitions::new(&[
                  ValueDefinition {
                      short: "ALLOWED_ZERO_0_1",
                      description: "VM entry allows control X to be 0 if bit X in this MSR is zero",
                      bits_range: (0, 1),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_DEBUG_CONTROLS",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (2, 2),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_3_8",
                      description: "VM entry allows control X to be 0 if bit X in this MSR is zero",
                      bits_range: (3, 8),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_IA_32E_MODE_GUES",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (9, 9),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_ENTRY_TO_SMM",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (10, 10),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_DEACTIVATE_DUAL__MONITOR_TREATMENT",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (11, 11),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_12",
                      description: "VM entry allows control X to be 0 if bit X in this MSR is zero",
                      bits_range: (12, 12),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_IA32_PERF_GLOBAL_CTRL",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (13, 13),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_IA32_PAT",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (14, 14),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_IA32_EFER",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (15, 15),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_IA32_BNDCFGS",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (16, 16),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_CONCEAL_VMX_FROM_PT",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (17, 17),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_IA32_RTIT_CTL",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (18, 18),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_UINV",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (19, 19),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_CET_STATE",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (20, 20),
                      policy: ProfilePolicy::Static(0)
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_GUEST_IA32_LBR_CTL",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (21, 21),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_LOAD_PKRS",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (22, 22),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_23_24",
                      description: "VM entry allows control X to be 0 if bit X in this MSR is zero",
                      bits_range: (23, 24),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ZERO_ALLOW_SEAM_GUEST_TELEMETRY",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (25, 25),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ZERO_26_31",
                      description: "VM entry allows control X to be 0 if bit X in this MSR is zero",
                      bits_range: (26, 31),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ONE_0_1",
                      description:"VM entry allows control X to be 1 if bit X + 32 in this MSR is 1",
                      bits_range: (32, 33),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_DEBUG_CONTROLS",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (34, 34),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ONE_3_8",
                      description:"VM entry allows control X to be 1 if bit X + 32 in this MSR is 1",
                      bits_range: (35, 40),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_IA_32E_MODE_GUES",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (41, 41),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_ENTRY_TO_SMM",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (42, 42),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_DEACTIVATE_DUAL__MONITOR_TREATMENT",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (43, 43),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ONE_12",
                      description:"VM entry allows control X to be 1 if bit X + 32 in this MSR is 1",
                      bits_range: (44, 44),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_IA32_PERF_GLOBAL_CTRL",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (45, 45),
                      policy: ProfilePolicy::Static(0)
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_IA32_PAT",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (46, 46),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_IA32_EFER",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (47, 47),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_IA32_BNDCFGS",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (48, 48),
                      policy: ProfilePolicy::Static(0)
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_CONCEAL_VMX_FROM_PT",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (49, 49),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_IA32_RTIT_CTL",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (50, 50),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_UINV",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (51, 51),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_CET_STATE",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (52, 52),
                      policy: ProfilePolicy::Static(0)
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_GUEST_IA32_LBR_CTL",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (53, 53),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_LOAD_PKRS",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (54, 54),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ONE_23_24",
                      description:"VM entry allows control X to be 1 if bit X + 32 in this MSR is 1",
                      bits_range: (55, 56),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short:"ALLOWED_ONE_ALLOW_SEAM_GUEST_TELEMETRY",
                      description: "See Intel SDM Vol.3C Section 26.8.1 Table 26-17. (Definitions of VM-Entry Controls)",
                      bits_range: (57, 57),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ONE_26_31",
                      description:"VM entry allows control X to be 1 if bit X + 32 in this MSR is 1",
                      bits_range: (58, 63),
                      policy: ProfilePolicy::Inherit
                  },
                ])
            ),

            (
              RegisterAddress::IA32_VMX_VMFUNC,
              ValueDefinitions::new(&[
                  ValueDefinition {
                      short:"ALLOWED_ONE_EPTP_SWITCHING",
                      description: "See Intel SDM Vol.3C Section 26.6.14 Table 26-10. (Definitions of VM-Function Controls)",
                      bits_range: (0, 0),
                      policy: ProfilePolicy::Inherit
                },
                  ValueDefinition {
                      short:"ALLOWED_ONE_1_63",
                      description: "See Intel SDM Vol.3C Section 26.6.14 Table 26-10. (Definitions of VM-Function Controls)",
                      bits_range: (1, 63),
                      policy: ProfilePolicy::Inherit
                },

              ])
            ),

            // NOTE: This MSR is currently not supported by KVM. We keep the definition here regardless. (TODO: Maybe it would be better to remove it?)
            (
                RegisterAddress::IA32_VMX_PROCBASED_CTLS3,
                ValueDefinitions::new(&[
                    ValueDefinition {
                        short: "ALLOWED_ONE_LOADIWKEY_EXITING",
                        description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-8 (Definitions of Tertiary Processor-Based VM-Execution Controls)",
                        bits_range: (0,0),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "ALLOWED_ONE_ENABLE_HLAT",
                        description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-8 (Definitions of Tertiary Processor-Based VM-Execution Controls)",
                        bits_range: (1,1),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "ALLOWED_ONE_EPT_PAGING_WRITE_CONTROL",
                        description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-8 (Definitions of Tertiary Processor-Based VM-Execution Controls)",
                        bits_range: (2,2),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "ALLOWED_ONE_GUEST_PAGING_VERIFICATION",
                        description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-8 (Definitions of Tertiary Processor-Based VM-Execution Controls)",
                        bits_range: (3,3),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "ALLOWED_ONE_IPI_VIRTUALIZATION",
                        description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-8 (Definitions of Tertiary Processor-Based VM-Execution Controls)",
                        bits_range: (4,4),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "ALLOWED_ONE_SEAM_GUEST_PHYSICAL_ADDRESS_WIDTH",
                        description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-8 (Definitions of Tertiary Processor-Based VM-Execution Controls)",
                        bits_range: (5,5),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "ALLOWED_ONE_ENABLE_MSR_LIST_INSTRUCTIONS",
                        description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-8 (Definitions of Tertiary Processor-Based VM-Execution Controls)",
                        bits_range: (6,6),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "ALLOWED_ONE_VIRTUALIZE_IA32_SPEC_CTRL",
                        description: "See Intel SDM Vol.3C Section 26.6.2 Table 26-8 (Definitions of Tertiary Processor-Based VM-Execution Controls)",
                        bits_range: (7,7),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "ALLOWED_ONE_8_63",
                        description: "Control X is allowed to be 1 if bit X in this MSR is 1",
                        bits_range: (8,63),
                        policy: ProfilePolicy::Inherit
                    },
                ])
            ),

            // NOTE: This MSR is currently not supported by KVM. We keep the definition here regardless. (TODO: Maybe it would be better to remove it?)
            (
                RegisterAddress::IA32_VMX_EXIT_CTLS2,
                ValueDefinitions::new(&[
                  ValueDefinition {
                      short: "ALLOWED_ONE_0_2",
                      description:"VM entry allows control X to be 1 if bit X is 1",
                      bits_range: (0, 2),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ONE_PREMATURELY_BUSY_SHADOW_STACK",
                      description:"See Intel SDM Vol.3C Section 26.7.1",
                      bits_range: (3, 3),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ONE_4_63",
                      description:"VM entry allows control X to be 1 if bit X is 1",
                      bits_range: (4, 63),
                      policy: ProfilePolicy::Inherit
                  }
                ])
            ),
        (
        RegisterAddress::MSR_PLATFORM_INFO,
        ValueDefinitions::new(&[
            ValueDefinition {
                short: "PLATFORM_INFORMATION",
                description: "Contains power management and other model specific features enumeration. In reality bits 15:8 describe the maximum frequency that does not require turbo. All other bits are reserved",
                bits_range: (0, 63),
                policy: ProfilePolicy::Deny
            }
        ])
    )
    ])
};

/// Convenience function to lookup value definitions corresponding to the given MSR register address (as a const parameter).
#[cold]
#[inline(never)]
pub(in crate::x86_64) const fn msr_definitions<const REG_ADDR: u32>() -> &'static [ValueDefinition]
{
    const {
        let mut out = [].as_slice();
        let intel_definitions = INTEL_MSR_FEATURE_DEFINITIONS.as_slice();
        let mut i = 0;
        let length = intel_definitions.len();
        while i < length {
            let (addr, definitions) = intel_definitions[i];
            if addr.0 == REG_ADDR {
                out = definitions.as_slice();
                break;
            }
            i += 1;
        }
        if out.is_empty() {
            panic!("MSR definition not found");
        }
        out
    }
}

/// Check that the `src_feature_msrs` are compatible with those given in `dest_feature_msrs`.
///
/// If this check fails, then software that works under the `src_feature_msrs`, may no longer
/// behave correctly with `dest_feature_msrs`.
///
/// The `src_id` and `dest_id` strings are only used for logging purposes to identify what
/// is being compared (e.g. CPU profile vs host where the profile should be applied, etc).
///
/// NOTE: This function assumes CPUID compatibility.
///
/// All register addresses/keys in [`INTEL_MSR_FEATURE_DEFINITIONS`] are checked, except for:
/// - IA32_BIOS_SIGN_ID,
/// - IA32_PERF_CAPABILITIES,
/// - MSR_PLATFORM_INFO
///
/// IA32_PERF_CAPABILITIES are inherently incompatible between different VMs and we do not
/// think it makes much sense to compare IA32_BIOS_SIGN_ID or MSR_PLATFORM_INFO in this context.
///
/// # Errors
///
/// This function does not return early upon error, but rather attempts all MSR-based feature
/// checks while logging errors it encounters. If any of these checks fail an error is returned
/// at the end.
///
/// We also just use the unit type as the error variant for now, as not much can be done to
/// recover from these errors at runtime and the logs should provide the user with enough
/// information to debug the problem.
///
/// At this moment in time we prefer the aforementioned approach over designing a complex
/// error type capable of tracking everything that might fail.
pub(in crate::x86_64) fn check_feature_msr_compatibility(
    src_feature_msrs: &HashMap<u32, u64>,
    dest_feature_msrs: &HashMap<u32, u64>,
    src_id: &str,
    dest_id: &str,
) -> Result<(), ()> {
    let mut is_err = false;
    // First check IA32_ARCH_CAPABILITIES
    // Since we are assuming CPUID to be compatible we
    // may assume that either both src and dest have this
    // MSR or none of them do
    if let Some((src_val, dest_val)) = src_feature_msrs
        .get(&RegisterAddress::IA32_ARCH_CAPABILITIES.0)
        .zip(dest_feature_msrs.get(&RegisterAddress::IA32_ARCH_CAPABILITIES.0))
    {
        is_err |=
            check_arch_capabilities_compatibility(*src_val, *dest_val, src_id, dest_id).is_err();
    }

    // Next let us consider IA32_VMX_BASIC
    let mut true_ctls_exist_src = false;
    let mut true_ctls_exist_dest = false;
    // Since we assume compatibility of CPUID we can again check that either both src and dest
    // have the IA32_VMX_BASIC MSR or none of them do
    if let Some((src_val, dest_val)) = src_feature_msrs
        .get(&RegisterAddress::IA32_VMX_BASIC.0)
        .zip(dest_feature_msrs.get(&RegisterAddress::IA32_VMX_BASIC.0))
    {
        true_ctls_exist_src = (*src_val & (1 << 55)) != 0;
        true_ctls_exist_dest = (*dest_val & (1 << 55)) != 0;
        is_err |= check_vmx_basic_compatibility(*src_val, *dest_val, src_id, dest_id).is_err();
    }
    // The following closure saves us some boiler plate when checking the various VMX CTLS that have a default1 class
    let check_vmx_ctls_with_default1_class = |vmx_ctrl_reg_address: RegisterAddress,
                                              vmx_true_ctrl_reg_address: RegisterAddress,
                                              check_id: &str,
                                              src_id: &str,
                                              dest_id: &str|
     -> Result<(), ()> {
        let mut is_err = false;
        let src_reg_address = {
            conditional_select(
                vmx_ctrl_reg_address.0,
                vmx_true_ctrl_reg_address.0,
                true_ctls_exist_src,
            )
        };

        let dest_reg_address = {
            conditional_select(
                vmx_ctrl_reg_address.0,
                vmx_true_ctrl_reg_address.0,
                true_ctls_exist_dest,
            )
        };

        let src_val = src_feature_msrs.get(&src_reg_address);
        let dest_val = dest_feature_msrs.get(&dest_reg_address);
        if src_val.is_some() && dest_val.is_none() {
            error!(
                "{check_id} compatibility check failed: unable to compare value of MSR {src_reg_address:#x} of {src_id} with value of MSR {dest_reg_address:#x} of {dest_id}, because the latter value was not found"
            );
            is_err = true;
        }
        if let Some((src_val, dest_val)) = src_val.zip(dest_val)
            && let Err(CtlsCheck {
                bitset_only_zero_src_lo,
                bitset_only_one_src_hi,
            }) = check_negative_subset_lo_and_subset_hi(*src_val, *dest_val)
        {
            is_err = true;
            if let Some(bitset) = bitset_only_zero_src_lo {
                for_each_bitpos(bitset, |bit_pos| {
                    debug!(
                        "{check_id} compatibility check failed: bit {bit_pos} is 0 in MSR:={src_reg_address:#x} of {src_id}, but 1 in MSR:={dest_reg_address:#x} of {dest_id}"
                    );
                });
            }

            if let Some(bitset) = bitset_only_one_src_hi {
                for_each_bitpos(bitset, |bit_pos| {
                    debug!(
                        "{check_id} compatibility check failed: bit {bit_pos} is 1 in MSR:={src_reg_address:#x} of {src_id}, but 0 in MSR:={dest_reg_address:#x} of {dest_id}"
                    );
                });
            }
        }

        if is_err {
            if let Some(src_val) = src_val
                && let Some(dest_val) = dest_val
            {
                error!(
                    "{check_id} compatibility check failed: {src_id} register address:={src_reg_address:#x}, {src_id} value:={:#x}, {dest_id} register address:={dest_reg_address:#x}, {dest_id} value:={:#x}",
                    *src_val, *dest_val
                );
            }
            Err(())
        } else {
            Ok(())
        }
    };

    // Now we consider IA32_VMX_PINBASED_CTLS and/or IA32_VMX_TRUE_BINBASED_CTLS
    // (Intel SDM Vol.3D A.3.1)
    is_err |= check_vmx_ctls_with_default1_class(
        RegisterAddress::IA32_VMX_PINBASED_CTLS,
        RegisterAddress::IA32_VMX_TRUE_PINBASED_CTLS,
        "IA32_VMX_PINBASED_CTLS",
        src_id,
        dest_id,
    )
    .is_err();

    // Next up is IA32_VMX_PROCBASED_CTLS and/or IA32_VMX_TRUE_PROCBASED_CTLS
    // (Intel SDM Vol.3D A.3.2.)
    is_err |= check_vmx_ctls_with_default1_class(
        RegisterAddress::IA32_VMX_PROCBASED_CTLS,
        RegisterAddress::IA32_VMX_TRUE_PROCBASED_CTLS,
        "IA32_PROCBASED_CTLS",
        src_id,
        dest_id,
    )
    .is_err();
    // Check IA32_VMX_EXIT_CTLS and/or IA32_VMX_TRUE_EXIT_CTLS
    // (Intel SDM Vol.3D A.4)
    is_err |= check_vmx_ctls_with_default1_class(
        RegisterAddress::IA32_VMX_EXIT_CTLS,
        RegisterAddress::IA32_VMX_TRUE_EXIT_CTLS,
        "IA32_VMX_EXIT_CTLS",
        src_id,
        dest_id,
    )
    .is_err();
    // Check IA32_VMX_ENTRY_CTLS and/or IA32_VMX_TRUE_ENTRY_CTLS
    // (Intel SDM Vol.3D A.5)
    is_err |= check_vmx_ctls_with_default1_class(
        RegisterAddress::IA32_VMX_ENTRY_CTLS,
        RegisterAddress::IA32_VMX_TRUE_ENTRY_CTLS,
        "IA32_VMX_ENTRY_CTLS",
        src_id,
        dest_id,
    )
    .is_err();
    // Check IA32_VMX_MISC
    if let Some((src_val, dest_val)) = src_feature_msrs
        .get(&RegisterAddress::IA32_VMX_MISC.0)
        .zip(dest_feature_msrs.get(&RegisterAddress::IA32_VMX_MISC.0))
    {
        is_err |= check_vmx_misc_msr(*src_val, *dest_val, src_id, dest_id).is_err();
    }
    // Check IA32_VMX_CR0_FIXED0
    if let Some((src_fixed0, dest_fixed0)) = src_feature_msrs
        .get(&RegisterAddress::IA32_VMX_CR0_FIXED0.0)
        .zip(dest_feature_msrs.get(&RegisterAddress::IA32_VMX_CR0_FIXED0.0))
    {
        is_err |=
            check_cr_i_compatibility::<0>(*src_fixed0, *dest_fixed0, src_id, dest_id).is_err();
    }

    // Check IA32_VMX_CR4_FIXED0
    if let Some((src_fixed0, dest_fixed0)) = src_feature_msrs
        .get(&RegisterAddress::IA32_VMX_CR4_FIXED0.0)
        .zip(dest_feature_msrs.get(&RegisterAddress::IA32_VMX_CR4_FIXED0.0))
    {
        is_err |=
            check_cr_i_compatibility::<4>(*src_fixed0, *dest_fixed0, src_id, dest_id).is_err();
    }

    // Check IA32_VMX_VMCS_ENUM
    if let Some((src_val, dest_val)) = src_feature_msrs
        .get(&RegisterAddress::IA32_VMX_VMCS_ENUM.0)
        .zip(dest_feature_msrs.get(&RegisterAddress::IA32_VMX_VMCS_ENUM.0))
    {
        is_err |= check_vmx_vmcs_enum_compatibility(*src_val, *dest_val, src_id, dest_id).is_err();
    }

    // Check IA32_VMX_PROCBASED_CTLS2
    // This MSR exists only if bit 63 of IA32_VMX_PROCBASED_CTLS is set
    // (note that if it is set on src then our IA32_VMX_PROCBASED_CTLS check
    // ensures that it is also set on dest)
    if let Some((src_val, dest_val)) = src_feature_msrs
        .get(&RegisterAddress::IA32_VMX_PROCBASED_CTLS2.0)
        .zip(dest_feature_msrs.get(&RegisterAddress::IA32_VMX_PROCBASED_CTLS2.0))
    {
        let src_val = *src_val;
        let dest_val = *dest_val;
        // First verify that the first 32 bits are indeed 0 as documented by Intel, otherwise we have misunderstood the documentation
        // and we should not continue.
        let lo_mask = u64::from(u32::MAX);
        assert_eq!(
            src_val & lo_mask,
            0,
            "BUG: The 32-first bits of the IA32_VMX_PROCBASED_CTLS2 MSR were not zero for src"
        );
        assert_eq!(
            dest_val & lo_mask,
            0,
            "BUG: The 32-first bits of the IA32_VMX_PROCBASED_CTLS2 MSR were not zero for dest"
        );
        // Note that the 32-first bits are documented to always be 0
        if let Err(bits_only_in_src) = check_subset(src_val, dest_val) {
            is_err = true;
            error!(
                "IA32_VMX_PROCBASED_CTLS2 compatibility check failed: {src_id} value:={src_val:#x}, {dest_id} value:={dest_val:#x}"
            );
            for_each_bitpos(bits_only_in_src, |bit_pos| {
                debug!(
                    "IA32_VMX_PROCBASED_CTLS2 check failed: VM entry allows control X:={bit_pos} to be 1 for {src_id}, but not for {dest_id}"
                );
            });
        }
    }

    // Check IA32_VMX_PROCBASED_CTLS3
    // This MSR exists only if bit 49 of IA32_VMX_PROCBASED_CTLS is set
    // (note that if it is set on src then our IA32_VMX_PROCBASED_CTLS check
    // ensures that it is also set on dest)

    if let Some((src_val, dest_val)) = src_feature_msrs
        .get(&RegisterAddress::IA32_VMX_PROCBASED_CTLS3.0)
        .zip(dest_feature_msrs.get(&RegisterAddress::IA32_VMX_PROCBASED_CTLS3.0))
        && let Err(bits_only_in_src) = check_subset(*src_val, *dest_val)
    {
        is_err = true;
        error!(
            "IA32_VMX_PROCBASED_CTLS3 compatibility check failed: {src_id} value:= {:#x}, {dest_id} value:={:#x}",
            *src_val, *dest_val
        );

        for_each_bitpos(bits_only_in_src, |bit_pos| {
            debug!(
                "IA32_VMX_PROCBASED_CTLS3 compatibility check failed: VM entry allows control X:={bit_pos} for {src_id}, but not for {dest_id}"
            );
        });
    }

    // Check IA32_VMX_EXIT_CTLS2
    // This MSR exists only if bit 63 of the IA32_VMX_EXIT_CTLS is set
    // (note that if it is set on src then our IA32_VMX_EXIT_CTLS check
    // ensures that it is also set on dest)
    if let Some((src_val, dest_val)) = src_feature_msrs
        .get(&RegisterAddress::IA32_VMX_EXIT_CTLS2.0)
        .zip(dest_feature_msrs.get(&RegisterAddress::IA32_VMX_EXIT_CTLS2.0))
        && let Err(bits_only_in_src) = check_subset(*src_val, *dest_val)
    {
        is_err = true;
        error!(
            "IA32_VMX_EXIT_CTLS2 compatibility check failed: {src_id} value:={:#x}, {dest_id} value:={:#x}",
            *src_val, *dest_val
        );
        for_each_bitpos(bits_only_in_src, |bit_pos| {
            debug!(
                "IA32_VMX_EXIT_CTLS2 compatibility check failed: bit {bit_pos} is set for {src_id}, but not for {dest_id}"
            );
        });
    }

    // Check IA32_VMX_EPT_VPID_CAP (Intel SDM Vol.3D A.10)
    //
    // This MSR is only available on processors where bit 63 of IA32_VMX_PROCBASED_CTLS is 1 and that either
    // have bit 33 of IA32_VMX_PROCBASED_CTLS2 set, or bit 37 of IA32_VMX_PROC_BASED_CTLS2 set. Since we
    // already check for compatibility of those bits, we may assume that if this MSR is available for src, then
    // it is also available for dest.
    if let Some((src_val, dest_val)) = src_feature_msrs
        .get(&RegisterAddress::IA32_VMX_EPT_VPID_CAP.0)
        .zip(dest_feature_msrs.get(&RegisterAddress::IA32_VMX_EPT_VPID_CAP.0))
    {
        is_err |= check_vpid_and_ept_capabilities(*src_val, *dest_val, src_id, dest_id).is_err();
    }

    if let Some((src_val, dest_val)) = src_feature_msrs
        .get(&RegisterAddress::IA32_VMX_VMFUNC.0)
        .zip(dest_feature_msrs.get(&RegisterAddress::IA32_VMX_VMFUNC.0))
        && let Err(bits_only_in_src) = check_subset(*src_val, *dest_val)
    {
        is_err = true;
        error!(
            "IA32_VMX_VMFUNC compatibility check failed: {src_id} value:={:#x}, {dest_id} value:={:#x}",
            *src_val, *dest_val
        );
        for_each_bitpos(bits_only_in_src, |bit_pos| {
            debug!(
                "IA32_VMX_VMFUNC compatibility check failed: VM entry allows bit X:={bit_pos} of the VM-function controls to be 1 for {src_id}, but not for {dest_id}"
            );
        });
    }

    if is_err { Err(()) } else { Ok(()) }
}

/// `a` if `condition` else `b`
fn conditional_select(a: u32, b: u32, condition: bool) -> u32 {
    let a_mask = u32::from(condition).wrapping_neg();
    let b_mask = !a_mask;
    (a & a_mask) | (b & b_mask)
}

/// Check that the values of MSR IA32_ARCH_CAPABILITIES are compatible.
///
/// If this check fails then programs that work when the value is `src_val`, may possibly
/// no longer work if the value is `dest_val`.
///
/// See: Ch.2 Table 2-2. IA-32 Architectural MSRs in Intel SDM Vol.4
fn check_arch_capabilities_compatibility(
    src_val: u64,
    dest_val: u64,
    src_id: &str,
    dest_id: &str,
) -> Result<(), ()> {
    // Make a mask out of
    const RDCL_NO: u64 = 1 << 0;
    const IBRS_ALL: u64 = 1 << 1;
    const SKIP_L1_DFL_VMENTRY: u64 = 1 << 3;
    const SSB_NO: u64 = 1 << 4;
    const MDS_NO: u64 = 1 << 5;
    const TSX_CONTROL: u64 = 1 << 7;
    const TAA_NO: u64 = 1 << 8;
    const MCU_CONTROL: u64 = 1 << 9;
    const MISC_PACKAGE_CTLS: u64 = 1 << 10;
    const ENERGY_FILTERING_CTL: u64 = 1 << 11;
    const DOITM: u64 = 1 << 12;
    const MCU_ENUMERATION: u64 = 1 << 16;
    const FB_CLEAR: u64 = 1 << 17;
    const FB_CLEAR_CTRL: u64 = 1 << 18;
    const BHI_NO: u64 = 1 << 20;
    const XAPIC_DISABLE_STATUS: u64 = 1 << 21;
    const MCU_EXTENDED_SERVICE: u64 = 1 << 22;
    const OVERCLOCKING_STATUS: u64 = 1 << 23;
    const PBRSB_NO: u64 = 1 << 24;
    const GDS_CTRL: u64 = 1 << 25;
    const GDS_NO: u64 = 1 << 26;
    const RFDS_NO: u64 = 1 << 27;
    // TODO: Should we perhaps ignore checking this (is it too strict)?
    const RFDS_CLEAR: u64 = 1 << 28;
    const IGN_UMONITOR_SUPPORT: u64 = 1 << 29;
    const MON_UMON_MITG_SUPPORT: u64 = 1 << 30;
    const PBOPT_SUPPORT: u64 = 1 << 32;

    let mask: u64 = {
        RDCL_NO
            | IBRS_ALL
            | SKIP_L1_DFL_VMENTRY
            | SSB_NO
            | MDS_NO
            | TAA_NO
            | TSX_CONTROL
            | MCU_CONTROL
            | MISC_PACKAGE_CTLS
            | ENERGY_FILTERING_CTL
            | DOITM
            | MCU_ENUMERATION
            | FB_CLEAR
            | FB_CLEAR_CTRL
            | XAPIC_DISABLE_STATUS
            | MCU_EXTENDED_SERVICE
            | OVERCLOCKING_STATUS
            | GDS_CTRL
            | IGN_UMONITOR_SUPPORT
            | MON_UMON_MITG_SUPPORT
            | PBOPT_SUPPORT
            | RFDS_CLEAR
            | PBRSB_NO
            | GDS_NO
            | RFDS_NO
            | BHI_NO
    };
    if let Err(only_in_src) = check_subset(src_val & mask, dest_val & mask) {
        error!(
            "IA32_ARCH_CAPABILITIES compatibility check failed: {src_id} value:={src_val:#x}, {dest_id} value:={dest_val:#x}"
        );
        let definitions = msr_definitions::<{ RegisterAddress::IA32_ARCH_CAPABILITIES.0 }>();
        log_features_only_in_src(only_in_src, src_id, definitions, "IA32_ARCH_CAPABILITIES");
        Err(())
    } else {
        Ok(())
    }
}

/// Check that the values of MSR IA32_VMX_BASIC are compatible.
///
/// See Intel SDM Vol.3D A.1 for more information about the IA32_VMX_BASIC MSR
fn check_vmx_basic_compatibility(
    src_val: u64,
    dest_val: u64,
    src_id: &str,
    dest_id: &str,
) -> Result<(), ()> {
    let mut is_err = false;
    // All bits between 0 and 53 are expected to be equal (except bit 49)
    let req_eq_mask: u64 = ((1 << 54) - 1) & (!(1 << 49));
    let src_req_eq = src_val & req_eq_mask;
    let dest_req_eq = dest_val & req_eq_mask;
    if src_req_eq != dest_req_eq {
        is_err = true;
        let definitions = msr_definitions::<{ RegisterAddress::IA32_VMX_BASIC.0 }>();
        log_inequalities(
            src_req_eq,
            dest_req_eq,
            definitions,
            src_id,
            dest_id,
            "IA32_VMX_BASIC compatibility",
        );
    }
    // bits 49, 54, 55, and 56 indicate some form of capability and we need to check
    // that these bits in the `src_value` are a subset of those in `dest_value`
    let req_subset_eq_mask: u64 = (1 << 54) | (1 << 55) | (1 << 56) | (1 << 49);
    let src_val_seq = req_subset_eq_mask & src_val;
    let dest_val_seq = req_subset_eq_mask & dest_val;
    is_err |= check_subset(src_val_seq, dest_val_seq).is_err();

    if is_err {
        error!(
            "IA32_VMX_BASIC compatibility check failed: {src_id} value:={src_val:#x}, {dest_id} value:={dest_val:#x}"
        );
        Err(())
    } else {
        Ok(())
    }
}

/// Check that no values are only in a
///
/// Upon error a bitset is returned with the
/// bits that are only available in `src_val`
fn check_subset(src_val: u64, dest_val: u64) -> Result<(), u64> {
    let only_in_src_val = src_val & (src_val ^ dest_val);
    if only_in_src_val != 0 {
        Err(only_in_src_val)
    } else {
        Ok(())
    }
}

/// Checks the following:
/// 1. For any X < 32; If bit X of src_val is 0 then  bit X  of dest_val is also 0
/// 2. For any X >= 32; If bit X of src_val is 1 then bit X of dest_val is also 1
struct CtlsCheck {
    bitset_only_zero_src_lo: Option<u64>,
    bitset_only_one_src_hi: Option<u64>,
}

fn check_negative_subset_lo_and_subset_hi(src_val: u64, dest_val: u64) -> Result<(), CtlsCheck> {
    let lo_mask = (1_u64 << 32) - 1;
    let hi_mask = !lo_mask;

    let lo_check = check_subset((!src_val) & lo_mask, (!dest_val) & lo_mask);

    let hi_check = check_subset(src_val & hi_mask, dest_val & hi_mask);

    if lo_check.is_ok() && hi_check.is_ok() {
        Ok(())
    } else {
        Err(CtlsCheck {
            bitset_only_zero_src_lo: lo_check.err(),
            bitset_only_one_src_hi: hi_check.err(),
        })
    }
}

/// Check that the values of MSR IA32_VMX_MISC are compatible.
///
/// See Intel SDM Vol.3D A.6 for more information about the IA32_VMX_MISC MSR
fn check_vmx_misc_msr(
    src_value: u64,
    dest_value: u64,
    src_id: &str,
    dest_id: &str,
) -> Result<(), ()> {
    let mut is_err = false;
    let subset_eq_check_mask: u64 = {
        (1 << 5)
            | (1 << 6)
            | (1 << 7)
            | (1 << 8)
            | (1 << 14)
            | (1 << 15)
            | (1 << 28)
            | (1 << 29)
            | (1 << 30)
    };
    if let Err(only_in_src) = check_subset(
        subset_eq_check_mask & src_value,
        subset_eq_check_mask & dest_value,
    ) {
        is_err = true;
        let definitions = msr_definitions::<{ RegisterAddress::IA32_VMX_MISC.0 }>();
        log_features_only_in_src(only_in_src, src_id, definitions, "IA32_VMX_MISC");
    }

    let eq_mask: u64 = {
        // TODO: Do we also need to check that the MSEG revisions match?
        (16..=24).fold(0_u64, |acc, next| acc | (1 << next))
    };

    let src_req_eq_val = src_value & eq_mask;
    let dest_req_eq_val = dest_value & eq_mask;
    if src_req_eq_val != dest_req_eq_val {
        is_err = true;
        let definitions = msr_definitions::<{ RegisterAddress::IA32_VMX_MISC.0 }>();
        log_inequalities(
            src_req_eq_val,
            dest_req_eq_val,
            definitions,
            src_id,
            dest_id,
            "IA32_VMX_MISC",
        );
    }

    let leq_mask: u64 = { (25..=27).fold(0_u64, |acc, next| acc | (1 << next)) };

    let src_req_leq = src_value & leq_mask;
    let dest_req_leq = dest_value & leq_mask;
    if src_req_leq > dest_req_leq {
        is_err = true;
        debug!(
            "IA32_VMX_MISC compatibility check failed when checking definition: {:?}, {src_id} has value:={src_req_leq}, {dest_id} has value:={dest_req_leq}",
            max_msr_store_lists_def(),
        );
    }

    if is_err {
        error!(
            "IA32_VMX_MISC compatibility check failed: {src_id} value:={src_value:#x}, {dest_id} value:={dest_value:#x}"
        );
        Err(())
    } else {
        Ok(())
    }
}

/// Check compatibility of MSRs IA32_VMX_CR{I}_FIXED0 for I = 0, 4.
///
/// See Intel SDM Vol.3D A.7 & A.8 for more information about these MSRs.
///
/// NOTE: We don't need to check compatibility for CR{I}_FIXED1 because
/// that is ensured by CPUID.
fn check_cr_i_compatibility<const I: u8>(
    src_fixed0: u64,
    dest_fixed0: u64,
    src_id: &str,
    dest_id: &str,
) -> Result<(), ()> {
    let cri = const {
        match I {
            0 => "CR0",
            4 => "CR4",
            _ => {
                panic!("only 0 and 4 may be used")
            }
        }
    };

    // Need to ensure that there are no bits that are only 0 in src_fixed0 and also no bits
    // that are only 1 in src_fixed1.

    if let Err(only_zero_in_src) = check_subset(!src_fixed0, !dest_fixed0) {
        error!(
            "IA32_VMX_{cri}_FIXED0 compatibility check failed: {src_id} value:={src_fixed0:#x}, {dest_id} value:={dest_fixed0:#x}"
        );
        for_each_bitpos(only_zero_in_src, |bit_pos| {
            debug!(
                "IA32_VMX_{cri}_FIXED0 compatibility check failed: bit {bit_pos} is allowed to be 0 in {cri} for {src_id}, but not for {dest_id}"
            );
        });
        Err(())
    } else {
        Ok(())
    }
}

/// Check compatibility of MSRs IA32_VMX_VMCS_ENUM.
///
/// See Intel SDM Vol.3D A.9 for more information about IA32_VMX_VMCS_ENUM.
fn check_vmx_vmcs_enum_compatibility(
    src_value: u64,
    dest_value: u64,
    src_id: &str,
    dest_id: &str,
) -> Result<(), ()> {
    let mask = (1..=9).fold(0_u64, |acc, next| acc | (1 << next));
    let src_req_leq = src_value & mask;
    let dest_req_leq = dest_value & mask;
    if src_req_leq > dest_req_leq {
        error!(
            "VMX_VMCS_ENUM compatibility check failed: MAX_INDEX for {src_id}:={src_req_leq} is greater than MAX_INDEX:={dest_req_leq} for {dest_id}"
        );
        Err(())
    } else {
        Ok(())
    }
}

/// Check compatibility of MSRs IA32_VMX_EPT_VPID_CAP.
///
/// See (Intel TODO:) Vol. 3D A.10 for more information about IA32_VMX_EPT_VPID_CAP.
// Only if IA32_VMX_PROCBASED_CTLS[63] & (IA32_VMX_PROCBASED_CTLS2[33] | IA32_VMX_PROCBASED_CTLS2[37])
fn check_vpid_and_ept_capabilities(
    src_value: u64,
    dest_value: u64,
    src_id: &str,
    dest_id: &str,
) -> Result<(), ()> {
    let mut is_err = false;
    let subset_eq_mask = { (1 << 44) - 1 };

    if let Err(bits_only_in_src) =
        check_subset(src_value & subset_eq_mask, dest_value & subset_eq_mask)
    {
        is_err = true;
        let definitions = msr_definitions::<{ RegisterAddress::IA32_VMX_EPT_VPID_CAP.0 }>();
        log_features_only_in_src(
            bits_only_in_src,
            src_id,
            definitions,
            "IA32_VMX_EPT_VPID_CAP",
        );
    }

    let leq_mask = { (48..=53).fold(0_u64, |acc, next| acc | (1 << next)) };
    let src_req_leq = src_value & leq_mask;
    let dest_req_leq = dest_value & leq_mask;
    if src_req_leq > dest_req_leq {
        is_err = true;
        debug!(
            "IA32_VMX_EPT_VPID_CAP compatibility check failed: maximum HLAT prefix size is {src_req_leq} for {src_id}, but {dest_req_leq} for {dest_id}"
        );
    }
    if is_err {
        error!(
            "IA32_VMX_EPT_VPID_CAP compatibility check failed: {src_id} value:={src_value:#x}, {dest_id} value:={dest_value:#x}"
        );
        Err(())
    } else {
        Ok(())
    }
}

fn for_each_bitpos(bits: u64, mut cb: impl FnMut(u8)) {
    let mut bits = bits;
    while bits != 0 {
        let pos = bits.trailing_zeros() as u8;
        cb(pos);
        let lsb = bits & bits.wrapping_neg();
        bits ^= lsb;
    }
}

#[inline(never)]
#[cold]
fn log_features_only_in_src(
    only_in_src: u64,
    src_id: &str,
    definitions: &[ValueDefinition],
    check_id: &str,
) {
    for_each_bitpos(only_in_src, |bit_pos| {
        let Some(def) = definitions
            .iter()
            .find(|def| (def.bits_range.0..=def.bits_range.1).contains(&bit_pos))
        else {
            debug!(
                "{check_id} compatibility check failed: bit:={bit_pos} is only set for {src_id}"
            );
            warn!(
                "unable to produce proper debug log: No MSR value definition found for bit:={bit_pos} check:={check_id} compatibility"
            );
            return;
        };
        debug!(
            "{check_id} compatibility check failed: feature bit {bit_pos} only set for {src_id}: feature definition:={def:?}"
        );
    });
}

#[inline(never)]
#[cold]
fn log_inequalities(
    src_val: u64,
    dest_val: u64,
    definitions: &[ValueDefinition],
    src_id: &str,
    dest_id: &str,
    check_id: &str,
) {
    for def in definitions {
        let mask =
            (def.bits_range.0..=def.bits_range.1).fold(0_u64, |acc, next| acc | (1_u64 << next));
        let val_src = mask & src_val;
        let val_dest = mask & dest_val;
        if src_val != dest_val {
            debug!(
                "Check: {check_id} compatibility failed: on definition:={def:?}, values are required to be equal, but we have {src_id} value:={val_src:#x}, {dest_id} value:={val_dest:#x}"
            );
        }
    }
}

#[inline(never)]
#[cold]
const fn max_msr_store_lists_def() -> &'static ValueDefinition {
    const {
        let defs = msr_definitions::<{ RegisterAddress::IA32_VMX_MISC.0 }>();
        // Currently stored at index = 8, if this changes we make sure that we fail at compile time.
        // We do not perform a search as the order is unlikely to change frequently and we want to keep
        // compile times down.
        let def = &defs[8];
        assert!(
            def.bits_range.0 == 25,
            "MAX_MSR_STORE_LISTS definition is no longer at index 8 in the ValueDefinitions corresponding to IA32_VMX_MISC, please update the index"
        );
        assert!(
            def.bits_range.1 == 27,
            "MAX_MSR_STORE_LISTS definition is no longer at index 8 in the ValueDefinitions corresponding to IA32_VMX_MISC, please update the index"
        );
        def
    }
}
