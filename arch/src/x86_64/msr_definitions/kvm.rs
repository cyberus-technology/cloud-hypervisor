// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! This module lists KVM defined MSRS. It is currently only used when generating CPU profiles
//! (hence feature gated), but may possibly be extended and utilized for better debug logs in
//! the future.
pub(in crate::x86_64) use permitted_msrs::PROFILE_PERMITTED_KVM_MSRS;

use crate::x86_64::CpuidReg;
use crate::x86_64::cpuid_definitions::Parameters;

mod permitted_msrs {
    use super::{CpuidReg, Parameters};
    use crate::x86_64::cpuid_definitions::kvm::assert_not_denied_cpuid_feature;

    const MSR_KVM_WALL_CLOCK: u32 = 0x11;
    const MSR_KVM_SYSTEM_TIME: u32 = 0x12;
    const _KVM_CLOCKSOURCE_CPUID_CHECK: () = assert_not_denied_cpuid_feature::<0>(&Parameters {
        leaf: 0x4000_0001,
        sub_leaf: (0..=0),
        register: CpuidReg::EAX,
    });

    const MSR_KVM_WALL_CLOCK_NEW: u32 = 0x4b564d00;
    const MSR_KVM_SYSTEM_TIME_NEW: u32 = 0x4b564d01;
    const _KVM_CLOCKSOURCE2_CHECK: () = assert_not_denied_cpuid_feature::<3>(&Parameters {
        leaf: 0x4000_0001,
        sub_leaf: (0..=0),
        register: CpuidReg::EAX,
    });

    const MSR_KVM_ASYNC_PF_EN: u32 = 0x4b564d02;
    const _KVM_ASYNC_PF_CHECK: () = assert_not_denied_cpuid_feature::<4>(&Parameters {
        leaf: 0x4000_0001,
        sub_leaf: (0..=0),
        register: CpuidReg::EAX,
    });

    const MSR_KVM_STEAL_TIME: u32 = 0x4b564d03;
    const _KVM_STEAL_TIME_CHECK: () = assert_not_denied_cpuid_feature::<5>(&Parameters {
        leaf: 0x4000_0001,
        sub_leaf: (0..=0),
        register: CpuidReg::EAX,
    });

    const MSR_KVM_EOI_EN: u32 = 0x4b564d04;
    const _KVM_EOI_EN_CHECK: () = assert_not_denied_cpuid_feature::<6>(&Parameters {
        leaf: 0x4000_0001,
        sub_leaf: (0..=0),
        register: CpuidReg::EAX,
    });

    const MSR_KVM_POLL_CONTROL: u32 = 0x4b564d05;
    const _KVM_POLL_CONTROL_CHECK: () = assert_not_denied_cpuid_feature::<12>(&Parameters {
        leaf: 0x4000_0001,
        sub_leaf: (0..=0),
        register: CpuidReg::EAX,
    });

    const MSR_KVM_ASYNC_PF_INT: u32 = 0x4b564d06;
    const MSR_KVM_ASYNC_PF_ACK: u32 = 0x4b564d07;
    const _KVM_ASYNC_PF_INT_ACK_CHECK: () = assert_not_denied_cpuid_feature::<14>(&Parameters {
        leaf: 0x4000_0001,
        sub_leaf: (0..=0),
        register: CpuidReg::EAX,
    });

    const MSR_KVM_MIGRATION_CONTROL: u32 = 0x4b564d08;
    const _KVM_MIGRATION_CONTROL_CHECK: () = assert_not_denied_cpuid_feature::<17>(&Parameters {
        leaf: 0x4000_0001,
        sub_leaf: (0..=0),
        register: CpuidReg::EAX,
    });

    /// KVM defined MSRS that CPU profiles may inclide in their permitted MSR definitions.
    ///
    /// This list is (currently) only utilized when generating CPU profiles.
    pub(in crate::x86_64) const PROFILE_PERMITTED_KVM_MSRS: [u32; 11] = [
        MSR_KVM_WALL_CLOCK,
        MSR_KVM_SYSTEM_TIME,
        MSR_KVM_WALL_CLOCK_NEW,
        MSR_KVM_SYSTEM_TIME_NEW,
        MSR_KVM_ASYNC_PF_EN,
        MSR_KVM_STEAL_TIME,
        MSR_KVM_EOI_EN,
        MSR_KVM_POLL_CONTROL,
        MSR_KVM_ASYNC_PF_INT,
        MSR_KVM_ASYNC_PF_ACK,
        MSR_KVM_MIGRATION_CONTROL,
    ];
}
