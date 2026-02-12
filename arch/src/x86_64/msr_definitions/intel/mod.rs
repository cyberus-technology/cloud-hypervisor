// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

#[cfg(any(test, feature = "cpu_profile_generation"))]
mod architectural_msrs;

mod msr_based_features;

#[cfg(feature = "cpu_profile_generation")]
pub(in crate::x86_64) use architectural_msrs::FORBIDDEN_IA32_MSR_RANGES;
#[cfg(any(test, feature = "cpu_profile_generation"))]
pub(in crate::x86_64) use architectural_msrs::PERMITTED_IA32_MSRS;
pub use msr_based_features::INTEL_MSR_FEATURE_DEFINITIONS;
pub(in crate::x86_64) use msr_based_features::check_feature_msr_compatibility;
