// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//
mod msr_based_features;

pub use msr_based_features::INTEL_MSR_FEATURE_DEFINITIONS;
pub(in crate::x86_64) use msr_based_features::check_feature_msr_compatibility;
