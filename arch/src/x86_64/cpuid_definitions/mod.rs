// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

use std::ops::RangeInclusive;

use serde::{Deserialize, Serialize};

use crate::x86_64::CpuidReg;
use crate::{deserialize_u32_hex, serialize_u32_hex};

pub mod intel;
#[cfg(feature = "kvm")]
pub mod kvm;

/// Parameters for inspecting CPUID definitions.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Parameters {
    // The leaf (EAX) parameter used with the CPUID instruction
    #[serde(
        serialize_with = "serialize_u32_hex",
        deserialize_with = "deserialize_u32_hex"
    )]
    pub leaf: u32,
    // The sub-leaf (ECX) parameter used with the CPUID instruction
    #[serde(
        serialize_with = "serialize_range_hex",
        deserialize_with = "deserialize_range_hex"
    )]
    pub sub_leaf: RangeInclusive<u32>,
    // The register we are interested in inspecting which gets filled by the CPUID instruction
    pub register: CpuidReg,
}

// Only used for (de-)serialization
#[derive(Debug, Serialize, Deserialize)]
struct ProvisionalRangeInclusive {
    #[serde(
        serialize_with = "serialize_u32_hex",
        deserialize_with = "deserialize_u32_hex"
    )]
    start: u32,
    #[serde(
        serialize_with = "serialize_u32_hex",
        deserialize_with = "deserialize_u32_hex"
    )]
    end: u32,
}

fn serialize_range_hex<S: serde::Serializer>(
    input: &RangeInclusive<u32>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let provisional = ProvisionalRangeInclusive {
        start: *input.start(),
        end: *input.end(),
    };
    provisional.serialize(serializer)
}

fn deserialize_range_hex<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<RangeInclusive<u32>, D::Error> {
    let ProvisionalRangeInclusive { start, end } =
        ProvisionalRangeInclusive::deserialize(deserializer)?;
    Ok(start..=end)
}

/// Describes a policy for how the corresponding CPUID data should be considered when building
/// a CPU profile.
///
/// This enum is mostly intended for the CPU profile generation tool, but it's debug representation
/// might also appear in logs if/when CPUID compatibility checks fail at runtime.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ProfilePolicy {
    /// Store the corresponding data when building the CPU profile.
    ///
    /// When the CPU profile gets utilized the corresponding data will be set into the modified
    /// CPUID instruction(s).
    Inherit,
    /// Ignore the corresponding data when building the CPU profile.
    ///
    /// When the CPU profile gets utilized the corresponding data will then instead get
    /// extracted from the host.
    ///
    /// This variant is typically set for data that has no effect on migration compatibility,
    /// but there may be some exceptions such as data which is necessary to run the VM at all,
    /// but must coincide with whatever is on the host.
    Passthrough,
    /// Set the following hardcoded value in the CPU profile.
    ///
    /// This variant is typically used for features/values that don't work well with live migration (even when using the exact same physical CPU model).
    Static(u32),
}

/// A description of a range of bits in a register populated by the CPUID instruction with specific parameters.
#[derive(Clone, Copy, Debug)]
pub struct ValueDefinition {
    /// A short name for the value obtainable through CPUID
    pub short: &'static str,
    /// A description of the value obtainable through CPUID
    pub description: &'static str,
    /// The range of bits in the output register corresponding to this feature or value.
    ///
    /// This is not a `RangeInclusive<u8>` because that type does unfortunately not implement `Copy`.
    pub bits_range: (u8, u8),
    /// The policy corresponding to this value when building CPU profiles.
    pub policy: ProfilePolicy,
}

/// Describes values within a register populated by the CPUID instruction with specific parameters.
pub struct ValueDefinitions(&'static [ValueDefinition]);
impl ValueDefinitions {
    /// Constructor permitting at most 32 entries.
    const fn new(cpuid_descriptions: &'static [ValueDefinition]) -> Self {
        // Note that this function is only called within this module, at compile time, hence it is fine to have some
        // additional sanity checks such as the following assert.
        assert!(cpuid_descriptions.len() <= 32);
        Self(cpuid_descriptions)
    }
    /// Converts this into a slice representation. This is the only way to read values of this type.
    pub const fn as_slice(&self) -> &'static [ValueDefinition] {
        self.0
    }

    /// Lookup the [`ValueDefinition`] whose bits range contains the given `BIT`.
    pub const fn find_bit<const BIT: u8>(&self) -> Option<&ValueDefinition> {
        let mut idx = 0;
        let len = self.0.len();
        while idx < len {
            let def = &self.0[idx];
            let start = def.bits_range.0;
            let end = def.bits_range.1;
            if (start <= BIT) & (end >= BIT) {
                return Some(def);
            }
            idx += 1;
        }
        None
    }
}

/// Describes multiple CPUID outputs.
///
/// Each wrapped [`ValueDefinitions`] corresponds to the given [`Parameters`] in the same tuple.
///
pub struct CpuidDefinitions<const NUM_PARAMETERS: usize>(
    [(Parameters, ValueDefinitions); NUM_PARAMETERS],
);

impl<const NUM_PARAMETERS: usize> CpuidDefinitions<NUM_PARAMETERS> {
    pub const fn as_slice(&self) -> &[(Parameters, ValueDefinitions); NUM_PARAMETERS] {
        &self.0
    }

    /// Lookup the [`ValueDefinitions`] corresponding to the given `parameters`.
    pub const fn get(&self, parameters: &Parameters) -> Option<&ValueDefinitions> {
        let mut idx = 0;
        let len = self.0.len();
        let leaf = parameters.leaf;
        let sub_leaf_start = *parameters.sub_leaf.start();
        let sub_leaf_end = *parameters.sub_leaf.end();
        // Note that as of today const Rust is quite a bit more vorbose than normal Rust.
        // This is why the following implementation doesn't look so idiomatic.
        let is_eax = matches!(parameters.register, CpuidReg::EAX);
        let is_ebx = matches!(parameters.register, CpuidReg::EBX);
        let is_ecx = matches!(parameters.register, CpuidReg::ECX);
        let is_edx = matches!(parameters.register, CpuidReg::EDX);
        while idx < len {
            let (param, defs) = &self.0[idx];
            let matching_leaf = leaf == param.leaf;
            let matching_sub_leaf = (sub_leaf_start >= *param.sub_leaf.start())
                & (sub_leaf_end <= *param.sub_leaf.end());
            let matching_reg = {
                match param.register {
                    CpuidReg::EAX => is_eax,
                    CpuidReg::EBX => is_ebx,
                    CpuidReg::ECX => is_ecx,
                    CpuidReg::EDX => is_edx,
                }
            };
            if matching_leaf & matching_sub_leaf & matching_reg {
                return Some(defs);
            }
            idx += 1;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::Parameters;
    use crate::x86_64::CpuidReg;

    // Check that serializing and then deserializing a value of type `Parameter` results in the
    // same value we started with.
    //
    // Also check that the serialized numeric values are hex strings
    proptest! {
        #[test]
        fn parameter_serialization_roundtrip_works(leaf in any::<u32>(), x1 in 0u32..100, x2 in 0u32..100, reg in 0..4) {
            let sub_leaf_range_start = std::cmp::min(x1, x2);
            let sub_leaf_range_end = std::cmp::max(x1,x2);
            let sub_leaf = sub_leaf_range_start..=sub_leaf_range_end;
            let register = match reg {
                0 => CpuidReg::EAX,
                1 => CpuidReg::EBX,
                2 => CpuidReg::ECX,
                3 => CpuidReg::EDX,
                _ => unreachable!()
            };
            let cpuid_parameters = Parameters {
                leaf,
                sub_leaf,
                register
            };
            let serialized = serde_json::to_string(&cpuid_parameters).unwrap();
            let deserialized: Parameters = serde_json::from_str(&serialized).unwrap();
            prop_assert_eq!(&deserialized, &cpuid_parameters);

            // Check that all numeric values are hex strings when serialized to json
            let params_json = serde_json::to_value(cpuid_parameters).unwrap();
            prop_assert!(params_json.get("leaf").unwrap().as_str().unwrap().starts_with("0x"));
            let sub_leaf_map = params_json.get("sub_leaf").unwrap().as_object().unwrap();
            prop_assert!(sub_leaf_map.get("start").unwrap().as_str().unwrap().starts_with("0x"));
            prop_assert!(sub_leaf_map.get("end").unwrap().as_str().unwrap().starts_with("0x"));
        }
    }
}
