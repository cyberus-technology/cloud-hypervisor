// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io::Write;

use hypervisor::arch::x86::{CpuIdEntry, MsrEntry};
use hypervisor::{CpuVendor, HypervisorType};
use log::error;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::deserialize_u32_hex;
use crate::x86_64::CpuidReg;
use crate::x86_64::cpuid_definitions::Parameters;
use crate::x86_64::msr_definitions::RegisterAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
/// A [`CpuProfile`] is a mechanism for ensuring live migration compatibility
/// between host's with potentially different CPU models.
pub enum CpuProfile {
    #[default]
    Host,
    #[cfg(feature = "kvm")]
    Skylake,
    #[cfg(feature = "kvm")]
    SapphireRapids,
}

impl CpuProfile {
    /// Loads pre-generated CPUID data associated with a CPU profile.
    ///
    /// If the `amx` flag is false then the AMX tile state components will be
    /// zeroed out from the associated profile data. This is necessary because
    /// they will then not be present in the vector of [`CpuidEntry`] values
    /// obtained from the hypervisor.
    //
    // We can only generate CPU profiles for the KVM hypervisor for the time being.
    #[cfg(feature = "kvm")]
    pub(in crate::x86_64) fn cpuid_data(&self, amx: bool) -> Option<CpuIdProfileData> {
        let mut data: CpuIdProfileData = match self {
            Self::Host => None,
            Self::Skylake => Some(
                serde_json::from_slice(include_bytes!("cpu_profiles/skylake.cpuid.json"))
                    .inspect_err(|e| {
                        error!("BUG: could not deserialize CPU profile. Got error: {e:?}");
                    })
                    .expect("should be able to deserialize pre-generated data"),
            ),
            Self::SapphireRapids => Some(
                serde_json::from_slice(include_bytes!("cpu_profiles/sapphire-rapids.cpuid.json"))
                    .inspect_err(|e| {
                        error!("BUG: could not deserialize CPU profile. Got error: {e:?}");
                    })
                    .expect("should be able to deserialize pre-generated data"),
            ),
        }?;

        if !amx {
            // In this case we will need to wipe out the AMX tile state components (if they are included in the profile)
            for adj in data.adjustments.iter_mut() {
                if adj.0.sub_leaf.start() != adj.0.sub_leaf.end() {
                    continue;
                }
                let sub_leaf = *adj.0.sub_leaf.start();
                let leaf = adj.0.leaf;
                if (leaf == 0xd) && (sub_leaf == 0) && (adj.0.register == CpuidReg::EAX) {
                    adj.1.replacements &= !((1 << 17) | (1 << 18));
                }

                if (leaf == 0xd) && (sub_leaf == 1) && (adj.0.register == CpuidReg::ECX) {
                    adj.1.replacements &= !((1 << 17) | (1 << 18));
                }

                if (leaf == 0xd) && ((sub_leaf == 17) | (sub_leaf == 18)) {
                    adj.1.replacements = 0;
                }
            }
        }

        Some(data)
    }

    #[cfg(not(feature = "kvm"))]
    pub(in crate::x86_64) fn cpuid_data(&self, _amx: bool) -> Option<CpuIdProfileData> {
        if matches!(*self, Self::Host) {
            return None;
        }
        // This will need to be addressed before upstreaming.
        // We will probably need one profile per hypervisor.
        unreachable!()
    }

    /// Loads pre-generated MSR data associated with a CPU profile.
    #[cfg(feature = "kvm")]
    pub(in crate::x86_64) fn msr_data(&self) -> Option<MsrProfileData> {
        match self {
            Self::Host => None,
            Self::Skylake => Some(
                serde_json::from_slice(include_bytes!("cpu_profiles/skylake.msr.json"))
                    .inspect_err(|e| {
                        error!("BUG: could not deserialize CPU profile. Got error: {e:?}");
                    })
                    .expect("should be able to deserialize pre-generated data"),
            ),
            Self::SapphireRapids => Some(
                serde_json::from_slice(include_bytes!("cpu_profiles/sapphire-rapids.msr.json"))
                    .inspect_err(|e| {
                        error!("BUG: could not deserialize CPU profile. Got error: {e:?}");
                    })
                    .expect("should be able to deserialize pre-generated data"),
            ),
        }
    }

    #[cfg(not(feature = "kvm"))]
    pub(in crate::x86_64) fn msr_data(&self) -> Option<MsrProfileData> {
        if matches!(*self, Self::Host) {
            return None;
        }
        // CPU profiles are currently only available when using KVM as the hypervisor.
        unreachable!()
    }
}

/// Every [`CpuProfile`] different from `Host` has associated [`CpuIdProfileData`].
///
/// New constructors of this struct may only be generated through the CHV CLI (when built from source with
/// the `cpu-profile-generation` feature) which other hosts may then attempt to load in order to
/// increase the likelihood of successful live migrations among all hosts that opted in to the given
/// CPU profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct CpuIdProfileData {
    /// The hypervisor used when generating this CPU profile.
    pub(in crate::x86_64) hypervisor: HypervisorType,
    /// The vendor of the CPU belonging to the host that generated this CPU profile.
    pub(in crate::x86_64) cpu_vendor: CpuVendor,
    /// Adjustments necessary to become compatible with the desired target.
    pub(in crate::x86_64) adjustments: Vec<(Parameters, CpuidOutputRegisterAdjustments)>,
}

/// Used for adjusting an entire cpuid output register (EAX, EBX, ECX or EDX)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub(super) struct CpuidOutputRegisterAdjustments {
    #[serde(deserialize_with = "deserialize_u32_hex")]
    pub(in crate::x86_64) replacements: u32,
    /// Used to zero out the area `replacements` occupy. This mask is not necessarily !replacements, as replacements may pack values of different types (i.e. it is wrong to think of it as a bitset conceptually speaking).
    #[serde(deserialize_with = "deserialize_u32_hex")]
    pub(in crate::x86_64) mask: u32,
}

/*
We want to serialize the values as 10 bytes, starting with 0x,
regardless of the value. This makes it easier for humans to compare different serialized values.
*/
impl Serialize for CpuidOutputRegisterAdjustments {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("CpuidOutputRegisterAdjustments", 2)?;
        let mut serialize_field = |key, value| {
            // two bytes for "0x" prefix and eight for the hex encoded number
            let mut buffer = [0_u8; 10];
            write!(&mut buffer[..], "{value:#010x}").expect("This write should be infallible");
            let str = core::str::from_utf8(&buffer[..])
                .expect("the buffer should be filled with valid UTF-8 bytes");
            s.serialize_field(key, str)
        };
        serialize_field("replacements", self.replacements)?;
        serialize_field("mask", self.mask)?;
        s.end()
    }
}

impl CpuidOutputRegisterAdjustments {
    pub(in crate::x86_64) fn adjust(self, cpuid_output_register: &mut u32) {
        let temp_register_copy = *cpuid_output_register;
        let replacements_area_masked_in_temp_copy = temp_register_copy & self.mask;
        *cpuid_output_register = replacements_area_masked_in_temp_copy | self.replacements;
    }

    pub(in crate::x86_64) fn adjust_cpuid_entries(
        mut cpuid: Vec<CpuIdEntry>,
        adjustments: &[(Parameters, Self)],
    ) -> Result<Vec<CpuIdEntry>, MissingCpuidEntriesError> {
        for entry in &mut cpuid {
            for (reg, reg_value) in [
                (CpuidReg::EAX, &mut entry.eax),
                (CpuidReg::EBX, &mut entry.ebx),
                (CpuidReg::ECX, &mut entry.ecx),
                (CpuidReg::EDX, &mut entry.edx),
            ] {
                // Get the adjustment corresponding to the entry's function/leaf and index/sub-leaf for each of the register. If no such
                // adjustment is found we use the trivial adjustment (leading to the register being zeroed out entirely).
                let adjustment = adjustments
                    .iter()
                    .find_map(|(param, adjustment)| {
                        ((param.leaf == entry.function)
                            & param.sub_leaf.contains(&entry.index)
                            & (param.register == reg))
                            .then_some(*adjustment)
                    })
                    .unwrap_or(CpuidOutputRegisterAdjustments {
                        mask: 0,
                        replacements: 0,
                    });
                adjustment.adjust(reg_value);
            }
        }

        Self::expected_entries_found(&cpuid, adjustments).map(|_| cpuid)
    }

    /// Check that we found every value that was supposed to be replaced with something else than 0
    ///
    /// IMPORTANT: This function assumes that the given `cpuid` has already been adjusted with the
    /// provided `adjustments`.
    fn expected_entries_found(
        cpuid: &[CpuIdEntry],
        adjustments: &[(Parameters, Self)],
    ) -> Result<(), MissingCpuidEntriesError> {
        let mut missing_entry = false;

        // Invalid state components can be ignored. The next few lines obtain the relevant entries to
        // check for this.
        let eax_0xd_0 = cpuid
            .iter()
            .find(|entry| (entry.function == 0xd) && (entry.index == 0))
            .map_or(0, |entry| entry.eax);
        let ecx_0xd_1 = cpuid
            .iter()
            .find(|entry| (entry.function == 0xd) && (entry.index == 1))
            .map_or(0, |entry| entry.ecx);

        let edx_0xd_0 = cpuid
            .iter()
            .find(|entry| (entry.function == 0xd) && (entry.index == 0))
            .map_or(0, |entry| entry.edx);
        let edx_0xd_1 = cpuid
            .iter()
            .find(|entry| (entry.function == 0xd) && (entry.index == 1))
            .map_or(0, |entry| entry.edx);

        for (param, adjustment) in adjustments {
            if adjustment.replacements == 0 {
                continue;
            }
            let sub_start = *param.sub_leaf.start();
            let sub_end = *param.sub_leaf.end();

            let can_skip_lo = if (param.leaf == 0xd) && (2..32).contains(&sub_start) {
                let start = sub_start;
                let end = std::cmp::min(sub_end, 31);
                let mask = (start..=end).fold(0, |acc, next| acc | (1 << next));
                ((mask & eax_0xd_0) == 0) & ((mask & ecx_0xd_1) == 0)
            } else {
                false
            };

            let can_skip_hi = if (param.leaf == 0xd) && (32..64).contains(&sub_end) {
                let start = std::cmp::max(32, sub_start);
                let end = sub_end;
                let mask = (start..=end)
                    .map(|val| val - 32)
                    .fold(0, |acc, next| acc | (1 << next));
                ((mask & edx_0xd_0) == 0) & ((mask & edx_0xd_1) == 0)
            } else {
                false
            };

            if can_skip_lo && can_skip_hi {
                // This means that all state components referred to by the specified sub-leaf range are not valid
                // and may be skipped.
                continue;
            }
            if !cpuid.iter().any(|entry| {
                (entry.function == param.leaf) && (param.sub_leaf.contains(&entry.index))
            }) {
                error!(
                    "cannot adjust CPU profile. No entry found matching the required parameters: {param:?}"
                );
                missing_entry = true;
            }
        }
        if missing_entry {
            Err(MissingCpuidEntriesError)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone)]
pub(in crate::x86_64) struct FeatureMsrAdjustment {
    pub(in crate::x86_64) mask: u64,
    pub(in crate::x86_64) replacements: u64,
}

impl Serialize for FeatureMsrAdjustment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("FeatureMsrAdjustment", 2)?;
        let mut serialize_field = |key, value| {
            // two bytes for "0x" prefix and 16 for the hex encoded number
            let mut buffer = [0_u8; 18];
            let _ = write!(&mut buffer[..], "{value:#018x}");
            let str = core::str::from_utf8(&buffer[..])
                .expect("the buffer should be filled with valid UTF-8 bytes");
            s.serialize_field(key, str)
        };
        serialize_field("mask", self.mask)?;
        serialize_field("replacements", self.replacements)?;
        s.end()
    }
}

impl<'de> Deserialize<'de> for FeatureMsrAdjustment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct ProvisionalFeatureMsrAdjustment<'a> {
            #[serde(borrow)]
            mask: &'a str,
            #[serde(borrow)]
            replacements: &'a str,
        }

        let ProvisionalFeatureMsrAdjustment { mask, replacements } =
            ProvisionalFeatureMsrAdjustment::deserialize(deserializer)?;
        let parse_u64 = |hex: &str, field_name: &str| {
            u64::from_str_radix(hex.strip_prefix("0x").unwrap_or(""), 16).map_err(|_| {
                    <D::Error as serde::de::Error>::custom(format!("Unable to deserialize FeatureMsrAdjustment: could not deserialize {field_name} the value {hex} is not a hex encoded 64 bit integer"))
                })
        };
        let mask = parse_u64(mask, "mask")?;
        let replacements = parse_u64(replacements, "replacements")?;
        Ok(FeatureMsrAdjustment { mask, replacements })
    }
}

impl FeatureMsrAdjustment {
    /// Returns a struct describing the Feature MSRs that should be set
    /// and the ones that should be denied based on `adjustments` and the given
    /// `feature_msrs`.
    ///
    /// # Errors
    ///
    /// The only way for this to error is if there exists one or more entries in
    /// `adjustments` that do not have a corresponding entry in `feature_msrs`.
    /// In this case the missing MSR will be logged and the unit type is returned
    /// as the error variant.
    pub(in crate::x86_64) fn adjust_to(
        adjustments: &[(RegisterAddress, FeatureMsrAdjustment)],
        feature_msrs: &[MsrEntry],
    ) -> Result<Vec<MsrEntry>, ()> {
        let mut output_feature_msrs = Vec::with_capacity(feature_msrs.len());
        for (reg_address, adjustment) in adjustments {
            let Some(entry) = feature_msrs
                .iter()
                .find(|entry| entry.index == reg_address.0)
            else {
                error!(
                    "Did not find feature based MSR entry for MSR:={:#x}",
                    reg_address.0
                );
                return Err(());
            };
            // Adjust the entry and push it to outputs
            {
                let mut entry = *entry;
                let data = entry.data;
                entry.data = (adjustment.mask & data) | adjustment.replacements;
                // TODO: Perhaps trace! would be a better log level?
                log::debug!(
                    "adjusted MSR-based feature: register address:={:#x} value:={:#x}, previous value:={data:#x}",
                    entry.index,
                    entry.data
                );
                output_feature_msrs.push(entry);
            }
        }
        Ok(output_feature_msrs)
    }
}

pub struct RequiredMsrUpdates {
    pub msr_based_features: Vec<MsrEntry>,
    pub denied_msrs: Vec<RegisterAddress>,
}

/// Every [`CpuProfile`] different from `Host` has associated [`MsrProfileData`].
///
/// New constructors of this struct may only be generated through the CHV CLI (when built from source with
/// the `cpu-profile-generation` feature) which other hosts may then attempt to load in order to
/// increase the likelihood of successful live migrations among all hosts that opted in to the given
/// CPU profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::x86_64) struct MsrProfileData {
    pub(in crate::x86_64) cpu_vendor: CpuVendor,
    pub(in crate::x86_64) hypervisor_type: HypervisorType,
    pub(in crate::x86_64) adjustments: Vec<(RegisterAddress, FeatureMsrAdjustment)>,
    pub(in crate::x86_64) permitted_msrs: Vec<RegisterAddress>,
}

#[derive(Debug, Error)]
#[error("Required CPUID entries not found")]
pub struct MissingCpuidEntriesError;

#[derive(Debug, Error)]
#[error("Required MSR entries not found")]
pub struct MissingMsrEntriesError;

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::CpuidOutputRegisterAdjustments;

    // Check that serializing and then deserializing `CpuidOutputResiterAdjustments` results in the same value we started with.
    //
    // Also check that the serialized numeric values satisfy our expectations: They are 10-byte hex encoded strings
    proptest! {
        #[test]
        fn cpuid_output_register_adjustments_serialization_works(replacements in any::<u32>(), mask in any::<u32>()) {
            // Randomly generate these values. Several of the generated values will not represent anything that may be
            // produced in practice, but (de-)serialization does not take such domain knowledge into account (if that changes
            // then this test will need to be updated).
            let adjustments = CpuidOutputRegisterAdjustments {
                replacements,
                mask
            };
            let serialized = serde_json::to_string(&adjustments).unwrap();
            let deserialized: CpuidOutputRegisterAdjustments = serde_json::from_str(&serialized).unwrap();
            prop_assert_eq!(&deserialized, &adjustments);
            let json = serde_json::to_value(adjustments).unwrap();
            let replacements_str = json.get("replacements").unwrap().as_str().unwrap();
            let mask_str = json.get("mask").unwrap().as_str().unwrap();
            let check_str_invariants = |value: &str| {
                prop_assert!(value.starts_with("0x"));
                prop_assert_eq!(value.len(),10);
                prop_assert!(value.as_bytes().iter().all(|byte| byte.is_ascii()));
                let is_hex_digit = |byte: &u8| -> bool {
                    byte.is_ascii_digit() | (*byte == b'a') | (*byte == b'b') | (*byte == b'c') | (*byte == b'd') | (*byte == b'e') | (*byte == b'f')
                };
                prop_assert!(
                    value.as_bytes()[2..].iter().all(is_hex_digit)
                );
                Ok(())
            };
            check_str_invariants(replacements_str)?;
            check_str_invariants(mask_str)?;
        }
    }
}
