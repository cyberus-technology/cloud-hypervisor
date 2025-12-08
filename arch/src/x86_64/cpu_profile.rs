use hypervisor::arch::x86::CpuIdEntry;
use hypervisor::{CpuVendor, HypervisorType};
use serde::{Deserialize, Serialize};

use crate::x86_64::CpuidReg;
use crate::x86_64::cpuid_definitions::{Parameters, deserialize_from_hex, serialize_as_hex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
#[allow(non_camel_case_types)]
/// A [`CpuProfile`] is a mechanism for ensuring live migration compatibility
/// between host's with potentially different CPU models.
pub enum CpuProfile {
    #[default]
    Host,
    Skylake,
    SapphireRapids,
}

impl CpuProfile {
    // We can only generate CPU profiles for the KVM hypervisor for the time being.
    #[cfg(feature = "kvm")]
    pub(in crate::x86_64) fn data(&self, amx: bool) -> Option<CpuProfileData> {
        let mut data: CpuProfileData = match self {
            Self::Host => None,
            Self::Skylake => Some(
                serde_json::from_slice(include_bytes!("cpu_profiles/skylake.json"))
                    .inspect_err(|e| {
                        error!("BUG: could not deserialize CPU profile. Got error: {:?}", e)
                    })
                    .expect("should be able to deserialize pre-generated data"),
            ),
            Self::SapphireRapids => Some(
                serde_json::from_slice(include_bytes!("cpu_profiles/sapphire-rapids.json"))
                    .inspect_err(|e| {
                        error!("BUG: could not deserialize CPU profile. Got error: {:?}", e)
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
    pub(in crate::x86_64) fn data(&self) -> Option<CpuProfileData> {
        unimplemented!()
    }
}

/// Every [`CpuProfile`] different from `Host` has associated [`CpuProfileData`].
///
/// New constructors of this struct may only be generated through the CHV CLI (when built from source with
/// the `cpu-profile-generation` feature) which other hosts may then attempt to load in order to
/// increase the likelyhood of successful live migrations among all hosts that opted in to the given
/// CPU profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct CpuProfileData {
    /// The hypervisor used when generating this CPU profile.
    pub(in crate::x86_64) hypervisor: HypervisorType,
    /// The vendor of the CPU belonging to the host that generated this CPU profile.
    pub(in crate::x86_64) cpu_vendor: CpuVendor,
    /// Adjustments necessary to become compatible with the desired target.
    pub(in crate::x86_64) adjustments: Vec<(Parameters, CpuidOutputRegisterAdjustments)>,
}

/* TODO: The [`CpuProfile`] struct will likely need a few more iterations. The following
sections should explain why:

# MSR restrictions

CPU profiles also need to restrict which MSRs may be manipulated by the guest as various physical CPUs
can have differing supported MSRs.

The CPU profile will thus necessarily need to contain some data related to MSR restrictions. That will
be taken care of in a follow up MR.

# Raw hardware CPUID for advanced opt-in features

Some more advanced CPU Features may either not be present when prompting the hypervisor for supported CPUID
enries (especially if this is done with the hypervisor in its default configuration), or may otherwise be
declared to be overwritten by all CPU profiles (as a safest default).

We may still want to let users opt-in to using such features if permitted by the hardware and hypervisor
however. Hence we may also want the `CpuProfile` to contain all CPUID entries obtained directly from the
hardware of the host the profile was built from.

This hardware information can then later be used on other hosts running under this pre-generated CPU
profile whenever the user wants to opt-in to more advanced CPU futures. If we can determine that the
feature is satisfied by both the hypervisor, the hardware of the host generating the profile, and the
current host then this should preserve live migration compatibility (unless the feature in inherently
incompatible with live migration of course).
*/

/// Used for adjusting an entire cpuid output register (EAX, EBX, ECX or EDX)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct CpuidOutputRegisterAdjustments {
    #[serde(serialize_with = "serialize_as_hex")]
    #[serde(deserialize_with = "deserialize_from_hex")]
    pub(in crate::x86_64) replacements: u32,
    /// Used to zero out the area `replacements` occupy. This mask is not necessarily !replacements, as replacements may pack values of different types (i.e. it is wrong to think of it as a bitset conceptually speaking).
    #[serde(serialize_with = "serialize_as_hex")]
    #[serde(deserialize_with = "deserialize_from_hex")]
    pub(in crate::x86_64) mask: u32,
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
        // Check that we found every value that was supposed to be replaced with something else than 0
        let mut missing_entry = false;

        let eax_0xd_0 = cpuid
            .iter()
            .find(|entry| (entry.function == 0xd) && (entry.index == 0))
            .map(|entry| entry.eax)
            .unwrap_or(0);
        let ecx_0xd_1 = cpuid
            .iter()
            .find(|entry| (entry.function == 0xd) && (entry.index == 1))
            .map(|entry| entry.ecx)
            .unwrap_or(0);

        let edx_0xd_0 = cpuid
            .iter()
            .find(|entry| (entry.function == 0xd) && (entry.index == 0))
            .map(|entry| entry.edx)
            .unwrap_or(0);
        let edx_0xd_1 = cpuid
            .iter()
            .find(|entry| (entry.function == 0xd) && (entry.index == 1))
            .map(|entry| entry.edx)
            .unwrap_or(0);

        for (param, adjustment) in adjustments {
            if adjustment.replacements == 0 {
                continue;
            }
            let sub_start = *param.sub_leaf.start();
            let sub_end = *param.sub_leaf.end();
            if (param.leaf == 0xd) && (sub_start >= 2) && (sub_start < 32) && (sub_start == sub_end)
            {
                if (((1 << sub_start) & eax_0xd_0) == 0) && (((1 << sub_start) & ecx_0xd_1) == 0) {
                    // This means that the sub-leaf is to be considered invalid anyway and it is OK if we don't find it
                    continue;
                }
            }

            if (param.leaf == 0xd) && (sub_start >= 32) && (sub_start < 64) {
                if (((1 << (sub_start - 32)) & edx_0xd_0) == 0)
                    && (((1 << (sub_start - 32)) & edx_0xd_1) == 0)
                {
                    // This means that the sub-leaf is to be considered invalid anyway and it is OK if we don't find it
                    continue;
                }
            }

            if !cpuid.iter().any(|entry| {
                (entry.function == param.leaf) && (param.sub_leaf.contains(&entry.index))
            }) {
                error!(
                    "cannot adjust CPU profile. No entry found matching the required parameters: {:?}",
                    param
                );
                missing_entry = true;
            }
        }
        if missing_entry {
            Err(MissingCpuidEntriesError)
        } else {
            Ok(cpuid)
        }
    }
}

#[derive(Debug)]
pub(in crate::x86_64) struct MissingCpuidEntriesError;

impl core::fmt::Display for MissingCpuidEntriesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Required CPUID entries not found")
    }
}

impl core::error::Error for MissingCpuidEntriesError {}
