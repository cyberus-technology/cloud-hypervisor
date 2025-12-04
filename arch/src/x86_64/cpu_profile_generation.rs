use crate::x86_64::CpuidReg;
#[cfg(feature = "kvm")]
use crate::x86_64::cpuid_definitions::CpuidDefinitions;
use crate::x86_64::{
    CpuidOutputRegisterAdjustments,
    cpu_profile::CpuProfileData,
    cpuid_definitions::{
        Parameters, ProfilePolicy, hypervisor::KVM_CPUID_DEFINITIONS,
        intel::INTEL_CPUID_DEFINITIONS,
    },
};

use anyhow::{Context, anyhow};
use hypervisor::Hypervisor;
use hypervisor::HypervisorType;
use hypervisor::arch::x86::CpuIdEntry;
use hypervisor::{CpuVendor, arch::x86::XsaveState};
use std::io::Write;
use std::ops::RangeInclusive;

/// Generate CPU profile data and convert it to a string, embeddable as Rust code, which is
/// written to the given `writer` (e.g. a File).
//
// NOTE: The MVP only works with KVM as the hypervisor and Intel CPUs.
#[cfg(feature = "kvm")]
pub fn generate_profile_data(
    mut writer: impl Write,
    hypervisor: &dyn Hypervisor,
) -> anyhow::Result<()> {
    let cpu_vendor = hypervisor.get_cpu_vendor();
    if cpu_vendor != CpuVendor::Intel {
        unimplemented!("CPU profiles can only be generated for Intel CPUs at this point in time");
    }
    let hypervisor_type = hypervisor.hypervisor_type();
    // This is just a reality check.
    if hypervisor_type != HypervisorType::Kvm {
        unimplemented!(
            "CPU profiles can only be generated when using KVM as the hypervisor at this point in time"
        );
    }
    let supported_cpuid_sorted = supported_cpuid_sorted(hypervisor)?;
    generate_cpu_profile_data_with(
        hypervisor_type,
        cpu_vendor,
        supported_cpuid_sorted,
        &INTEL_CPUID_DEFINITIONS,
        &KVM_CPUID_DEFINITIONS,
        &mut writer,
    )
}

/// Computes [`CpuProfileData`] based on the given sorted vector of CPUID entries, hypervisor type, cpu_vendor
/// and cpuid_definitions.
///
/// The computed [`CpuProfileData`] is then converted to a string representation, embeddable as Rust code, which is
/// then written by the given `writer`.
///
// TODO: Consider making a snapshot test or two for this function.
fn generate_cpu_profile_data_with<const N: usize, const M: usize>(
    hypervisor_type: HypervisorType,
    cpu_vendor: CpuVendor,
    supported_cpuid_sorted: Vec<CpuIdEntry>,
    processor_cpuid_definitions: &CpuidDefinitions<N>,
    hypervisor_cpuid_definitions: &CpuidDefinitions<M>,
    mut writer: &mut impl Write,
) -> anyhow::Result<()> {
    let mut adjustments: Vec<(Parameters, CpuidOutputRegisterAdjustments)> = Vec::new();

    for (parameter, values) in processor_cpuid_definitions
        .0
        .iter()
        .chain(hypervisor_cpuid_definitions.0.iter())
    {
        for (sub_leaf_range, maybe_matching_register_output_value) in
            extract_parameter_matches(parameter, &supported_cpuid_sorted)
        {
            // If the compatibility target (current host) has multiple sub-leaves matching the parameter's range
            // then we want to specialize:
            let mut mask: u32 = 0;
            let mut replacements: u32 = 0;
            for value in values.as_slice() {
                // Reality check on the bit range listed in `value`
                {
                    assert!(value.bits_range.0 <= value.bits_range.1);
                    assert!(value.bits_range.1 < 32);
                }

                match value.policy {
                    ProfilePolicy::Passthrough => {
                        // The profile should take whatever we get from the host, hence there is no adjustment, but our
                        // mask needs to retain all bits in the range of bits corresponding to this value
                        let (first_bit_pos, last_bit_pos) = value.bits_range;
                        mask |= bit_range_mask(first_bit_pos, last_bit_pos);
                    }
                    ProfilePolicy::Overwrite(overwrite_value) => {
                        replacements |= overwrite_value << value.bits_range.0;
                    }
                    ProfilePolicy::Inherit => {
                        // The value is supposed to be obtained from the compatibility target if it exists
                        let (first_bit_pos, last_bit_pos) = value.bits_range;
                        if let Some(matching_register_value) = maybe_matching_register_output_value
                        {
                            let extraction_mask = bit_range_mask(first_bit_pos, last_bit_pos);
                            let value = matching_register_value & extraction_mask;
                            replacements |= value;
                        }
                    }
                }
            }
            adjustments.push((
                Parameters {
                    leaf: parameter.leaf,
                    sub_leaf: sub_leaf_range,
                    register: parameter.register,
                },
                CpuidOutputRegisterAdjustments { mask, replacements },
            ));
        }
    }

    let profile_data = CpuProfileData {
        hypervisor: hypervisor_type,
        cpu_vendor,
        adjustments,
    };

    serde_json::to_writer_pretty(&mut writer, &profile_data)
        .context("failed to serialize the generated profile data to the given writer")?;
    writer
        .flush()
        .context("CPU profile generation failed: Unable to flush cpu profile data")
}

/// Get the supported CPUID entries from the hypervisor and make sure that they are sorted by function and index
fn supported_cpuid_sorted(hypervisor: &dyn Hypervisor) -> anyhow::Result<Vec<CpuIdEntry>> {
    // Check for AMX compatibility. If this is supported we need to call arch_prctl before requesting the supported
    // CPUID entries from the hypervisor
    if XsaveState::amx_supported(hypervisor).is_ok() {
        XsaveState::enable_amx_state_components(hypervisor).map_err(|e| anyhow!(e))?;
    }

    hypervisor
        .get_supported_cpuid()
        .context("CPU profile data generation failed")
        .map(sort_entries)
}

fn sort_entries(mut cpuid: Vec<CpuIdEntry>) -> Vec<CpuIdEntry> {
    cpuid.sort_by(|entry, other_entry| {
        let fn_cmp = entry.function.cmp(&other_entry.function);
        if fn_cmp == core::cmp::Ordering::Equal {
            entry.index.cmp(&other_entry.index)
        } else {
            fn_cmp
        }
    });
    cpuid
}
/// Returns a `u32` where each bit between `first_bit_pos` and `last_bit_pos` is set (including both ends) and all other bits are 0.
fn bit_range_mask(first_bit_pos: u8, last_bit_pos: u8) -> u32 {
    let ones_until_last_bit_pos = u32::MAX >> (32 - last_bit_pos - 1);
    let ones_until_but_not_including_first_bit_pos = (1_u32 << first_bit_pos) - 1;
    let mask = ones_until_last_bit_pos & (!ones_until_but_not_including_first_bit_pos);
    // Reality checks
    {
        assert_eq!(
            u8::try_from(mask.count_ones()).unwrap(),
            (last_bit_pos - first_bit_pos) + 1
        );
        assert_eq!(
            mask.checked_shr(u32::from(last_bit_pos) + 1).unwrap_or(0),
            0
        );
        assert_eq!(u8::try_from(mask.trailing_zeros()).unwrap(), first_bit_pos);
    }
    mask
}

/// Returns a vector of exact parameter matches ((sub_leaf ..= sub_leaf), register_value) interleaved by
/// the sub_leaf ranges specified by `param` that did not match any cpuid entry.
fn extract_parameter_matches(
    param: &Parameters,
    supported_cpuid_sorted: &[CpuIdEntry],
) -> Vec<(RangeInclusive<u32>, Option<u32>)> {
    let register_value = |entry: &CpuIdEntry| -> u32 {
        match param.register {
            CpuidReg::EAX => entry.eax,
            CpuidReg::EBX => entry.ebx,
            CpuidReg::ECX => entry.ecx,
            CpuidReg::EDX => entry.edx,
        }
    };
    let mut out = Vec::new();
    let param_range = param.sub_leaf.clone();
    let mut range_for_consideration = param_range.clone();
    let range_end = *range_for_consideration.end();
    for sub_leaf_entry in supported_cpuid_sorted
        .iter()
        .filter(|entry| entry.function == param.leaf && param_range.contains(&entry.index))
    {
        let matching_subleaf = sub_leaf_entry.index;

        // If we are in the middle of the range, it means there is no entry matching the first few sub-leaves within the range
        let current_range_start = *range_for_consideration.start();
        if current_range_start < matching_subleaf {
            let range_not_matching = RangeInclusive::new(current_range_start, matching_subleaf - 1);
            out.push((range_not_matching, None));
        }

        out.push((
            RangeInclusive::new(matching_subleaf, matching_subleaf),
            Some(register_value(sub_leaf_entry)),
        ));
        if matching_subleaf == range_end {
            return out;
        }
        // Update range_for_consideration: Note that we must have index + 1 <= range_end
        range_for_consideration = RangeInclusive::new(matching_subleaf + 1, range_end);
    }
    // We did not find the last entry within the range hence we push the final range for consideration together with no matching register value
    out.push((range_for_consideration, None));
    out
}
