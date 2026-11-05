// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashSet;
use std::fs::File;
use std::io::Write;
use std::ops::{BitOr, RangeInclusive, Shl};
use std::path::PathBuf;

use anyhow::{Context, anyhow};
use hypervisor::arch::x86::{CpuIdEntry, MsrEntry};
use hypervisor::{CpuVendor, Hypervisor, HypervisorError, HypervisorType};
use jiff::Zoned;
use log::warn;

use crate::x86_64::CpuidReg;
use crate::x86_64::cpu_profile::cpuid_adjustments::{
    CpuidOutputRegisterAdjustments, CpuidProfileData,
};
#[cfg(feature = "kvm")]
use crate::x86_64::cpu_profile::msr_adjustments::{FeatureMsrAdjustment, MsrProfileData};
use crate::x86_64::cpuid_definitions::intel::INTEL_CPUID_DEFINITIONS;
#[cfg(feature = "kvm")]
use crate::x86_64::cpuid_definitions::kvm::KVM_CPUID_DEFINITIONS;
use crate::x86_64::cpuid_definitions::{CpuidDefinitions, Parameters, ProfilePolicy};
use crate::x86_64::hyperv_msrs::HYPERV_MSRS;
use crate::x86_64::msr_definitions::{self, MsrDefinitions, RegisterAddress};

/// Generate CPU profile data and convert it to a string, embeddable as Rust code, which is
/// written to the given `writer` (e.g. a File).
//
// NOTE: The MVP only works with KVM as the hypervisor and Intel CPUs.
#[cfg(feature = "kvm")]
pub fn generate_profile_data(
    hypervisor: &dyn Hypervisor,
    profile_name: &str,
) -> anyhow::Result<()> {
    let cpu_vendor = hypervisor.get_cpu_vendor();
    if cpu_vendor != CpuVendor::Intel {
        unimplemented!("CPU profiles can only be generated for Intel CPUs at this point in time");
    }

    let hypervisor_type = hypervisor.hypervisor_type();
    // This is just a reality check.
    if !matches!(hypervisor_type, HypervisorType::Kvm) {
        unimplemented!(
            "CPU profiles can only be generated when using KVM as the hypervisor at this point in time"
        );
    }

    let brand_string_bytes = cpu_brand_string_bytes(cpu_vendor, profile_name)?;
    let cpuid = supported_cpuid(hypervisor)?;
    let cpuid = overwrite_brand_string(cpuid, brand_string_bytes);
    let supported_cpuid_sorted = sort_entries(cpuid);

    let Files {
        cpuid_data_file,
        cpuid_data_license_file,
        msr_data_file,
        msr_data_license_file,
    } = create_files(profile_name)?;

    generate_cpuid_profile_data_with(
        &supported_cpuid_sorted,
        &INTEL_CPUID_DEFINITIONS,
        &KVM_CPUID_DEFINITIONS,
        cpuid_data_file,
        cpuid_data_license_file,
    )?;

    let supported_feature_msrs = hypervisor.get_feature_msrs().context("CPU profile generation failed: Could not get the supported MSR-based features from the hypervisor")?;
    let supported_msrs = hypervisor
        .get_msr_index_list()
        .context("CPU profile generation failed: Could not get MSR index list")?
        .into_iter()
        .collect();

    generate_msr_profile_data_with(
        MsrProfileDataParams {
            processor_feature_msr_definitions:
                &msr_definitions::intel::INTEL_MSR_FEATURE_DEFINITIONS,
            supported_feature_msrs: &supported_feature_msrs,
            supported_msrs,
            permitted_architectural_msrs: &msr_definitions::intel::PERMITTED_IA32_MSRS[..],
            permitted_hypervisor_msrs: &msr_definitions::kvm::PROFILE_PERMITTED_KVM_MSRS[..],
            permitted_hyperv_msrs: &HYPERV_MSRS[..],
            non_architectural_msrs: &msr_definitions::intel::NON_ARCHITECTURAL_INTEL_MSRS[..],
            forbidden_architectural_msrs: &msr_definitions::intel::FORBIDDEN_IA32_MSR_RANGES[..],
            hypervisor_type,
        },
        msr_data_file,
        msr_data_license_file,
    )
}

struct Files {
    cpuid_data_file: File,
    cpuid_data_license_file: File,
    msr_data_file: File,
    msr_data_license_file: File,
}
/// Create empty files with names derived from the name given to the CPU profile.
/// The name will be lowercase and spaces are replaced with "-".
fn create_files(profile_name: &str) -> anyhow::Result<Files> {
    let profile_file_name = {
        let mut name = String::new();
        for part in profile_name.split_whitespace().map(|s| s.to_lowercase()) {
            if !name.is_empty() {
                name.push('-');
            }
            name.push_str(&part);
        }
        name
    };

    let create_file = |path: PathBuf| {
        File::create(path.clone()).with_context(|| {
            format!(
                "CPU profile generation failed: Could not create file:={}",
                path.to_string_lossy()
            )
        })
    };

    let path_with_license = |mut path: PathBuf| {
        path.as_mut_os_string().push(".license");
        path
    };

    let current_dir = std::env::current_dir()
        .context("CPU profile generation failed: Unable to get the current working directory")?;

    let common_path = format!("arch/src/x86_64/cpu_profiles/{profile_file_name}");

    let cpuid_profile_file_name = {
        let mut path = current_dir.clone();
        path.push(format!("{common_path}.cpuid.json"));
        path
    };

    let cpuid_data_file = create_file(cpuid_profile_file_name.clone())?;

    let cpuid_data_license_file_path = path_with_license(cpuid_profile_file_name);

    let cpuid_data_license_file = create_file(cpuid_data_license_file_path)?;

    let msr_profile_file_name = {
        let mut path = current_dir;
        path.push(format!("{common_path}.msr.json"));
        path
    };

    let msr_data_file = create_file(msr_profile_file_name.clone())?;

    let msr_data_license_file_path = path_with_license(msr_profile_file_name);
    let msr_data_license_file = create_file(msr_data_license_file_path)?;

    Ok(Files {
        cpuid_data_file,
        cpuid_data_license_file,
        msr_data_file,
        msr_data_license_file,
    })
}

/// Prepare the bytes which the brand string should consist of
fn cpu_brand_string_bytes(cpu_vendor: CpuVendor, profile_name: &str) -> anyhow::Result<[u8; 48]> {
    let cpu_vendor_str: String = serde_json::to_string(&cpu_vendor)
        .expect("Should be possible to serialize CPU vendor to a string");
    let cpu_vendor_str = cpu_vendor_str.trim_start_matches('"').trim_end_matches('"');
    let mut brand_string_bytes = [0_u8; 4 * 3 * 4];
    if cpu_vendor_str.len() + 1 + profile_name.len() > brand_string_bytes.len() {
        return Err(anyhow!(
            "The profile name is too long. Try using a shorter name"
        ));
    }
    for (b, brand_byte) in cpu_vendor_str
        .as_bytes()
        .iter()
        .chain(std::iter::once(&b' '))
        .chain(profile_name.as_bytes())
        .zip(brand_string_bytes.iter_mut())
    {
        *brand_byte = *b;
    }
    Ok(brand_string_bytes)
}
/// Computes [`CpuIdProfileData`] based on the given sorted vector of CPUID entries, hypervisor type, cpu_vendor
/// and cpuid_definitions.
///
/// The computed [`CpuIdProfileData`] is then converted to a string representation, embeddable as Rust code, which is
/// then written by the given `writer`.
///
// TODO: Consider making a snapshot test or two for this function.
fn generate_cpuid_profile_data_with<const N: usize, const M: usize>(
    supported_cpuid_sorted: &[CpuIdEntry],
    processor_cpuid_definitions: &CpuidDefinitions<N>,
    hypervisor_cpuid_definitions: &CpuidDefinitions<M>,
    mut cpuid_data_file: impl Write,
    cpuid_license_file: impl Write,
) -> anyhow::Result<()> {
    let mut adjustments: Vec<(Parameters, CpuidOutputRegisterAdjustments)> = Vec::new();

    for (parameter, values) in processor_cpuid_definitions
        .as_slice()
        .iter()
        .chain(hypervisor_cpuid_definitions.as_slice().iter())
    {
        for (sub_leaf_range, maybe_matching_register_output_value) in
            extract_parameter_matches(parameter, supported_cpuid_sorted)
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
                        mask |= bit_range_mask::<u32>(first_bit_pos, last_bit_pos);
                    }
                    ProfilePolicy::Static(overwrite_value) => {
                        replacements |= overwrite_value << value.bits_range.0;
                    }
                    ProfilePolicy::Inherit => {
                        // The value is supposed to be obtained from the compatibility target if it exists
                        let (first_bit_pos, last_bit_pos) = value.bits_range;
                        if let Some(matching_register_value) = maybe_matching_register_output_value
                        {
                            let extraction_mask =
                                bit_range_mask::<u32>(first_bit_pos, last_bit_pos);
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

    let cpuid_profile_data = CpuidProfileData { adjustments };

    serde_json::to_writer_pretty(&mut cpuid_data_file, &cpuid_profile_data)
        .context("Cpu profile generation failed: Could not serialize the generated cpuid profile data to the given writer")?;
    cpuid_data_file
        .flush()
        .context("CPU profile generation failed: Unable to flush cpuid profile data")?;
    write_license_file(cpuid_license_file, "CPUID")
}

struct MsrProfileDataParams<'a, const N: usize> {
    hypervisor_type: HypervisorType,
    processor_feature_msr_definitions: &'a MsrDefinitions<N>,
    /// MSR-based features supported by the hardware and hypervisor used to
    /// generate this CPU profile.
    supported_feature_msrs: &'a [MsrEntry],
    /// MSRs supported by the hardware and hypervisor used to generate this
    /// CPU profile.
    supported_msrs: HashSet<u32>,
    /// A list of all architectural MSRs that are permitted if they are also
    /// contained in `supported_msrs`.
    permitted_architectural_msrs: &'a [u32],
    /// MSRs defined by the hypervisor that are permitted if they are supported
    /// by the hardware and hypervisor used when generating this CPU profile
    ///
    /// We let CHV make the final decision at runtime whether they should be
    /// available to guests (currently via CPUID)
    permitted_hypervisor_msrs: &'a [u32],
    /// Hyper-V related MSRs.
    ///
    /// NOTE: We can only know if these are truly permitted  when the profile is
    ///applied at runtime, hence we  include them in the profile regardless and
    ///let  CHV remove them if necessary upon applying the  CPU profile.
    permitted_hyperv_msrs: &'a [u32],
    /// A list of known non-architectural MSRs. This list is only used to help
    /// us detect MSRs that we might not be aware of.
    non_architectural_msrs: &'a [u32],
    /// A list of known ranges of architectural msrs, that should not be
    /// permitted by any generated CPU profile. This list is only used to help
    /// us detect MSRs that we might not be aware of.
    forbidden_architectural_msrs: &'a [(u32, u32)],
}

fn generate_msr_profile_data_with<'a, const N: usize>(
    MsrProfileDataParams {
        hypervisor_type,
        processor_feature_msr_definitions,
        supported_feature_msrs,
        supported_msrs,
        permitted_architectural_msrs,
        permitted_hypervisor_msrs,
        permitted_hyperv_msrs,
        non_architectural_msrs,
        forbidden_architectural_msrs,
    }: MsrProfileDataParams<'a, N>,
    mut msr_data_file: impl Write,
    msr_license_file: impl Write,
) -> anyhow::Result<()> {
    const KVM_GET_NOT_SET_MSRS: [RegisterAddress; 6] = [
        RegisterAddress::IA32_VMX_PINBASED_CTLS,
        RegisterAddress::IA32_VMX_PROCBASED_CTLS,
        RegisterAddress::IA32_VMX_EXIT_CTLS,
        RegisterAddress::IA32_VMX_ENTRY_CTLS,
        RegisterAddress::IA32_VMX_CR0_FIXED1,
        RegisterAddress::IA32_VMX_CR4_FIXED1,
    ];
    let mut entries_encountered = 0;
    let mut adjustments = Vec::new();
    let mut permitted_msrs = HashSet::new();
    'table: for (reg_addr, definitions) in processor_feature_msr_definitions.as_slice() {
        let Some(entry) = supported_feature_msrs
            .iter()
            .find(|e| e.index == reg_addr.0)
        else {
            continue;
        };
        entries_encountered += 1;

        // NOTE: For now this tool only supports KVM, but we insert this check so we don't forget
        // about (possible) KVM specific behavior.
        #[cfg(feature = "kvm")]
        if matches!(hypervisor_type, HypervisorType::Kvm) && KVM_GET_NOT_SET_MSRS.contains(reg_addr)
        {
            // In this case we do not want to record an update, but just that the MSR is permitted.
            permitted_msrs.insert(reg_addr.0);
            continue;
        }

        let value = entry.data;
        let mut replacements = 0;
        let mut mask = 0;
        let mut bits_accounted_for = 0;
        for msr_definitions::ValueDefinition {
            policy,
            bits_range: (first_bit_pos, last_bit_pos),
            ..
        } in definitions.as_slice().iter().copied()
        {
            let temp_mask = bit_range_mask::<u64>(first_bit_pos, last_bit_pos);
            bits_accounted_for |= temp_mask;
            match policy {
                msr_definitions::ProfilePolicy::Deny => {
                    // This can only be applied to the entire MSR
                    assert_eq!(first_bit_pos, 0);
                    assert_eq!(last_bit_pos, 63);
                    continue 'table;
                }
                msr_definitions::ProfilePolicy::Inherit => {
                    replacements |= value & temp_mask;
                }
                msr_definitions::ProfilePolicy::Passthrough => {
                    mask |= temp_mask;
                }
                msr_definitions::ProfilePolicy::Static(overwrite_value) => {
                    replacements |= (overwrite_value) << (first_bit_pos);
                }
            }
        }
        // Reserved bit positions within an MSR value may get assigned meaning by hardware vendors in the future.
        // For this reason we decide to have an "inherit" policy for these bits during profile generation.
        let reserved_values = value & (!bits_accounted_for);
        replacements |= reserved_values;

        permitted_msrs.insert(reg_addr.0);
        adjustments.push((*reg_addr, FeatureMsrAdjustment { mask, replacements }));
    }

    if entries_encountered != supported_feature_msrs.len() {
        let unknown_register_address = supported_feature_msrs.iter().find(|entry| !processor_feature_msr_definitions.as_slice().iter().any(|(reg_addr, _)| reg_addr.0 == entry.index )).expect("We have checked that there should be at least one unknown supported MSR-based feature").index;
        Err(anyhow!(
            "CPU profile generation failed: The hardware and hypervisor supports MSR-based feature with register address:={unknown_register_address:#x}, but the CPU profile generation tool does not know what to do with this MSR. Please update the appropriate `MsrDefinitions` and try again."
        ))?;
    }

    for msr in permitted_architectural_msrs
        .iter()
        .chain(permitted_hypervisor_msrs)
        .chain(permitted_hyperv_msrs)
    {
        if supported_msrs.contains(msr) {
            let _ = permitted_msrs.insert(*msr);
        }
    }

    // Also check to see if there are any MSRs on the system that we are not aware off. In that case
    // it might be a sign that this tool needs to update its definitions!
    for msr in supported_msrs.difference(&permitted_msrs) {
        let is_proc_feat_msr = processor_feature_msr_definitions
            .as_slice()
            .iter()
            .any(|(reg_addr, _)| reg_addr.0 == *msr);

        let is_architectural_msr = forbidden_architectural_msrs
            .iter()
            .any(|r| (r.0..=r.1).contains(msr));

        let is_non_architectural_msr = non_architectural_msrs.contains(msr);

        if is_proc_feat_msr || is_architectural_msr || is_non_architectural_msr {
            continue;
        }

        // TODO: Make this a hard error before upstreaming
        warn!(
            "Encountered unknown MSR:={:#x} when generating CPU profile. This CPU profile generation tool might not be up-to-date",
            *msr
        );
    }

    let permitted_msrs: Vec<RegisterAddress> = {
        let mut permitted_msrs: Vec<u32> = permitted_msrs.into_iter().collect();
        permitted_msrs.sort();
        permitted_msrs.into_iter().map(RegisterAddress).collect()
    };

    let msr_profile_data = MsrProfileData {
        adjustments,
        required_msrs: permitted_msrs,
    };

    serde_json::to_writer_pretty(&mut msr_data_file, &msr_profile_data)
        .context("Cpu profile generation failed: Could not serialize the generated MSR profile data to the given writer")?;
    msr_data_file
        .flush()
        .context("CPU profile generation failed: Unable to flush MSR profile data")?;
    write_license_file(msr_license_file, "MSR")
}

fn write_license_file(mut license_file: impl Write, data_type: &str) -> anyhow::Result<()> {
    let year = Zoned::now().year();
    let license_text = {
        format!(
            r#"SPDX-FileCopyrightText: {year} Cyberus Technology GmbH

SPDX-License-Identifier: Apache-2.0
"#
        )
    };
    license_file
        .write_all(license_text.as_bytes())
        .with_context(|| {
            format!("CPU profile generation failed: Unable to write to {data_type} profile data license file")
        })?;
    license_file.flush().context(format!(
        "CPU profile generation failed: Unable to flush {data_type} profile data license file"
    ))
}
/// Get as many of the supported CPUID entries from the hypervisor as possible.
fn supported_cpuid(hypervisor: &dyn Hypervisor) -> anyhow::Result<Vec<CpuIdEntry>> {
    // Check for AMX compatibility. If this is supported we need to call arch_prctl before requesting the supported
    // CPUID entries from the hypervisor. We simply call the enable_amx_state_components method on the hypervisor and
    // ignore any AMX not supported error to achieve this.
    match hypervisor.enable_amx_state_components() {
        Ok(()) => {}
        Err(HypervisorError::CouldNotEnableAmxStateComponents(amx_err)) => {
            if matches!(
                amx_err,
                hypervisor::arch::x86::AmxGuestSupportError::AmxGuestTileRequest { .. }
            ) {
                return Err(amx_err).context("Unable to enable AMX state tiles for guests");
            }
        }
        Err(_) => unreachable!("Unexpected error when checking AMX support"),
    }

    hypervisor
        .get_supported_cpuid()
        .context("CPU profile data generation failed")
}

/// Overwrite the Processor brand string with the given `brand_string_bytes`
fn overwrite_brand_string(
    mut cpuid: Vec<CpuIdEntry>,
    brand_string_bytes: [u8; 48],
) -> Vec<CpuIdEntry> {
    let mut iter = brand_string_bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_le_bytes(*c));
    let mut overwrite = |leaf: u32| CpuIdEntry {
        function: leaf,
        index: 0,
        flags: 0,
        eax: iter.next().unwrap_or(0),
        ebx: iter.next().unwrap_or(0),
        ecx: iter.next().unwrap_or(0),
        edx: iter.next().unwrap_or(0),
    };
    for leaf in [0x80000002, 0x80000003, 0x80000004] {
        if let Some(entry) = cpuid
            .iter_mut()
            .find(|entry| (entry.function == leaf) && (entry.index == 0))
        {
            *entry = overwrite(leaf);
        } else {
            cpuid.push(overwrite(leaf));
        }
    }
    cpuid
}

/// Sort the CPUID entries by function and index
fn sort_entries(mut cpuid: Vec<CpuIdEntry>) -> Vec<CpuIdEntry> {
    cpuid.sort_unstable_by(|entry, other_entry| {
        let fn_cmp = entry.function.cmp(&other_entry.function);
        if fn_cmp == core::cmp::Ordering::Equal {
            entry.index.cmp(&other_entry.index)
        } else {
            fn_cmp
        }
    });
    cpuid
}

/// Returns a numeric value where each bit between `first_bit_pos` and `last_bit_pos` is set (including both ends) and all other bits are 0.
fn bit_range_mask<T>(first_bit_pos: u8, last_bit_pos: u8) -> T
where
    T: Shl<u8, Output = T>,
    T: BitOr<Output = T>,
    T: From<u8>,
{
    (first_bit_pos..=last_bit_pos).fold(T::from(0_u8), |acc, next| acc | ((T::from(1_u8)) << next))
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
