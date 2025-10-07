use std::ops::RangeInclusive;

use serde::{Deserialize, Serialize};

use crate::x86_64::CpuidReg;

/// Parameters for inspecting CPUID definitions.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Parameters {
    // The leaf (EAX) parameter used with the CPUID instruction
    pub leaf: u32,
    // The sub-leaf (ECX) parameter used with the CPUID instruction
    pub sub_leaf: RangeInclusive<u32>,
    // The register we are interested in inspecting which gets filled by the CPUID instruction
    pub register: CpuidReg,
}

/// Describes a policy for how the corresponding CPUID data should be considered when building
/// a CPU profile.
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
    /// This variant is typically used for features/values that don't work well with live migration (even when using the exact same physical CPU model)
    Overwrite(u32),
}

/// Describes how values within a CPUID output on two different hosts must relate to another in order for live-migration to be considered acceptable.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MigrationCompatibilityRequirement {
    /// The value must be equal.
    Eq,
    /// The target host must have at least the same bits set.
    ContainsBits,
    /// The target's value must be greater or equal to the source's.
    GtEq,
    /// The target's value must be less than or equal to the source's.
    LtEq,
    /// The value does not have to be compared.
    Ignore,
}

/// A description of a range of bits in a register populated by the CPUID instruction with specific parameters.
#[derive(Clone, Copy)]
pub struct ValueDefinition {
    /// A short name for the value obtainable through CPUID
    pub short: &'static str,
    /// A description of the value obtainable through CPUID
    pub description: &'static str,
    /// The range of bits in the output register corresponding to this feature or value.
    pub bits_range: (u8, u8),
    /// The policy corresponding to this value when building CPU profiles.
    pub policy: ProfilePolicy,
    pub migration_compatibility_req: MigrationCompatibilityRequirement,
}

/// Describes values within a register populated by the CPUID instruction with specific parameters.
///
/// NOTE: The only way to interact with this value (beyond this crate) is via the const [`Self::as_slice()`](Self::as_slice) method.
pub struct ValueDefinitions(&'static [ValueDefinition]);
impl ValueDefinitions {
    /// Constructor permitting less than 32 entries.
    const fn new(cpuid_descriptions: &'static [ValueDefinition]) -> Self {
        Self(cpuid_descriptions)
    }
    /// Converts this into a slice representation. This is the only way to read values of this type.
    ///
    // Altough, not necessary we prefer to annotate lifetimes in this case in order to simplify satefy analysis
    pub const fn as_slice(&self) -> &'static [ValueDefinition] {
        self.0
    }
}

/// Describes multiple CPUID outputs.
///
/// Each wraped [`ValueDefinitions`] corresponds to the given [`Parameters`] in the same tuple.
///
// TODO: Consider introducing a const as_slice method to make it impossible for the parameter -> value definitions
// constraints being broken.
pub struct CpuidDefinitions<const NUM_PARAMETERS: usize>(
    pub [(Parameters, ValueDefinitions); NUM_PARAMETERS],
);
