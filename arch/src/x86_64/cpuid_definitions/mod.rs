use std::io::Write;
use std::ops::RangeInclusive;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::x86_64::CpuidReg;

pub mod intel;

pub(in crate::x86_64) fn serialize_as_hex<S: Serializer>(
    input: &u32,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    // two bytes for "0x" prefix and eight for the hex encoded number
    let mut buffer = [0_u8; 10];
    let _ = write!(&mut buffer[..], "{:#010x}", input);
    let str = core::str::from_utf8(&buffer[..])
        .expect("the buffer should be filled with valid UTF-8 bytes");
    serializer.serialize_str(str)
}

pub(in crate::x86_64) fn deserialize_from_hex<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<u32, D::Error> {
    let hex = <&'de str as Deserialize>::deserialize(deserializer)?;
    u32::from_str_radix(hex.strip_prefix("0x").unwrap_or(""), 16).map_err(|_| {
        <D::Error as serde::de::Error>::custom(format!("{hex} is not a hex encoded 32 bit integer"))
    })
}

/// Parameters for inspecting CPUID definitions.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Parameters {
    // The leaf (EAX) parameter used with the CPUID instruction
    #[serde(serialize_with = "serialize_as_hex")]
    #[serde(deserialize_with = "deserialize_from_hex")]
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
///
/// NOTE: The only way to interact with this value (beyond this crate) is via the const [`Self::as_slice()`](Self::as_slice) method.
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
}
