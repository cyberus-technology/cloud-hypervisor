use std::io::Write;
use std::ops::RangeInclusive;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::x86_64::CpuidReg;

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
