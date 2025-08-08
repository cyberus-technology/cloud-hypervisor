mod cpuid_feature_flags_impl;
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CpuProfile {
    #[default]
    Host,
    CascadelakeServerV1,
}
