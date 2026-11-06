#[cfg(all(feature = "kvm", feature = "sev_snp", feature = "fw_cfg"))]
pub(crate) mod sev;
mod shared_page_tracker;

pub(crate) use shared_page_tracker::CvmSharedPageTracker;
