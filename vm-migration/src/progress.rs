// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0

//! Module for reporting status and progress of live migrations.
//!
//! The main export is [`MigrationProgress`].
//!
//! # Motivation
//!
//! Monitoring a live-migration is important for debugging of cloud deployments,
//! for cloud monitoring in general, and for network optimization, such as
//! verifying the throughput for the migration is as high as expected.
//!
//! It also helps to analyze the downtime of VMs and see how much pressure a
//! guest is putting on its memory (by writing), which is slowing down
//! migrations.

use std::error::Error;
use std::fmt;
use std::fmt::Display;
use std::num::NonZeroU32;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(
    Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum TransportationMode {
    Local,
    Tcp { connections: NonZeroU32, tls: bool },
}

/// Carries information about the transmission of the VM's memory.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct MemoryTransmissionInfo {
    /// The memory iteration (only in precopy mode).
    pub memory_iteration: u64,
    /// Memory bytes per second.
    pub memory_transmission_bps: u64,
    /// The total size of the VMs memory in bytes.
    pub memory_bytes_total: u64,
    /// The total size of transmitted bytes.
    pub memory_bytes_transmitted: u64,
    /// The amount of remaining bytes for this iteration.
    pub memory_bytes_remaining_iteration: u64,
    /// The amount of transmitted 4k pages.
    pub memory_pages_4k_transmitted: u64,
    /// The amount of remaining 4k pages for this iteration.
    pub memory_pages_4k_remaining_iteration: u64,
    /// The amount of constant pages for that we could take a shortcut.
    /// Pages where all bits are either zero or one.
    pub memory_pages_constant_count: u64,
    /// Current memory dirty rate in pages per seconds (pps).
    pub memory_dirty_rate_pps: u64,
}

/// The different phases of an ongoing ([`MigrationState::Ongoing`]) migration
/// (good case).
///
/// The states correspond to the [live-migration protocol].
///
/// [live-migration protocol]: super::protocol
#[derive(
    Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum MigrationStateOngoingPhase {
    /// The migration process is initiated. No checks or connections are
    /// established yet.
    Starting,
    /// The initial connection is established and the migration protocol
    /// handshake succeeded.
    Started,
    /// Transfer of memory FDs.
    ///
    /// Only used for local migrations.
    MemoryFds,
    /// Transfer of VM memory in precopy mode.
    ///
    /// Not used for local migrations.
    MemoryPrecopy,
    // TODO eventually add MemoryPostcopy here
    /// The VM migration is completing. This means the last chunks of memory
    /// are transmitted as well as the final VM state (vCPUs, devices).
    Completing,
}

impl Display for MigrationStateOngoingPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Starting => write!(f, "starting"),
            Self::Started => write!(f, "started"),
            Self::MemoryFds => write!(f, "memory FDs"),
            Self::MemoryPrecopy => write!(f, "memory (precopy)"),
            Self::Completing => write!(f, "completing"),
        }
    }
}

/// The different states of a migration, covering steady progress and failure.
#[derive(
    Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum MigrationState {
    /// The migration has been cancelled.
    Cancelled {},
    /// The migration has failed.
    Failed {
        /// Stringified error.
        error_msg: String,
        /// Debug-stringified error.
        error_msg_debug: String,
        // TODO this is very tricky because I need clone()
        // error: Box<dyn Error>,
    },
    /// The migration has finished successfully.
    Finished {},
    /// The migration is ongoing.
    Ongoing {
        phase: MigrationStateOngoingPhase,
        /// Percent in range `0..=100`.
        vcpu_throttle_percent: u8,
    },
}

impl Display for MigrationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MigrationState::Cancelled { .. } => write!(f, "{}", self.state_name()),
            MigrationState::Failed { error_msg, .. } => {
                write!(f, "{}: {error_msg}", self.state_name())
            }
            MigrationState::Finished { .. } => write!(f, "{}", self.state_name()),
            MigrationState::Ongoing {
                phase,
                vcpu_throttle_percent,
            } => write!(
                f,
                "{}: phase={phase}, vcpu_throttle={vcpu_throttle_percent}",
                self.state_name()
            ),
        }
    }
}

impl MigrationState {
    fn state_name(&self) -> &'static str {
        match self {
            MigrationState::Cancelled { .. } => "cancelled",
            MigrationState::Failed { .. } => "failed",
            MigrationState::Finished { .. } => "finished",
            MigrationState::Ongoing { .. } => "ongoing",
        }
    }
}

/// Returns the current UNIX timestamp in ms.
fn current_unix_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("should be valid duration")
        .as_millis() as u64
}

/// Holds a snapshot of progress and status information for an ongoing live
/// migration, or the last snapshot of a canceled or aborted migration.
///
/// This type carries insightful information for every step of the
/// [live-migration protocol] in a way that makes it easy for API users to
/// parse the data with ease while retaining all important information.
///
/// [live-migration protocol]: super::protocol
#[derive(
    Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct MigrationProgress {
    /// UNIX timestamp of the start of the live-migration process in ms.
    pub timestamp_begin_ms: u64,
    /// UNIX timestamp of the current snapshot in ms.
    pub timestamp_snapshot_ms: u64,
    /// Relative timestamp since the beginning of the migration in ms.
    pub timestamp_snapshot_relative_ms: u64,
    /// Configured target downtime.
    pub downtime_configured_ms: u64,
    /// Currently estimated (computed) downtime given the remaining
    /// transmissions and the bandwidth.
    ///
    /// If this is `0`, the downtime could not yet be calculated.
    pub downtime_estimated_ms: u64,
    /// Requested transportation mode.
    pub transportation_mode: TransportationMode,
    /// Snapshot of the current phase.
    pub state: MigrationState,
    /// Latest [`MemoryTransmissionInfo`] info, if any.
    ///
    /// The most interesting phase is when current state is
    /// [`MigrationState::Ongoing`] and [`MigrationStateOngoingPhase::MemoryPrecopy`]
    /// as this value will be updated frequently.
    pub memory_transmission_info: MemoryTransmissionInfo,
}

impl MigrationProgress {
    /// Creates new progress in a valid init state.
    ///
    /// This progress must be updated using any of:
    /// - [`Self::update`]
    /// - [`Self::mark_as_finished`]
    /// - [`Self::mark_as_failed`]
    /// - [`Self::mark_as_cancelled`]
    pub fn new(transportation_mode: TransportationMode, target_downtime: Duration) -> Self {
        let timestamp = current_unix_timestamp_ms();
        Self {
            timestamp_begin_ms: timestamp,
            timestamp_snapshot_ms: timestamp,
            timestamp_snapshot_relative_ms: 0,
            downtime_configured_ms: target_downtime.as_millis() as u64,
            downtime_estimated_ms: 0,
            transportation_mode,
            state: MigrationState::Ongoing {
                phase: MigrationStateOngoingPhase::Starting,
                vcpu_throttle_percent: 0,
            },
            memory_transmission_info: MemoryTransmissionInfo::default(),
        }
    }

    /// Updates the state of an ongoing migration.
    ///
    /// Only updates new values that are provided via `Some`.
    ///
    /// # Arguments
    ///
    /// - `new_phase`: The current [`MigrationStateOngoingPhase`].
    /// - `new_memory_transmission_info`: If `Some`, the current [`MemoryTransmissionInfo`].
    /// - `new_cpu_throttle_percent`: If `Some`, the current value of the vCPU throttle percentage.
    ///   Must be in range `0..=100`.
    /// - `new_estimated_downtime`: If `Some`, the latest expected (calculated) downtime.
    pub fn update(
        &mut self,
        new_phase: MigrationStateOngoingPhase,
        new_memory_transmission_info: Option<MemoryTransmissionInfo>,
        new_cpu_throttle_percent: Option<u8>,
        new_estimated_downtime: Option<Duration>,
    ) {
        if let Some(percent) = new_cpu_throttle_percent {
            assert!(percent <= 100);
        }

        if let Some(downtime) = new_estimated_downtime {
            self.downtime_estimated_ms = u64::try_from(downtime.as_millis()).unwrap();
        } else {
            // This is better than showing `0` and it is likely close to the final actual downtime.
            self.downtime_estimated_ms = self.downtime_configured_ms;
        }

        match &self.state {
            MigrationState::Ongoing {
                phase: _old_phase,
                vcpu_throttle_percent: old_vcpu_throttle_percent,
            } => {
                self.timestamp_snapshot_ms = current_unix_timestamp_ms();
                self.timestamp_snapshot_relative_ms =
                    self.timestamp_snapshot_ms - self.timestamp_begin_ms;

                self.memory_transmission_info =
                    new_memory_transmission_info.unwrap_or(self.memory_transmission_info);
                self.state = MigrationState::Ongoing {
                    phase: new_phase,
                    vcpu_throttle_percent: new_cpu_throttle_percent
                        .unwrap_or(*old_vcpu_throttle_percent),
                };
            }
            illegal => {
                // panic is fine as we have a logic error here, nothing that was caused by a user.
                panic!(
                    "illegal state transition: {} -> ongoing",
                    illegal.state_name(),
                );
            }
        }
    }

    /// Sets the underlying state to [`MigrationState::Cancelled`] and
    /// updates all corresponding metadata.
    ///
    /// After this state change, the object is supposed to be handled as immutable.
    ///
    /// # Panics
    ///
    /// If the current state is not [`MigrationState::Ongoing`], this function panics.
    pub fn mark_as_cancelled(&mut self) {
        if !matches!(self.state, MigrationState::Ongoing { .. }) {
            panic!(
                "illegal state transition: {} -> cancelled",
                self.state.state_name()
            );
        }
        self.timestamp_snapshot_ms = current_unix_timestamp_ms();
        self.timestamp_snapshot_relative_ms = self.timestamp_snapshot_ms - self.timestamp_begin_ms;
        self.state = MigrationState::Cancelled {};
    }

    /// Sets the underlying state to [`MigrationState::Failed`] and
    /// updates all corresponding metadata.
    ///
    /// After this state change, the object is supposed to be handled as immutable.
    ///
    /// # Panics
    ///
    /// If the current state is not [`MigrationState::Ongoing`], this function panics.
    pub fn mark_as_failed(&mut self, error: &dyn Error) {
        if !matches!(self.state, MigrationState::Ongoing { .. }) {
            panic!(
                "illegal state transition: {} -> failed",
                self.state.state_name()
            );
        }
        self.timestamp_snapshot_ms = current_unix_timestamp_ms();
        self.timestamp_snapshot_relative_ms = self.timestamp_snapshot_ms - self.timestamp_begin_ms;
        self.state = MigrationState::Failed {
            error_msg: format!("{error}",),
            error_msg_debug: format!("{error:?}",),
        };
    }

    /// Sets the underlying state to [`MigrationState::Finished`] and
    /// updates all corresponding metadata.
    ///
    /// After this state change, the object is supposed to be handled as immutable.
    ///
    /// # Panics
    ///
    /// If the current state is not [`MigrationState::Ongoing`], this function panics.
    pub fn mark_as_finished(&mut self) {
        if !matches!(self.state, MigrationState::Ongoing { .. }) {
            panic!(
                "illegal state transition: {} -> finished",
                self.state.state_name()
            );
        }
        self.timestamp_snapshot_ms = current_unix_timestamp_ms();
        self.timestamp_snapshot_relative_ms = self.timestamp_snapshot_ms - self.timestamp_begin_ms;
        self.state = MigrationState::Finished {};
    }
}

#[cfg(test)]
mod unit_tests {
    use std::thread;

    use super::*;

    fn tcp_mode() -> TransportationMode {
        TransportationMode::Tcp {
            connections: NonZeroU32::new(2).unwrap(),
            tls: true,
        }
    }

    #[test]
    fn new_initializes_valid_state() {
        let target = Duration::from_millis(150);
        let progress = MigrationProgress::new(tcp_mode(), target);

        assert_eq!(progress.timestamp_snapshot_ms, progress.timestamp_begin_ms);
        assert_eq!(progress.timestamp_snapshot_relative_ms, 0);
        assert_eq!(progress.downtime_configured_ms, 150);
        assert_eq!(progress.downtime_estimated_ms, 0);

        match progress.state {
            MigrationState::Ongoing {
                phase,
                vcpu_throttle_percent,
            } => {
                assert_eq!(phase, MigrationStateOngoingPhase::Starting);
                assert_eq!(vcpu_throttle_percent, 0);
            }
            _ => panic!("expected Ongoing state"),
        }

        assert_eq!(
            progress.memory_transmission_info,
            MemoryTransmissionInfo::default()
        );
    }

    #[test]
    fn update_changes_phase_and_preserves_previous_values() {
        let mut progress =
            MigrationProgress::new(TransportationMode::Local, Duration::from_millis(200));

        let initial_timestamp = progress.timestamp_snapshot_ms;

        thread::sleep(Duration::from_millis(1));

        progress.update(MigrationStateOngoingPhase::MemoryPrecopy, None, None, None);

        match progress.state {
            MigrationState::Ongoing {
                phase,
                vcpu_throttle_percent,
            } => {
                assert_eq!(phase, MigrationStateOngoingPhase::MemoryPrecopy);
                assert_eq!(vcpu_throttle_percent, 0); // unchanged
            }
            _ => panic!("expected Ongoing"),
        }

        assert!(progress.timestamp_snapshot_ms >= initial_timestamp);
        assert!(progress.timestamp_snapshot_relative_ms > 0);

        // If no estimated downtime provided, fallback to configured value
        assert_eq!(
            progress.downtime_estimated_ms,
            progress.downtime_configured_ms
        );
    }

    #[test]
    fn update_replaces_memory_info_and_throttle() {
        let mut progress =
            MigrationProgress::new(TransportationMode::Local, Duration::from_millis(100));

        let mem = MemoryTransmissionInfo {
            memory_iteration: 3,
            memory_transmission_bps: 10_000,
            memory_bytes_total: 1_000_000,
            memory_bytes_transmitted: 400_000,
            memory_bytes_remaining_iteration: 100_000,
            memory_pages_4k_transmitted: 100,
            memory_pages_4k_remaining_iteration: 25,
            memory_pages_constant_count: 10,
            memory_dirty_rate_pps: 500,
        };

        progress.update(
            MigrationStateOngoingPhase::MemoryPrecopy,
            Some(mem),
            Some(42),
            Some(Duration::from_millis(55)),
        );

        assert_eq!(progress.memory_transmission_info, mem);
        assert_eq!(progress.downtime_estimated_ms, 55);

        match progress.state {
            MigrationState::Ongoing {
                phase,
                vcpu_throttle_percent,
            } => {
                assert_eq!(phase, MigrationStateOngoingPhase::MemoryPrecopy);
                assert_eq!(vcpu_throttle_percent, 42);
            }
            _ => panic!("expected Ongoing"),
        }
    }

    #[test]
    #[should_panic]
    fn update_panics_if_not_ongoing() {
        let mut progress =
            MigrationProgress::new(TransportationMode::Local, Duration::from_millis(10));
        progress.mark_as_finished();

        progress.update(MigrationStateOngoingPhase::Completing, None, None, None);
    }

    #[test]
    #[should_panic]
    fn throttle_above_100_panics() {
        let mut progress =
            MigrationProgress::new(TransportationMode::Local, Duration::from_millis(10));

        progress.update(
            MigrationStateOngoingPhase::MemoryPrecopy,
            None,
            Some(101),
            None,
        );
    }

    #[test]
    fn mark_as_finished_transitions_state() {
        let mut progress =
            MigrationProgress::new(TransportationMode::Local, Duration::from_millis(10));

        thread::sleep(Duration::from_millis(1));
        progress.mark_as_finished();

        match progress.state {
            MigrationState::Finished {} => {}
            _ => panic!("expected Finished"),
        }

        assert!(progress.timestamp_snapshot_relative_ms > 0);
    }

    #[test]
    #[should_panic]
    fn mark_as_finished_twice_panics() {
        let mut progress =
            MigrationProgress::new(TransportationMode::Local, Duration::from_millis(10));

        progress.mark_as_finished();
        progress.mark_as_finished();
    }

    #[test]
    fn mark_as_failed_sets_error_strings() {
        #[derive(Debug)]
        struct TestError;

        impl fmt::Display for TestError {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "test error")
            }
        }

        impl Error for TestError {}

        let mut progress =
            MigrationProgress::new(TransportationMode::Local, Duration::from_millis(10));

        progress.mark_as_failed(&TestError);

        match &progress.state {
            MigrationState::Failed {
                error_msg,
                error_msg_debug,
            } => {
                assert_eq!(error_msg, "test error");
                assert!(error_msg_debug.contains("TestError"));
            }
            _ => panic!("expected Failed"),
        }
    }

    #[test]
    fn display_formats_are_stable() {
        let mut progress =
            MigrationProgress::new(TransportationMode::Local, Duration::from_millis(10));

        progress.update(
            MigrationStateOngoingPhase::MemoryPrecopy,
            None,
            Some(12),
            None,
        );

        let s = format!("{}", progress.state);
        assert!(s.contains("ongoing"));
        assert!(s.contains("phase=memory (precopy)"));
        assert!(s.contains("vcpu_throttle=12"));

        progress.mark_as_cancelled();
        assert_eq!(format!("{}", progress.state), "cancelled");
    }
}
