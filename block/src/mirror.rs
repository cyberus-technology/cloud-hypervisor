// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0

//! Blockdev-mirroring for virtio-blk devices.
//!
//! Mirrors guest writes to a destination disk while a background
//! worker copies existing data from source to destination. Once
//! both sides are in sync the device manager can complete the mirror,
//! switching the device to serve I/O from the destination.

use std::mem;
use std::sync::{Arc, Mutex};

use libc::{iovec, off_t};
use log::warn;
use vmm_sys_util::eventfd::EventFd;

use crate::BatchRequest;
use crate::async_io::{AsyncIo, AsyncIoResult};

/// Phase of a mirror.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MirrorPhase {
    /// Background copy is in progress.
    Running,
    /// All blocks copied. Source and destination are in sync.
    Ready,
    /// Switch-over to the destination is in progress.
    Completing,
    /// All virtqueues switched to the destination.
    Completed,
    /// Mirror cancellation is in progress.
    Cancelling,
    /// The mirror has failed.
    Failed,
}

/// State shared by the copy worker and the per-queue mirroring
/// `AsyncIo` handles.
pub struct MirrorState {
    /// Current phase of the mirror.
    phase: Mutex<MirrorPhase>,
}

impl MirrorState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            phase: Mutex::new(MirrorPhase::Running),
        })
    }

    /// Returns a snapshot of the current phase.
    pub fn phase(&self) -> MirrorPhase {
        self.phase.lock().unwrap().clone()
    }

    /// Attempts a phase transition.
    ///
    /// Only documented transitions are applied. Invalid transitions panic.
    ///
    /// Allowed transitions:
    /// ```text
    /// Running    -> Ready | Cancelling | Failed
    /// Ready      -> Completing | Cancelling | Failed
    /// Completing -> Completed
    /// Failed     -> Cancelling
    /// ```
    ///
    /// Plus idempotent self-transitions. `Completed` and `Cancelling` are
    /// terminal: the mirror handle is dropped out of them, after which
    /// `Block::mirror_status` reports no active mirror.
    pub fn transition_to_phase(&self, target: MirrorPhase) {
        use MirrorPhase::*;
        let mut current = self.phase.lock().unwrap();

        if mem::discriminant(&*current) == mem::discriminant(&target) {
            return;
        }

        let transition_allowed = matches!(
            (&*current, &target),
            (Running, Ready)
                | (Running, Cancelling)
                | (Running, Failed)
                | (Ready, Completing)
                | (Ready, Cancelling)
                | (Ready, Failed)
                | (Completing, Completed)
                | (Failed, Cancelling)
        );

        if !transition_allowed {
            // An invalid transition indicates a programming error. Reverting the
            // virtqueue workers requires sending a `BlockQueueCommand` to each
            // worker, which `MirrorState` cannot do.
            panic!(
                "Invalid mirror phase transition attempted: {:?} -> {:?}",
                *current, target
            );
        }

        *current = target;
    }
}

/// Per-virtqueue [`AsyncIo`] backend for an active block mirror.
#[expect(dead_code)]
pub struct MirroringAsyncIo {
    source: Box<dyn AsyncIo>,
    destination: Box<dyn AsyncIo>,
    state: Arc<MirrorState>,
}

impl AsyncIo for MirroringAsyncIo {
    fn notifier(&self) -> &EventFd {
        self.source.notifier()
    }

    fn read_vectored(
        &mut self,
        offset: off_t,
        iovecs: &[iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        self.source.read_vectored(offset, iovecs, user_data)
    }

    fn write_vectored(
        &mut self,
        offset: off_t,
        iovecs: &[iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        self.source.write_vectored(offset, iovecs, user_data)
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        self.source.fsync(user_data)
    }

    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        self.source.punch_hole(offset, length, user_data)
    }

    fn write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        self.source.write_zeroes(offset, length, user_data)
    }

    fn next_completed_request(&mut self) -> Option<(u64, i32)> {
        self.source.next_completed_request()
    }

    fn batch_requests_enabled(&self) -> bool {
        false
    }

    fn submit_batch_requests(&mut self, _batch_request: &[BatchRequest]) -> AsyncIoResult<()> {
        unimplemented!("Batch requests are not supported in MirroringAsyncIo")
    }

    fn alignment(&self) -> u64 {
        // Stricter alignment wins. Same iovec goes to both backends.
        self.source.alignment().max(self.destination.alignment())
    }
}
