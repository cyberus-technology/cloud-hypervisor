// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0

//! Blockdev-mirroring for virtio-blk devices.
//!
//! Mirrors guest writes to a destination disk while a background
//! worker copies existing data from source to destination. Once
//! both sides are in sync the device manager can complete the mirror,
//! switching the device to serve I/O from the destination.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex};
use std::{io, mem};

use thiserror::Error;
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::poll::PollContext;

use crate::async_io::{
    AsyncIo, AsyncIoCompletion, AsyncIoError, AsyncIoOperation, AsyncIoResult, OwnedIoBuffer,
};

/// Serializes overlapping byte ranges between the copy worker and the
/// per-queue mirror writes.
///
/// Each party calls [`Self::lock_range`] before submitting I/O and
/// holds the returned [`RangeGuard`] until completion. A conflicting
/// request blocks on a `Condvar` until the held guard is dropped.
struct RangeLockManager {
    /// Held ranges as `start -> end_exclusive`.
    ///
    /// The mutex makes the overlap check and insert in [`Self::lock_range`]
    /// atomic with respect to releases in [`Self::release`].
    ranges: Mutex<BTreeMap<u64, u64>>,
    /// Notified when a range is released.
    ///
    /// Waiters re-check their range.
    cv: Condvar,
}

impl RangeLockManager {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            ranges: Mutex::new(BTreeMap::new()),
            cv: Condvar::new(),
        })
    }

    /// Returns true if `[start, end)` overlaps any range in `ranges`.
    fn overlaps_any(ranges: &BTreeMap<u64, u64>, start: u64, end: u64) -> bool {
        ranges
            .range(..end)
            .next_back()
            .is_some_and(|(_, &e)| e > start)
    }

    /// Acquires an exclusive lock on `[offset, offset + length)`.
    ///
    /// Blocks while any held range overlaps.
    fn lock_range(self: Arc<Self>, offset: u64, length: u64) -> io::Result<RangeGuard> {
        if length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Range length is zero",
            ));
        }

        let end = offset
            .checked_add(length)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Range overflow"))?;
        {
            let mut ranges = self
                .cv
                .wait_while(self.ranges.lock().unwrap(), |ranges| {
                    RangeLockManager::overlaps_any(ranges, offset, end)
                })
                .unwrap();
            ranges.insert(offset, end);
        }

        Ok(RangeGuard {
            manager: self,
            start: offset,
        })
    }

    /// Releases the range starting at `start` and wakes all waiters.
    fn release(&self, start: u64) {
        let mut ranges = self.ranges.lock().unwrap();
        ranges.remove(&start);
        self.cv.notify_all();
    }
}

/// RAII handle for a range held in a [`RangeLockManager`].
///
/// Dropping the handle releases the range and wakes all waiters.
struct RangeGuard {
    manager: Arc<RangeLockManager>,
    start: u64,
}

impl Drop for RangeGuard {
    fn drop(&mut self) {
        self.manager.release(self.start);
    }
}

/// Failure that stopped an active block mirror.
#[derive(Debug, Error)]
pub enum MirrorFailure {
    /// A destination completion returned an unexpected result.
    #[error("Destination completion was {actual}, expected {expected}: user_data={user_data}")]
    DestinationCompletion {
        user_data: u64,
        actual: i32,
        expected: i32,
    },
    /// Submitting an operation to the destination failed.
    #[error("Destination request submission failed: {0}")]
    DestinationSubmit(#[source] AsyncIoError),
    /// Waiting for a destination completion failed.
    #[error("Destination wait failed for user_data={user_data}: {source}")]
    DestinationWait {
        user_data: u64,
        #[source]
        source: io::Error,
    },
    /// A source completion returned an unexpected result.
    #[error("Source completion was {actual}, expected {expected}: user_data={user_data}")]
    SourceCompletion {
        user_data: u64,
        actual: i32,
        expected: i32,
    },
}

/// Phase of a mirror.
#[derive(Debug, Clone)]
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
    Failed(Arc<MirrorFailure>),
}

/// State shared by the copy worker and the per-queue mirroring
/// `AsyncIo` handles.
pub struct MirrorState {
    /// Current phase of the mirror.
    phase: Mutex<MirrorPhase>,
    range_locks: Arc<RangeLockManager>,
}

impl MirrorState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            phase: Mutex::new(MirrorPhase::Running),
            range_locks: RangeLockManager::new(),
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
    /// Running    -> Ready | Cancelling | Failed(_)
    /// Ready      -> Completing | Cancelling | Failed(_)
    /// Completing -> Completed
    /// Failed(_)  -> Cancelling
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
                | (Running, Failed(_))
                | (Ready, Completing)
                | (Ready, Cancelling)
                | (Ready, Failed(_))
                | (Completing, Completed)
                | (Failed(_), Cancelling)
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
///
/// Reads use the source backend. Mutating requests use both the source and
/// destination backends.
///
/// If the destination backend fails, all subsequent disk operations are passed
/// through to the source backend.
pub struct MirroringAsyncIo {
    source: CompletionIo,
    destination: CompletionIo,
    state: Arc<MirrorState>,
    /// Source completions retained for delivery to the virtqueue, including
    /// owned read buffers needed for guest-memory copy-back.
    inflight_completions: VecDeque<AsyncIoCompletion>,
    /// Set once this virtqueue worker observes a failure.
    ///
    /// While true, the worker forwards only to the source and ignores the
    /// destination.
    bypass_destination: bool,
}

impl MirroringAsyncIo {
    /// Flips the mirror to the `Failed` phase.
    ///
    /// The operator must cancel to clean up the destination and the copy worker.
    fn fail(&mut self, failure: MirrorFailure) {
        // Phase fails the mirror globally, passthrough is per worker, so other queues fail independently.
        self.state
            .transition_to_phase(MirrorPhase::Failed(Arc::new(failure)));
        self.bypass_destination = true;
    }

    /// Calls source and destination submissions with mirror-specific error handling.
    ///
    /// A source submission error is returned to the guest. A destination submission
    /// error fails the mirror but is not returned, because `source` is the disk
    /// visible to the guest.
    fn mirror_request(
        &mut self,
        submit: impl Fn(&mut dyn AsyncIo) -> AsyncIoResult<()>,
    ) -> AsyncIoResult<()> {
        submit(self.source.io_mut())?;
        if let Err(error) = submit(self.destination.io_mut()) {
            self.fail(MirrorFailure::DestinationSubmit(error));
        }
        Ok(())
    }

    /// Blocks until `user_data`'s source completion and, unless already in
    /// passthrough mode, its destination completion arrive, then queues the
    /// guest-visible source completion.
    ///
    /// Other completions seen while waiting are stashed for later delivery.
    fn wait_for_completions(&mut self, user_data: u64, expected_result: i32) -> io::Result<()> {
        let source_completion = loop {
            let completion = self.source.next_completion()?;
            if completion.user_data == user_data {
                break completion;
            }
            self.inflight_completions.push_back(completion);
        };

        if !self.bypass_destination {
            match self.destination.next_completion().and_then(|completion| {
                if completion.user_data != user_data {
                    return Err(io::Error::other(format!(
                        "Unexpected destination completion {}, expected {user_data}",
                        completion.user_data
                    )));
                }
                Ok(completion.result)
            }) {
                Ok(dest_result) if dest_result != expected_result => {
                    self.fail(MirrorFailure::DestinationCompletion {
                        user_data,
                        actual: dest_result,
                        expected: expected_result,
                    });
                }
                Ok(_) => {}
                // The destination wait itself failed (broken notifier or epoll).
                // Hide it from the guest like any other destination failure.
                Err(source) => self.fail(MirrorFailure::DestinationWait { user_data, source }),
            }
        }

        if source_completion.result != expected_result {
            self.fail(MirrorFailure::SourceCompletion {
                user_data,
                actual: source_completion.result,
                expected: expected_result,
            });
        }

        self.inflight_completions.push_back(source_completion);
        let _ = self.source.io().notifier().write(1);
        Ok(())
    }
}

impl AsyncIo for MirroringAsyncIo {
    /// Returns the source notifier.
    ///
    /// The destination notifier is consumed internally and is not exposed to
    /// the virtqueue worker.
    fn notifier(&self) -> &EventFd {
        self.source.io().notifier()
    }

    fn submit_data_operation(&mut self, op: AsyncIoOperation) -> AsyncIoResult<()> {
        if op.is_read() || self.bypass_destination {
            return self.source.io_mut().submit_data_operation(op);
        }

        let offset = u64::try_from(op.offset()).map_err(|_| {
            AsyncIoError::WriteVectored(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Negative mirror write offset",
            ))
        })?;
        let length = op.total_len();
        let expected_result = i32::try_from(length)
            .map_err(|_| AsyncIoError::WriteVectored(io::Error::other("Write is too large")))?;
        let user_data = op.user_data();
        let _guard = Arc::clone(&self.state.range_locks)
            .lock_range(offset, length as u64)
            .map_err(AsyncIoError::WriteVectored)?;

        let alignment = self.alignment().unwrap_or(1) as usize;
        let mut destination_buffer =
            OwnedIoBuffer::new(length, alignment).map_err(AsyncIoError::WriteVectored)?;
        op.read_bytes_at(0, destination_buffer.as_mut_slice())
            .map_err(AsyncIoError::WriteVectored)?;
        let source_op = match op {
            AsyncIoOperation::WriteFromMemory { offset, .. } => {
                let mut source_buffer =
                    OwnedIoBuffer::new(length, alignment).map_err(AsyncIoError::WriteVectored)?;
                source_buffer
                    .as_mut_slice()
                    .copy_from_slice(destination_buffer.as_slice());
                AsyncIoOperation::write_from_vec(offset, source_buffer, user_data)
            }
            op => op,
        };
        let destination_op =
            AsyncIoOperation::write_from_vec(source_op.offset(), destination_buffer, user_data);

        self.source.io_mut().submit_data_operation(source_op)?;
        if let Err(error) = self
            .destination
            .io_mut()
            .submit_data_operation(destination_op)
        {
            self.fail(MirrorFailure::DestinationSubmit(error));
        }
        self.wait_for_completions(user_data, expected_result)
            .map_err(AsyncIoError::WriteVectored)
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        if self.bypass_destination {
            return self.source.io_mut().fsync(user_data);
        }

        self.mirror_request(|backend| backend.fsync(user_data))?;

        // A tracked fsync (Some) waits for its completion. A barrier fsync (None) does not.
        if let Some(user_data) = user_data {
            self.wait_for_completions(user_data, 0)
                .map_err(AsyncIoError::Fsync)?;
        }
        Ok(())
    }

    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        if self.bypass_destination {
            return self.source.io_mut().punch_hole(offset, length, user_data);
        }

        let _guard = Arc::clone(&self.state.range_locks)
            .lock_range(offset, length)
            .map_err(AsyncIoError::PunchHole)?;
        self.mirror_request(|backend| backend.punch_hole(offset, length, user_data))?;

        self.wait_for_completions(user_data, 0)
            .map_err(AsyncIoError::PunchHole)?;
        Ok(())
    }

    fn write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        if self.bypass_destination {
            return self.source.io_mut().write_zeroes(offset, length, user_data);
        }

        let _guard = Arc::clone(&self.state.range_locks)
            .lock_range(offset, length)
            .map_err(AsyncIoError::WriteZeroes)?;
        self.mirror_request(|backend| backend.write_zeroes(offset, length, user_data))?;

        self.wait_for_completions(user_data, 0)
            .map_err(AsyncIoError::WriteZeroes)?;
        Ok(())
    }

    fn next_completed_request(&mut self) -> Option<AsyncIoCompletion> {
        // Deliver completions saved while waiting for a mirrored write first.
        self.inflight_completions
            .pop_front()
            .or_else(|| self.source.io_mut().next_completed_request())
    }

    fn batch_requests_enabled(&self) -> bool {
        // Only batch when bypassing the destination to avoid reordering mirrored writes.
        self.bypass_destination && self.source.io().batch_requests_enabled()
    }

    fn submit_batch_requests(&mut self, batch_request: Vec<AsyncIoOperation>) -> AsyncIoResult<()> {
        if batch_request.is_empty() {
            return Ok(());
        }

        if !self.batch_requests_enabled() {
            return Err(AsyncIoError::SubmitBatchRequests(io::Error::other(
                "non-empty batch outside source passthrough",
            )));
        }

        self.source.io_mut().submit_batch_requests(batch_request)
    }

    fn alignment(&self) -> Option<u64> {
        if self.bypass_destination {
            return self.source.io().alignment();
        }

        // Stricter alignment wins for request validation and buffer allocation.
        self.source
            .io()
            .alignment()
            .max(self.destination.io().alignment())
    }
}

/// Owns an [`AsyncIo`] backend and waits for its completions.
///
/// Waiting uses a poller because the backend's notifier is created
/// non-blocking and therefore never blocks on read.
struct CompletionIo {
    poll: PollContext<()>,
    io: Box<dyn AsyncIo>,
}

#[cfg_attr(not(test), expect(dead_code))]
impl CompletionIo {
    fn new(io: Box<dyn AsyncIo>) -> io::Result<Self> {
        let poll = PollContext::new()?;
        poll.add(io.notifier(), ())?;
        Ok(Self { poll, io })
    }

    fn io(&self) -> &dyn AsyncIo {
        self.io.as_ref()
    }

    fn io_mut(&mut self) -> &mut dyn AsyncIo {
        self.io.as_mut()
    }

    /// Blocks until the owned backend reports a completion, then returns it.
    fn next_completion(&mut self) -> io::Result<AsyncIoCompletion> {
        loop {
            if let Some(completion) = self.io.next_completed_request() {
                return Ok(completion);
            }
            // EINTR is retried inside `wait`.
            self.poll.wait()?;
            // Drain the eventfd so the next wait does not fire on a stale signal.
            self.io.notifier().read()?;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::FileExt;

    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::async_io::GuestMemoryTarget;
    use crate::disk_file::AsyncDiskFile;
    use crate::formats::raw::{RawBackend, RawDisk};

    fn mirror_with_files() -> (MirroringAsyncIo, TempFile, TempFile) {
        let source = TempFile::new().unwrap();
        let destination = TempFile::new().unwrap();
        let create_io = |file: &TempFile| {
            file.as_file().set_len(4096).unwrap();
            let disk = RawDisk::new(file.as_file().try_clone().unwrap(), RawBackend::Sync, false);
            CompletionIo::new(disk.create_async_io(1).unwrap()).unwrap()
        };
        let mirror = MirroringAsyncIo {
            source: create_io(&source),
            destination: create_io(&destination),
            state: MirrorState::new(),
            inflight_completions: VecDeque::new(),
            bypass_destination: false,
        };
        (mirror, source, destination)
    }

    #[test]
    fn owned_writes_fan_out_and_preserve_interleaved_read_buffer() {
        let (mut mirror, source, destination) = mirror_with_files();
        source.as_file().write_all_at(&[0x42; 4096], 0).unwrap();

        mirror
            .read_to_vec(0, OwnedIoBuffer::from_vec(vec![0; 4096]), 1)
            .unwrap();
        mirror
            .write_from_vec(0, OwnedIoBuffer::from_vec(vec![0x71; 4096]), 2)
            .unwrap();

        let read = mirror.next_completed_request().unwrap();
        assert_eq!((read.user_data, read.result), (1, 4096));
        assert_eq!(read.buffer.unwrap().as_slice(), &[0x42; 4096]);
        let write = mirror.next_completed_request().unwrap();
        assert_eq!((write.user_data, write.result), (2, 4096));
        assert!(write.buffer.is_none());
        assert!(mirror.next_completed_request().is_none());
        for disk in [&source, &destination] {
            let mut bytes = [0; 4096];
            disk.as_file().read_exact_at(&mut bytes, 0).unwrap();
            assert_eq!(bytes, [0x71; 4096]);
        }
    }

    #[test]
    fn guest_memory_writes_are_snapshotted_for_both_backends() {
        let (mut mirror, source, destination) = mirror_with_files();
        let mem = Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
        mem.write_slice(&[0x53; 4096], GuestAddress(0)).unwrap();
        let target = GuestMemoryTarget::new(mem, &[(GuestAddress(0), 4096)]).unwrap();
        mirror.write_from_memory(0, target, 3).unwrap();
        let completion = mirror.next_completed_request().unwrap();
        assert_eq!((completion.user_data, completion.result), (3, 4096));
        for disk in [&source, &destination] {
            let mut bytes = [0; 4096];
            disk.as_file().read_exact_at(&mut bytes, 0).unwrap();
            assert_eq!(bytes, [0x53; 4096]);
        }
        assert!(mirror.state.range_locks.ranges.lock().unwrap().is_empty());
    }

    /// Overlap is detected whether the held range precedes the query or starts
    /// inside it.
    #[test]
    fn overlaps_detects_overlap() {
        let mut preceding = BTreeMap::new();
        preceding.insert(10u64, 25u64);
        assert!(RangeLockManager::overlaps_any(&preceding, 20, 30));

        let mut starts_inside = BTreeMap::new();
        starts_inside.insert(10u64, 20u64);
        starts_inside.insert(25u64, 30u64);
        assert!(RangeLockManager::overlaps_any(&starts_inside, 21, 26));
    }

    #[test]
    fn overlaps_disjoint_returns_false() {
        let mut locked = BTreeMap::new();
        locked.insert(10u64, 20u64);
        locked.insert(30u64, 40u64);
        assert!(!RangeLockManager::overlaps_any(&locked, 22, 28));
    }

    #[test]
    fn overlaps_touching_boundary_is_not_overlap() {
        let mut locked = BTreeMap::new();
        locked.insert(10u64, 20u64);
        assert!(!RangeLockManager::overlaps_any(&locked, 20, 30));
    }

    /// Verifies that empty and overflowing ranges are rejected as invalid input.
    #[test]
    fn range_lock_rejects_empty_and_overflowing_ranges() {
        let manager = RangeLockManager::new();

        let empty = Arc::clone(&manager).lock_range(0, 0).err().unwrap();
        assert_eq!(empty.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(empty.to_string(), "Range length is zero");

        let overflow = manager.lock_range(u64::MAX, 1).err().unwrap();
        assert_eq!(overflow.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(overflow.to_string(), "Range overflow");
    }
}
