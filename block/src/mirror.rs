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
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::{io, mem, thread};

use libc::{iovec, off_t};
use log::warn;
use thiserror::Error;
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::poll::PollContext;

use crate::async_io::{AsyncIo, AsyncIoError, AsyncIoResult};
use crate::disk_file::AsyncFullDiskFile;
use crate::error::BlockResult;
use crate::qcow_common::AlignedBuf;
use crate::{BatchRequest, RequestType};

/// Block size for the copy worker, in which it copies data from
/// source to destination and holds the range lock.
pub const MIRROR_BLOCK_SIZE: usize = 512 * 1024; // 512 KiB

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
    pub fn new() -> Arc<Self> {
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

    /// Acquires a [`RangeGuard`] covering the contiguous bytes from
    /// `offset` through the end of `iovecs`.
    fn lock_iovecs(self: Arc<Self>, offset: off_t, iovecs: &[iovec]) -> io::Result<RangeGuard> {
        let total_len = iovecs
            .iter()
            .try_fold(0u64, |acc, v| acc.checked_add(v.iov_len as u64))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "iovec length overflow"))?;

        self.lock_range(offset as u64, total_len)
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

/// Describes a failure recorded in a block mirror's shared state.
#[derive(Debug, Error)]
pub enum MirrorFailure {
    /// The background copy worker failed.
    #[error("Copy worker failed: {0}")]
    CopyWorker(#[source] io::Error),
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
    /// Installing the mirror backend failed.
    #[error("Mirror installation failed")]
    Installation,
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
    copied_bytes: AtomicU64,
    total_bytes: u64,
}

impl MirrorState {
    pub fn new(logical_disk_size: u64) -> Arc<Self> {
        Arc::new(Self {
            phase: Mutex::new(MirrorPhase::Running),
            range_locks: RangeLockManager::new(),
            copied_bytes: AtomicU64::new(0),
            total_bytes: logical_disk_size,
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

    /// Returns a snapshot of the mirror phase and copy progress.
    pub fn status(&self) -> MirrorStatus {
        MirrorStatus {
            phase: self.phase(),
            copied_bytes: self.copied_bytes.load(Ordering::Relaxed),
            total_bytes: self.total_bytes,
        }
    }
}

/// Snapshot of an active block mirror's phase and copy progress.
pub struct MirrorStatus {
    /// Current lifecycle phase.
    pub phase: MirrorPhase,
    /// Number of source bytes copied by the background worker.
    pub copied_bytes: u64,
    /// Total logical number of bytes to copy.
    pub total_bytes: u64,
}

/// Per-virtqueue [`AsyncIo`] backend for an active block mirror.
///
/// Reads use the source backend. Mutating requests use both the source and
/// destination backends.
pub struct MirroringAsyncIo {
    source: CompletionIo,
    destination: CompletionIo,
    state: Arc<MirrorState>,
    /// Queued completions `(user_data, result)` for
    /// [`AsyncIo::next_completed_request`].
    ///
    /// The `user_data` identifies the request it was submitted with. The
    /// result is the number of bytes transferred or a negative errno.
    inflight_completions: VecDeque<(u64, i32)>,
}

impl MirroringAsyncIo {
    /// Creates a mirroring backend for one virtqueue.
    ///
    /// `state` must be shared with the copy worker and all other virtqueue
    /// backends for the same mirror.
    pub fn create(
        source_disk: &dyn AsyncFullDiskFile,
        destination_disk: &dyn AsyncFullDiskFile,
        state: Arc<MirrorState>,
        ring_depth: u32,
    ) -> BlockResult<Self> {
        let source = CompletionIo::new(source_disk.create_async_io(ring_depth)?)?;
        let destination = CompletionIo::new(destination_disk.create_async_io(ring_depth)?)?;

        Ok(Self {
            source,
            destination,
            state,
            inflight_completions: VecDeque::new(),
        })
    }

    /// Flips the mirror to the `Failed` phase.
    ///
    /// The operator must cancel to clean up the destination and the copy worker.
    fn fail(&mut self, failure: MirrorFailure) {
        self.state
            .transition_to_phase(MirrorPhase::Failed(Arc::new(failure)));
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

    /// Blocks until `user_data`'s source and destination completions arrive,
    /// then queues the guest-visible `(user_data, src_result)`.
    ///
    /// Other completions seen while waiting are stashed for later delivery.
    fn wait_for_completions(&mut self, user_data: u64, expected_result: i32) -> io::Result<()> {
        let src_result =
            Self::await_completion(&mut self.source, &mut self.inflight_completions, user_data)?;

        match Self::await_completion(
            &mut self.destination,
            &mut self.inflight_completions,
            user_data,
        ) {
            // Destination reported an I/O error or incomplete operation.
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

        if src_result != expected_result {
            self.fail(MirrorFailure::SourceCompletion {
                user_data,
                actual: src_result,
                expected: expected_result,
            });
        }

        self.inflight_completions.push_back((user_data, src_result));
        let _ = self.source.io().notifier().write(1);
        Ok(())
    }

    /// Drains `completion_io` until `user_data`'s completion appears and pushes
    /// additional ones to `inflight_completions`.
    fn await_completion(
        completion_io: &mut CompletionIo,
        inflight_completions: &mut VecDeque<(u64, i32)>,
        user_data: u64,
    ) -> io::Result<i32> {
        loop {
            let (id, res) = completion_io.next_completion()?;
            if id == user_data {
                return Ok(res);
            }
            inflight_completions.push_back((id, res));
        }
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

    fn read_vectored(
        &mut self,
        offset: off_t,
        iovecs: &[iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        self.source
            .io_mut()
            .read_vectored(offset, iovecs, user_data)
    }

    fn write_vectored(
        &mut self,
        offset: off_t,
        iovecs: &[iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        let expected_result = iovecs
            .iter()
            .map(|iov| iov.iov_len)
            .sum::<usize>()
            .try_into()
            .map_err(|_| AsyncIoError::WriteVectored(io::Error::other("write is too large")))?;

        let _guard = self
            .state
            .range_locks
            .clone()
            .lock_iovecs(offset, iovecs)
            .map_err(AsyncIoError::WriteVectored)?;

        self.mirror_request(|backend| backend.write_vectored(offset, iovecs, user_data))?;

        self.wait_for_completions(user_data, expected_result)
            .map_err(AsyncIoError::WriteVectored)?;
        Ok(())
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        self.mirror_request(|backend| backend.fsync(user_data))?;

        // A tracked fsync (Some) waits for its completion. A barrier fsync (None) does not.
        if let Some(user_data) = user_data {
            self.wait_for_completions(user_data, 0)
                .map_err(AsyncIoError::Fsync)?;
        }
        Ok(())
    }

    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        let _guard = self
            .state
            .range_locks
            .clone()
            .lock_range(offset, length)
            .map_err(AsyncIoError::PunchHole)?;
        self.mirror_request(|backend| backend.punch_hole(offset, length, user_data))?;

        self.wait_for_completions(user_data, 0)
            .map_err(AsyncIoError::PunchHole)?;
        Ok(())
    }

    fn write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        let _guard = self
            .state
            .range_locks
            .clone()
            .lock_range(offset, length)
            .map_err(AsyncIoError::WriteZeroes)?;
        self.mirror_request(|backend| backend.write_zeroes(offset, length, user_data))?;

        self.wait_for_completions(user_data, 0)
            .map_err(AsyncIoError::WriteZeroes)?;
        Ok(())
    }

    fn next_completed_request(&mut self) -> Option<(u64, i32)> {
        // Mirrored writes are awaited synchronously. Only async source reads complete here.
        while let Some((id, res)) = self.source.io_mut().next_completed_request() {
            self.inflight_completions.push_back((id, res));
        }
        self.inflight_completions.pop_front()
    }

    fn batch_requests_enabled(&self) -> bool {
        true
    }

    fn submit_batch_requests(&mut self, batch_request: &[BatchRequest]) -> AsyncIoResult<()> {
        for req in batch_request {
            let result = match req.request_type {
                RequestType::In => self.read_vectored(req.offset, &req.iovecs, req.user_data),
                RequestType::Out => self.write_vectored(req.offset, &req.iovecs, req.user_data),
                // Only In and Out are batched, see request.rs.
                _ => unreachable!("Unexpected batch request type: {:?}", req.request_type),
            };

            // Push partial batch error to completions, vectored op has not
            // pushed it to the inflight_completions queue.
            if result.is_err() {
                self.inflight_completions
                    .push_back((req.user_data, -libc::EIO));
                let _ = self.source.io().notifier().write(1);
            }
        }
        Ok(())
    }

    fn alignment(&self) -> u64 {
        // Stricter alignment wins. Same iovec goes to both backends.
        self.source
            .io()
            .alignment()
            .max(self.destination.io().alignment())
    }
}

/// Owns the copy worker thread's [`JoinHandle`].
pub struct CopyWorkerHandle {
    join: JoinHandle<()>,
}

impl CopyWorkerHandle {
    /// Returns whether the copy worker has finished.
    pub fn is_finished(&self) -> bool {
        self.join.is_finished()
    }

    /// Waits for the copy worker thread to finish.
    pub fn join(self) -> thread::Result<()> {
        self.join.join()
    }
}

/// Background thread that copies existing source bytes to destination
/// in fixed-size blocks.
///
/// The worker holds a [`RangeGuard`] across each block so virtqueue mirror
/// writes cannot race the copy.
pub struct CopyWorker {
    source_io: CompletionIo,
    dest_io: CompletionIo,
    state: Arc<MirrorState>,
    block_size_bytes: usize,
    /// Tracks the next user_data for request and completion notifications.
    next_user_data: u64,
}

impl CopyWorker {
    /// Builds and spawns the copy worker on a named thread.
    ///
    /// Queue depth 1 is enough because the worker is sequential. The caller
    /// must initialize the destination disk.
    pub fn spawn(
        source_disk: &dyn AsyncFullDiskFile,
        destination_disk: &dyn AsyncFullDiskFile,
        state: Arc<MirrorState>,
        block_size_bytes: usize,
    ) -> BlockResult<CopyWorkerHandle> {
        let source_io = CompletionIo::new(source_disk.create_async_io(1)?)?;
        let dest_io = CompletionIo::new(destination_disk.create_async_io(1)?)?;

        let worker = Self {
            source_io,
            dest_io,
            state,
            block_size_bytes,
            next_user_data: 0,
        };
        let state = worker.state.clone();
        let join = thread::Builder::new()
            .name("blockdev-mirror-copy-worker".into())
            .spawn(move || {
                let mut worker = worker;
                if let Err(error) = worker.run() {
                    state.transition_to_phase(MirrorPhase::Failed(Arc::new(
                        MirrorFailure::CopyWorker(error),
                    )));
                }
            })?;

        Ok(CopyWorkerHandle { join })
    }

    /// Drives the block-by-block copy for predefined [`MirrorState::total_bytes`],
    /// then transitions the migration phase to [`MirrorPhase::Ready`].
    fn run(&mut self) -> io::Result<()> {
        let alignment = self
            .source_io
            .io()
            .alignment()
            .max(self.dest_io.io().alignment());
        let mut buf = AlignedBuf::new(self.block_size_bytes, alignment as usize)?;
        let total_size = self.state.total_bytes;
        let max_length = self.block_size_bytes as u64;
        let mut offset = 0;

        while offset < total_size {
            if !matches!(self.state.phase(), MirrorPhase::Running) {
                return Ok(());
            }

            let length = max_length.min(total_size - offset) as usize;
            self.copy_block(offset, length, &mut buf)?;
            offset += length as u64;
        }

        let user_data = self.generate_user_data();
        self.dest_io.flush(user_data)?;
        self.state.transition_to_phase(MirrorPhase::Ready);
        Ok(())
    }

    /// Copies `length` bytes at `offset` from source to destination.
    ///
    /// Holds a range lock for the duration so virtqueue mirror writes cannot race
    /// the copy.
    fn copy_block(&mut self, offset: u64, length: usize, buf: &mut AlignedBuf) -> io::Result<()> {
        let _guard = self
            .state
            .range_locks
            .clone()
            .lock_range(offset, length as u64)?;

        let iovecs = [iovec {
            iov_base: buf.as_mut_slice(length).as_mut_ptr().cast(),
            iov_len: length,
        }];

        // Read from source into buf.
        buf.as_mut_slice(length).fill(0);
        let read_id = self.generate_user_data();
        self.source_io
            .io_mut()
            .read_vectored(offset as off_t, &iovecs, read_id)
            .map_err(|error| io::Error::other(format!("async io read_vectored failed: {error}")))?;
        let (user_data, result) = self.source_io.next_completion()?;
        if result < 0 {
            return Err(io::Error::from_raw_os_error(-result));
        }
        debug_assert_eq!(user_data, read_id);

        // Write buf to destination.
        let write_id = self.generate_user_data();
        self.dest_io
            .io_mut()
            .write_vectored(offset as off_t, &iovecs, write_id)
            .map_err(|error| {
                io::Error::other(format!("async io write_vectored failed: {error}"))
            })?;
        let (user_data, result) = self.dest_io.next_completion()?;
        if result < 0 {
            return Err(io::Error::from_raw_os_error(-result));
        }
        debug_assert_eq!(user_data, write_id);

        self.state
            .copied_bytes
            .fetch_add(length as u64, Ordering::Relaxed);

        Ok(())
    }

    /// Returns the current [`Self::next_user_data`] and increments it, wrapping on overflow.
    fn generate_user_data(&mut self) -> u64 {
        let user_data = self.next_user_data;
        self.next_user_data = self.next_user_data.wrapping_add(1);

        user_data
    }
}

/// Represents an active block mirror operation.
///
/// The operation must be completed or cancelled before the handle is dropped.
/// Dropping it does not stop or join the background copy worker.
pub struct BlockMirrorHandle {
    /// Shared lifecycle state and copy progress.
    pub state: Arc<MirrorState>,
    /// Handle for joining the background copy worker.
    pub copy_worker: CopyWorkerHandle,
    /// Destination backend of the mirror.
    pub destination: Box<dyn AsyncFullDiskFile>,
    /// Host path backing the destination.
    pub destination_path: PathBuf,
}

/// Owns an [`AsyncIo`] backend and waits for its completions.
///
/// Waiting uses a poller because the backend's notifier is created
/// non-blocking and therefore never blocks on read.
struct CompletionIo {
    poll: PollContext<()>,
    io: Box<dyn AsyncIo>,
}

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
    fn next_completion(&mut self) -> io::Result<(u64, i32)> {
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

    /// Submits a tracked flush and waits for its matching successful completion.
    ///
    /// The completion must carry `user_data` and report zero, as required by
    /// [`AsyncIo::fsync`].
    fn flush(&mut self, user_data: u64) -> io::Result<()> {
        self.io
            .fsync(Some(user_data))
            .map_err(|error| io::Error::other(format!("async io fsync failed: {error}")))?;

        let (completed_user_data, result) = self.next_completion()?;
        if completed_user_data != user_data {
            return Err(io::Error::other(format!(
                "fsync completed with unexpected user data {completed_user_data}, expected {user_data}"
            )));
        }
        if result != 0 {
            return Err(if result < 0 {
                io::Error::from_raw_os_error(-result)
            } else {
                io::Error::other(format!("fsync completed with unexpected result {result}"))
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let empty = manager.clone().lock_range(0, 0).err().unwrap();
        assert_eq!(empty.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(empty.to_string(), "Range length is zero");

        let overflow = manager.lock_range(u64::MAX, 1).err().unwrap();
        assert_eq!(overflow.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(overflow.to_string(), "Range overflow");
    }
}
