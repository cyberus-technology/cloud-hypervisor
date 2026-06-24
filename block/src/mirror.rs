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

use thiserror::Error;
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::poll::PollContext;

use crate::async_io::{
    AsyncIo, AsyncIoCompletion, AsyncIoError, AsyncIoOperation, AsyncIoResult, OwnedIoBuffer,
};
use crate::disk_file::AsyncFullDiskFile;
use crate::error::BlockResult;

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

    /// Non-panicking variant of [`Self::transition_to_phase`] that returns the
    /// rejected `(from, to)` phases.
    fn try_transition_to_phase(
        &self,
        target: MirrorPhase,
    ) -> Result<(), (MirrorPhase, MirrorPhase)> {
        use MirrorPhase::*;
        let mut current = self.phase.lock().unwrap();

        if mem::discriminant(&*current) == mem::discriminant(&target) {
            return Ok(());
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
            return Err((current.clone(), target));
        }

        *current = target;

        Ok(())
    }

    /// Attempts a phase transition.
    ///
    /// Only allowed transitions are applied. Invalid transitions panic.
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
        if let Err((from, to)) = self.try_transition_to_phase(target) {
            // An invalid transition indicates a programming error. Reverting the
            // virtqueue workers requires sending a `BlockQueueCommand` to each
            // worker, which `MirrorState` cannot do.
            panic!("Invalid mirror phase transition attempted: {from:?} -> {to:?}");
        }
    }

    /// Applies the copy worker's result unless another thread already left
    /// [`MirrorPhase::Running`].
    pub(crate) fn finish_copy(&self, result: io::Result<()>) {
        let target = match result {
            Ok(()) => MirrorPhase::Ready,
            Err(error) => MirrorPhase::Failed(Arc::new(MirrorFailure::CopyWorker(error))),
        };

        let _ = self.try_transition_to_phase(target);
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
            bypass_destination: false,
        })
    }

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

/// Owns the copy worker thread's [`JoinHandle`].
pub struct CopyWorkerHandle {
    join: JoinHandle<()>,
}

impl CopyWorkerHandle {
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
    dest_is_sparse: bool,
    state: Arc<MirrorState>,
    block_size_bytes: usize,
    /// Tracks the next user_data for request and completion notifications.
    next_user_data: u64,
    alignment: u64,
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

        let io_alignment = source_io
            .io()
            .alignment()
            .max(dest_io.io().alignment())
            .unwrap_or(1);
        // Include disk topology when choosing buffer alignment; request offsets
        // and lengths only need to satisfy the backends' I/O constraints.
        let alignment = source_disk
            .topology()
            .logical_block_size
            .max(destination_disk.topology().logical_block_size)
            .max(io_alignment);

        if block_size_bytes == 0
            || block_size_bytes > i32::MAX as usize
            || !(block_size_bytes as u64).is_multiple_of(io_alignment)
            || !state.total_bytes.is_multiple_of(io_alignment)
            || state.total_bytes > i64::MAX as u64
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid mirror copy size or alignment",
            )
            .into());
        }

        let worker = Self {
            source_io,
            dest_io,
            dest_is_sparse: destination_disk.supports_sparse_operations(),
            state,
            block_size_bytes,
            next_user_data: 0,
            alignment,
        };
        let state = Arc::clone(&worker.state);
        let join = thread::Builder::new()
            .name("blockdev-mirror-copy-worker".into())
            .spawn(move || {
                let mut worker = worker;
                state.finish_copy(worker.run());
            })?;

        Ok(CopyWorkerHandle { join })
    }

    /// Drives the block-by-block copy for predefined [`MirrorState::total_bytes`].
    ///
    /// Returns once all bytes are copied or the mirror left `Running`. The
    /// caller records the result with [`MirrorState::finish_copy`].
    fn run(&mut self) -> io::Result<()> {
        let total_size = self.state.total_bytes;
        let max_length = self.block_size_bytes as u64;
        let mut offset = 0;

        while offset < total_size {
            if !matches!(self.state.phase(), MirrorPhase::Running) {
                return Ok(());
            }

            let length = max_length.min(total_size - offset) as usize;
            self.copy_block(offset, length)?;
            offset += length as u64;
        }

        let user_data = self.generate_user_data();
        self.dest_io.flush(user_data)?;
        Ok(())
    }

    /// Copies `length` bytes at `offset` from source to destination.
    ///
    /// Holds a range lock for the duration so virtqueue mirror writes cannot race
    /// the copy.
    fn copy_block(&mut self, offset: u64, length: usize) -> io::Result<()> {
        let _guard = Arc::clone(&self.state.range_locks).lock_range(offset, length as u64)?;
        let expected_result =
            i32::try_from(length).map_err(|_| io::Error::other("Copy block is too large"))?;
        let offset = libc::off_t::try_from(offset)
            .map_err(|_| io::Error::other("Copy offset is too large"))?;

        // The read operation owns the buffer until it is returned in the completion.
        let buffer = OwnedIoBuffer::new(length, self.alignment as usize)?;
        let read_id = self.generate_user_data();
        self.source_io
            .io_mut()
            .read_to_vec(offset, buffer, read_id)
            .map_err(io::Error::other)?;
        let completion = self
            .source_io
            .wait_for_completion(read_id, expected_result)?;
        let buffer = completion
            .buffer
            .ok_or_else(|| io::Error::other("Source read completed without a buffer"))?;

        let write_id = self.generate_user_data();
        let punch_hole = self.dest_is_sparse && buffer.as_slice().iter().all(|&byte| byte == 0);
        if punch_hole {
            // Source block is all zeros: punch a hole to keep the destination sparse.
            self.dest_io
                .io_mut()
                .punch_hole(offset as u64, length as u64, write_id)
                .map_err(io::Error::other)?;
        } else {
            self.dest_io
                .io_mut()
                .write_from_vec(offset, buffer, write_id)
                .map_err(io::Error::other)?;
        }
        self.dest_io
            .wait_for_completion(write_id, if punch_hole { 0 } else { expected_result })?;

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

    /// Waits for the next completion and validates its identifier and result.
    /// Used by the sequential copy worker, which has one request in flight.
    fn wait_for_completion(
        &mut self,
        user_data: u64,
        expected_result: i32,
    ) -> io::Result<AsyncIoCompletion> {
        let completion = self.next_completion()?;
        if completion.user_data != user_data {
            return Err(io::Error::other(format!(
                "Unexpected completion user data {}, expected {user_data}",
                completion.user_data
            )));
        }
        if completion.result != expected_result {
            return Err(if completion.result < 0 {
                io::Error::from_raw_os_error(-completion.result)
            } else {
                io::Error::other(format!(
                    "Unexpected completion result {}, expected {expected_result}",
                    completion.result
                ))
            });
        }
        Ok(completion)
    }

    /// Submits a tracked flush and waits for its matching successful completion.
    fn flush(&mut self, user_data: u64) -> io::Result<()> {
        self.io.fsync(Some(user_data)).map_err(io::Error::other)?;
        self.wait_for_completion(user_data, 0)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::FileExt;
    use std::sync::atomic::AtomicUsize;

    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::async_io::GuestMemoryTarget;
    use crate::formats::raw::{RawBackend, RawDisk};

    fn mirror_with_files() -> (MirroringAsyncIo, TempFile, TempFile) {
        let source = TempFile::new().unwrap();
        let destination = TempFile::new().unwrap();
        let create_disk = |file: &TempFile| {
            file.as_file().set_len(4096).unwrap();
            RawDisk::new(file.as_file().try_clone().unwrap(), RawBackend::Sync, false)
        };
        let mirror = MirroringAsyncIo::create(
            &create_disk(&source),
            &create_disk(&destination),
            MirrorState::new(4096),
            1,
        )
        .unwrap();
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

    #[test]
    fn copy_worker_copies_multiple_blocks_and_partial_tail() {
        for size in [0, 8192 + 17] {
            let source = TempFile::new().unwrap();
            let destination = TempFile::new().unwrap();
            let bytes: Vec<u8> = (0..size)
                .map(|i| {
                    if (4096..8192).contains(&i) {
                        0
                    } else {
                        (i % 251) as u8
                    }
                })
                .collect();
            source.as_file().write_all_at(&bytes, 0).unwrap();
            destination
                .as_file()
                .write_all_at(&vec![0xff; size], 0)
                .unwrap();
            let source_disk = RawDisk::new(
                source.as_file().try_clone().unwrap(),
                RawBackend::Sync,
                false,
            );
            let destination_disk = RawDisk::new(
                destination.as_file().try_clone().unwrap(),
                RawBackend::Sync,
                false,
            );
            let state = MirrorState::new(size as u64);
            CopyWorker::spawn(&source_disk, &destination_disk, Arc::clone(&state), 4096)
                .unwrap()
                .join()
                .unwrap();
            assert!(matches!(state.phase(), MirrorPhase::Ready));
            assert_eq!(state.copied_bytes.load(Ordering::Relaxed), size as u64);
            let mut copied = vec![0; size];
            destination.as_file().read_exact_at(&mut copied, 0).unwrap();
            assert_eq!(copied, bytes);

            assert!(CopyWorker::spawn(&source_disk, &destination_disk, state, 0).is_err());
        }
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

    use std::collections::VecDeque;
    use std::sync::mpsc;
    use std::time::Duration;

    /// Submission counters shared between a [`MockAsyncIo`] and the test.
    #[derive(Default)]
    struct MockStats {
        read_submissions: AtomicUsize,
        write_submissions: AtomicUsize,
    }

    /// In-memory [`AsyncIo`] backend that completes submissions immediately.
    struct MockAsyncIo {
        evt: EventFd,
        completions: VecDeque<AsyncIoCompletion>,
        completion_result: Option<i32>,
        /// When set, the write submission at this 0-based index fails instead
        /// of completing.
        fail_on_nth_write: Option<usize>,
        /// Byte written into read buffers.
        fill_byte: u8,
        /// Submission counters shared with the test.
        stats: Arc<MockStats>,
    }

    impl MockStats {
        #[track_caller]
        fn assert_submissions(&self, reads: usize, writes: usize, message: &str) {
            assert_eq!(
                (
                    self.read_submissions.load(Ordering::SeqCst),
                    self.write_submissions.load(Ordering::SeqCst)
                ),
                (reads, writes),
                "{message}"
            );
        }
    }

    impl MockAsyncIo {
        fn new() -> Self {
            Self::with_fill_byte(0)
        }

        /// Creates a mock that fills read buffers with `fill_byte` so a test
        /// can tell which backend served a read.
        fn with_fill_byte(fill_byte: u8) -> Self {
            Self {
                evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
                completions: VecDeque::new(),
                completion_result: None,
                fail_on_nth_write: None,
                fill_byte,
                stats: Arc::new(MockStats::default()),
            }
        }

        /// Returns the shared submission counters.
        fn stats(&self) -> Arc<MockStats> {
            Arc::clone(&self.stats)
        }

        /// Fails the write submission at `index`, counting from zero.
        fn fail_on_nth_write_submission(&mut self, index: usize) {
            self.fail_on_nth_write = Some(index);
        }

        /// Records a completion and signals the notifier.
        fn complete(&mut self, mut completion: AsyncIoCompletion) {
            completion.result = self.completion_result.take().unwrap_or(completion.result);
            self.completions.push_back(completion);
            self.evt.write(1).unwrap();
        }
    }

    impl AsyncIo for MockAsyncIo {
        fn notifier(&self) -> &EventFd {
            &self.evt
        }
        fn submit_data_operation(&mut self, mut op: AsyncIoOperation) -> AsyncIoResult<()> {
            let len = op.total_len();
            if op.is_read() {
                self.stats.read_submissions.fetch_add(1, Ordering::SeqCst);
                op.write_bytes_at(0, &vec![self.fill_byte; len])
                    .map_err(AsyncIoError::ReadVectored)?;
            } else {
                let index = self.stats.write_submissions.fetch_add(1, Ordering::SeqCst);
                if self.fail_on_nth_write == Some(index) {
                    return Err(AsyncIoError::WriteVectored(io::Error::other(
                        "Injected write submit failure",
                    )));
                }
            }
            self.complete(AsyncIoCompletion::from_operation(op, len as i32));
            Ok(())
        }
        fn fsync(&mut self, ud: Option<u64>) -> AsyncIoResult<()> {
            if let Some(ud) = ud {
                self.complete(AsyncIoCompletion::new(ud, 0, None));
            }
            Ok(())
        }
        fn punch_hole(&mut self, _o: u64, _l: u64, ud: u64) -> AsyncIoResult<()> {
            self.complete(AsyncIoCompletion::new(ud, 0, None));
            Ok(())
        }
        fn write_zeroes(&mut self, _o: u64, _l: u64, ud: u64) -> AsyncIoResult<()> {
            self.complete(AsyncIoCompletion::new(ud, 0, None));
            Ok(())
        }
        fn next_completed_request(&mut self) -> Option<AsyncIoCompletion> {
            self.completions.pop_front()
        }
    }

    fn mirror_with_mocks() -> MirroringAsyncIo {
        mirror_from(
            MockAsyncIo::new(),
            MockAsyncIo::new(),
            MirrorState::new(1 << 20),
        )
    }

    /// The one place to update when `MirroringAsyncIo`'s fields change.
    fn mirror_from<S: AsyncIo + 'static, D: AsyncIo + 'static>(
        source: S,
        destination: D,
        state: Arc<MirrorState>,
    ) -> MirroringAsyncIo {
        MirroringAsyncIo {
            source: CompletionIo::new(Box::new(source)).unwrap(),
            destination: CompletionIo::new(Box::new(destination)).unwrap(),
            state,
            inflight_completions: VecDeque::new(),
            bypass_destination: false,
        }
    }

    /// Runs `f` on a worker thread and fails the test if it does not finish
    /// within `timeout`.
    ///
    /// This turns a submit-path deadlock into a clean failure instead of a hung
    /// suite: the worker stays blocked, but the test thread resumes after the
    /// timeout and panics.
    fn run_with_watchdog(timeout: Duration, f: impl FnOnce() + Send + 'static) {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            f();
            let _ = tx.send(());
        });
        if rx.recv_timeout(timeout).is_err() {
            panic!("scenario did not finish within {timeout:?} (deadlock)");
        }
    }

    /// Drains completions until `n` have arrived (or the budget is exhausted).
    fn drain_n(mirror: &mut MirroringAsyncIo, n: usize) -> Vec<u64> {
        let mut acked = Vec::new();
        for _ in 0..64 {
            while let Some(completion) = mirror.next_completed_request() {
                assert!(
                    completion.result >= 0,
                    "Unexpected error completion: {completion:?}"
                );
                acked.push(completion.user_data);
            }
            if acked.len() >= n {
                break;
            }
        }
        acked
    }

    /// Returns the stored failure or panics if the mirror has not failed.
    fn failure_reason(state: &MirrorState) -> Arc<MirrorFailure> {
        let MirrorPhase::Failed(reason) = state.phase() else {
            panic!("mirror did not enter the failed phase");
        };
        reason
    }

    /// Two overlapping guest writes submitted before either is reaped must both
    /// complete in submission order without deadlocking.
    #[test]
    fn overlapping_writes_complete_in_order() {
        run_with_watchdog(Duration::from_secs(5), || {
            let mut mirror = mirror_with_mocks();
            let buf = [0u8; 4096];

            mirror
                .write_from_vec(0, OwnedIoBuffer::from_vec(buf.to_vec()), 1)
                .unwrap();
            mirror
                .write_from_vec(0, OwnedIoBuffer::from_vec(buf.to_vec()), 2)
                .unwrap();

            assert_eq!(
                drain_n(&mut mirror, 2),
                vec![1, 2],
                "both overlapping writes complete in submission order"
            );
        });
    }

    /// While the copy worker holds a range (simulated by holding a `RangeGuard`
    /// on the shared lock manager), an overlapping guest write must block and
    /// proceed only once the range is released.
    #[test]
    fn copy_worker_hold_serializes_overlapping_guest_write() {
        let state = MirrorState::new(1 << 20);
        // The "copy worker" holds [0, 4096).
        let guard = Arc::clone(&state.range_locks).lock_range(0, 4096).unwrap();

        let mut mirror = mirror_from(MockAsyncIo::new(), MockAsyncIo::new(), Arc::clone(&state));

        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let buf = [0u8; 4096];
            mirror
                .write_from_vec(0, OwnedIoBuffer::from_vec(buf.to_vec()), 1)
                .unwrap();
            tx.send(()).unwrap();
        });

        // The held range must block the overlapping guest write.
        assert!(
            rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "guest write proceeded while the copy worker held the range"
        );

        // Releasing the range lets the write through.
        drop(guard);
        assert!(
            rx.recv_timeout(Duration::from_secs(5)).is_ok(),
            "guest write did not proceed after the range was released"
        );
        handle.join().unwrap();
    }

    /// Reads are source-only passthrough (no range lock) and still complete.
    #[test]
    fn read_passes_through_to_source() {
        run_with_watchdog(Duration::from_secs(5), || {
            let source = MockAsyncIo::with_fill_byte(0xaa);
            let source_stats = source.stats();
            let destination = MockAsyncIo::with_fill_byte(0xbb);
            let destination_stats = destination.stats();
            let state = MirrorState::new(1 << 20);
            let mut mirror = mirror_from(source, destination, Arc::clone(&state));

            // The copy worker holds the range while it copies the block. A read
            // that took the range lock would stall here until the watchdog fires.
            let _guard = Arc::clone(&state.range_locks).lock_range(0, 4096).unwrap();

            mirror
                .read_to_vec(0, OwnedIoBuffer::from_vec(vec![0; 4096]), 7)
                .unwrap();

            let completion = mirror.next_completed_request().unwrap();
            assert_eq!((completion.user_data, completion.result), (7, 4096));
            let buf = completion.buffer.unwrap();
            assert!(
                buf.as_slice().iter().all(|byte| *byte == 0xaa),
                "read must return source data, not destination data"
            );
            source_stats.assert_submissions(1, 0, "the read is submitted to the source");
            destination_stats.assert_submissions(0, 0, "no read is submitted to the destination");
        });
    }

    /// A destination submit failure degrades the mirror to source passthrough:
    /// the phase goes `Failed`, and a subsequent write is submitted to the
    /// source only.
    #[test]
    fn destination_submit_failure_degrades_to_passthrough() {
        run_with_watchdog(Duration::from_secs(5), || {
            let source = MockAsyncIo::new();
            let source_stats = source.stats();
            let mut dest = MockAsyncIo::new();
            let dest_stats = dest.stats();
            dest.fail_on_nth_write_submission(0);
            let mut mirror = mirror_from(source, dest, MirrorState::new(1 << 20));
            let buf = [0u8; 4096];

            mirror
                .write_from_vec(0, OwnedIoBuffer::from_vec(buf.to_vec()), 1)
                .unwrap();
            assert!(
                matches!(mirror.state.phase(), MirrorPhase::Failed(_)),
                "destination failure transitions the mirror to Failed"
            );

            // Subsequent write goes to the source only.
            mirror
                .write_from_vec(0, OwnedIoBuffer::from_vec(buf.to_vec()), 2)
                .unwrap();

            let mut acked = drain_n(&mut mirror, 2);
            acked.sort();
            assert_eq!(acked, vec![1, 2], "both writes complete off the source");
            source_stats.assert_submissions(0, 2, "both writes are submitted to the source");
            dest_stats.assert_submissions(0, 1, "the destination sees only the mirrored write");
        });
    }

    /// Verifies that a short destination completion fails the mirror while the guest
    /// receives the successful source completion.
    #[test]
    fn short_destination_completion_uses_source_result() {
        let mut destination = MockAsyncIo::new();
        destination.completion_result = Some(2048);
        let mut mirror = mirror_from(MockAsyncIo::new(), destination, MirrorState::new(4096));
        let buf = [0u8; 4096];

        mirror
            .write_from_vec(0, OwnedIoBuffer::from_vec(buf.to_vec()), 7)
            .unwrap();

        let completion = mirror.next_completed_request().unwrap();
        assert_eq!((completion.user_data, completion.result), (7, 4096));
        assert!(mirror.bypass_destination);
        assert!(matches!(
            failure_reason(&mirror.state).as_ref(),
            MirrorFailure::DestinationCompletion {
                user_data: 7,
                actual: 2048,
                expected: 4096,
            }
        ));
    }

    /// Verifies that a source I/O error fails the mirror and is reported to the guest.
    #[test]
    fn source_io_error_reaches_guest() {
        let mut source = MockAsyncIo::new();
        source.completion_result = Some(-libc::EIO);
        let mut mirror = mirror_from(source, MockAsyncIo::new(), MirrorState::new(4096));
        let buf = [0u8; 4096];

        mirror
            .write_from_vec(0, OwnedIoBuffer::from_vec(buf.to_vec()), 9)
            .unwrap();

        let completion = mirror.next_completed_request().unwrap();
        assert_eq!((completion.user_data, completion.result), (9, -libc::EIO));
        assert!(matches!(
            failure_reason(&mirror.state).as_ref(),
            MirrorFailure::SourceCompletion {
                user_data: 9,
                actual,
                expected: 4096,
            } if *actual == -libc::EIO
        ));
    }

    /// Mock backend whose completions are withheld until [`Gate::release`], so a
    /// test can hold a write parked in `wait_for_completions`.
    struct GatedMockAsyncIo {
        evt: EventFd,
        inner: Arc<Mutex<GatedInner>>,
        /// Notified on each submit, so a test can wait until the in-flight write
        /// has reached this backend (and so already holds its range guard).
        on_submit: mpsc::Sender<()>,
    }

    struct GatedInner {
        /// Submitted, not yet released.
        pending: VecDeque<AsyncIoCompletion>,
        /// Released, deliverable via `next_completed_request`.
        ready: VecDeque<AsyncIoCompletion>,
    }

    /// Releases a [`GatedMockAsyncIo`]'s withheld completions from another thread.
    struct Gate {
        evt: EventFd,
        inner: Arc<Mutex<GatedInner>>,
    }

    impl Gate {
        fn release(&self) {
            let mut inner = self.inner.lock().unwrap();
            while let Some(completion) = inner.pending.pop_front() {
                inner.ready.push_back(completion);
            }
            self.evt.write(1).unwrap();
        }
    }

    impl GatedMockAsyncIo {
        fn new(on_submit: mpsc::Sender<()>) -> Self {
            Self {
                evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
                inner: Arc::new(Mutex::new(GatedInner {
                    pending: VecDeque::new(),
                    ready: VecDeque::new(),
                })),
                on_submit,
            }
        }

        fn gate(&self) -> Gate {
            Gate {
                evt: self.evt.try_clone().unwrap(),
                inner: Arc::clone(&self.inner),
            }
        }

        fn submit(&self, completion: AsyncIoCompletion) {
            self.inner.lock().unwrap().pending.push_back(completion);
            let _ = self.on_submit.send(());
        }
    }

    impl AsyncIo for GatedMockAsyncIo {
        fn notifier(&self) -> &EventFd {
            &self.evt
        }
        fn submit_data_operation(&mut self, op: AsyncIoOperation) -> AsyncIoResult<()> {
            let result = op.total_len() as i32;
            self.submit(AsyncIoCompletion::from_operation(op, result));
            Ok(())
        }
        fn fsync(&mut self, ud: Option<u64>) -> AsyncIoResult<()> {
            if let Some(ud) = ud {
                self.submit(AsyncIoCompletion::new(ud, 0, None));
            }
            Ok(())
        }
        fn punch_hole(&mut self, _o: u64, _l: u64, ud: u64) -> AsyncIoResult<()> {
            self.submit(AsyncIoCompletion::new(ud, 0, None));
            Ok(())
        }
        fn write_zeroes(&mut self, _o: u64, _l: u64, ud: u64) -> AsyncIoResult<()> {
            self.submit(AsyncIoCompletion::new(ud, 0, None));
            Ok(())
        }
        fn next_completed_request(&mut self) -> Option<AsyncIoCompletion> {
            self.inner.lock().unwrap().ready.pop_front()
        }
    }

    /// The range guard must stay held across the whole synchronous submit+wait,
    /// not just acquisition.
    ///
    /// A regression to `let _ =` drops it early and lets an overlapping
    /// `lock_range` acquire while the write is still in flight.
    #[test]
    fn guard_is_held_across_submit_and_wait() {
        let state = MirrorState::new(1 << 20);

        // Source completes immediately; destination is gated, so the write parks
        // waiting on the destination completion while holding the range lock.
        let (submitted_tx, submitted_rx) = mpsc::channel();
        let dest = GatedMockAsyncIo::new(submitted_tx);
        let gate = dest.gate();
        let mut mirror = mirror_from(MockAsyncIo::new(), dest, Arc::clone(&state));

        let writer = thread::spawn(move || {
            mirror
                .write_from_vec(0, OwnedIoBuffer::from_vec(vec![0; 4096]), 1)
                .unwrap();
        });

        // The write reached the destination submit, so its range guard is held.
        submitted_rx.recv_timeout(Duration::from_secs(5)).unwrap();

        // An overlapping lock_range must block while the in-flight write holds it.
        let locker_state = Arc::clone(&state);
        let (locked_tx, locked_rx) = mpsc::channel();
        let locker = thread::spawn(move || {
            let _g = Arc::clone(&locker_state.range_locks)
                .lock_range(0, 4096)
                .unwrap();
            locked_tx.send(()).unwrap();
        });
        assert!(
            locked_rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "lock_range acquired while the in-flight write still held the range"
        );

        // Releasing the destination completion lets the write finish and drop its
        // guard, which unblocks the overlapping lock_range.
        gate.release();
        writer.join().unwrap();
        assert!(
            locked_rx.recv_timeout(Duration::from_secs(5)).is_ok(),
            "lock_range did not acquire after the write released the range"
        );
        locker.join().unwrap();
    }

    /// The lifecycle advances Running -> Ready -> Completing -> Completed, each
    /// state reached only from its documented predecessor.
    #[test]
    fn phase_advances_through_the_lifecycle() {
        let state = MirrorState::new(1 << 20);
        assert!(matches!(state.phase(), MirrorPhase::Running));
        state.transition_to_phase(MirrorPhase::Ready);
        state.transition_to_phase(MirrorPhase::Completing);
        state.transition_to_phase(MirrorPhase::Completed);
        assert!(matches!(state.phase(), MirrorPhase::Completed));
    }

    /// An invalid phase transition panics.
    #[test]
    #[should_panic(expected = "Invalid mirror phase transition attempted")]
    fn invalid_phase_transition_panics() {
        let state = MirrorState::new(1 << 20);
        // Running -> Completed skips Ready and Completing, so it is rejected.
        state.transition_to_phase(MirrorPhase::Completed);
    }

    /// `Completed` is terminal: no later transition is accepted.
    #[test]
    #[should_panic(expected = "Invalid mirror phase transition attempted")]
    fn completed_phase_is_terminal() {
        let state = MirrorState::new(1 << 20);
        state.transition_to_phase(MirrorPhase::Ready);
        state.transition_to_phase(MirrorPhase::Completing);
        state.transition_to_phase(MirrorPhase::Completed);
        state.transition_to_phase(MirrorPhase::Cancelling);
    }

    /// A failure keeps its first reason (transitions compare only the variant)
    /// and can still move to `Cancelling` for cleanup.
    #[test]
    fn failed_keeps_first_reason_then_cancels() {
        let state = MirrorState::new(1 << 20);
        let first = Arc::new(MirrorFailure::SourceCompletion {
            user_data: 1,
            actual: -libc::EIO,
            expected: 0,
        });
        state.transition_to_phase(MirrorPhase::Failed(Arc::clone(&first)));
        state.transition_to_phase(MirrorPhase::Failed(Arc::new(
            MirrorFailure::SourceCompletion {
                user_data: 2,
                actual: -libc::EIO,
                expected: 0,
            },
        )));
        let MirrorPhase::Failed(reason) = state.phase() else {
            panic!("mirror did not enter the failed phase");
        };
        assert!(Arc::ptr_eq(&reason, &first));
        state.transition_to_phase(MirrorPhase::Cancelling);
        assert!(matches!(state.phase(), MirrorPhase::Cancelling));
    }

    /// The copy worker records its result while `Running`, and drops it once
    /// cancellation or a queue failure changed the phase.
    #[test]
    fn finish_copy_records_or_drops_the_worker_result() {
        let running = MirrorState::new(1 << 20);
        running.finish_copy(Ok(()));
        assert!(matches!(running.phase(), MirrorPhase::Ready));

        let cancelled = MirrorState::new(1 << 20);
        cancelled.transition_to_phase(MirrorPhase::Cancelling);
        cancelled.finish_copy(Err(io::Error::other("write failed")));
        assert!(matches!(cancelled.phase(), MirrorPhase::Cancelling));

        let failed = MirrorState::new(1 << 20);
        failed.transition_to_phase(MirrorPhase::Failed(Arc::new(MirrorFailure::Installation)));
        failed.finish_copy(Ok(()));
        assert!(matches!(failed.phase(), MirrorPhase::Failed(_)));
    }

    /// A tracked fsync (`Some`) flushes both backends and surfaces one guest
    /// completion for its user_data.
    #[test]
    fn tracked_fsync_completes_to_guest() {
        run_with_watchdog(Duration::from_secs(5), || {
            let mut mirror = mirror_with_mocks();
            mirror.fsync(Some(5)).unwrap();
            assert_eq!(drain_n(&mut mirror, 1), vec![5]);
        });
    }

    /// A barrier fsync (`None`) flushes both backends but owes the guest no
    /// completion, so nothing surfaces.
    #[test]
    fn barrier_fsync_surfaces_no_completion() {
        let mut mirror = mirror_with_mocks();
        mirror.fsync(None).unwrap();
        assert!(mirror.next_completed_request().is_none());
    }

    /// `write_zeroes` mirrors to both backends under the range lock and
    /// surfaces one guest completion, like a write.
    #[test]
    fn write_zeroes_mirrors_and_completes() {
        run_with_watchdog(Duration::from_secs(5), || {
            let mut mirror = mirror_with_mocks();
            mirror.write_zeroes(0, 4096, 3).unwrap();
            assert_eq!(drain_n(&mut mirror, 1), vec![3]);
        });
    }

    /// Once degraded to passthrough, every mutating op forwards to the source
    /// alone and still completes, with no destination and no range lock.
    #[test]
    fn degraded_mirror_passes_all_ops_through_to_source() {
        run_with_watchdog(Duration::from_secs(5), || {
            let mut dest = MockAsyncIo::new();
            dest.fail_on_nth_write_submission(0);
            let mut mirror = mirror_from(MockAsyncIo::new(), dest, MirrorState::new(1 << 20));
            // The first write fails on the destination and flips to passthrough.
            mirror
                .write_from_vec(0, OwnedIoBuffer::from_vec(vec![0; 4096]), 1)
                .unwrap();
            assert!(matches!(mirror.state.phase(), MirrorPhase::Failed(_)));

            // Subsequent ops take the source-only passthrough branch.
            mirror.fsync(Some(2)).unwrap();
            mirror.punch_hole(0, 4096, 3).unwrap();
            mirror.write_zeroes(0, 4096, 4).unwrap();

            let mut acked = drain_n(&mut mirror, 4);
            acked.sort();
            assert_eq!(acked, vec![1, 2, 3, 4]);
        });
    }
}
