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

/// Failure that stopped an active block mirror.
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
    /// The caller records the result with [`MirrorState::finish_copy`].
    fn run(&mut self) -> io::Result<()> {
        let total_size = self.state.total_bytes;
        let max_length = self.block_size_bytes as u64;
        let mut offset = 0;

        while offset < total_size {
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

        // Transfer ownership to the destination. Write completions do not return
        // the buffer, so the next block allocates a new one.
        let write_id = self.generate_user_data();
        self.dest_io
            .io_mut()
            .write_from_vec(offset, buffer, write_id)
            .map_err(io::Error::other)?;
        self.dest_io
            .wait_for_completion(write_id, expected_result)?;

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
            state: MirrorState::new(4096),
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

    #[test]
    fn copy_worker_copies_multiple_blocks_and_partial_tail() {
        for size in [0, 8192 + 17] {
            let source = TempFile::new().unwrap();
            let destination = TempFile::new().unwrap();
            let bytes: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
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
}
