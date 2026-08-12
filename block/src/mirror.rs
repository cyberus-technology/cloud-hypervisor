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

use event_monitor::event;
use libc::{iovec, off_t};
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
    /// Disk identifier of the block device being mirrored.
    disk_id: String,
    /// Current phase of the mirror.
    phase: Mutex<MirrorPhase>,
    range_locks: Arc<RangeLockManager>,
    copied_bytes: AtomicU64,
    total_bytes: u64,
}

impl MirrorState {
    pub fn new(logical_disk_size: u64, disk_id: String) -> Arc<Self> {
        Arc::new(Self {
            disk_id,
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
    /// Reaching the `Ready` and `Failed(_)` outcomes emits the
    /// `vm:disk-mirror-ready` and `vm:disk-mirror-failed` events. Exactly one
    /// event fires per outcome because only the first transition applies.
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

        match *current {
            Ready => event!("vm", "disk-mirror-ready", "id", &self.disk_id),
            Failed(_) => event!("vm", "disk-mirror-failed", "id", &self.disk_id),
            _ => {}
        }
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
    /// Queued completions `(user_data, result)` for
    /// [`AsyncIo::next_completed_request`].
    ///
    /// The `user_data` identifies the request it was submitted with. The
    /// result is the number of bytes transferred or a negative errno.
    inflight_completions: VecDeque<(u64, i32)>,
    /// Set once this virtqueue worker observes a failure.
    ///
    /// While true, the worker forwards only to the source and ignores the
    /// destination.
    source_passthrough: bool,
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
            source_passthrough: false,
        })
    }

    /// Flips the mirror to the `Failed` phase.
    ///
    /// The operator must cancel to clean up the destination and the copy worker.
    fn fail(&mut self, failure: MirrorFailure) {
        // Phase fails the mirror globally, passthrough is per worker, so other queues fail independently.
        self.state
            .transition_to_phase(MirrorPhase::Failed(Arc::new(failure)));
        self.source_passthrough = true;
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
    /// guest-visible `(user_data, src_result)`.
    ///
    /// Other completions seen while waiting are stashed for later delivery.
    fn wait_for_completions(&mut self, user_data: u64, expected_result: i32) -> io::Result<()> {
        let src_result =
            Self::await_completion(&mut self.source, &mut self.inflight_completions, user_data)?;

        if !self.source_passthrough {
            match Self::await_completion(
                &mut self.destination,
                &mut self.inflight_completions,
                user_data,
            ) {
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
        if self.source_passthrough {
            return self
                .source
                .io_mut()
                .write_vectored(offset, iovecs, user_data);
        }

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
        if self.source_passthrough {
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
        if self.source_passthrough {
            return self.source.io_mut().punch_hole(offset, length, user_data);
        }

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
        if self.source_passthrough {
            return self.source.io_mut().write_zeroes(offset, length, user_data);
        }

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
        // Mirrored writes are awaited synchronously, only reads and post-failure passthrough writes surface here.
        while let Some((id, res)) = self.source.io_mut().next_completed_request() {
            self.inflight_completions.push_back((id, res));
        }
        self.inflight_completions.pop_front()
    }

    fn batch_requests_enabled(&self) -> bool {
        if self.source_passthrough {
            return self.source.io().batch_requests_enabled();
        }

        true
    }

    fn submit_batch_requests(&mut self, batch_request: &[BatchRequest]) -> AsyncIoResult<()> {
        if self.source_passthrough {
            return self.source.io_mut().submit_batch_requests(batch_request);
        }

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
        if self.source_passthrough {
            return self.source.io().alignment();
        }

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
    dest_is_sparse: bool,
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
            dest_is_sparse: destination_disk.supports_sparse_operations(),
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
        let expected_result =
            i32::try_from(length).map_err(|_| io::Error::other("copy block is too large"))?;

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
        if result != expected_result {
            return Err(io::Error::other(format!(
                "source read completed {result} bytes, expected {expected_result}"
            )));
        }
        debug_assert_eq!(user_data, read_id);

        let write_id = self.generate_user_data();
        let punch_hole = self.dest_is_sparse && buf.as_slice(length).iter().all(|&byte| byte == 0);
        if punch_hole {
            // Source block is all zeros: punch a hole to keep the destination sparse.
            self.dest_io
                .io_mut()
                .punch_hole(offset, length as u64, write_id)
                .map_err(|error| {
                    io::Error::other(format!("async io punch_hole failed: {error}"))
                })?;
        } else {
            // Write buf to destination.
            self.dest_io
                .io_mut()
                .write_vectored(offset as off_t, &iovecs, write_id)
                .map_err(|error| {
                    io::Error::other(format!("async io write_vectored failed: {error}"))
                })?;
        }

        let (user_data, result) = self.dest_io.next_completion()?;
        if result < 0 {
            return Err(io::Error::from_raw_os_error(-result));
        }
        let expected_result = if punch_hole { 0 } else { expected_result };
        if result != expected_result {
            return Err(io::Error::other(format!(
                "destination write completed {result} bytes, expected {expected_result}"
            )));
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

    use std::collections::VecDeque;
    use std::sync::mpsc;
    use std::time::Duration;

    /// In-memory [`AsyncIo`] backend for driving [`MirroringAsyncIo`] in a unit
    /// test without a real fd, io_uring, or the copy worker.
    ///
    /// Each submission is recorded as an immediately available completion and
    /// signals the notifier eventfd.
    struct MockAsyncIo {
        evt: EventFd,
        completions: VecDeque<(u64, i32)>,
        completion_result: Option<i32>,
        /// When set, the `write_vectored` submit at this 0-based index returns
        /// an error instead of completing.
        ///
        /// Drives the destination-failure and partial-batch paths.
        fail_on_nth_write: Option<usize>,
        writes_seen: usize,
    }

    impl MockAsyncIo {
        fn new() -> Self {
            Self {
                evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
                completions: VecDeque::new(),
                completion_result: None,
                fail_on_nth_write: None,
                writes_seen: 0,
            }
        }

        /// Records a completion and wakes any waiter parked on the notifier.
        fn complete(&mut self, user_data: u64, result: i32) {
            let result = self.completion_result.take().unwrap_or(result);
            self.completions.push_back((user_data, result));
            self.evt.write(1).unwrap();
        }
    }

    impl AsyncIo for MockAsyncIo {
        fn notifier(&self) -> &EventFd {
            &self.evt
        }
        fn read_vectored(&mut self, _o: off_t, iovecs: &[iovec], ud: u64) -> AsyncIoResult<()> {
            self.complete(
                ud,
                iovecs.iter().map(|iov| iov.iov_len).sum::<usize>() as i32,
            );
            Ok(())
        }
        fn write_vectored(&mut self, _o: off_t, iovecs: &[iovec], ud: u64) -> AsyncIoResult<()> {
            let index = self.writes_seen;
            self.writes_seen += 1;
            if self.fail_on_nth_write == Some(index) {
                return Err(AsyncIoError::WriteVectored(io::Error::other(
                    "injected write submit failure",
                )));
            }
            self.complete(
                ud,
                iovecs.iter().map(|iov| iov.iov_len).sum::<usize>() as i32,
            );
            Ok(())
        }
        fn fsync(&mut self, ud: Option<u64>) -> AsyncIoResult<()> {
            if let Some(ud) = ud {
                self.complete(ud, 0);
            }
            Ok(())
        }
        fn punch_hole(&mut self, _o: u64, _l: u64, ud: u64) -> AsyncIoResult<()> {
            self.complete(ud, 0);
            Ok(())
        }
        fn write_zeroes(&mut self, _o: u64, _l: u64, ud: u64) -> AsyncIoResult<()> {
            self.complete(ud, 0);
            Ok(())
        }
        fn next_completed_request(&mut self) -> Option<(u64, i32)> {
            self.completions.pop_front()
        }
    }

    fn mirror_with_mocks() -> MirroringAsyncIo {
        mirror_from(
            MockAsyncIo::new(),
            MockAsyncIo::new(),
            MirrorState::new(1 << 20, "test-disk".into()),
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
            source_passthrough: false,
        }
    }

    /// One iovec over `buf`. The mocks never read it, so it only needs to
    /// outlive the submit call.
    fn iov_of(buf: &[u8]) -> [iovec; 1] {
        [iovec {
            iov_base: buf.as_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        }]
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
            while let Some((user_data, result)) = mirror.next_completed_request() {
                assert!(result >= 0, "unexpected error completion: {result}");
                acked.push(user_data);
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
            let iov = iov_of(&buf);

            mirror.write_vectored(0, &iov, 1).unwrap();
            mirror.write_vectored(0, &iov, 2).unwrap();

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
        let state = MirrorState::new(1 << 20, "test-disk".into());
        // The "copy worker" holds [0, 4096).
        let guard = state.range_locks.clone().lock_range(0, 4096).unwrap();

        let mut mirror = mirror_from(MockAsyncIo::new(), MockAsyncIo::new(), state.clone());

        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let buf = [0u8; 4096];
            let iov = iov_of(&buf);
            mirror.write_vectored(0, &iov, 1).unwrap();
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
            let mut mirror = mirror_with_mocks();
            let buf = [0u8; 4096];
            let iov = iov_of(&buf);

            mirror.read_vectored(0, &iov, 7).unwrap();

            let mut got = None;
            for _ in 0..64 {
                if let Some(completion) = mirror.next_completed_request() {
                    got = Some(completion);
                    break;
                }
            }
            assert_eq!(got, Some((7, 4096)), "read completes via the source");
        });
    }

    /// A destination submit failure degrades the mirror to source passthrough:
    /// the phase goes `Failed`, and both the failing write and a subsequent
    /// write still complete to the guest off the source alone.
    #[test]
    fn destination_submit_failure_degrades_to_passthrough() {
        run_with_watchdog(Duration::from_secs(5), || {
            let mut dest = MockAsyncIo::new();
            dest.fail_on_nth_write = Some(0);
            let mut mirror = mirror_from(
                MockAsyncIo::new(),
                dest,
                MirrorState::new(1 << 20, "test-disk".into()),
            );
            let buf = [0u8; 4096];
            let iov = iov_of(&buf);

            mirror.write_vectored(0, &iov, 1).unwrap();
            assert!(
                matches!(mirror.state.phase(), MirrorPhase::Failed(_)),
                "destination failure transitions the mirror to Failed"
            );

            // Subsequent write goes to the source only.
            mirror.write_vectored(0, &iov, 2).unwrap();

            let mut acked = drain_n(&mut mirror, 2);
            acked.sort();
            assert_eq!(acked, vec![1, 2], "both writes complete off the source");
        });
    }

    /// Verifies that a short destination completion fails the mirror while the guest
    /// receives the successful source completion.
    #[test]
    fn short_destination_completion_uses_source_result() {
        let mut destination = MockAsyncIo::new();
        destination.completion_result = Some(2048);
        let mut mirror = mirror_from(
            MockAsyncIo::new(),
            destination,
            MirrorState::new(4096, "test-disk".into()),
        );
        let buf = [0u8; 4096];

        mirror.write_vectored(0, &iov_of(&buf), 7).unwrap();

        assert_eq!(mirror.next_completed_request(), Some((7, 4096)));
        assert!(mirror.source_passthrough);
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
        let mut mirror = mirror_from(
            source,
            MockAsyncIo::new(),
            MirrorState::new(4096, "test-disk".into()),
        );
        let buf = [0u8; 4096];

        mirror.write_vectored(0, &iov_of(&buf), 9).unwrap();

        assert_eq!(mirror.next_completed_request(), Some((9, -libc::EIO)));
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
        pending: VecDeque<(u64, i32)>,
        /// Released, deliverable via `next_completed_request`.
        ready: VecDeque<(u64, i32)>,
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

        fn submit(&self, user_data: u64, result: i32) {
            self.inner
                .lock()
                .unwrap()
                .pending
                .push_back((user_data, result));
            let _ = self.on_submit.send(());
        }
    }

    impl AsyncIo for GatedMockAsyncIo {
        fn notifier(&self) -> &EventFd {
            &self.evt
        }
        fn read_vectored(&mut self, _o: off_t, iovecs: &[iovec], ud: u64) -> AsyncIoResult<()> {
            self.submit(
                ud,
                iovecs.iter().map(|iov| iov.iov_len).sum::<usize>() as i32,
            );
            Ok(())
        }
        fn write_vectored(&mut self, _o: off_t, iovecs: &[iovec], ud: u64) -> AsyncIoResult<()> {
            self.submit(
                ud,
                iovecs.iter().map(|iov| iov.iov_len).sum::<usize>() as i32,
            );
            Ok(())
        }
        fn fsync(&mut self, ud: Option<u64>) -> AsyncIoResult<()> {
            if let Some(ud) = ud {
                self.submit(ud, 0);
            }
            Ok(())
        }
        fn punch_hole(&mut self, _o: u64, _l: u64, ud: u64) -> AsyncIoResult<()> {
            self.submit(ud, 0);
            Ok(())
        }
        fn write_zeroes(&mut self, _o: u64, _l: u64, ud: u64) -> AsyncIoResult<()> {
            self.submit(ud, 0);
            Ok(())
        }
        fn next_completed_request(&mut self) -> Option<(u64, i32)> {
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
        let state = MirrorState::new(1 << 20, "test-disk".into());

        // Source completes immediately; destination is gated, so the write parks
        // waiting on the destination completion while holding the range lock.
        let (submitted_tx, submitted_rx) = mpsc::channel();
        let dest = GatedMockAsyncIo::new(submitted_tx);
        let gate = dest.gate();
        let mut mirror = mirror_from(MockAsyncIo::new(), dest, state.clone());

        let writer = thread::spawn(move || {
            let buf = [0u8; 4096];
            let iov = iov_of(&buf);
            mirror.write_vectored(0, &iov, 1).unwrap();
        });

        // The write reached the destination submit, so its range guard is held.
        submitted_rx.recv().unwrap();

        // An overlapping lock_range must block while the in-flight write holds it.
        let locker_state = state.clone();
        let (locked_tx, locked_rx) = mpsc::channel();
        let locker = thread::spawn(move || {
            let _g = locker_state
                .range_locks
                .clone()
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

    /// A single-iovec `Out` batch entry backed by `buf`.
    fn batch_write(offset: off_t, buf: &[u8], user_data: u64) -> BatchRequest {
        BatchRequest {
            offset,
            iovecs: [iovec {
                iov_base: buf.as_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            }]
            .into_iter()
            .collect(),
            user_data,
            request_type: RequestType::Out,
        }
    }

    /// A mid-batch submit failure must still return `Ok` with one completion per
    /// entry, including an error completion for the failed one.
    ///
    /// The worker records the batch as in-flight only on `Ok`, so aborting with
    /// `Err` strands the completions already queued for earlier entries.
    #[test]
    fn failed_batch_submit_accounts_every_request() {
        // Second write (index 1) fails at submit on the source; the first
        // already went through.
        let mut source = MockAsyncIo::new();
        source.fail_on_nth_write = Some(1);
        let mut mirror = mirror_from(
            source,
            MockAsyncIo::new(),
            MirrorState::new(1 << 20, "test-disk".into()),
        );
        let buf = [0u8; 4096];

        let batch = [batch_write(0, &buf, 1), batch_write(4096, &buf, 2)];

        mirror
            .submit_batch_requests(&batch)
            .expect("a mid-batch submit failure must not fail the whole batch");

        let mut completions = Vec::new();
        while let Some(completion) = mirror.next_completed_request() {
            completions.push(completion);
        }
        completions.sort_by_key(|(user_data, _)| *user_data);

        assert_eq!(
            completions.len(),
            2,
            "every batch entry owes exactly one completion"
        );
        assert_eq!(
            completions[0],
            (1, 4096),
            "first write completes successfully"
        );
        assert_eq!(completions[1].0, 2, "second entry is still accounted");
        assert!(
            completions[1].1 < 0,
            "second entry carries an error result (reported IOERR), not an orphan"
        );
    }

    /// The lifecycle advances Running -> Ready -> Completing -> Completed, each
    /// state reached only from its documented predecessor.
    #[test]
    fn phase_advances_through_the_lifecycle() {
        let state = MirrorState::new(1 << 20, "test-disk".into());
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
        let state = MirrorState::new(1 << 20, "test-disk".into());
        // Running -> Completed skips Ready and Completing, so it is rejected.
        state.transition_to_phase(MirrorPhase::Completed);
    }

    /// `Completed` is terminal: no later transition is accepted.
    #[test]
    #[should_panic(expected = "Invalid mirror phase transition attempted")]
    fn completed_phase_is_terminal() {
        let state = MirrorState::new(1 << 20, "test-disk".into());
        state.transition_to_phase(MirrorPhase::Ready);
        state.transition_to_phase(MirrorPhase::Completing);
        state.transition_to_phase(MirrorPhase::Completed);
        state.transition_to_phase(MirrorPhase::Cancelling);
    }

    /// A failure keeps its first reason (transitions compare only the variant)
    /// and can still move to `Cancelling` for cleanup.
    #[test]
    fn failed_keeps_first_reason_then_cancels() {
        let state = MirrorState::new(1 << 20, "test-disk".into());
        let first = Arc::new(MirrorFailure::SourceCompletion {
            user_data: 1,
            actual: -libc::EIO,
            expected: 0,
        });
        state.transition_to_phase(MirrorPhase::Failed(first.clone()));
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
            dest.fail_on_nth_write = Some(0);
            let mut mirror = mirror_from(
                MockAsyncIo::new(),
                dest,
                MirrorState::new(1 << 20, "test-disk".into()),
            );
            let buf = [0u8; 4096];
            let iov = iov_of(&buf);

            // The first write fails on the destination and flips to passthrough.
            mirror.write_vectored(0, &iov, 1).unwrap();
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
