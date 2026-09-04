// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::cmp::max;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::num::Wrapping;
use std::ops::Deref;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Barrier, Mutex, mpsc};
use std::time::{Duration, Instant};
use std::{io, result, thread};

use anyhow::anyhow;
use block::async_io::{AsyncIo, AsyncIoError};
use block::disk_file::AsyncFullDiskFile;
use block::error::BlockError;
use block::fcntl::{LockError, LockGranularity, LockGranularityChoice, LockType};
use block::mirror::{
    BlockMirrorHandle, CopyWorker, CopyWorkerHandle, MIRROR_BLOCK_SIZE, MirrorFailure, MirrorPhase,
    MirrorState, MirrorStatus, MirroringAsyncIo,
};
use block::{
    ExecuteAsync, ExecuteError, MAX_DISCARD_WRITE_ZEROES_SEG, Request, RequestType,
    VirtioBlockConfig, build_serial,
};
use event_monitor::event;
use log::{debug, error, info, warn};
use rate_limiter::TokenType;
use rate_limiter::group::{RateLimiterGroup, RateLimiterGroupHandle};
use seccompiler::SeccompAction;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use virtio_bindings::virtio_blk::*;
use virtio_bindings::virtio_config::*;
use virtio_bindings::virtio_ring::{VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC};
use virtio_queue::{Queue, QueueOwnedT, QueueT};
use vm_memory::{ByteValued, Bytes, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryError};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vm_virtio::AccessPlatform;
use vmm_sys_util::eventfd::EventFd;

use super::{
    ActivateError, ActivateResult, EPOLL_HELPER_EVENT_LAST, EpollHelper, EpollHelperError,
    EpollHelperHandler, Error as DeviceError, VirtioCommon, VirtioDevice, VirtioDeviceType,
    VirtioInterruptType,
};
use crate::seccomp_filters::Thread;
use crate::thread_helper::spawn_virtio_thread;
use crate::{GuestMemoryMmap, VirtioInterrupt};

const SECTOR_SHIFT: u8 = 9;
pub const SECTOR_SIZE: u64 = 0x01 << SECTOR_SHIFT;

// New descriptors are pending on the virtio queue.
const QUEUE_AVAIL_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;
// New completed tasks are pending on the completion ring.
const COMPLETION_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 2;
// New 'wake up' event from the rate limiter
const RATE_LIMITER_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 3;

// A `BlockQueueCommand` has been queued for this worker to apply (e.g. swap disk_image).
const BLOCK_COMMAND_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 4;

// Maximum duration to wait for a command to be acknowledged by the virtqueue worker.
const MIRROR_COMMAND_ACK_TIMEOUT: Duration = Duration::from_secs(5);

// latency scale, for reduce precision loss in calculate.
const LATENCY_SCALE: u64 = 10000;

pub const MINIMUM_BLOCK_QUEUE_SIZE: u16 = 2;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to parse the request")]
    RequestParsing(#[source] block::Error),
    #[error("Failed to execute the request")]
    RequestExecuting(#[source] block::ExecuteError),
    #[error("Failed to complete the request")]
    RequestCompleting(#[source] block::Error),
    #[error("Missing the expected entry in the list of requests")]
    MissingEntryRequestList,
    #[error("The asynchronous request returned with failure")]
    AsyncRequestFailure,
    #[error("Failed synchronizing the file")]
    Fsync(#[source] AsyncIoError),
    #[error("Failed adding used index")]
    QueueAddUsed(#[source] virtio_queue::Error),
    #[error("Failed creating an iterator over the queue")]
    QueueIterator(#[source] virtio_queue::Error),
    #[error("Duplicated head index in the queue")]
    QueueDuplicatedHeadIndex,
    #[error("Failed to update request status")]
    RequestStatus(#[source] GuestMemoryError),
    #[error("Failed to enable notification")]
    QueueEnableNotification(#[source] virtio_queue::Error),
    #[error("Failed to get {lock_type:?} lock for disk image: {path}")]
    LockDiskImage {
        /// The underlying error.
        #[source]
        error: LockError,
        /// The requested lock type.
        lock_type: LockType,
        /// The path of the disk image.
        path: PathBuf,
    },
    #[error("Disk image size is not a multiple of {}", SECTOR_SIZE)]
    InvalidSize,
    #[error("Failed to pause vcpus")]
    PauseVcpus(#[source] MigratableError),
    #[error("Failed to resume vcpus")]
    ResumeVcpus(#[source] MigratableError),
    #[error("Failed signal config interrupt")]
    ConfigChange(#[source] io::Error),
    #[error("Disk resize failed")]
    DiskResize(#[source] BlockError),
    #[error("Mirror is currently active")]
    MirrorActive,
}

pub type Result<T> = result::Result<T, Error>;

/// Describes errors reported by synchronous block mirror operations.
#[derive(Error, Debug)]
pub enum MirrorError {
    /// Reports an underlying block backend operation failure.
    #[error("Block mirror backend operation failed")]
    Backend(#[source] BlockError),
    /// Indicates that the source and destination have different logical sizes.
    #[error(
        "Mirror destination logical size ({destination_size} bytes) differs from source logical size ({source_size} bytes)"
    )]
    DestinationSizeMismatch {
        source_size: u64,
        destination_size: u64,
    },
    /// Reports a failure to acquire the mirror destination advisory lock.
    #[error("Failed to acquire {lock_type:?} lock for mirror destination: {path}")]
    DestinationLock {
        path: PathBuf,
        lock_type: LockType,
        #[source]
        error: LockError,
    },
    /// Indicates that a mirror operation was requested before device activation.
    #[error("Mirror operation rejected: the device is not active")]
    DeviceNotActive,
    /// Indicates that a mirror operation was requested while the device is paused.
    #[error("Mirror operation rejected: the device is paused")]
    DevicePaused,
    /// Indicates that a mirror operation was requested without an active mirror.
    #[error("No active mirror for the device")]
    NotActive,
    /// Indicates that completion was requested before the mirror became ready.
    #[error("Mirror is not yet ready, cannot complete")]
    NotReady,
    /// Indicates that the source or destination does not support mirroring.
    #[error("Block mirroring is not supported")]
    Unsupported(#[source] BlockError),
    /// Indicates that cancellation was requested after completion started.
    #[error("Mirror completion already in progress")]
    CompletionInProgress,
    /// Reports a failure to register the new disk notifier.
    #[error("Failed to register new disk notifier")]
    RegisterNotifier(#[source] EpollHelperError),
    /// Reports a failure to deregister the old disk notifier.
    #[error("Failed to deregister old disk notifier")]
    DeregisterNotifier(#[source] EpollHelperError),
    /// Indicates that a queue already has a pending mirror command.
    #[error("Mirror command slot is occupied")]
    CommandSlotOccupied,
    /// Reports a failure to notify a virtqueue worker about a mirror command.
    #[error("Failed to notify mirror queue worker")]
    NotifyWorker(#[source] io::Error),
    /// Reports a missing or late acknowledgement from a virtqueue worker.
    #[error("Failed waiting for mirror command acknowledgement")]
    Ack(#[source] mpsc::RecvTimeoutError),
}

/// Represents the result of a synchronous block mirror operation.
pub type MirrorResult<T> = result::Result<T, MirrorError>;

/// Lifecycle command kind for a virtqueue worker.
#[derive(Debug, Clone, Copy)]
pub enum BlockQueueCommandKind {
    /// Replaces the plain source backend with a mirroring backend.
    InstallMirror,
    /// Replaces the mirroring backend with a destination backend.
    CompleteToDestination,
    /// Replaces the mirroring backend with a source backend.
    CancelToSource,
}

/// Acknowledgement sent by the corresponding virtqueue worker after handling
/// its command.
pub struct BlockQueueAck {
    /// Result of applying the command inside the worker.
    pub result: MirrorResult<()>,
}

/// Command sent from `Block` to a virtqueue worker to change the worker's
/// active block I/O backend.
pub struct BlockQueueCommand {
    /// Lifecycle action the worker should apply.
    pub kind: BlockQueueCommandKind,
    /// New async I/O backend that will replace the worker's current
    /// `disk_image` after the old backend has drained.
    ///
    /// For start this is a `MirroringAsyncIo`. For cancel this is a plain
    /// source `AsyncIo`. For completion this is a plain destination `AsyncIo`.
    pub async_io: Box<dyn AsyncIo>,

    /// Channel used by the worker to report that the command was applied or
    /// failed.
    pub ack: Sender<BlockQueueAck>,
}

/// One command per virtqueue, each paired with the sender of its queue.
type QueueCommands<'a> = Vec<(&'a BlockQueueCommandSender, BlockQueueCommand)>;

/// Worker side of the per-virtqueue command channel that receives commands
/// to swap the `disk_image` at runtime.
///
/// `cmd` and `evt` are shared with the API thread, which puts a
/// [`BlockQueueCommand`] into `cmd` (from [`Block::start_mirror`],
/// `complete_mirror`, or `cancel_mirror`) and writes to `evt` to wake the
/// worker. The worker takes the command and applies it.
pub struct BlockQueueCommandReceiver {
    /// Stores this worker's reference to the command slot held by `Block`.
    ///
    /// Each virtqueue worker has its own slot. `Block` writes a command to each
    /// slot and signals the matching `evt` after the write.
    pub cmd: Arc<Mutex<Option<BlockQueueCommand>>>,
    /// Wakes the worker after `cmd` is filled.
    ///
    /// Fires `BLOCK_COMMAND_EVENT` on the worker's epoll set.
    pub evt: EventFd,
    /// Command taken from `cmd` and held until `disk_image` reports no
    /// in-flight requests.
    pending_block_queue_command: Option<BlockQueueCommand>,
}

/// API-thread handles used to stage and signal commands for one virtqueue.
struct BlockQueueCommandSender {
    /// Single command slot shared with the virtqueue worker.
    cmd: Arc<Mutex<Option<BlockQueueCommand>>>,
    /// Eventfd used to wake the virtqueue worker.
    evt: EventFd,
    /// Virtqueue size used as the replacement backend's ring depth.
    queue_size: u16,
}

// latency will be records as microseconds, average latency
// will be save as scaled value.
#[derive(Clone)]
pub struct BlockCounters {
    read_bytes: Arc<AtomicU64>,
    read_ops: Arc<AtomicU64>,
    read_latency_min: Arc<AtomicU64>,
    read_latency_max: Arc<AtomicU64>,
    read_latency_avg: Arc<AtomicU64>,
    write_bytes: Arc<AtomicU64>,
    write_ops: Arc<AtomicU64>,
    write_latency_min: Arc<AtomicU64>,
    write_latency_max: Arc<AtomicU64>,
    write_latency_avg: Arc<AtomicU64>,
}

impl Default for BlockCounters {
    fn default() -> Self {
        BlockCounters {
            read_bytes: Arc::new(AtomicU64::new(0)),
            read_ops: Arc::new(AtomicU64::new(0)),
            read_latency_min: Arc::new(AtomicU64::new(u64::MAX)),
            read_latency_max: Arc::new(AtomicU64::new(u64::MAX)),
            read_latency_avg: Arc::new(AtomicU64::new(u64::MAX)),
            write_bytes: Arc::new(AtomicU64::new(0)),
            write_ops: Arc::new(AtomicU64::new(0)),
            write_latency_min: Arc::new(AtomicU64::new(u64::MAX)),
            write_latency_max: Arc::new(AtomicU64::new(u64::MAX)),
            write_latency_avg: Arc::new(AtomicU64::new(u64::MAX)),
        }
    }
}

/// Releases one active request count when dropped.
struct ActiveRequestGuard {
    counter: Arc<AtomicUsize>,
}

impl ActiveRequestGuard {
    fn new(counter: &Arc<AtomicUsize>) -> Self {
        Self {
            counter: counter.clone(),
        }
    }
}

impl Drop for ActiveRequestGuard {
    fn drop(&mut self) {
        let previous = self.counter.fetch_sub(1, Ordering::SeqCst);
        debug_assert!(previous > 0);
    }
}

struct BlockEpollHandler {
    queue_index: u16,
    queue: Queue,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    disk_image: Box<dyn AsyncIo>,
    disk_nsectors: Arc<AtomicU64>,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    serial: Box<[u8]>,
    kill_evt: EventFd,
    pause_evt: EventFd,
    writeback: Arc<AtomicBool>,
    counters: BlockCounters,
    queue_evt: EventFd,
    inflight_requests: VecDeque<(u16, Request)>,
    // The active count includes `inflight_requests` plus requests in transition
    // from the queue to inflight or inflight to completion.
    active_request_count: Arc<AtomicUsize>,
    // True when draining before pause.
    draining_active_requests: Arc<AtomicBool>,
    rate_limiter: Option<RateLimiterGroupHandle>,
    access_platform: Option<Arc<dyn AccessPlatform>>,
    host_cpus: Option<Box<[usize]>>,
    acked_features: u64,
    disable_sector0_writes: bool,
    /// Receives mirror lifecycle commands for this virtqueue worker.
    mirror_cmd_receiver: Option<BlockQueueCommandReceiver>,
}

fn has_feature(features: u64, feature_flag: u64) -> bool {
    (features & (1u64 << feature_flag)) != 0
}

impl BlockEpollHandler {
    fn check_request(
        features: u64,
        request: &Request,
        disable_sector0_writes: bool,
    ) -> result::Result<(), ExecuteError> {
        let request_type = request.request_type();
        if (has_feature(features, VIRTIO_BLK_F_RO.into()))
            && !(request_type == RequestType::In
                || request_type == RequestType::GetDeviceId
                || request_type == RequestType::Flush)
        {
            // For virtio spec compliance
            // "A device MUST set the status byte to VIRTIO_BLK_S_IOERR for a write request
            // if the VIRTIO_BLK_F_RO feature if offered, and MUST NOT write any data."
            warn!(
                "Rejecting block request {request_type:?}: device is read-only (VIRTIO_BLK_F_RO negotiated)"
            );
            return Err(ExecuteError::ReadOnly);
        }

        if request_type == RequestType::Out && disable_sector0_writes && request.sector() == 0 {
            warn!("Attempting to write to sector 0 on a disk without specifying image_type");
            return Err(ExecuteError::ReadOnly);
        }

        Ok(())
    }

    // A spec-compliant driver never reuses a virtqueue head_index while the
    // corresponding chain is still available (virtio 1.x §2.7.13.4).
    // Double check the guest driver is behaving.
    fn is_head_in_flight(
        inflight: &VecDeque<(u16, Request)>,
        batch: &[(u16, Request)],
        head: u16,
    ) -> bool {
        batch.iter().any(|(h, _)| *h == head) || inflight.iter().any(|(h, _)| *h == head)
    }

    fn process_queue_submit(&mut self) -> Result<()> {
        // Artificially bump the active counter while submitting so pause doesn't
        // race and read a zero.
        self.active_request_count.fetch_add(1, Ordering::SeqCst);
        let _active_request = ActiveRequestGuard::new(&self.active_request_count);
        // Clone the Arc so the `self.queue` mutable borrow is allowed.
        let draining_active_requests = self.draining_active_requests.clone();
        if draining_active_requests.load(Ordering::SeqCst) {
            return Ok(());
        }

        // Defer submitting new descriptors while a mirror swap is draining.
        // The queue_evt is kicked at the end of the swap.
        if self
            .mirror_cmd_receiver
            .as_ref()
            .is_some_and(|receiver| receiver.pending_block_queue_command.is_some())
        {
            return Ok(());
        }

        let queue = &mut self.queue;
        let queue_size = queue.size();
        let mut batch_requests = Vec::new();
        let mut batch_inflight_requests = Vec::new();
        let mut processed = 0;

        loop {
            // Cap a single drain at the virtqueue size. A compliant driver won't submit more that
            // queue_size, but a buggy or malicious one can keep adding as the VMM is reading.
            if processed >= queue_size {
                break;
            }
            if draining_active_requests.load(Ordering::SeqCst) {
                break;
            }
            processed += 1;
            let mut desc_chain = match queue
                .iter(self.mem.memory())
                .map_err(Error::QueueIterator)?
                .next()
            {
                Some(c) => c,
                None => break,
            };

            let head = desc_chain.head_index();
            if Self::is_head_in_flight(&self.inflight_requests, &batch_inflight_requests, head) {
                warn!("Guest reused virtio-blk head_index {head} while the chain was used");
                return Err(Error::QueueDuplicatedHeadIndex);
            }

            let mut request = Request::parse(&mut desc_chain, self.access_platform.as_deref())
                .map_err(Error::RequestParsing)?;

            // For virtio spec compliance
            // "A device MUST set the status byte to VIRTIO_BLK_S_IOERR for a write request
            // if the VIRTIO_BLK_F_RO feature if offered, and MUST NOT write any data."
            // Also, if sector 0 writes are disabled, treat writes to sector 0 as read-only as well.
            if let Err(e) =
                Self::check_request(self.acked_features, &request, self.disable_sector0_writes)
            {
                warn!("Request check failed: {request:x?} {e:?}");
                desc_chain
                    .memory()
                    .write_obj(VIRTIO_BLK_S_IOERR, request.status_addr())
                    .map_err(Error::RequestStatus)?;

                // If no asynchronous operation has been submitted, we can
                // simply return the used descriptor.
                queue
                    .add_used(desc_chain.memory(), desc_chain.head_index(), 1)
                    .map_err(Error::QueueAddUsed)?;
                queue
                    .enable_notification(self.mem.memory().deref())
                    .map_err(Error::QueueEnableNotification)?;
                continue;
            }

            if let Some(rate_limiter) = &mut self.rate_limiter {
                // If limiter.consume() fails it means there is no more TokenType::Ops
                // budget and rate limiting is in effect.
                if !rate_limiter.consume(1, TokenType::Ops) {
                    // Stop processing the queue and return this descriptor chain to the
                    // avail ring, for later processing.
                    queue.go_to_previous_position();
                    break;
                }
                // Exercise the rate limiter only if this request is of data transfer type.
                if request.request_type() == RequestType::In
                    || request.request_type() == RequestType::Out
                {
                    let mut bytes = Wrapping(0);
                    for (_, data_len) in request.data_descriptors() {
                        bytes += Wrapping(*data_len as u64);
                    }

                    // If limiter.consume() fails it means there is no more TokenType::Bytes
                    // budget and rate limiting is in effect.
                    if !rate_limiter.consume(bytes.0, TokenType::Bytes) {
                        // Revert the OPS consume().
                        rate_limiter.manual_replenish(1, TokenType::Ops);
                        // Stop processing the queue and return this descriptor chain to the
                        // avail ring, for later processing.
                        queue.go_to_previous_position();
                        break;
                    }
                }
            }

            request.writeback = self.writeback.load(Ordering::Acquire);

            let result = request.execute_async(
                desc_chain.memory(),
                self.disk_nsectors.load(Ordering::SeqCst),
                self.disk_image.as_mut(),
                &self.serial,
                self.disable_sector0_writes,
                desc_chain.head_index() as u64,
            );

            if let Ok(ExecuteAsync {
                async_complete: true,
                batch_request,
            }) = result
            {
                if let Some(batch_request) = batch_request {
                    match batch_request.request_type {
                        RequestType::In | RequestType::Out => batch_requests.push(batch_request),
                        _ => {
                            unreachable!(
                                "Unexpected batch request type: {:?}",
                                request.request_type()
                            )
                        }
                    }
                    batch_inflight_requests.push((desc_chain.head_index(), request));
                } else {
                    self.inflight_requests
                        .push_back((desc_chain.head_index(), request));
                    self.active_request_count.fetch_add(1, Ordering::SeqCst);
                }
            } else {
                let status = match result {
                    Ok(_) => VIRTIO_BLK_S_OK,
                    Err(e) => {
                        warn!("Request failed: {request:x?} {e:?}");
                        e.status() as u32
                    }
                };

                desc_chain
                    .memory()
                    .write_obj(status as u8, request.status_addr())
                    .map_err(Error::RequestStatus)?;

                let len = if status == VIRTIO_BLK_S_OK
                    && request.request_type() == RequestType::GetDeviceId
                {
                    self.serial.len() as u32 + 1
                } else {
                    1
                };
                // If no asynchronous operation has been submitted, we can
                // simply return the used descriptor.
                queue
                    .add_used(desc_chain.memory(), desc_chain.head_index(), len)
                    .map_err(Error::QueueAddUsed)?;
                queue
                    .enable_notification(self.mem.memory().deref())
                    .map_err(Error::QueueEnableNotification)?;
            }
        }

        match self.disk_image.submit_batch_requests(&batch_requests) {
            Ok(()) => {
                let batch_len = batch_inflight_requests.len();
                self.inflight_requests.extend(batch_inflight_requests);
                self.active_request_count
                    .fetch_add(batch_len, Ordering::SeqCst);
            }
            Err(e) => {
                // If batch submission fails, report VIRTIO_BLK_S_IOERR for all requests.
                for (user_data, request) in batch_inflight_requests {
                    warn!("Request failed with batch submission: {request:x?} {e:?}");
                    let desc_index = user_data;
                    let mem = self.mem.memory();
                    mem.write_obj(VIRTIO_BLK_S_IOERR as u8, request.status_addr())
                        .map_err(Error::RequestStatus)?;
                    queue
                        .add_used(mem.deref(), desc_index, 1)
                        .map_err(Error::QueueAddUsed)?;
                    queue
                        .enable_notification(mem.deref())
                        .map_err(Error::QueueEnableNotification)?;
                }
            }
        }

        Ok(())
    }

    fn try_signal_used_queue(&mut self) -> result::Result<(), EpollHelperError> {
        if self
            .queue
            .needs_notification(self.mem.memory().deref())
            .map_err(|e| {
                EpollHelperError::HandleEvent(anyhow!("Failed to check needs_notification: {e:?}"))
            })?
        {
            self.signal_used_queue().map_err(|e| {
                EpollHelperError::HandleEvent(anyhow!("Failed to signal used queue: {e:?}"))
            })?;
        }

        Ok(())
    }

    fn process_queue_submit_and_signal(&mut self) -> result::Result<(), EpollHelperError> {
        match self.process_queue_submit() {
            Ok(()) => {}
            Err(e @ (Error::QueueIterator(_) | Error::QueueDuplicatedHeadIndex)) => {
                // Virtqueue is corrupted or guest driver is misbehaving; exit
                // the worker so spawn_virtio_thread marks the device NEEDS_RESET.
                return Err(EpollHelperError::HandleEvent(anyhow!(
                    "Failed to process queue (submit): {e}"
                )));
            }
            Err(e) => {
                // Per-request errors are logged but non-device fatal.
                warn!("Failed to process queue (submit): {e}");
            }
        }

        self.try_signal_used_queue()
    }

    /// Replaces the active [`AsyncIo`] backend and updates its completion-event
    /// registration.
    fn replace_disk_image(
        &mut self,
        new_disk_image: Box<dyn AsyncIo>,
        helper: &mut EpollHelper,
    ) -> MirrorResult<()> {
        let new_disk_fd = new_disk_image.notifier().as_raw_fd();
        let old_disk_fd = self.disk_image.notifier().as_raw_fd();

        // Register the new backend's completion eventFd.
        helper
            .add_event(new_disk_fd, COMPLETION_EVENT)
            .map_err(MirrorError::RegisterNotifier)?;

        // Deregister the old backend's completion eventFd.
        if let Err(error) =
            helper.del_event_custom(old_disk_fd, COMPLETION_EVENT, epoll::Events::EPOLLIN)
        {
            // Rollback the new disk_image registration.
            let _ = helper.del_event_custom(new_disk_fd, COMPLETION_EVENT, epoll::Events::EPOLLIN);
            return Err(MirrorError::DeregisterNotifier(error));
        }

        // Commit the swap.
        self.disk_image = new_disk_image;

        Ok(())
    }

    /// Applies a pending mirror update if one is staged and the current
    /// `disk_image` has no in-flight requests.
    ///
    /// Returns `Ok(())` without changes when either condition is not met. The
    /// next completion event triggers another attempt.
    fn try_apply_pending_block_queue_command(
        &mut self,
        helper: &mut EpollHelper,
    ) -> result::Result<(), EpollHelperError> {
        // If any disk requests are in flight, we can't apply the pending command.
        if !self.inflight_requests.is_empty() {
            return Ok(());
        }

        let Some(cmd_receiver) = self.mirror_cmd_receiver.as_mut() else {
            return Ok(());
        };

        let Some(command) = cmd_receiver.pending_block_queue_command.take() else {
            return Ok(());
        };

        let BlockQueueCommand {
            kind: _,
            async_io,
            ack,
        } = command;

        let result = self.replace_disk_image(async_io, helper);

        let _ = ack.send(BlockQueueAck { result });

        // While the command was pending, QUEUE_AVAIL_EVENT handling consumed the
        // guest's kicks without submitting (see the guard in process_queue_submit).
        // The guest won't kick again for descriptors it already queued, so process
        // the avail ring now, whether the command succeeded or failed, or those
        // requests stall until unrelated guest I/O arrives.
        let rate_limit_reached = self.rate_limiter.as_ref().is_some_and(|r| r.is_blocked());
        if !rate_limit_reached {
            self.process_queue_submit_and_signal()?;
        }

        Ok(())
    }

    #[inline]
    fn find_inflight_request(&mut self, completed_head: u16) -> Result<Request> {
        // This loop neatly handles the fast path where the completions are
        // in order (it turns into just a pop_front()) and the 1% of the time
        // (analysis during boot) where slight out of ordering has been
        // observed e.g.
        // Submissions: 1 2 3 4 5 6 7
        // Completions: 2 1 3 5 4 7 6
        // In this case find the corresponding item and swap it with the front
        // This is a O(1) operation and is prepared for the future as it it likely
        // the next completion would be for the one that was skipped which will
        // now be the new front.
        for (i, (head, _)) in self.inflight_requests.iter().enumerate() {
            if head == &completed_head {
                return Ok(self.inflight_requests.swap_remove_front(i).unwrap().1);
            }
        }

        Err(Error::MissingEntryRequestList)
    }

    fn process_queue_complete(&mut self) -> Result<()> {
        let mem = self.mem.memory();
        let mut read_bytes = Wrapping(0);
        let mut write_bytes = Wrapping(0);
        let mut read_ops = Wrapping(0);
        let mut write_ops = Wrapping(0);

        while let Some((user_data, result)) = self.disk_image.next_completed_request() {
            let desc_index = user_data as u16;

            let mut request = self.find_inflight_request(desc_index)?;
            let _active_request = ActiveRequestGuard::new(&self.active_request_count);

            request
                .complete_async(&mem)
                .map_err(Error::RequestCompleting)?;

            let latency = request.start().elapsed().as_micros() as u64;
            let read_ops_last = self.counters.read_ops.load(Ordering::Relaxed);
            let write_ops_last = self.counters.write_ops.load(Ordering::Relaxed);
            let read_max = self.counters.read_latency_max.load(Ordering::Relaxed);
            let write_max = self.counters.write_latency_max.load(Ordering::Relaxed);
            let mut read_avg = self.counters.read_latency_avg.load(Ordering::Relaxed);
            let mut write_avg = self.counters.write_latency_avg.load(Ordering::Relaxed);
            let (status, len) = if result >= 0 {
                match request.request_type() {
                    RequestType::In => {
                        for (_, data_len) in request.data_descriptors() {
                            read_bytes += Wrapping(*data_len as u64);
                        }
                        read_ops += Wrapping(1);
                        if latency < self.counters.read_latency_min.load(Ordering::Relaxed) {
                            self.counters
                                .read_latency_min
                                .store(latency, Ordering::Relaxed);
                        }
                        if latency > read_max || read_max == u64::MAX {
                            self.counters
                                .read_latency_max
                                .store(latency, Ordering::Relaxed);
                        }

                        // Special case the first real latency report
                        read_avg = if read_avg == u64::MAX {
                            latency * LATENCY_SCALE
                        } else {
                            // Cumulative average is guaranteed to be
                            // positive if being calculated properly
                            (read_avg as i64
                                + ((latency * LATENCY_SCALE) as i64 - read_avg as i64)
                                    / (read_ops_last + read_ops.0) as i64)
                                .try_into()
                                .unwrap()
                        };
                    }
                    RequestType::Out => {
                        if !request.writeback {
                            self.disk_image.fsync(None).map_err(Error::Fsync)?;
                        }
                        for (_, data_len) in request.data_descriptors() {
                            write_bytes += Wrapping(*data_len as u64);
                        }
                        write_ops += Wrapping(1);
                        if latency < self.counters.write_latency_min.load(Ordering::Relaxed) {
                            self.counters
                                .write_latency_min
                                .store(latency, Ordering::Relaxed);
                        }
                        if latency > write_max || write_max == u64::MAX {
                            self.counters
                                .write_latency_max
                                .store(latency, Ordering::Relaxed);
                        }

                        // Special case the first real latency report
                        write_avg = if write_avg == u64::MAX {
                            latency * LATENCY_SCALE
                        } else {
                            // Cumulative average is guaranteed to be
                            // positive if being calculated properly
                            (write_avg as i64
                                + ((latency * LATENCY_SCALE) as i64 - write_avg as i64)
                                    / (write_ops_last + write_ops.0) as i64)
                                .try_into()
                                .unwrap()
                        }
                    }
                    _ => {}
                }

                self.counters
                    .read_latency_avg
                    .store(read_avg, Ordering::Relaxed);

                self.counters
                    .write_latency_avg
                    .store(write_avg, Ordering::Relaxed);

                let len = if request.request_type() == RequestType::In {
                    result as u32 + 1
                } else {
                    1
                };
                (VIRTIO_BLK_S_OK as u8, len)
            } else {
                warn!(
                    "Request failed: {:x?} {:?}",
                    request,
                    io::Error::from_raw_os_error(-result)
                );
                (VIRTIO_BLK_S_IOERR as u8, 1)
            };

            mem.write_obj(status, request.status_addr())
                .map_err(Error::RequestStatus)?;

            let queue = &mut self.queue;

            queue
                .add_used(mem.deref(), desc_index, len)
                .map_err(Error::QueueAddUsed)?;
            queue
                .enable_notification(mem.deref())
                .map_err(Error::QueueEnableNotification)?;
        }

        self.counters
            .write_bytes
            .fetch_add(write_bytes.0, Ordering::AcqRel);
        self.counters
            .write_ops
            .fetch_add(write_ops.0, Ordering::AcqRel);

        self.counters
            .read_bytes
            .fetch_add(read_bytes.0, Ordering::AcqRel);
        self.counters
            .read_ops
            .fetch_add(read_ops.0, Ordering::AcqRel);

        Ok(())
    }

    fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        self.interrupt_cb
            .trigger(VirtioInterruptType::Queue(self.queue_index))
            .map_err(|e| {
                error!("Failed to signal used queue: {e:?}");
                DeviceError::FailedSignalingUsedQueue(e)
            })
    }

    fn set_queue_thread_affinity(&self) {
        // Prepare the CPU set the current queue thread is expected to run onto.
        let cpuset = self.host_cpus.as_ref().map(|host_cpus| {
            // SAFETY: all zeros is a valid pattern
            let mut cpuset: libc::cpu_set_t = unsafe { std::mem::zeroed() };
            // SAFETY: FFI call, trivially safe
            unsafe { libc::CPU_ZERO(&mut cpuset) };
            for host_cpu in host_cpus {
                // SAFETY: FFI call, trivially safe
                unsafe { libc::CPU_SET(*host_cpu, &mut cpuset) };
            }
            cpuset
        });

        // Schedule the thread to run on the expected CPU set
        if let Some(cpuset) = cpuset.as_ref() {
            let cpuset: *const libc::cpu_set_t = cpuset;
            // SAFETY: FFI call with correct arguments
            let ret = unsafe {
                libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), cpuset)
            };

            if ret != 0 {
                error!(
                    "Failed scheduling the virtqueue thread {} on the expected CPU set: {}",
                    self.queue_index,
                    io::Error::last_os_error()
                );
            }
        }
    }

    fn run(
        &mut self,
        paused: &AtomicBool,
        paused_sync: &Barrier,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(self.queue_evt.as_raw_fd(), QUEUE_AVAIL_EVENT)?;
        helper.add_event(self.disk_image.notifier().as_raw_fd(), COMPLETION_EVENT)?;
        if let Some(rate_limiter) = &self.rate_limiter {
            helper.add_event(rate_limiter.as_raw_fd(), RATE_LIMITER_EVENT)?;
        }
        if let Some(cmd_receiver) = &self.mirror_cmd_receiver {
            helper.add_event(cmd_receiver.evt.as_raw_fd(), BLOCK_COMMAND_EVENT)?;
        }
        self.set_queue_thread_affinity();
        helper.run(paused, paused_sync, self)?;

        Ok(())
    }
}

impl EpollHelperHandler for BlockEpollHandler {
    fn handle_event(
        &mut self,
        helper: &mut EpollHelper,
        event: &epoll::Event,
    ) -> result::Result<(), EpollHelperError> {
        let ev_type = event.data as u16;
        match ev_type {
            QUEUE_AVAIL_EVENT => {
                self.queue_evt.read().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!("Failed to get queue event: {e:?}"))
                })?;

                let rate_limit_reached = self.rate_limiter.as_ref().is_some_and(|r| r.is_blocked());

                // Process the queue only when the rate limit is not reached
                if !rate_limit_reached {
                    self.process_queue_submit_and_signal()?;
                }
            }
            COMPLETION_EVENT => {
                self.disk_image.notifier().read().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!("Failed to get queue event: {e:?}"))
                })?;

                if let Err(e) = self.process_queue_complete() {
                    warn!("Failed to process queue (complete): {e:?}");
                }

                self.try_signal_used_queue()?;

                let rate_limit_reached = self.rate_limiter.as_ref().is_some_and(|r| r.is_blocked());

                // Process the queue only when the rate limit is not reached
                if !rate_limit_reached {
                    self.process_queue_submit_and_signal()?;
                }
                self.try_apply_pending_block_queue_command(helper)?;
            }
            RATE_LIMITER_EVENT => {
                if let Some(rate_limiter) = &mut self.rate_limiter {
                    // Upon rate limiter event, call the rate limiter handler
                    // and restart processing the queue.
                    rate_limiter.event_handler().map_err(|e| {
                        EpollHelperError::HandleEvent(anyhow!(
                            "Failed to process rate limiter event: {e:?}"
                        ))
                    })?;

                    self.process_queue_submit_and_signal()?;
                } else {
                    return Err(EpollHelperError::HandleEvent(anyhow!(
                        "Unexpected 'RATE_LIMITER_EVENT' when rate_limiter is not enabled."
                    )));
                }
            }
            BLOCK_COMMAND_EVENT => {
                if let Some(cmd_receiver) = self.mirror_cmd_receiver.as_mut() {
                    cmd_receiver.evt.read().map_err(|error| {
                        EpollHelperError::HandleEvent(anyhow!(
                            "Failed to read block command event: {error:?}"
                        ))
                    })?;
                    if let Some(update) = cmd_receiver.cmd.lock().unwrap().take()
                        && let Some(stale) =
                            cmd_receiver.pending_block_queue_command.replace(update)
                    {
                        warn!(
                            "Replacing pending block queue command {:?} before it was applied",
                            stale.kind
                        );
                    }
                }
                self.try_apply_pending_block_queue_command(helper)?;
            }
            _ => {
                return Err(EpollHelperError::HandleEvent(anyhow!(
                    "Unexpected event: {ev_type}"
                )));
            }
        }
        Ok(())
    }
}

/// Virtio device for exposing block level read/write operations on a host file.
pub struct Block {
    common: VirtioCommon,
    id: String,
    disk_image: Box<dyn AsyncFullDiskFile>,
    disk_path: PathBuf,
    disk_nsectors: Arc<AtomicU64>,
    config: VirtioBlockConfig,
    writeback: Arc<AtomicBool>,
    counters: BlockCounters,
    seccomp_action: SeccompAction,
    rate_limiter: Option<Arc<RateLimiterGroup>>,
    exit_evt: EventFd,
    serial: Box<[u8]>,
    queue_affinity: BTreeMap<u16, Box<[usize]>>,
    disable_sector0_writes: bool,
    lock_granularity_choice: LockGranularityChoice,
    /// The current lock status.
    // There is no way to query what locks are already held, so we need to cache that information.
    held_lock: LockType,
    device_status: Arc<AtomicU8>,
    active_request_count: Arc<AtomicUsize>,
    draining_active_requests: Arc<AtomicBool>,
    /// Per-virtqueue mirror writer-side handles, populated at
    /// activation.
    ///
    /// `Block::start_mirror` fills each slot with a [`BlockQueueCommand`] and
    /// writes the corresponding eventfd.
    queue_cmd_senders: Vec<BlockQueueCommandSender>,
    mirror_handle: Option<BlockMirrorHandle>,
}

#[derive(Serialize, Deserialize)]
pub struct BlockState {
    pub disk_path: String,
    pub disk_nsectors: u64,
    pub avail_features: u64,
    pub acked_features: u64,
    pub config: VirtioBlockConfig,
}

impl Block {
    /// Create a new virtio block device that operates on the given file.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        disk_image: Box<dyn AsyncFullDiskFile>,
        disk_path: PathBuf,
        read_only: bool,
        access_platform_enabled: bool,
        num_queues: usize,
        queue_size: u16,
        serial: Option<String>,
        seccomp_action: SeccompAction,
        rate_limiter: Option<Arc<RateLimiterGroup>>,
        exit_evt: EventFd,
        state: Option<BlockState>,
        queue_affinity: BTreeMap<u16, Box<[usize]>>,
        sparse: bool,
        disable_sector0_writes: bool,
        lock_granularity: LockGranularityChoice,
    ) -> io::Result<Self> {
        let (disk_nsectors, avail_features, acked_features, config, paused) =
            if let Some(state) = state {
                info!("Restoring virtio-block {id}");
                (
                    state.disk_nsectors,
                    state.avail_features,
                    state.acked_features,
                    state.config,
                    true,
                )
            } else {
                let disk_size = disk_image
                    .logical_size()
                    .map_err(|e| io::Error::other(format!("Failed getting disk size: {e}")))?;
                if disk_size % SECTOR_SIZE != 0 {
                    warn!(
                        "Disk size {disk_size} is not a multiple of sector size {SECTOR_SIZE}; \
                 the remainder will not be visible to the guest."
                    );
                }

                let mut avail_features = (1u64 << VIRTIO_F_VERSION_1)
                    | (1u64 << VIRTIO_BLK_F_FLUSH)
                    | (1u64 << VIRTIO_BLK_F_CONFIG_WCE)
                    | (1u64 << VIRTIO_BLK_F_BLK_SIZE)
                    | (1u64 << VIRTIO_BLK_F_TOPOLOGY)
                    | (1u64 << VIRTIO_BLK_F_SEG_MAX)
                    | (1u64 << VIRTIO_RING_F_EVENT_IDX)
                    | (1u64 << VIRTIO_RING_F_INDIRECT_DESC);

                // When backend supports sparse operations:
                // - Always advertise WRITE_ZEROES (safe for all drivers)
                // - Advertise DISCARD only when sparse=true, since DISCARD
                //   deallocates space via punch_hole and should require
                //   explicit user opt in.
                let mut discard_supported = false;
                if disk_image.supports_sparse_operations() {
                    avail_features |= 1u64 << VIRTIO_BLK_F_WRITE_ZEROES;
                    if sparse {
                        avail_features |= 1u64 << VIRTIO_BLK_F_DISCARD;
                        discard_supported = true;
                    }
                } else if sparse {
                    warn!("sparse=on requested but backend does not support sparse operations");
                }

                if access_platform_enabled {
                    avail_features |= 1u64 << VIRTIO_F_ACCESS_PLATFORM;
                }

                if read_only {
                    avail_features |= 1u64 << VIRTIO_BLK_F_RO;
                }

                let topology = disk_image.topology();
                info!("Disk topology: {topology:?}");

                let logical_block_size = if topology.logical_block_size > 512 {
                    topology.logical_block_size
                } else {
                    512
                };

                // Calculate the exponent that maps physical block to logical block
                let mut physical_block_exp = 0;
                let mut size = logical_block_size;
                while size < topology.physical_block_size {
                    physical_block_exp += 1;
                    size <<= 1;
                }

                let disk_nsectors = disk_size / SECTOR_SIZE;
                let mut config = VirtioBlockConfig {
                    capacity: disk_nsectors,
                    writeback: 1,
                    blk_size: topology.logical_block_size as u32,
                    physical_block_exp,
                    min_io_size: (topology.minimum_io_size / logical_block_size) as u16,
                    opt_io_size: (topology.optimal_io_size / logical_block_size) as u32,
                    seg_max: (queue_size - MINIMUM_BLOCK_QUEUE_SIZE) as u32,
                    ..Default::default()
                };

                if avail_features & (1u64 << VIRTIO_BLK_F_WRITE_ZEROES) != 0 {
                    config.max_write_zeroes_sectors = u32::MAX;
                    config.max_write_zeroes_seg = MAX_DISCARD_WRITE_ZEROES_SEG;
                    config.write_zeroes_may_unmap = if discard_supported { 1 } else { 0 };
                }
                if avail_features & (1u64 << VIRTIO_BLK_F_DISCARD) != 0 {
                    config.max_discard_sectors = u32::MAX;
                    config.max_discard_seg = MAX_DISCARD_WRITE_ZEROES_SEG;
                    config.discard_sector_alignment = (logical_block_size / SECTOR_SIZE) as u32;
                }

                if num_queues > 1 {
                    avail_features |= 1u64 << VIRTIO_BLK_F_MQ;
                    config.num_queues = num_queues as u16;
                }

                (disk_nsectors, avail_features, 0, config, false)
            };

        let serial = serial
            .map_or_else(|| build_serial(&disk_path), Vec::from)
            .into_boxed_slice();

        Ok(Block {
            common: VirtioCommon {
                device_type: VirtioDeviceType::Block as u32,
                avail_features,
                acked_features,
                paused_sync: Some(Arc::new(Barrier::new(num_queues + 1))),
                queue_sizes: vec![queue_size; num_queues],
                min_queues: 1,
                paused: Arc::new(AtomicBool::new(paused)),
                ..Default::default()
            },
            id,
            disk_image,
            disk_path,
            disk_nsectors: Arc::new(AtomicU64::new(disk_nsectors)),
            config,
            writeback: Arc::new(AtomicBool::new(true)),
            counters: BlockCounters::default(),
            seccomp_action,
            rate_limiter,
            exit_evt,
            serial,
            queue_affinity,
            disable_sector0_writes,
            lock_granularity_choice: lock_granularity,
            held_lock: LockType::Unlock,
            device_status: Arc::new(AtomicU8::new(0)),
            active_request_count: Arc::new(AtomicUsize::new(0)),
            draining_active_requests: Arc::new(AtomicBool::new(false)),
            queue_cmd_senders: Vec::new(),
            mirror_handle: None,
        })
    }

    fn wait_for_active_requests(&self) -> result::Result<(), anyhow::Error> {
        const BLOCK_PAUSE_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
        const BLOCK_PAUSE_FIRST_DRAIN_WARNING: Duration = Duration::from_secs(1);
        const BLOCK_PAUSE_DRAIN_WARNING_INTERVAL: Duration = Duration::from_secs(5);

        let started = Instant::now();
        let mut next_warning = BLOCK_PAUSE_FIRST_DRAIN_WARNING;

        loop {
            let active = self.active_request_count.load(Ordering::SeqCst);
            if active == 0 {
                return Ok(());
            }

            let elapsed = started.elapsed();
            if elapsed >= BLOCK_PAUSE_DRAIN_TIMEOUT {
                return Err(anyhow!("timed out draining block requests"));
            }

            if elapsed >= next_warning {
                warn!("pause: still waiting for {active} active block requests after {elapsed:?}");
                next_warning += BLOCK_PAUSE_DRAIN_WARNING_INTERVAL;
            }

            thread::yield_now();
        }
    }

    fn read_only(&self) -> bool {
        has_feature(self.features(), VIRTIO_BLK_F_RO.into())
    }

    /// Returns the advisory lock granularity to use for `disk_image`.
    ///
    /// The granularity follows the `lock_granularity` choice in the block config.
    fn lock_granularity(
        &self,
        disk_image: &dyn AsyncFullDiskFile,
        disk_path: &Path,
    ) -> LockGranularity {
        match self.lock_granularity_choice {
            LockGranularityChoice::Full => LockGranularity::WholeFile,
            LockGranularityChoice::ByteRange => {
                // Byte range lock covering [0, max(logical, physical))
                // logical > physical for sparse files, physical > logical
                // for small dense files due to filesystem block rounding.
                let logical = disk_image.logical_size();
                let physical = disk_image.physical_size();
                match (logical, physical) {
                    (Ok(l), Ok(p)) => LockGranularity::ByteRange(0, max(l, p)),
                    (Ok(l), Err(_)) => LockGranularity::ByteRange(0, l),
                    (Err(_), Ok(p)) => LockGranularity::ByteRange(0, p),
                    (Err(e), Err(_)) => {
                        let fallback = LockGranularity::WholeFile;
                        warn!(
                            "Can't get disk size for id={},path={}, falling back to {:?}: error: {e}",
                            self.id,
                            disk_path.display(),
                            fallback
                        );
                        fallback
                    }
                }
            }
            LockGranularityChoice::QemuCompatible => LockGranularity::QemuCompatible,
        }
    }

    /// Tries to acquire an advisory lock for an arbitrary disk backend.
    fn try_lock_disk_image(
        &self,
        disk_image: &dyn AsyncFullDiskFile,
        disk_path: &Path,
        lock_type: LockType,
        current_lock: LockType,
    ) -> result::Result<(), LockError> {
        let granularity = self.lock_granularity(disk_image, disk_path);
        debug!(
            "Attempting to acquire {lock_type:?} lock for disk image: id={},path={},granularity={granularity:?}",
            self.id,
            disk_path.display()
        );
        let fd = disk_image.fd();
        granularity
            .try_acquire_lock(&fd, lock_type, current_lock)
            .inspect_err(|_| {
                error!(
                    "Cannot acquire {lock_type:?} lock for disk image: id={},path={},granularity={granularity:?}",
                    self.id,
                    disk_path.display()
                );
            })?;
        info!(
            "Acquired {lock_type:?} lock for disk image id={},path={}",
            self.id,
            disk_path.display()
        );
        Ok(())
    }

    /// Tries to set an advisory lock for the corresponding disk image.
    pub fn try_lock_image(&mut self) -> Result<()> {
        let lock_type = match self.read_only() {
            true => LockType::Read,
            false => LockType::Write,
        };
        self.try_lock_disk_image(
            self.disk_image.as_ref(),
            &self.disk_path,
            lock_type,
            self.held_lock,
        )
        .map_err(|error| Error::LockDiskImage {
            path: self.disk_path.clone(),
            error,
            lock_type,
        })?;
        self.held_lock = lock_type;
        Ok(())
    }

    /// Releases the advisory lock held for the corresponding disk image.
    pub fn unlock_image(&mut self) -> Result<()> {
        let granularity = self.lock_granularity(self.disk_image.as_ref(), &self.disk_path);

        // It is very unlikely that this fails;
        // Should we remove the Result to simplify the error propagation on
        // higher levels?
        let fd = self.disk_image.fd();
        granularity
            .clear_lock(&fd)
            .map_err(|error| Error::LockDiskImage {
                path: self.disk_path.clone(),
                error,
                lock_type: LockType::Unlock,
            })?;
        self.held_lock = LockType::Unlock;
        Ok(())
    }

    fn state(&self) -> BlockState {
        BlockState {
            disk_path: self.disk_path.to_str().unwrap().to_owned(),
            disk_nsectors: self.disk_nsectors.load(Ordering::SeqCst),
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
            config: self.config,
        }
    }

    /// The virtio v1.2 spec says "If VIRTIO_BLK_F_CONFIG_WCE was not
    /// negotiated but VIRTIO_BLK_F_FLUSH was, the driver SHOULD assume
    /// presence of a writeback cache." It also says "If
    /// VIRTIO_BLK_F_CONFIG_WCE is negotiated but VIRTIO_BLK_F_FLUSH is not,
    /// the device MUST initialize writeback to 0."
    fn is_writeback_enabled(&self, desired: bool) -> bool {
        let flush = self.common.feature_acked(VIRTIO_BLK_F_FLUSH.into());
        let wce = self.common.feature_acked(VIRTIO_BLK_F_CONFIG_WCE.into());
        if wce { flush && desired } else { flush }
    }

    fn set_writeback_mode(&mut self, enabled: bool) {
        self.config.writeback = enabled as u8;
        self.writeback.store(enabled, Ordering::Release);
        info!(
            "Changing cache mode to {}",
            if enabled { "writeback" } else { "writethrough" }
        );
    }

    pub fn resize(&mut self, new_size: u64) -> Result<()> {
        if !new_size.is_multiple_of(SECTOR_SIZE) {
            return Err(Error::InvalidSize);
        }

        if self.mirror_handle.is_some() {
            return Err(Error::MirrorActive);
        }

        self.disk_image
            .resize(new_size)
            .map_err(Error::DiskResize)?;

        let nsectors = new_size / SECTOR_SIZE;

        self.common.pause().map_err(Error::PauseVcpus)?;

        self.disk_nsectors.store(nsectors, Ordering::SeqCst);
        self.config.capacity = nsectors;
        self.state().disk_nsectors = nsectors;

        self.common.resume().map_err(Error::ResumeVcpus)?;

        self.common
            .trigger_interrupt(VirtioInterruptType::Config)
            .map_err(Error::ConfigChange)
    }

    /// Starts mirroring the device's disk to `destination`.
    ///
    /// `destination` is an already-opened disk backend whose file lives in
    /// the host filesystem, typically on a different mount than the source
    /// (e.g. another host mounted NFS share).
    /// `destination_path` is the host path backing it.
    ///
    /// Each virtqueue worker swaps its `disk_image` to a new
    /// [`MirroringAsyncIo`] that fans every mutating request out to both
    /// backends. A background [`CopyWorker`] copies existing source bytes
    /// to destination until all initial bytes are copied.
    /// The [`MirroringAsyncIo`] stays in place until completion, keeping the device's
    /// disk and `destination` in sync.
    ///
    /// The destination is write-locked before queue installation. Its open file
    /// description retains that lock until completion transfers the backend to
    /// the device or cancellation drops the final destination descriptor.
    pub fn start_mirror(
        &mut self,
        destination: Box<dyn AsyncFullDiskFile>,
        destination_path: PathBuf,
    ) -> MirrorResult<()> {
        self.supports_mirroring()?;
        destination
            .supports_mirroring()
            .map_err(MirrorError::Unsupported)?;

        // Mirroring requires activation to have installed at least one live queue worker.
        if self.common.epoll_threads.is_none() || self.queue_cmd_senders.is_empty() {
            return Err(MirrorError::DeviceNotActive);
        }
        self.ensure_not_paused_for_mirror()?;
        let source_size = self
            .disk_image
            .logical_size()
            .map_err(MirrorError::Backend)?;
        let destination_size = destination.logical_size().map_err(MirrorError::Backend)?;
        if destination_size != source_size {
            return Err(MirrorError::DestinationSizeMismatch {
                source_size,
                destination_size,
            });
        }

        self.try_lock_disk_image(
            destination.as_ref(),
            &destination_path,
            LockType::Write,
            LockType::Unlock,
        )
        .map_err(|error| MirrorError::DestinationLock {
            path: destination_path.clone(),
            lock_type: LockType::Write,
            error,
        })?;

        let (state, copy_worker) = self.initialize_mirror(destination.as_ref(), source_size)?;

        self.mirror_handle = Some(BlockMirrorHandle {
            state,
            copy_worker,
            destination,
            destination_path,
        });
        Ok(())
    }

    /// Returns an error if this disk image cannot participate in block mirroring.
    pub fn supports_mirroring(&self) -> MirrorResult<()> {
        self.disk_image
            .supports_mirroring()
            .map_err(MirrorError::Unsupported)
    }

    /// Switch the device's mirroring wrapper to the destination disk.
    ///
    /// Each virtqueue worker swaps its [`MirroringAsyncIo`] for a plain
    /// [`AsyncIo`] on the destination through the same slot and eventfd
    /// mechanism used to install the mirror. After this call the source
    /// disk is no longer used by the VM and the operator can detach or
    /// remove it.
    ///
    /// Returns [`MirrorError::NotActive`] when no mirror is active for the
    /// device, and [`MirrorError::NotReady`] when the copy worker has not yet
    /// reported the ready phase or the mirror has since failed. Both errors
    /// return before any queue command is sent, so the mirror handle is left in
    /// place and the caller can poll the state and retry.
    ///
    /// # Panics
    ///
    /// Panics if a queue command cannot be sent or acknowledged after the
    /// switch-over has started. At that point some queues may already write
    /// to the destination only, and there is no revert that keeps
    /// acknowledged writes, so aborting is preferred over data loss.
    pub fn complete_mirror(&mut self) -> MirrorResult<PathBuf> {
        self.ensure_not_paused_for_mirror()?;

        let handle = self.mirror_handle.as_ref().ok_or(MirrorError::NotActive)?;

        if !matches!(handle.state.phase(), MirrorPhase::Ready) {
            return Err(MirrorError::NotReady);
        }

        let destination_lock = if self.read_only() {
            LockType::Read
        } else {
            LockType::Write
        };
        self.try_lock_disk_image(
            handle.destination.as_ref(),
            &handle.destination_path,
            destination_lock,
            LockType::Write,
        )
        .map_err(|error| MirrorError::DestinationLock {
            path: handle.destination_path.clone(),
            lock_type: destination_lock,
            error,
        })?;

        let (commands, ack_rx) = self.create_mirror_queue_commands(
            BlockQueueCommandKind::CompleteToDestination,
            |ring_depth| {
                handle
                    .destination
                    .create_async_io(ring_depth)
                    .map_err(MirrorError::Backend)
            },
        )?;

        // A concurrent destination failure may have moved the mirror to
        // Failed since the phase check above. Confirm Completing took effect
        // before sending any command, otherwise we would swap the device
        // onto a failed mirror.
        handle.state.transition_to_phase(MirrorPhase::Completing);
        if !matches!(handle.state.phase(), MirrorPhase::Completing) {
            return Err(MirrorError::NotReady);
        }

        // Once the first command is sent a queue may write to the destination
        // only, so a partial switch-over has no safe revert. We panic rather
        // than risk losing acknowledged writes.
        Self::send_mirror_queue_commands(commands).expect("mirror queue commands sent");
        self.wait_for_mirror_queue_command_acks(&ack_rx)
            .expect("mirror queue command acks received");
        handle.state.transition_to_phase(MirrorPhase::Completed);

        let BlockMirrorHandle {
            destination,
            destination_path,
            copy_worker,
            state: _,
        } = self.mirror_handle.take().unwrap();
        if let Err(error) = copy_worker.join() {
            error!("copy worker thread panicked: {error:?}");
        }

        self.disk_image = destination;
        self.disk_path = destination_path.clone();
        self.held_lock = destination_lock;
        event!("vm", "disk-mirror-completed", "id", &self.id);
        Ok(destination_path)
    }

    /// Fails with [`MirrorError::DevicePaused`] when the device is paused, since a
    /// parked worker cannot apply a staged mirror command.
    fn ensure_not_paused_for_mirror(&self) -> MirrorResult<()> {
        if self.common.paused.load(Ordering::SeqCst) {
            return Err(MirrorError::DevicePaused);
        }
        Ok(())
    }

    /// Installs the mirror backends and starts the copy worker.
    ///
    /// On success, returns after every virtqueue has acknowledged the new
    /// backend. If installation fails after commands are created, the queues
    /// are reverted to the source backend.
    fn initialize_mirror(
        &mut self,
        destination: &dyn AsyncFullDiskFile,
        source_size: u64,
    ) -> MirrorResult<(Arc<MirrorState>, CopyWorkerHandle)> {
        let state = MirrorState::new(source_size, self.id.clone());
        let (commands, ack_rx) = self.create_mirror_queue_commands(
            BlockQueueCommandKind::InstallMirror,
            |ring_depth| {
                Ok(Box::new(
                    MirroringAsyncIo::create(
                        self.disk_image.as_ref(),
                        destination,
                        state.clone(),
                        ring_depth,
                    )
                    .map_err(MirrorError::Backend)?,
                ))
            },
        )?;

        Self::send_mirror_queue_commands(commands)
            .inspect_err(|_| self.rollback_mirror_installation(&state))?;

        self.wait_for_mirror_queue_command_acks(&ack_rx)
            .inspect_err(|_| self.rollback_mirror_installation(&state))?;

        let copy_worker = CopyWorker::spawn(
            self.disk_image.as_ref(),
            destination,
            state.clone(),
            MIRROR_BLOCK_SIZE,
        )
        .map_err(MirrorError::Backend)
        .inspect_err(|_| self.rollback_mirror_installation(&state))?;

        Ok((state, copy_worker))
    }

    /// Marks a mirror installation as failed and reverts to the source.
    fn rollback_mirror_installation(&mut self, state: &Arc<MirrorState>) {
        state.transition_to_phase(MirrorPhase::Failed(Arc::new(MirrorFailure::Installation)));

        if let Err(revert_error) = self.revert_queues_to_source() {
            error!(
                "failed to revert virtqueues to source after mirror install failure: {revert_error}"
            );
        }
    }

    /// Creates one command per virtqueue, all sharing one ack channel.
    ///
    /// Returns each command paired with the sender of its queue, plus
    /// the receiving end of the channel.
    ///
    /// `new_async_io` is called once per queue with the ring depth of
    /// that queue and returns the backend the worker swaps to.
    ///
    /// The ack sender lives only inside the returned commands. Once
    /// every worker has consumed or dropped its command, a lost ack
    /// shows up as `Disconnected` on the receiver instead of costing
    /// the full ack timeout, and only the workers can ack this op.
    fn create_mirror_queue_commands(
        &self,
        kind: BlockQueueCommandKind,
        mut new_async_io: impl FnMut(u32) -> MirrorResult<Box<dyn AsyncIo>>,
    ) -> MirrorResult<(QueueCommands<'_>, Receiver<BlockQueueAck>)> {
        let (ack_tx, ack_rx) = mpsc::channel();
        let commands = self
            .queue_cmd_senders
            .iter()
            .map(|sender| {
                Ok((
                    sender,
                    BlockQueueCommand {
                        kind,
                        async_io: new_async_io(u32::from(sender.queue_size))?,
                        ack: ack_tx.clone(),
                    },
                ))
            })
            .collect::<MirrorResult<_>>()?;
        Ok((commands, ack_rx))
    }

    /// Sends one staged mirror command to each virtqueue worker.
    fn send_mirror_queue_commands(commands: QueueCommands<'_>) -> MirrorResult<()> {
        for (sender, command) in commands {
            let mut slot = sender.cmd.lock().unwrap();

            if slot.is_some() {
                return Err(MirrorError::CommandSlotOccupied);
            }

            *slot = Some(command);
            sender.evt.write(1).map_err(MirrorError::NotifyWorker)?;
        }

        Ok(())
    }

    /// Waits for all mirror-command acknowledgements.
    ///
    /// Returns an error when the shared deadline expires or an acknowledgement
    /// reports an error.
    fn wait_for_mirror_queue_command_acks(
        &self,
        ack_rx: &Receiver<BlockQueueAck>,
    ) -> MirrorResult<()> {
        let deadline = Instant::now() + MIRROR_COMMAND_ACK_TIMEOUT;

        for _ in 0..self.queue_cmd_senders.len() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let ack = ack_rx.recv_timeout(remaining).map_err(MirrorError::Ack)?;

            ack.result?;
        }

        Ok(())
    }

    /// Swaps every virtqueue worker back to a plain `AsyncIo` on the source disk.
    fn revert_queues_to_source(&mut self) -> MirrorResult<()> {
        let (commands, ack_rx) = self.create_mirror_queue_commands(
            BlockQueueCommandKind::CancelToSource,
            |ring_depth| {
                self.disk_image
                    .create_async_io(ring_depth)
                    .map_err(MirrorError::Backend)
            },
        )?;
        Self::send_mirror_queue_commands(commands)?;
        self.wait_for_mirror_queue_command_acks(&ack_rx)
    }

    /// Cancels an active mirror and reverts the device to the source disk.
    ///
    /// Transitions the mirror to [`MirrorPhase::Cancelling`] to mark that
    /// cancellation has started, reverts every virtqueue worker to a plain
    /// [`AsyncIo`] on the source, then joins the copy worker and releases the
    /// destination.
    ///
    /// Returns [`MirrorError::NotActive`] when no mirror is active, and
    /// [`MirrorError::CompletionInProgress`] once a completion has been
    /// attempted, because a queue may already write to the destination only
    /// and reverting would lose acknowledged guest writes.
    ///
    /// If the revert fails the mirror stays in [`MirrorPhase::Cancelling`]
    /// with the handle held, so calling this again retries the revert and
    /// finishes the cancellation.
    ///
    /// Blocks until the copy worker finishes its current block and joins,
    /// which can stall on a slow or hung destination.
    pub fn cancel_mirror(&mut self) -> MirrorResult<()> {
        self.ensure_not_paused_for_mirror()?;
        let state = self
            .mirror_handle
            .as_ref()
            .ok_or(MirrorError::NotActive)?
            .state
            .clone();

        if !matches!(
            state.phase(),
            MirrorPhase::Running
                | MirrorPhase::Ready
                | MirrorPhase::Failed(_)
                | MirrorPhase::Cancelling
        ) {
            return Err(MirrorError::CompletionInProgress);
        }

        state.transition_to_phase(MirrorPhase::Cancelling);
        self.revert_queues_to_source()?;

        if let Some(handle) = self.mirror_handle.take()
            && let Err(e) = handle.copy_worker.join()
        {
            error!("copy worker thread panicked: {e:?}");
        }

        event!("vm", "disk-mirror-cancelled", "id", &self.id);

        Ok(())
    }

    /// Returns a snapshot of the current mirror progress.
    pub fn mirror_status(&self) -> Option<MirrorStatus> {
        self.mirror_handle
            .as_ref()
            .map(|handle| handle.state.status())
    }

    #[cfg(fuzzing)]
    pub fn wait_for_epoll_threads(&mut self) {
        self.common.wait_for_epoll_threads();
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        let mirror_handle = self.mirror_handle.take();
        if let Some(handle) = mirror_handle.as_ref() {
            handle.state.transition_to_phase(MirrorPhase::Cancelling);
        }

        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
        self.common.wait_for_epoll_threads();

        let Some(handle) = mirror_handle else {
            return;
        };

        if !handle.copy_worker.is_finished() {
            warn!("copy worker is still running during block teardown");
            return;
        }

        if let Err(error) = handle.copy_worker.join() {
            error!("copy worker thread panicked: {error:?}");
        }
    }
}

impl VirtioDevice for Block {
    fn device_type(&self) -> u32 {
        self.common.device_type
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.common.queue_sizes
    }

    fn features(&self) -> u64 {
        self.common.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        self.common.ack_features(value);
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.read_config_from_slice(self.config.as_slice(), offset, data);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        // The "writeback" field is the only mutable field
        let writeback_offset =
            (&raw const self.config.writeback as u64) - (&raw const self.config as u64);
        if offset != writeback_offset || data.len() != std::mem::size_of_val(&self.config.writeback)
        {
            error!(
                "Attempt to write to read-only field: offset {:x} length {}",
                offset,
                data.len()
            );
            return;
        }

        let writeback = self.is_writeback_enabled(data[0] == 1);
        self.set_writeback_mode(writeback);
    }

    fn activate(&mut self, context: crate::device::ActivationContext) -> ActivateResult {
        let crate::device::ActivationContext {
            mem,
            interrupt_cb,
            mut queues,
            device_status,
        } = context;
        self.device_status = device_status;
        // See if the guest didn't ack the device being read-only.
        // If so, warn and pretend it did.
        let original_acked_features = self.common.acked_features;
        self.common.acked_features |= self.common.avail_features & (1u64 << VIRTIO_BLK_F_RO);
        if original_acked_features != self.common.acked_features {
            warn!("Guest did not acknowledge that device is read-only, acting as if it did!");
        }
        self.common.activate(&queues, interrupt_cb.clone())?;

        // Recompute the barrier size from the queues that are actually activated.
        self.common.paused_sync = Some(Arc::new(Barrier::new(queues.len() + 1)));

        let writeback = self.is_writeback_enabled(self.config.writeback == 1);
        self.set_writeback_mode(writeback);

        let mut epoll_threads = Vec::new();
        let event_idx = self.common.feature_acked(VIRTIO_RING_F_EVENT_IDX.into());

        // Discard command handles from a previous activation before rebuilding them.
        self.queue_cmd_senders.clear();

        for i in 0..queues.len() {
            let (_, mut queue, queue_evt) = queues.remove(0);
            queue.set_event_idx(event_idx);

            let queue_size = queue.size();
            let (kill_evt, pause_evt) = self.common.dup_eventfds();
            let queue_idx = i as u16;

            let queue_command: Arc<Mutex<Option<BlockQueueCommand>>> = Arc::new(Mutex::new(None));
            let queue_command_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(|error| {
                error!("failed to create mirror eventfd: {error}");
                ActivateError::BadActivate
            })?;
            let mirror_handler_evt = queue_command_evt.try_clone().map_err(|error| {
                error!("failed to clone mirror eventfd: {error}");
                ActivateError::BadActivate
            })?;
            let cmd_receiver = BlockQueueCommandReceiver {
                cmd: queue_command.clone(),
                evt: mirror_handler_evt,
                pending_block_queue_command: None,
            };
            self.queue_cmd_senders.push(BlockQueueCommandSender {
                cmd: queue_command,
                evt: queue_command_evt,
                queue_size,
            });

            let mut handler = BlockEpollHandler {
                queue_index: queue_idx,
                queue,
                mem: mem.clone(),
                disk_image: self
                    .disk_image
                    .create_async_io(queue_size as u32)
                    .map_err(|e| {
                        error!("failed to create new AsyncIo: {e}");
                        ActivateError::BadActivate
                    })?,
                disk_nsectors: self.disk_nsectors.clone(),
                interrupt_cb: interrupt_cb.clone(),
                serial: self.serial.clone(),
                kill_evt,
                pause_evt,
                writeback: self.writeback.clone(),
                counters: self.counters.clone(),
                queue_evt,
                // Analysis during boot shows around ~40 maximum requests
                // This gives head room for systems with slower I/O without
                // compromising the cost of the reallocation or memory overhead
                inflight_requests: VecDeque::with_capacity(64),
                rate_limiter: self
                    .rate_limiter
                    .as_ref()
                    .map(|r| r.new_handle())
                    .transpose()
                    .unwrap(),
                access_platform: self.common.access_platform(),
                host_cpus: self.queue_affinity.get(&queue_idx).cloned(),
                acked_features: self.common.acked_features,
                disable_sector0_writes: self.disable_sector0_writes,
                active_request_count: self.active_request_count.clone(),
                draining_active_requests: self.draining_active_requests.clone(),
                mirror_cmd_receiver: Some(cmd_receiver),
            };

            let paused = self.common.paused.clone();
            let paused_sync = self.common.paused_sync.clone();

            spawn_virtio_thread(
                &format!("{}_q{}", self.id.clone(), i),
                &self.seccomp_action,
                Thread::VirtioBlock,
                &mut epoll_threads,
                &self.exit_evt,
                self.device_status.clone(),
                interrupt_cb.clone(),
                move || handler.run(&paused, paused_sync.as_ref().unwrap()),
            )?;
        }

        self.common.epoll_threads = Some(epoll_threads);
        event!("virtio-device", "activated", "id", &self.id);

        Ok(())
    }

    fn reset(&mut self) {
        self.common.reset();
        self.queue_cmd_senders.clear();
        self.draining_active_requests.store(false, Ordering::SeqCst);
        self.active_request_count.store(0, Ordering::SeqCst);
        self.set_writeback_mode(true);
        event!("virtio-device", "reset", "id", &self.id);
    }

    fn counters(&self) -> Option<HashMap<&'static str, Wrapping<u64>>> {
        let mut counters = HashMap::new();

        counters.insert(
            "read_bytes",
            Wrapping(self.counters.read_bytes.load(Ordering::Acquire)),
        );
        counters.insert(
            "write_bytes",
            Wrapping(self.counters.write_bytes.load(Ordering::Acquire)),
        );
        counters.insert(
            "read_ops",
            Wrapping(self.counters.read_ops.load(Ordering::Acquire)),
        );
        counters.insert(
            "write_ops",
            Wrapping(self.counters.write_ops.load(Ordering::Acquire)),
        );
        counters.insert(
            "write_latency_min",
            Wrapping(self.counters.write_latency_min.load(Ordering::Acquire)),
        );
        counters.insert(
            "write_latency_max",
            Wrapping(self.counters.write_latency_max.load(Ordering::Acquire)),
        );
        counters.insert(
            "write_latency_avg",
            Wrapping(self.counters.write_latency_avg.load(Ordering::Acquire) / LATENCY_SCALE),
        );
        counters.insert(
            "read_latency_min",
            Wrapping(self.counters.read_latency_min.load(Ordering::Acquire)),
        );
        counters.insert(
            "read_latency_max",
            Wrapping(self.counters.read_latency_max.load(Ordering::Acquire)),
        );
        counters.insert(
            "read_latency_avg",
            Wrapping(self.counters.read_latency_avg.load(Ordering::Acquire) / LATENCY_SCALE),
        );

        Some(counters)
    }

    fn set_access_platform(&mut self, access_platform: Arc<dyn AccessPlatform>) {
        self.common.set_access_platform(access_platform);
    }

    fn access_platform(&self) -> Option<Arc<dyn AccessPlatform>> {
        self.common.access_platform()
    }
}

impl Pausable for Block {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.draining_active_requests.store(true, Ordering::SeqCst);

        // Drain before parking the worker threads: the workers are what
        // complete in-flight I/O, so they must keep running until the count
        // reaches zero. Roll back the drain flag if any step fails.
        let result = self
            .wait_for_active_requests()
            .map_err(MigratableError::Pause)
            .and_then(|()| self.common.pause());

        self.draining_active_requests.store(false, Ordering::SeqCst);
        result
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.draining_active_requests.store(false, Ordering::SeqCst);
        self.common.resume()
    }
}

impl Snapshottable for Block {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        if self.mirror_handle.is_some() {
            return Err(MigratableError::Snapshot(anyhow!(
                "Cannot snapshot while mirror is active"
            )));
        }

        Snapshot::new_from_state(&self.state())
    }
}
impl Transportable for Block {}
impl Migratable for Block {}

#[cfg(test)]
mod unit_tests {
    use block::error::BlockErrorKind;
    use block::qcow::{BackingFileConfig, ImageType, QcowFile, RawFile};
    use block::qcow_disk::QcowDisk;
    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    const TEST_DISK_SIZE: u64 = 1 << 20;

    fn qcow2_disk(with_backing_file: bool) -> (TempFile, Box<dyn AsyncFullDiskFile>) {
        let image = TempFile::new().unwrap();
        let backing = with_backing_file.then(|| TempFile::new().unwrap());

        if let Some(backing) = &backing {
            backing.as_file().set_len(TEST_DISK_SIZE).unwrap();
            let backing_config = BackingFileConfig {
                path: backing.as_path().to_string_lossy().into_owned(),
                format: Some(ImageType::Raw),
            };
            let raw = RawFile::new(image.as_file().try_clone().unwrap(), false);
            QcowFile::new_from_backing(raw, 3, TEST_DISK_SIZE, &backing_config, true).unwrap();
        } else {
            let raw = RawFile::new(image.as_file().try_clone().unwrap(), false);
            QcowFile::new(raw, 3, TEST_DISK_SIZE, true).unwrap();
        }

        let disk = QcowDisk::new(
            image.as_file().try_clone().unwrap(),
            false,
            with_backing_file,
            true,
            false,
        )
        .unwrap();

        (image, Box::new(disk))
    }

    fn block_with_disk(disk_path: &Path, disk: Box<dyn AsyncFullDiskFile>) -> Block {
        Block::new(
            "test".to_string(),
            disk,
            disk_path.to_path_buf(),
            false,
            false,
            1,
            128,
            None,
            SeccompAction::Allow,
            None,
            EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            None,
            BTreeMap::new(),
            true,
            false,
            LockGranularityChoice::QemuCompatible,
        )
        .unwrap()
    }

    #[test]
    fn mirror_rejects_qcow2_backing_source() {
        let (source_file, source) = qcow2_disk(true);
        let (destination_file, destination) = qcow2_disk(false);
        let mut block = block_with_disk(source_file.as_path(), source);

        let error = block
            .start_mirror(destination, destination_file.as_path().to_path_buf())
            .unwrap_err();

        assert!(matches!(
            error,
            MirrorError::Unsupported(error)
                if error.kind() == BlockErrorKind::UnsupportedFeature
        ));
    }

    #[test]
    fn mirror_rejects_qcow2_backing_destination() {
        let (source_file, source) = qcow2_disk(false);
        let (destination_file, destination) = qcow2_disk(true);
        let mut block = block_with_disk(source_file.as_path(), source);

        let error = block
            .start_mirror(destination, destination_file.as_path().to_path_buf())
            .unwrap_err();

        assert!(matches!(
            error,
            MirrorError::Unsupported(error)
                if error.kind() == BlockErrorKind::UnsupportedFeature
        ));
    }
}
