// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::net::IpAddr;
use std::num::Wrapping;
use std::ops::Deref;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::{result, thread};

use anyhow::anyhow;
use event_monitor::event;
use log::{debug, error, info, trace, warn};
#[cfg(not(fuzzing))]
use net_util::virtio_features_to_tap_offload;
use net_util::{
    CtrlQueue, MAC_ADDR_LEN, MacAddr, NetCounters, NetQueuePair, OpenTapError, RxVirtio, Tap,
    TapError, TxVirtio, VirtioNetConfig, build_net_config_space, build_net_config_space_with_mq,
    open_tap, vnet_hdr_len,
};
use seccompiler::SeccompAction;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use virtio_bindings::virtio_config::*;
use virtio_bindings::virtio_net::*;
use virtio_bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use virtio_queue::{Queue, QueueT};
use vm_memory::{ByteValued, GuestAddressSpace, GuestMemoryAtomic};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vm_virtio::AccessPlatform;
use vmm_sys_util::eventfd::EventFd;

use super::{
    ActivateError, ActivateResult, EPOLL_HELPER_EVENT_LAST, EpollHelper, EpollHelperError,
    EpollHelperHandler, Error as DeviceError, RateLimiterConfig, VirtioCommon, VirtioDevice,
    VirtioDeviceType, VirtioInterruptType,
};
use crate::device::PostMigrationAnnouncer;
use crate::seccomp_filters::Thread;
use crate::thread_helper::spawn_virtio_thread;
use crate::{GuestMemoryMmap, VirtioInterrupt};

/// Control queue
// Event available on the control queue.
const CTRL_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;

// Following the VIRTIO specification, the MTU should be at least 1280.
pub const MIN_MTU: u16 = 1280;

pub struct NetCtrlEpollHandler {
    pub mem: GuestMemoryAtomic<GuestMemoryMmap>,
    pub kill_evt: EventFd,
    pub pause_evt: EventFd,
    pub ctrl_q: CtrlQueue,
    pub queue_evt: EventFd,
    pub queue: Queue,
    pub access_platform: Option<Arc<dyn AccessPlatform>>,
    pub interrupt_cb: Arc<dyn VirtioInterrupt>,
    pub queue_index: u16,
}

impl NetCtrlEpollHandler {
    fn signal_used_queue(&self, queue_index: u16) -> result::Result<(), DeviceError> {
        self.interrupt_cb
            .trigger(VirtioInterruptType::Queue(queue_index))
            .map_err(|e| {
                error!("Failed to signal used queue: {e:?}");
                DeviceError::FailedSignalingUsedQueue(e)
            })
    }

    pub fn run_ctrl(
        &mut self,
        paused: &AtomicBool,
        paused_sync: &Barrier,
    ) -> std::result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(self.queue_evt.as_raw_fd(), CTRL_QUEUE_EVENT)?;
        helper.run(paused, paused_sync, self)?;

        Ok(())
    }
}

impl EpollHelperHandler for NetCtrlEpollHandler {
    fn handle_event(
        &mut self,
        _helper: &mut EpollHelper,
        event: &epoll::Event,
    ) -> result::Result<(), EpollHelperError> {
        let ev_type = event.data as u16;
        match ev_type {
            CTRL_QUEUE_EVENT => {
                let mem = self.mem.memory();
                self.queue_evt.read().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!(
                        "Failed to get control queue event: {e:?}"
                    ))
                })?;
                self.ctrl_q
                    .process(
                        mem.deref(),
                        &mut self.queue,
                        self.access_platform.as_deref(),
                    )
                    .map_err(|e| {
                        EpollHelperError::HandleEvent(anyhow!(
                            "Failed to process control queue: {e:?}"
                        ))
                    })?;
                match self.queue.needs_notification(mem.deref()) {
                    Ok(true) => {
                        self.signal_used_queue(self.queue_index).map_err(|e| {
                            EpollHelperError::HandleEvent(anyhow!(
                                "Error signalling that control queue was used: {e:?}"
                            ))
                        })?;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        return Err(EpollHelperError::HandleEvent(anyhow!(
                            "Error getting notification state of control queue: {e}"
                        )));
                    }
                }
            }
            _ => {
                return Err(EpollHelperError::HandleEvent(anyhow!(
                    "Unknown event for virtio-net control queue"
                )));
            }
        }

        Ok(())
    }
}

/// Rx/Tx queue pair
// The guest has made a buffer available to receive a frame into.
pub const RX_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;
// The transmit queue has a frame that is ready to send from the guest.
pub const TX_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 2;
// A frame is available for reading from the tap device to receive in the guest.
pub const RX_TAP_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 3;
// The TAP can be written to. Used after an EAGAIN error to retry TX.
pub const TX_TAP_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 4;
// New 'wake up' event from the rx rate limiter
pub const RX_RATE_LIMITER_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 5;
// New 'wake up' event from the tx rate limiter
pub const TX_RATE_LIMITER_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 6;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to open taps")]
    OpenTap(#[source] OpenTapError),
    #[error("Using existing tap")]
    TapError(#[source] TapError),
    #[error("Error calling dup() on tap fd")]
    DuplicateTapFd(#[source] std::io::Error),
}

pub type Result<T> = result::Result<T, Error>;

struct NetEpollHandler {
    net: NetQueuePair,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    kill_evt: EventFd,
    pause_evt: EventFd,
    queue_index_base: u16,
    queue_pair: (Queue, Queue),
    queue_evt_pair: (EventFd, EventFd),
    // Always generate interrupts until the driver has signalled to the device.
    // This mitigates a problem with interrupts from tap events being "lost" upon
    // a restore as the vCPU thread isn't ready to handle the interrupt. This causes
    // issues when combined with VIRTIO_RING_F_EVENT_IDX interrupt suppression.
    driver_awake: bool,
}

impl NetEpollHandler {
    fn signal_used_queue(&self, queue_index: u16) -> result::Result<(), DeviceError> {
        self.interrupt_cb
            .trigger(VirtioInterruptType::Queue(queue_index))
            .map_err(|e| {
                error!("Failed to signal used queue: {e:?}");
                DeviceError::FailedSignalingUsedQueue(e)
            })
    }

    fn handle_rx_event(&mut self) -> result::Result<(), DeviceError> {
        let queue_evt = &self.queue_evt_pair.0;
        if let Err(e) = queue_evt.read() {
            error!("Failed to get rx queue event: {e:?}");
        }

        self.net.rx_desc_avail = true;

        let rate_limit_reached = self
            .net
            .rx_rate_limiter
            .as_ref()
            .is_some_and(|r| r.is_blocked());

        // Start to listen on RX_TAP_EVENT only when the rate limit is not reached
        if !self.net.rx_tap_listening && !rate_limit_reached {
            net_util::register_listener(
                self.net.epoll_fd.unwrap(),
                self.net.tap.as_raw_fd(),
                epoll::Events::EPOLLIN,
                u64::from(self.net.tap_rx_event_id),
            )
            .map_err(DeviceError::IoError)?;
            self.net.rx_tap_listening = true;
        }

        Ok(())
    }

    fn process_tx(&mut self) -> result::Result<(), DeviceError> {
        if self
            .net
            .process_tx(&self.mem.memory(), &mut self.queue_pair.1)
            .map_err(DeviceError::NetQueuePair)?
            || !self.driver_awake
        {
            self.signal_used_queue(self.queue_index_base + 1)?;
            debug!("Signalling TX queue");
        } else {
            debug!("Not signalling TX queue");
        }
        Ok(())
    }

    fn handle_tx_event(&mut self) -> result::Result<(), DeviceError> {
        let rate_limit_reached = self
            .net
            .tx_rate_limiter
            .as_ref()
            .is_some_and(|r| r.is_blocked());

        if !rate_limit_reached {
            self.process_tx()?;
        }

        Ok(())
    }

    fn handle_rx_tap_event(&mut self) -> result::Result<(), DeviceError> {
        if self
            .net
            .process_rx(&self.mem.memory(), &mut self.queue_pair.0)
            .map_err(DeviceError::NetQueuePair)?
            || !self.driver_awake
        {
            self.signal_used_queue(self.queue_index_base)?;
            trace!("Signalling RX queue");
        } else {
            trace!("Not signalling RX queue");
        }
        Ok(())
    }

    fn run(
        &mut self,
        paused: &AtomicBool,
        paused_sync: &Barrier,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(self.queue_evt_pair.0.as_raw_fd(), RX_QUEUE_EVENT)?;
        helper.add_event(self.queue_evt_pair.1.as_raw_fd(), TX_QUEUE_EVENT)?;
        if let Some(rate_limiter) = &self.net.rx_rate_limiter {
            helper.add_event(rate_limiter.as_raw_fd(), RX_RATE_LIMITER_EVENT)?;
        }
        if let Some(rate_limiter) = &self.net.tx_rate_limiter {
            helper.add_event(rate_limiter.as_raw_fd(), TX_RATE_LIMITER_EVENT)?;
        }

        let mem = self.mem.memory();
        // If there are some already available descriptors on the RX queue,
        // then we can start the thread while listening onto the TAP.
        if self
            .queue_pair
            .0
            .used_idx(mem.deref(), Ordering::Acquire)
            .map_err(EpollHelperError::QueueRingIndex)?
            < self
                .queue_pair
                .0
                .avail_idx(mem.deref(), Ordering::Acquire)
                .map_err(EpollHelperError::QueueRingIndex)?
        {
            helper.add_event(self.net.tap.as_raw_fd(), RX_TAP_EVENT)?;
            self.net.rx_tap_listening = true;
            info!("Listener registered at start");
        }

        // The NetQueuePair needs the epoll fd.
        self.net.epoll_fd = Some(helper.as_raw_fd());

        helper.run(paused, paused_sync, self)?;

        Ok(())
    }
}

impl EpollHelperHandler for NetEpollHandler {
    fn handle_event(
        &mut self,
        _helper: &mut EpollHelper,
        event: &epoll::Event,
    ) -> result::Result<(), EpollHelperError> {
        let ev_type = event.data as u16;
        match ev_type {
            RX_QUEUE_EVENT => {
                self.driver_awake = true;
                self.handle_rx_event().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!("Error processing RX queue: {e:?}"))
                })?;
            }
            TX_QUEUE_EVENT => {
                let queue_evt = &self.queue_evt_pair.1;
                if let Err(e) = queue_evt.read() {
                    error!("Failed to get tx queue event: {e:?}");
                }
                self.driver_awake = true;
                self.handle_tx_event().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!("Error processing TX queue: {e:?}"))
                })?;
            }
            TX_TAP_EVENT => {
                self.handle_tx_event().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!(
                        "Error processing TX queue (TAP event): {e:?}"
                    ))
                })?;
            }
            RX_TAP_EVENT => {
                self.handle_rx_tap_event().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!("Error processing tap queue: {e:?}"))
                })?;
            }
            RX_RATE_LIMITER_EVENT => {
                if let Some(rate_limiter) = &mut self.net.rx_rate_limiter {
                    // Upon rate limiter event, call the rate limiter handler and register the
                    // TAP fd for further processing if some RX buffers are available
                    rate_limiter.event_handler().map_err(|e| {
                        EpollHelperError::HandleEvent(anyhow!(
                            "Error from 'rate_limiter.event_handler()': {e:?}"
                        ))
                    })?;

                    if !self.net.rx_tap_listening && self.net.rx_desc_avail {
                        net_util::register_listener(
                            self.net.epoll_fd.unwrap(),
                            self.net.tap.as_raw_fd(),
                            epoll::Events::EPOLLIN,
                            u64::from(self.net.tap_rx_event_id),
                        )
                        .map_err(|e| {
                            EpollHelperError::HandleEvent(anyhow!(
                                "Error register_listener with `RX_RATE_LIMITER_EVENT`: {e:?}"
                            ))
                        })?;

                        self.net.rx_tap_listening = true;
                    }
                } else {
                    return Err(EpollHelperError::HandleEvent(anyhow!(
                        "Unexpected RX_RATE_LIMITER_EVENT"
                    )));
                }
            }
            TX_RATE_LIMITER_EVENT => {
                if let Some(rate_limiter) = &mut self.net.tx_rate_limiter {
                    // Upon rate limiter event, call the rate limiter handler
                    // and restart processing the queue.
                    rate_limiter.event_handler().map_err(|e| {
                        EpollHelperError::HandleEvent(anyhow!(
                            "Error from 'rate_limiter.event_handler()': {e:?}"
                        ))
                    })?;

                    self.driver_awake = true;
                    self.process_tx().map_err(|e| {
                        EpollHelperError::HandleEvent(anyhow!("Error processing TX queue: {e:?}"))
                    })?;
                } else {
                    return Err(EpollHelperError::HandleEvent(anyhow!(
                        "Unexpected TX_RATE_LIMITER_EVENT"
                    )));
                }
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

pub struct Net {
    common: VirtioCommon,
    id: String,
    taps: Vec<Tap>,
    config: VirtioNetConfig,
    /// Tracks whether the guest still needs to acknowledge a post-migration
    /// announce request through the control queue.
    announce_pending: Arc<AtomicBool>,
    /// Generation counter used to invalidate active announcers created before a
    /// reset or device teardown, so they stop sending notifications.
    announce_generation: Arc<AtomicU64>,
    ctrl_queue_epoll_thread: Option<thread::JoinHandle<()>>,
    counters: NetCounters,
    seccomp_action: SeccompAction,
    rate_limiter_config: Option<RateLimiterConfig>,
    exit_evt: EventFd,
}

#[derive(Serialize, Deserialize)]
/// Serialized snapshot of the device state. The fields are copied from the
/// live device when snapshotting and restored back into a new device instance.
///
/// Fields not present in previous versions are tagged with `#[serde(default)]`
/// to allow deserialization if the field is not present.
pub struct NetState {
    pub avail_features: u64,
    pub acked_features: u64,
    pub config: VirtioNetConfig,
    #[serde(default)]
    pub announce_pending: bool,
    pub queue_size: Vec<u16>,
}

// Minimum length of an ethernet frame. This size omits the FCS/CRC (frame check
// sequence), which will be added by the hardware. This size can also be found
// in the Linux kernel's UAPI headers.
const ETH_FRAME_LEN: usize = 60;

/// Constructor-time copy of the fields needed to initialize the live device
/// state, derived either from a restored NetState or from fresh defaults.
struct NetConstructorState {
    avail_features: u64,
    acked_features: u64,
    config: VirtioNetConfig,
    announce_pending: bool,
    queue_sizes: Vec<u16>,
    paused: bool,
}

impl Net {
    /// Restores a [`NetConstructorState`] from the provided [`NetState`].
    fn restored_constructor_state(id: &str, state: NetState) -> NetConstructorState {
        info!("Restoring virtio-net {id}");

        NetConstructorState {
            avail_features: state.avail_features,
            acked_features: state.acked_features,
            config: state.config,
            announce_pending: state.announce_pending,
            queue_sizes: state.queue_size,
            paused: true,
        }
    }

    #[allow(clippy::too_many_arguments)]
    /// Creates a new [`NetConstructorState`].
    fn fresh_constructor_state(
        guest_mac: Option<MacAddr>,
        iommu: bool,
        mtu: u16,
        num_queues: usize,
        queue_size: u16,
        offload_tso: bool,
        offload_ufo: bool,
        offload_csum: bool,
    ) -> NetConstructorState {
        let mut avail_features =
            (1 << VIRTIO_NET_F_MTU) | (1 << VIRTIO_RING_F_EVENT_IDX) | (1 << VIRTIO_F_VERSION_1);

        if iommu {
            avail_features |= 1u64 << VIRTIO_F_IOMMU_PLATFORM;
        }

        // Configure TSO/UFO features when hardware checksum offload is enabled.
        if offload_csum {
            avail_features |= (1 << VIRTIO_NET_F_CSUM)
                | (1 << VIRTIO_NET_F_GUEST_CSUM)
                | (1 << VIRTIO_NET_F_CTRL_GUEST_OFFLOADS);

            if offload_tso {
                avail_features |= (1 << VIRTIO_NET_F_HOST_ECN)
                    | (1 << VIRTIO_NET_F_HOST_TSO4)
                    | (1 << VIRTIO_NET_F_HOST_TSO6)
                    | (1 << VIRTIO_NET_F_GUEST_ECN)
                    | (1 << VIRTIO_NET_F_GUEST_TSO4)
                    | (1 << VIRTIO_NET_F_GUEST_TSO6);
            }

            if offload_ufo {
                avail_features |= (1 << VIRTIO_NET_F_HOST_UFO) | (1 << VIRTIO_NET_F_GUEST_UFO);
            }
        }

        avail_features |= 1 << VIRTIO_NET_F_CTRL_VQ;
        avail_features |= 1 << VIRTIO_NET_F_STATUS;
        avail_features |= 1 << VIRTIO_NET_F_GUEST_ANNOUNCE;
        let queue_num = num_queues + 1;

        let mut config = VirtioNetConfig::default();
        if let Some(mac) = guest_mac {
            build_net_config_space(&mut config, mac, num_queues, Some(mtu), &mut avail_features);
        } else {
            build_net_config_space_with_mq(&mut config, num_queues, Some(mtu), &mut avail_features);
        }

        NetConstructorState {
            avail_features,
            acked_features: 0,
            config,
            announce_pending: false,
            queue_sizes: vec![queue_size; queue_num],
            paused: false,
        }
    }

    /// Create a new virtio network device with the given TAP interface.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_tap(
        id: String,
        taps: Vec<Tap>,
        guest_mac: Option<MacAddr>,
        iommu: bool,
        num_queues: usize,
        queue_size: u16,
        seccomp_action: SeccompAction,
        rate_limiter_config: Option<RateLimiterConfig>,
        exit_evt: EventFd,
        state: Option<NetState>,
        offload_tso: bool,
        offload_ufo: bool,
        offload_csum: bool,
    ) -> Result<Self> {
        assert!(!taps.is_empty());

        let mtu = taps[0].mtu().map_err(Error::TapError)? as u16;

        let constructor_state = if let Some(state) = state {
            Self::restored_constructor_state(&id, state)
        } else {
            Self::fresh_constructor_state(
                guest_mac,
                iommu,
                mtu,
                num_queues,
                queue_size,
                offload_tso,
                offload_ufo,
                offload_csum,
            )
        };

        Ok(Net {
            common: VirtioCommon {
                device_type: VirtioDeviceType::Net as u32,
                avail_features: constructor_state.avail_features,
                acked_features: constructor_state.acked_features,
                queue_sizes: constructor_state.queue_sizes,
                paused_sync: Some(Arc::new(Barrier::new((num_queues / 2) + 1))),
                min_queues: 2,
                paused: Arc::new(AtomicBool::new(constructor_state.paused)),
                ..Default::default()
            },
            id,
            taps,
            config: constructor_state.config,
            announce_pending: Arc::new(AtomicBool::new(constructor_state.announce_pending)),
            announce_generation: Arc::new(AtomicU64::new(0)),
            ctrl_queue_epoll_thread: None,
            counters: NetCounters::default(),
            seccomp_action,
            rate_limiter_config,
            exit_evt,
        })
    }

    /// Create a new virtio network device with the given IP address and
    /// netmask.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        if_name: Option<&str>,
        ip_addr: Option<IpAddr>,
        netmask: Option<IpAddr>,
        guest_mac: Option<MacAddr>,
        host_mac: &mut Option<MacAddr>,
        mtu: Option<u16>,
        iommu: bool,
        num_queues: usize,
        queue_size: u16,
        seccomp_action: SeccompAction,
        rate_limiter_config: Option<RateLimiterConfig>,
        exit_evt: EventFd,
        state: Option<NetState>,
        offload_tso: bool,
        offload_ufo: bool,
        offload_csum: bool,
    ) -> Result<Self> {
        let taps = open_tap(
            if_name,
            ip_addr,
            netmask,
            host_mac,
            mtu,
            num_queues / 2,
            None,
        )
        .map_err(Error::OpenTap)?;

        Self::new_with_tap(
            id,
            taps,
            guest_mac,
            iommu,
            num_queues,
            queue_size,
            seccomp_action,
            rate_limiter_config,
            exit_evt,
            state,
            offload_tso,
            offload_ufo,
            offload_csum,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_tap_fds(
        id: String,
        fds: &[RawFd],
        guest_mac: Option<MacAddr>,
        mtu: Option<u16>,
        iommu: bool,
        queue_size: u16,
        seccomp_action: SeccompAction,
        rate_limiter_config: Option<RateLimiterConfig>,
        exit_evt: EventFd,
        state: Option<NetState>,
        offload_tso: bool,
        offload_ufo: bool,
        offload_csum: bool,
    ) -> Result<Self> {
        let mut taps: Vec<Tap> = Vec::new();
        let num_queue_pairs = fds.len();

        for fd in fds.iter() {
            // Duplicate so that it can survive reboots
            // SAFETY: FFI call to dup. Trivially safe.
            let fd_duped = unsafe { libc::dup(*fd) };
            if fd_duped < 0 {
                return Err(Error::DuplicateTapFd(std::io::Error::last_os_error()));
            }
            debug!("dup'ed fd {fd} => {fd_duped} for virtio-net device {id}");
            let tap = Tap::from_tap_fd(fd_duped, num_queue_pairs).map_err(Error::TapError)?;
            taps.push(tap);
        }

        assert!(!taps.is_empty());

        if let Some(mtu) = mtu {
            taps[0].set_mtu(mtu as i32).map_err(Error::TapError)?;
        }

        Self::new_with_tap(
            id,
            taps,
            guest_mac,
            iommu,
            num_queue_pairs * 2,
            queue_size,
            seccomp_action,
            rate_limiter_config,
            exit_evt,
            state,
            offload_tso,
            offload_ufo,
            offload_csum,
        )
    }

    fn state(&self) -> NetState {
        NetState {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
            config: self.config,
            announce_pending: self.announce_pending.load(Ordering::Acquire),
            queue_size: self.common.queue_sizes.clone(),
        }
    }

    /// Return the guest-visible virtio-net config, recomputing `status` from the
    /// current state of the device.
    fn config_with_status(&self) -> VirtioNetConfig {
        let mut config = self.config;

        // We want to recompute the guest-visible status field from the current state of
        // the device. We clear this field first to avoid showing stale data.
        config.status = 0;

        if self.common.feature_acked(VIRTIO_NET_F_STATUS.into()) {
            config.status |= VIRTIO_NET_S_LINK_UP as u16;

            if self.announce_pending.load(Ordering::Acquire) {
                config.status |= VIRTIO_NET_S_ANNOUNCE as u16;
            }
        }

        config
    }

    #[cfg(fuzzing)]
    pub fn wait_for_epoll_threads(&mut self) {
        self.common.wait_for_epoll_threads();
    }

    // Builds a reverse ARP packet with this device's MAC address.
    fn build_rarp_announce(&self) -> [u8; ETH_FRAME_LEN] {
        const ETH_P_RARP: u16 = 0x8035; // Ethertype RARP
        const ARP_HTYPE_ETH: u16 = 0x1; // Hardware type Ethernet
        const ARP_PTYPE_IP: u16 = 0x0800; // Protocol type IPv4
        const ARP_OP_REQUEST_REV: u16 = 0x0003; // RARP Request opcode

        const IPV4_ADDR_LENGTH: usize = 4; // Size of an IPv4 address

        let mut buf = [0u8; ETH_FRAME_LEN];

        // Ethernet header
        buf[0..6].copy_from_slice(&[0xff; MAC_ADDR_LEN]); // This is a broadcast
        buf[6..12].copy_from_slice(&self.config.mac); // Src is this NIC
        buf[12..14].copy_from_slice(&ETH_P_RARP.to_be_bytes()); // This is a RARP packet

        // ARP Header
        buf[14..16].copy_from_slice(&ARP_HTYPE_ETH.to_be_bytes());
        buf[16..18].copy_from_slice(&ARP_PTYPE_IP.to_be_bytes());
        buf[18] = MAC_ADDR_LEN as u8; // Hardware address length (ethernet)
        buf[19] = IPV4_ADDR_LENGTH as u8; // Protocol address length (IPv4)
        // This is a "fake RARP" packet, we don't want to perform a real RARP lookup.
        // Thus the content of the next fields is largely irrelevant. Setting source
        // hardware address = target hardware address is fine according to RFC 903.
        buf[20..22].copy_from_slice(&ARP_OP_REQUEST_REV.to_be_bytes());
        buf[22..28].copy_from_slice(&self.config.mac); // Source hardware address
        buf[28..32].copy_from_slice(&[0x00; IPV4_ADDR_LENGTH]); // Source protocol address
        buf[32..38].copy_from_slice(&self.config.mac); // Target hardware address
        buf[38..42].copy_from_slice(&[0x00; IPV4_ADDR_LENGTH]); // Target protocol address

        buf
    }

    /// Re-notify the guest about a restored pending ANNOUNCE request once the
    /// transport has installed an interrupt callback during activation.
    fn notify_pending_guest_announce(&self) {
        if self.announce_pending.load(Ordering::Acquire)
            && self
                .common
                .feature_acked(VIRTIO_NET_F_GUEST_ANNOUNCE.into())
            && let Some(interrupt_cb) = &self.common.interrupt_cb
        {
            interrupt_cb
                .trigger(VirtioInterruptType::Config)
                .inspect_err(|e| {
                    warn!(
                        "Unable to resend pending announce interrupt for virtio-net device {}: {e}",
                        self.id
                    );
                })
                .ok();
        }
    }
}

impl Drop for Net {
    fn drop(&mut self) {
        self.announce_generation.fetch_add(1, Ordering::AcqRel);

        // Get a comma-separated list of the interface names of the tap devices
        // associated with this network device.
        let ifnames_str = self
            .taps
            .iter()
            .map(|tap| tap.if_name_as_str())
            .collect::<Vec<_>>();
        let ifnames_str = ifnames_str.join(",");
        debug!(
            "virtio-net device closed: id={}, ifnames=[{ifnames_str}]",
            self.id
        );

        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
        // Needed to ensure all references to tap FDs are dropped (#4868)
        self.common.wait_for_epoll_threads();
        if let Some(thread) = self.ctrl_queue_epoll_thread.take()
            && let Err(e) = thread.join()
        {
            error!("Error joining thread: {e:?}");
        }
    }
}

impl VirtioDevice for Net {
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
        let config = self.config_with_status();
        self.read_config_from_slice(config.as_slice(), offset, data);
    }

    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        mut queues: Vec<(usize, Queue, EventFd)>,
    ) -> ActivateResult {
        self.common.activate(&queues, interrupt_cb.clone())?;

        let num_queues = queues.len();
        let event_idx = self.common.feature_acked(VIRTIO_RING_F_EVENT_IDX.into());

        // The constructor initializes `paused_sync` using the configured queue count
        // (plus one for the main thread). This can be wrong if the guest enables a
        // different number of queues at activation time, which can make pause hang.
        // Recompute the barrier size from the queues that are actually activated.
        let has_ctrl_queue =
            self.common.feature_acked(VIRTIO_NET_F_CTRL_VQ.into()) && !num_queues.is_multiple_of(2);
        let ctrl_threads = if has_ctrl_queue { 1 } else { 0 };
        let qp_threads = (num_queues - ctrl_threads) / 2;

        // Size the pause barrier from the epoll threads we are about to spawn,
        // plus the main VMM thread initiating the pause.
        self.common.paused_sync = Some(Arc::new(Barrier::new(1 + qp_threads + ctrl_threads)));

        if has_ctrl_queue {
            let ctrl_queue_index = num_queues - 1;
            let (_, mut ctrl_queue, ctrl_queue_evt) = queues.remove(ctrl_queue_index);

            ctrl_queue.set_event_idx(event_idx);

            let (kill_evt, pause_evt) = self.common.dup_eventfds();
            let mut ctrl_handler = NetCtrlEpollHandler {
                mem: mem.clone(),
                kill_evt,
                pause_evt,
                ctrl_q: CtrlQueue::new(self.taps.clone(), Arc::clone(&self.announce_pending)),
                queue: ctrl_queue,
                queue_evt: ctrl_queue_evt,
                access_platform: self.common.access_platform.clone(),
                queue_index: ctrl_queue_index as u16,
                interrupt_cb: interrupt_cb.clone(),
            };

            let paused = self.common.paused.clone();
            let paused_sync = self.common.paused_sync.clone();

            let mut epoll_threads = Vec::new();
            spawn_virtio_thread(
                &format!("{}_ctrl", &self.id),
                &self.seccomp_action,
                Thread::VirtioNetCtl,
                &mut epoll_threads,
                &self.exit_evt,
                move || ctrl_handler.run_ctrl(&paused, paused_sync.as_ref().unwrap()),
            )?;
            self.ctrl_queue_epoll_thread = Some(epoll_threads.remove(0));
        }

        let mut epoll_threads = Vec::new();
        let mut taps = self.taps.clone();
        for i in 0..queues.len() / 2 {
            let rx = RxVirtio::new();
            let tx = TxVirtio::new();
            let rx_tap_listening = false;

            let (_, queue_0, queue_evt_0) = queues.remove(0);
            let (_, queue_1, queue_evt_1) = queues.remove(0);
            let mut queue_pair = (queue_0, queue_1);
            queue_pair.0.set_event_idx(event_idx);
            queue_pair.1.set_event_idx(event_idx);

            let queue_evt_pair = (queue_evt_0, queue_evt_1);

            let (kill_evt, pause_evt) = self.common.dup_eventfds();

            let rx_rate_limiter: Option<rate_limiter::RateLimiter> = self
                .rate_limiter_config
                .map(RateLimiterConfig::try_into)
                .transpose()
                .map_err(ActivateError::CreateRateLimiter)?;

            let tx_rate_limiter: Option<rate_limiter::RateLimiter> = self
                .rate_limiter_config
                .map(RateLimiterConfig::try_into)
                .transpose()
                .map_err(ActivateError::CreateRateLimiter)?;

            let tap = taps.remove(0);
            #[cfg(not(fuzzing))]
            tap.set_offload(virtio_features_to_tap_offload(self.common.acked_features))
                .map_err(|e| {
                    error!("Error programming tap offload: {e:?}");
                    ActivateError::BadActivate
                })?;

            let mut handler = NetEpollHandler {
                net: NetQueuePair {
                    tap_for_write_epoll: tap.clone(),
                    tap,
                    rx,
                    tx,
                    epoll_fd: None,
                    rx_tap_listening,
                    tx_tap_listening: false,
                    counters: self.counters.clone(),
                    tap_rx_event_id: RX_TAP_EVENT,
                    tap_tx_event_id: TX_TAP_EVENT,
                    rx_desc_avail: false,
                    rx_rate_limiter,
                    tx_rate_limiter,
                    access_platform: self.common.access_platform.clone(),
                },
                mem: mem.clone(),
                queue_index_base: (i * 2) as u16,
                queue_pair,
                queue_evt_pair,
                interrupt_cb: interrupt_cb.clone(),
                kill_evt,
                pause_evt,
                driver_awake: false,
            };

            let paused = self.common.paused.clone();
            let paused_sync = self.common.paused_sync.clone();

            spawn_virtio_thread(
                &format!("{}_qp{}", self.id.clone(), i),
                &self.seccomp_action,
                Thread::VirtioNet,
                &mut epoll_threads,
                &self.exit_evt,
                move || handler.run(&paused, paused_sync.as_ref().unwrap()),
            )?;
        }

        self.common.epoll_threads = Some(epoll_threads);
        self.notify_pending_guest_announce();

        event!("virtio-device", "activated", "id", &self.id);
        Ok(())
    }

    fn reset(&mut self) -> Option<Arc<dyn VirtioInterrupt>> {
        self.announce_pending.store(false, Ordering::Release);
        self.announce_generation.fetch_add(1, Ordering::AcqRel);
        let result = self.common.reset();
        event!("virtio-device", "reset", "id", &self.id);
        result
    }

    fn counters(&self) -> Option<HashMap<&'static str, Wrapping<u64>>> {
        let mut counters = HashMap::new();

        counters.insert(
            "rx_bytes",
            Wrapping(self.counters.rx_bytes.load(Ordering::Acquire)),
        );
        counters.insert(
            "rx_frames",
            Wrapping(self.counters.rx_frames.load(Ordering::Acquire)),
        );
        counters.insert(
            "tx_bytes",
            Wrapping(self.counters.tx_bytes.load(Ordering::Acquire)),
        );
        counters.insert(
            "tx_frames",
            Wrapping(self.counters.tx_frames.load(Ordering::Acquire)),
        );

        Some(counters)
    }

    fn set_access_platform(&mut self, access_platform: Arc<dyn AccessPlatform>) {
        self.common.set_access_platform(access_platform);
    }

    fn post_migration_announcer(&self) -> Option<Box<dyn PostMigrationAnnouncer>> {
        Some(Box::new(VirtioNetPostMigrationAnnouncer::new(self)))
    }
}

impl Pausable for Net {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()?;

        if let Some(ctrl_queue_epoll_thread) = &self.ctrl_queue_epoll_thread {
            ctrl_queue_epoll_thread.thread().unpark();
        }
        Ok(())
    }
}

impl Snapshottable for Net {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        Snapshot::new_from_state(&self.state())
    }
}
impl Transportable for Net {}
impl Migratable for Net {}

/// Announces this virtio-net device on the network.
/// Most fields are cloned references to device state so retry rounds can run
/// without borrowing the device itself.
pub struct VirtioNetPostMigrationAnnouncer {
    id: String,
    /// Remembers whether this device negotiated the guest-visible announce path.
    guest_announce_negotiated: bool,
    announce_pending: Arc<AtomicBool>,
    announce_generation: Arc<AtomicU64>,
    /// Captures the announce generation at creation time to invalidate stale
    /// retry sessions after reset or teardown.
    generation: u64,
    interrupt_cb: Option<Arc<dyn VirtioInterrupt>>,
    /// Prebuilt host-side RARP payload used for immediate post-migration
    /// announcement retries.
    rarp_announce: [u8; ETH_FRAME_LEN],
    taps: Vec<Tap>,
}

impl VirtioNetPostMigrationAnnouncer {
    pub fn new(dev: &Net) -> Self {
        Self {
            id: dev.id.clone(),
            guest_announce_negotiated: dev.common.feature_acked(VIRTIO_NET_F_GUEST_ANNOUNCE.into()),
            announce_pending: Arc::clone(&dev.announce_pending),
            announce_generation: Arc::clone(&dev.announce_generation),
            generation: dev.announce_generation.load(Ordering::Acquire),
            interrupt_cb: dev.common.interrupt_cb.clone(),
            rarp_announce: dev.build_rarp_announce(),
            taps: dev.taps.clone(),
        }
    }
}

impl PostMigrationAnnouncer for VirtioNetPostMigrationAnnouncer {
    // Send a host-side RARP immediately so the network can converge before the
    // guest runs again, and then also ask the guest to re-announce itself when
    // GUEST_ANNOUNCE was negotiated.
    fn announce(&mut self) {
        // If the announce generations don't match, we don't send any announcements.
        if self.announce_generation.load(Ordering::Acquire) != self.generation {
            return;
        }

        // We have to add a virtio-net header to the announce.
        let mut buf = vec![0u8; vnet_hdr_len() + self.rarp_announce.len()];
        buf[vnet_hdr_len()..].copy_from_slice(&self.rarp_announce);

        for tap in &self.taps {
            // SAFETY: `buf.as_ptr()` is valid for `buf.len()` bytes and remains
            // valid until the syscall returns. `tap.as_raw_fd()` is a valid TAP fd.
            let _ = unsafe {
                libc::write(
                    tap.as_raw_fd(),
                    buf.as_ptr() as *const libc::c_void,
                    buf.len(),
                )
            };
        }

        if self.guest_announce_negotiated
            && let Some(interrupt_cb) = &self.interrupt_cb
        {
            self.announce_pending.store(true, Ordering::Release);

            interrupt_cb
                .trigger(VirtioInterruptType::Config)
                .inspect_err(|e| {
                    warn!(
                        "Unable to send interrupt for virtio-net device {}: {e}",
                        self.id
                    );
                })
                .ok();
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use std::mem::size_of;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use seccompiler::SeccompAction;
    use virtio_bindings::virtio_net::{
        VIRTIO_NET_F_GUEST_ANNOUNCE, VIRTIO_NET_F_STATUS, VIRTIO_NET_S_ANNOUNCE,
        VIRTIO_NET_S_LINK_UP,
    };
    use vmm_sys_util::eventfd::EventFd;

    use super::*;
    use crate::device::{VirtioInterrupt, VirtioInterruptType};

    struct TestInterrupt {
        config_count: AtomicUsize,
    }

    impl TestInterrupt {
        fn new() -> Self {
            Self {
                config_count: AtomicUsize::new(0),
            }
        }
    }

    impl VirtioInterrupt for TestInterrupt {
        fn trigger(
            &self,
            int_type: VirtioInterruptType,
        ) -> std::result::Result<(), std::io::Error> {
            if matches!(int_type, VirtioInterruptType::Config) {
                self.config_count.fetch_add(1, Ordering::AcqRel);
            }
            Ok(())
        }
    }

    fn test_net(acked_features: u64, interrupt_cb: Option<Arc<dyn VirtioInterrupt>>) -> Net {
        Net {
            common: VirtioCommon {
                acked_features,
                interrupt_cb,
                ..Default::default()
            },
            id: "test-net".to_string(),
            taps: Vec::new(),
            config: VirtioNetConfig::default(),
            announce_pending: Arc::new(AtomicBool::new(false)),
            announce_generation: Arc::new(AtomicU64::new(0)),
            ctrl_queue_epoll_thread: None,
            counters: NetCounters::default(),
            seccomp_action: SeccompAction::Allow,
            rate_limiter_config: None,
            exit_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
        }
    }

    const STATUS_OFFSET: usize = std::mem::offset_of!(VirtioNetConfig, status);
    fn read_status(device: &Net) -> u16 {
        let mut data = vec![0; size_of::<VirtioNetConfig>()];
        device.read_config(0, &mut data);

        u16::from_le_bytes(
            data[STATUS_OFFSET..STATUS_OFFSET + size_of::<u16>()]
                .try_into()
                .unwrap(),
        )
    }

    #[test]
    fn test_fresh_constructor_state_exposes_status() {
        let state = Net::fresh_constructor_state(None, false, MIN_MTU, 2, 256, false, false, false);

        assert_ne!(state.avail_features & (1 << VIRTIO_NET_F_STATUS), 0);
    }

    #[test]
    fn test_status_feature_reports_link_up() {
        let net = test_net(1 << VIRTIO_NET_F_STATUS, None);

        assert_eq!(read_status(&net), VIRTIO_NET_S_LINK_UP as u16);
    }

    #[test]
    fn test_post_migration_sets_announce_and_triggers_config() {
        let interrupt = Arc::new(TestInterrupt::new());
        let net = test_net(
            (1 << VIRTIO_NET_F_GUEST_ANNOUNCE) | (1 << VIRTIO_NET_F_STATUS),
            Some(interrupt.clone() as Arc<dyn VirtioInterrupt>),
        );

        net.post_migration_announcer().unwrap().announce();

        assert!(net.announce_pending.load(Ordering::Acquire));
        assert_ne!(read_status(&net) & VIRTIO_NET_S_ANNOUNCE as u16, 0);
        assert_eq!(interrupt.config_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn test_post_migration_without_feature_is_noop() {
        let interrupt = Arc::new(TestInterrupt::new());
        let net = test_net(0, Some(interrupt.clone() as Arc<dyn VirtioInterrupt>));

        net.post_migration_announcer().unwrap().announce();

        assert!(!net.announce_pending.load(Ordering::Acquire));
        assert_eq!(read_status(&net) & VIRTIO_NET_S_ANNOUNCE as u16, 0);
        assert_eq!(interrupt.config_count.load(Ordering::Acquire), 0);
    }

    #[test]
    fn test_restored_pending_announce_retriggers_config_interrupt() {
        let interrupt = Arc::new(TestInterrupt::new());
        let net = test_net(
            (1 << VIRTIO_NET_F_GUEST_ANNOUNCE) | (1 << VIRTIO_NET_F_STATUS),
            Some(interrupt.clone() as Arc<dyn VirtioInterrupt>),
        );
        net.announce_pending.store(true, Ordering::Release);

        net.notify_pending_guest_announce();

        assert!(net.announce_pending.load(Ordering::Acquire));
        assert_ne!(read_status(&net) & VIRTIO_NET_S_ANNOUNCE as u16, 0);
        assert_eq!(interrupt.config_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn test_post_migration_retries_retrigger_config_interrupt() {
        let interrupt = Arc::new(TestInterrupt::new());
        let net = test_net(
            (1 << VIRTIO_NET_F_GUEST_ANNOUNCE) | (1 << VIRTIO_NET_F_STATUS),
            Some(interrupt.clone() as Arc<dyn VirtioInterrupt>),
        );
        let mut announcer = net.post_migration_announcer().unwrap();

        announcer.announce();
        announcer.announce();

        assert!(net.announce_pending.load(Ordering::Acquire));
        assert_ne!(read_status(&net) & VIRTIO_NET_S_ANNOUNCE as u16, 0);
        assert_eq!(interrupt.config_count.load(Ordering::Acquire), 2);
    }

    #[test]
    fn test_reset_clears_pending_announce() {
        let interrupt = Arc::new(TestInterrupt::new());
        let mut net = test_net(
            (1 << VIRTIO_NET_F_GUEST_ANNOUNCE) | (1 << VIRTIO_NET_F_STATUS),
            Some(interrupt.clone() as Arc<dyn VirtioInterrupt>),
        );

        net.post_migration_announcer().unwrap().announce();
        assert!(net.announce_pending.load(Ordering::Acquire));

        let _ = net.reset();

        assert!(!net.announce_pending.load(Ordering::Acquire));
        assert_eq!(read_status(&net) & VIRTIO_NET_S_ANNOUNCE as u16, 0);
    }

    #[test]
    fn test_reset_invalidates_old_announcer() {
        let interrupt = Arc::new(TestInterrupt::new());
        let mut net = test_net(
            1 << VIRTIO_NET_F_GUEST_ANNOUNCE,
            Some(interrupt.clone() as Arc<dyn VirtioInterrupt>),
        );
        let mut announcer = net.post_migration_announcer().unwrap();

        announcer.announce();
        assert_eq!(interrupt.config_count.load(Ordering::Acquire), 1);

        let _ = net.reset();
        announcer.announce();

        assert!(!net.announce_pending.load(Ordering::Acquire));
        assert_eq!(read_status(&net) & VIRTIO_NET_S_ANNOUNCE as u16, 0);
        assert_eq!(interrupt.config_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn test_drop_invalidates_old_announcer() {
        let interrupt = Arc::new(TestInterrupt::new());
        let mut announcer = {
            let net = test_net(
                1 << VIRTIO_NET_F_GUEST_ANNOUNCE,
                Some(interrupt.clone() as Arc<dyn VirtioInterrupt>),
            );
            let mut announcer = net.post_migration_announcer().unwrap();

            announcer.announce();
            assert_eq!(interrupt.config_count.load(Ordering::Acquire), 1);

            announcer
        };

        announcer.announce();

        assert_eq!(interrupt.config_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn test_net_state_deserialize_without_announce_pending_defaults_to_false() {
        // Older snapshots do not contain announce_pending. Restoring them on a
        // newer binary must treat the missing field as "no announce pending".
        let state = NetState {
            avail_features: 1,
            acked_features: 2,
            config: VirtioNetConfig::default(),
            announce_pending: true,
            queue_size: vec![256, 256],
        };
        let mut value = serde_json::to_value(state).unwrap();

        value.as_object_mut().unwrap().remove("announce_pending");

        let restored: NetState = serde_json::from_value(value).unwrap();

        assert!(!restored.announce_pending);
    }
}
