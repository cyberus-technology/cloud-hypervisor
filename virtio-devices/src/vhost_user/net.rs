// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::{result, thread};

use event_monitor::event;
use log::{error, info, warn};
use net_util::{CtrlQueue, MacAddr, VirtioNetConfig, build_net_config_space};
use seccompiler::SeccompAction;
use serde::{Deserialize, Serialize};
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost::vhost_user::{FrontendReqHandler, VhostUserFrontend, VhostUserFrontendReqHandler};
use virtio_bindings::virtio_net::{
    VIRTIO_NET_F_CSUM, VIRTIO_NET_F_CTRL_VQ, VIRTIO_NET_F_GUEST_ANNOUNCE, VIRTIO_NET_F_GUEST_CSUM,
    VIRTIO_NET_F_GUEST_ECN, VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_TSO6,
    VIRTIO_NET_F_GUEST_UFO, VIRTIO_NET_F_HOST_ECN, VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_TSO6,
    VIRTIO_NET_F_HOST_UFO, VIRTIO_NET_F_MAC, VIRTIO_NET_F_MRG_RXBUF, VIRTIO_NET_F_MTU,
    VIRTIO_NET_F_STATUS, VIRTIO_NET_S_ANNOUNCE, VIRTIO_NET_S_LINK_UP,
};
use virtio_bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use virtio_queue::{Queue, QueueT};
use vm_memory::{ByteValued, GuestMemoryAtomic};
use vm_migration::protocol::MemoryRangeTable;
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vmm_sys_util::eventfd::EventFd;

use crate::seccomp_filters::Thread;
use crate::thread_helper::spawn_virtio_thread;
use crate::vhost_user::vu_common_ctrl::{VhostUserConfig, VhostUserHandle};
use crate::vhost_user::{DEFAULT_VIRTIO_FEATURES, Error, Result, VhostUserCommon};
use crate::{
    ActivateResult, GuestMemoryMmap, GuestRegionMmap, NetCtrlEpollHandler, PostMigrationAnnouncer,
    VIRTIO_F_IOMMU_PLATFORM, VirtioCommon, VirtioDevice, VirtioDeviceType, VirtioInterrupt,
};

const DEFAULT_QUEUE_NUMBER: usize = 2;

#[derive(Serialize, Deserialize)]
/// Serialized snapshot of the device state. The fields are copied from the
/// live device when snapshotting and restored back into a new device instance.
///
/// Fields not present in previous versions are tagged with `#[serde(default)]`
/// to allow deserialization if the field is not present.
pub struct State {
    pub avail_features: u64,
    pub acked_features: u64,
    pub config: VirtioNetConfig,
    #[serde(default)]
    pub announce_pending: bool,
    pub acked_protocol_features: u64,
    pub vu_num_queues: usize,
}

struct BackendReqHandler {}
impl VhostUserFrontendReqHandler for BackendReqHandler {}

pub struct Net {
    common: VirtioCommon,
    vu_common: VhostUserCommon,
    id: String,
    config: VirtioNetConfig,
    /// Tracks whether the guest still needs to acknowledge a post-migration
    /// announce request through the control queue.
    announce_pending: Arc<AtomicBool>,
    guest_memory: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    ctrl_queue_epoll_thread: Option<thread::JoinHandle<()>>,
    epoll_thread: Option<thread::JoinHandle<()>>,
    seccomp_action: SeccompAction,
    exit_evt: EventFd,
    iommu: bool,
}

impl Net {
    /// Derive the guest-visible feature set from the backend-negotiated
    /// features plus frontend-only bits that Cloud Hypervisor implements
    /// locally, such as `VIRTIO_NET_F_MAC`, `VIRTIO_NET_F_STATUS`, and
    /// `VIRTIO_NET_F_GUEST_ANNOUNCE`.
    fn frontend_avail_features(backend_acked_features: u64) -> u64 {
        let mut guest_avail_features = backend_acked_features | (1 << VIRTIO_NET_F_MAC);

        // Guest announce is implemented by the frontend through config
        // changes and the locally handled control queue.
        if guest_avail_features & (1 << VIRTIO_NET_F_CTRL_VQ) != 0 {
            guest_avail_features |= 1 << VIRTIO_NET_F_STATUS;
            guest_avail_features |= 1 << VIRTIO_NET_F_GUEST_ANNOUNCE;
        }

        guest_avail_features
    }

    /// Create a new vhost-user-net device
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        mac_addr: MacAddr,
        mtu: Option<u16>,
        vu_cfg: VhostUserConfig,
        server: bool,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
        iommu: bool,
        state: Option<State>,
        offload_tso: bool,
        offload_ufo: bool,
        offload_csum: bool,
    ) -> Result<Net> {
        let mut num_queues = vu_cfg.num_queues;

        let mut vu =
            VhostUserHandle::connect_vhost_user(server, &vu_cfg.socket, num_queues as u64, false)?;

        let (
            avail_features,
            acked_features,
            acked_protocol_features,
            vu_num_queues,
            config,
            announce_pending,
            paused,
        ) = if let Some(state) = state {
            info!("Restoring vhost-user-net {id}");

            // The backend acknowledged features must not contain frontend-only
            // bits since we don't expect the backend to handle them.
            let backend_acked_features = state.acked_features
                & !((1 << VIRTIO_NET_F_MAC)
                    | (1 << VIRTIO_NET_F_STATUS)
                    | (1 << VIRTIO_NET_F_GUEST_ANNOUNCE));

            vu.set_protocol_features_vhost_user(
                backend_acked_features,
                state.acked_protocol_features,
            )?;

            // If the control queue feature has been negotiated, let's
            // increase the number of queues.
            if state.acked_features & (1 << VIRTIO_NET_F_CTRL_VQ) != 0 {
                num_queues += 1;
            }

            (
                state.avail_features,
                state.acked_features,
                state.acked_protocol_features,
                state.vu_num_queues,
                state.config,
                state.announce_pending,
                true,
            )
        } else {
            // Filling device and vring features VMM supports.
            let mut avail_features = (1 << VIRTIO_NET_F_MRG_RXBUF)
                | (1 << VIRTIO_NET_F_CTRL_VQ)
                | (1 << VIRTIO_NET_F_GUEST_ANNOUNCE)
                | DEFAULT_VIRTIO_FEATURES;

            if mtu.is_some() {
                avail_features |= 1u64 << VIRTIO_NET_F_MTU;
            }

            // Configure TSO/UFO features when hardware checksum offload is enabled.
            if offload_csum {
                avail_features |= (1 << VIRTIO_NET_F_CSUM) | (1 << VIRTIO_NET_F_GUEST_CSUM);

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

            let mut config = VirtioNetConfig::default();
            build_net_config_space(&mut config, mac_addr, num_queues, mtu, &mut avail_features);

            let avail_protocol_features = VhostUserProtocolFeatures::MQ
                | VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS
                | VhostUserProtocolFeatures::REPLY_ACK
                | VhostUserProtocolFeatures::INFLIGHT_SHMFD
                | VhostUserProtocolFeatures::LOG_SHMFD;

            let (acked_features, acked_protocol_features) =
                vu.negotiate_features_vhost_user(avail_features, avail_protocol_features)?;

            let backend_num_queues =
                if acked_protocol_features & VhostUserProtocolFeatures::MQ.bits() != 0 {
                    vu.socket_handle()
                        .get_queue_num()
                        .map_err(Error::VhostUserGetQueueMaxNum)? as usize
                } else {
                    DEFAULT_QUEUE_NUMBER
                };

            if num_queues > backend_num_queues {
                error!(
                    "vhost-user-net requested too many queues ({num_queues}) since the backend only supports {backend_num_queues}\n"
                );
                return Err(Error::BadQueueNum);
            }

            // If the control queue feature has been negotiated, let's increase
            // the number of queues.
            let vu_num_queues = num_queues;
            if acked_features & (1 << VIRTIO_NET_F_CTRL_VQ) != 0 {
                num_queues += 1;
            }

            // Build the feature set that gets exposed to the guest. Some frontend available
            // features are dependent on the features the backend supports.
            let guest_avail_features = Self::frontend_avail_features(acked_features);

            (
                guest_avail_features,
                // If part of the available features that have been acked,
                // the PROTOCOL_FEATURES bit must be already set through
                // the VIRTIO acked features as we know the guest would
                // never ack it, thus the feature would be lost.
                acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits(),
                acked_protocol_features,
                vu_num_queues,
                config,
                false,
                false,
            )
        };

        Ok(Net {
            id,
            common: VirtioCommon {
                device_type: VirtioDeviceType::Net as u32,
                queue_sizes: vec![vu_cfg.queue_size; num_queues],
                avail_features,
                acked_features,
                paused_sync: Some(Arc::new(Barrier::new(2))),
                min_queues: DEFAULT_QUEUE_NUMBER as u16,
                paused: Arc::new(AtomicBool::new(paused)),
                ..Default::default()
            },
            vu_common: VhostUserCommon {
                vu: Some(Arc::new(Mutex::new(vu))),
                acked_protocol_features,
                socket_path: vu_cfg.socket,
                vu_num_queues,
                server,
                ..Default::default()
            },
            config,
            announce_pending: Arc::new(AtomicBool::new(announce_pending)),
            guest_memory: None,
            ctrl_queue_epoll_thread: None,
            epoll_thread: None,
            seccomp_action,
            exit_evt,
            iommu,
        })
    }

    fn state(&self) -> State {
        State {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
            config: self.config,
            announce_pending: self.announce_pending.load(Ordering::Acquire),
            acked_protocol_features: self.vu_common.acked_protocol_features,
            vu_num_queues: self.vu_common.vu_num_queues,
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
}

impl Drop for Net {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.common.kill_evt.take()
            && let Err(e) = kill_evt.write(1)
        {
            error!("failed to kill vhost-user-net: {e:?}");
        }

        self.common.wait_for_epoll_threads();

        if let Some(thread) = self.epoll_thread.take()
            && let Err(e) = thread.join()
        {
            error!("Error joining thread: {e:?}");
        }

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
        let mut features = self.common.avail_features;
        if self.iommu {
            features |= 1u64 << VIRTIO_F_IOMMU_PLATFORM;
        }
        features
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
        self.guest_memory = Some(mem.clone());

        let num_queues = queues.len();
        let event_idx = self.common.feature_acked(VIRTIO_RING_F_EVENT_IDX.into());
        if self.common.feature_acked(VIRTIO_NET_F_CTRL_VQ.into()) && !num_queues.is_multiple_of(2) {
            let ctrl_queue_index = num_queues - 1;
            let (_, mut ctrl_queue, ctrl_queue_evt) = queues.remove(ctrl_queue_index);

            ctrl_queue.set_event_idx(event_idx);

            let (kill_evt, pause_evt) = self.common.dup_eventfds();

            let mut ctrl_handler = NetCtrlEpollHandler {
                mem: mem.clone(),
                kill_evt,
                pause_evt,
                ctrl_q: CtrlQueue::new(Vec::new(), Arc::clone(&self.announce_pending)),
                queue: ctrl_queue,
                queue_evt: ctrl_queue_evt,
                access_platform: None,
                interrupt_cb: interrupt_cb.clone(),
                queue_index: ctrl_queue_index as u16,
            };

            let paused = self.common.paused.clone();
            // Let's update the barrier as we need 1 for the control queue
            // thread + 1 for the common vhost-user thread + 1 for the main
            // thread signalling the pause.
            self.common.paused_sync = Some(Arc::new(Barrier::new(3)));
            let paused_sync = self.common.paused_sync.clone();

            let mut epoll_threads = Vec::new();
            spawn_virtio_thread(
                &format!("{}_ctrl", &self.id),
                &self.seccomp_action,
                Thread::VirtioVhostNetCtl,
                &mut epoll_threads,
                &self.exit_evt,
                move || ctrl_handler.run_ctrl(&paused, paused_sync.as_ref().unwrap()),
            )?;
            self.ctrl_queue_epoll_thread = Some(epoll_threads.remove(0));
        }

        let backend_req_handler: Option<FrontendReqHandler<BackendReqHandler>> = None;

        // The backend acknowledged features must not contain frontend-only
        // features since we don't expect the backend to handle them.
        let backend_acked_features = self.common.acked_features
            & !((1 << VIRTIO_NET_F_MAC)
                | (1 << VIRTIO_NET_F_STATUS)
                | (1 << VIRTIO_NET_F_GUEST_ANNOUNCE));

        // Run a dedicated thread for handling potential reconnections with
        // the backend.
        let (kill_evt, pause_evt) = self.common.dup_eventfds();

        let mut handler = self.vu_common.activate(
            mem,
            &queues,
            interrupt_cb,
            backend_acked_features,
            backend_req_handler,
            kill_evt,
            pause_evt,
        )?;

        let paused = self.common.paused.clone();
        let paused_sync = self.common.paused_sync.clone();

        let mut epoll_threads = Vec::new();
        spawn_virtio_thread(
            &self.id,
            &self.seccomp_action,
            Thread::VirtioVhostNet,
            &mut epoll_threads,
            &self.exit_evt,
            move || handler.run(&paused, paused_sync.as_ref().unwrap()),
        )?;
        self.epoll_thread = Some(epoll_threads.remove(0));

        Ok(())
    }

    fn reset(&mut self) -> Option<Arc<dyn VirtioInterrupt>> {
        self.announce_pending.store(false, Ordering::Release);
        // We first must resume the virtio thread if it was paused.
        if self.common.pause_evt.take().is_some() {
            self.common.resume().ok()?;
        }

        if let Some(vu) = &self.vu_common.vu
            && let Err(e) = vu.lock().unwrap().reset_vhost_user()
        {
            error!("Failed to reset vhost-user daemon: {e:?}");
            return None;
        }

        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }

        event!("virtio-device", "reset", "id", &self.id);

        // Return the interrupt
        Some(self.common.interrupt_cb.take().unwrap())
    }

    fn shutdown(&mut self) {
        self.vu_common.shutdown();
    }

    fn post_migration_announcer(&self) -> Option<Box<dyn PostMigrationAnnouncer>> {
        Some(Box::new(VhostUserNetPostMigrationAnnouncer::new(self)))
    }

    fn add_memory_region(
        &mut self,
        region: &Arc<GuestRegionMmap>,
    ) -> std::result::Result<(), crate::Error> {
        self.vu_common.add_memory_region(&self.guest_memory, region)
    }
}

impl Pausable for Net {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.pause()?;
        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()?;

        if let Some(epoll_thread) = &self.epoll_thread {
            epoll_thread.thread().unpark();
        }

        if let Some(ctrl_queue_epoll_thread) = &self.ctrl_queue_epoll_thread {
            ctrl_queue_epoll_thread.thread().unpark();
        }

        self.vu_common.resume()
    }
}

impl Snapshottable for Net {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        self.vu_common.snapshot(&self.state())
    }
}
impl Transportable for Net {}

impl Migratable for Net {
    fn start_dirty_log(&mut self) -> std::result::Result<(), MigratableError> {
        self.vu_common.start_dirty_log(&self.guest_memory)
    }

    fn stop_dirty_log(&mut self) -> std::result::Result<(), MigratableError> {
        self.vu_common.stop_dirty_log()
    }

    fn dirty_log(&mut self) -> std::result::Result<MemoryRangeTable, MigratableError> {
        self.vu_common.dirty_log(&self.guest_memory)
    }

    fn start_migration(&mut self) -> std::result::Result<(), MigratableError> {
        self.vu_common.start_migration()
    }

    fn complete_migration(&mut self) -> std::result::Result<(), MigratableError> {
        self.vu_common
            .complete_migration(self.common.kill_evt.take())
    }
}

/// Announces this vhost-user-net device on the network.
/// Most fields are cloned references to device state so retry rounds can run
/// without borrowing the device itself.
pub struct VhostUserNetPostMigrationAnnouncer {
    id: String,
    /// Remembers whether this device negotiated the guest-visible announce path.
    guest_announce_negotiated: bool,
    announce_pending: Arc<AtomicBool>,
    interrupt_cb: Option<Arc<dyn VirtioInterrupt>>,
}

impl VhostUserNetPostMigrationAnnouncer {
    pub fn new(dev: &Net) -> Self {
        Self {
            id: dev.id.clone(),
            guest_announce_negotiated: dev.common.feature_acked(VIRTIO_NET_F_GUEST_ANNOUNCE.into()),
            announce_pending: Arc::clone(&dev.announce_pending),
            interrupt_cb: dev.common.interrupt_cb.clone(),
        }
    }
}

impl PostMigrationAnnouncer for VhostUserNetPostMigrationAnnouncer {
    // Vhost-user-net relies on the guest-visible announce path: mark the
    // request pending and re-trigger the config interrupt while this retry
    // session remains valid.
    fn announce(&mut self) {
        if self.guest_announce_negotiated
            && let Some(interrupt_cb) = &self.interrupt_cb
        {
            self.announce_pending.store(true, Ordering::Release);

            interrupt_cb
                .trigger(crate::VirtioInterruptType::Config)
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
    use std::sync::atomic::{AtomicUsize, Ordering};

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
            vu_common: VhostUserCommon::default(),
            id: "test-vu-net".to_string(),
            config: VirtioNetConfig::default(),
            announce_pending: Arc::new(AtomicBool::new(false)),
            guest_memory: None,
            ctrl_queue_epoll_thread: None,
            epoll_thread: None,
            seccomp_action: SeccompAction::Allow,
            exit_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            iommu: false,
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
    fn test_frontend_avail_features_expose_guest_announce_and_status() {
        let avail_features = Net::frontend_avail_features(1 << VIRTIO_NET_F_CTRL_VQ);

        assert_ne!(avail_features & (1 << VIRTIO_NET_F_MAC), 0);
        assert_ne!(avail_features & (1 << VIRTIO_NET_F_STATUS), 0);
        assert_ne!(avail_features & (1 << VIRTIO_NET_F_GUEST_ANNOUNCE), 0);
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
    fn test_post_migration_with_ctrl_vq_but_without_guest_announce_is_noop() {
        let interrupt = Arc::new(TestInterrupt::new());
        let net = test_net(
            1 << VIRTIO_NET_F_CTRL_VQ,
            Some(interrupt.clone() as Arc<dyn VirtioInterrupt>),
        );

        net.post_migration_announcer().unwrap().announce();

        assert!(!net.announce_pending.load(Ordering::Acquire));
        assert_eq!(read_status(&net) & VIRTIO_NET_S_ANNOUNCE as u16, 0);
        assert_eq!(interrupt.config_count.load(Ordering::Acquire), 0);
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
    fn test_state_deserialize_without_announce_pending_defaults_to_false() {
        // Older snapshots do not contain announce_pending. Restoring them on a
        // newer binary must treat the missing field as "no announce pending".
        let state = State {
            avail_features: 1,
            acked_features: 2,
            config: VirtioNetConfig::default(),
            announce_pending: true,
            acked_protocol_features: 3,
            vu_num_queues: 4,
        };
        let mut value = serde_json::to_value(state).unwrap();

        value.as_object_mut().unwrap().remove("announce_pending");

        let restored: State = serde_json::from_value(value).unwrap();

        assert!(!restored.announce_pending);
    }
}
