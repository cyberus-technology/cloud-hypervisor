// Copyright (c) 2021 Intel Corporation. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use log::{debug, error, info, warn};
use thiserror::Error;
use virtio_bindings::virtio_net::{
    VIRTIO_NET_CTRL_ANNOUNCE, VIRTIO_NET_CTRL_ANNOUNCE_ACK, VIRTIO_NET_CTRL_GUEST_OFFLOADS,
    VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET, VIRTIO_NET_CTRL_MQ, VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX,
    VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN, VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET, VIRTIO_NET_CTRL_RX,
    VIRTIO_NET_CTRL_RX_ALLMULTI, VIRTIO_NET_CTRL_RX_ALLUNI, VIRTIO_NET_CTRL_RX_NOBCAST,
    VIRTIO_NET_CTRL_RX_NOMULTI, VIRTIO_NET_CTRL_RX_NOUNI, VIRTIO_NET_CTRL_RX_PROMISC,
    VIRTIO_NET_CTRL_VLAN, VIRTIO_NET_CTRL_VLAN_ADD, VIRTIO_NET_CTRL_VLAN_DEL, VIRTIO_NET_ERR,
    VIRTIO_NET_OK,
};
use virtio_queue::{Queue, QueueT};
use vm_memory::{ByteValued, Bytes, GuestMemoryError};
use vm_virtio::{AccessPlatform, Translatable};

use super::virtio_features_to_tap_offload;
use crate::{GuestMemoryMmap, Tap};

#[derive(Error, Debug)]
pub enum Error {
    /// Read queue failed.
    #[error("Read queue failed")]
    GuestMemory(#[source] GuestMemoryError),
    /// No control header descriptor
    #[error("No control header descriptor")]
    NoControlHeaderDescriptor,
    /// Missing the data descriptor in the chain.
    #[error("Missing the data descriptor in the chain")]
    NoDataDescriptor,
    /// No status descriptor
    #[error("No status descriptor")]
    NoStatusDescriptor,
    /// Failed adding used index
    #[error("Failed adding used index")]
    QueueAddUsed(#[source] virtio_queue::Error),
    /// Failed creating an iterator over the queue
    #[error("Failed creating an iterator over the queue")]
    QueueIterator(#[source] virtio_queue::Error),
    /// Failed enabling notification for the queue
    #[error("Failed enabling notification for the queue")]
    QueueEnableNotification(#[source] virtio_queue::Error),
}

type Result<T> = std::result::Result<T, Error>;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ControlHeader {
    pub class: u8,
    pub cmd: u8,
}

// SAFETY: ControlHeader only contains a series of integers
unsafe impl ByteValued for ControlHeader {}

fn is_tolerated_ctrl_command(ctrl_hdr: ControlHeader) -> bool {
    match u32::from(ctrl_hdr.class) {
        VIRTIO_NET_CTRL_RX => matches!(
            u32::from(ctrl_hdr.cmd),
            VIRTIO_NET_CTRL_RX_PROMISC
                | VIRTIO_NET_CTRL_RX_ALLMULTI
                | VIRTIO_NET_CTRL_RX_ALLUNI
                | VIRTIO_NET_CTRL_RX_NOMULTI
                | VIRTIO_NET_CTRL_RX_NOUNI
                | VIRTIO_NET_CTRL_RX_NOBCAST
        ),
        VIRTIO_NET_CTRL_VLAN => matches!(
            u32::from(ctrl_hdr.cmd),
            VIRTIO_NET_CTRL_VLAN_ADD | VIRTIO_NET_CTRL_VLAN_DEL
        ),
        _ => false,
    }
}

pub struct CtrlQueue {
    pub taps: Vec<Tap>,
    /// Tracks whether the guest still needs to acknowledge a post-migration
    /// announce request through the control queue.
    pub announce_pending: Arc<AtomicBool>,
}

impl CtrlQueue {
    pub fn new(taps: Vec<Tap>, announce_pending: Arc<AtomicBool>) -> Self {
        CtrlQueue {
            taps,
            announce_pending,
        }
    }

    pub fn process(
        &mut self,
        mem: &GuestMemoryMmap,
        queue: &mut Queue,
        access_platform: Option<&dyn AccessPlatform>,
    ) -> Result<()> {
        while let Some(mut desc_chain) = queue.pop_descriptor_chain(mem) {
            let ctrl_desc = desc_chain.next().ok_or(Error::NoControlHeaderDescriptor)?;

            let ctrl_hdr: ControlHeader = desc_chain
                .memory()
                .read_obj(
                    ctrl_desc
                        .addr()
                        .translate_gva(access_platform, ctrl_desc.len() as usize)
                        .map_err(|e| Error::GuestMemory(GuestMemoryError::IOError(e)))?,
                )
                .map_err(Error::GuestMemory)?;
            let (ok, status_desc) = match u32::from(ctrl_hdr.class) {
                VIRTIO_NET_CTRL_MQ => {
                    let data_desc = desc_chain.next().ok_or(Error::NoDataDescriptor)?;
                    let data_desc_addr = data_desc
                        .addr()
                        .translate_gva(access_platform, data_desc.len() as usize)
                        .map_err(|e| Error::GuestMemory(GuestMemoryError::IOError(e)))?;
                    let status_desc = desc_chain.next().ok_or(Error::NoStatusDescriptor)?;
                    let queue_pairs = desc_chain
                        .memory()
                        .read_obj::<u16>(data_desc_addr)
                        .map_err(Error::GuestMemory)?;
                    let ok = if u32::from(ctrl_hdr.cmd) != VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET {
                        warn!("Unsupported command: {}", ctrl_hdr.cmd);
                        false
                    } else if (queue_pairs < VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN as u16)
                        || (queue_pairs > VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX as u16)
                    {
                        warn!("Number of MQ pairs out of range: {queue_pairs}");
                        false
                    } else {
                        info!("Number of MQ pairs requested: {queue_pairs}");
                        true
                    };

                    (ok, status_desc)
                }
                VIRTIO_NET_CTRL_GUEST_OFFLOADS => {
                    let data_desc = desc_chain.next().ok_or(Error::NoDataDescriptor)?;
                    let data_desc_addr = data_desc
                        .addr()
                        .translate_gva(access_platform, data_desc.len() as usize)
                        .map_err(|e| Error::GuestMemory(GuestMemoryError::IOError(e)))?;
                    let status_desc = desc_chain.next().ok_or(Error::NoStatusDescriptor)?;
                    let features = desc_chain
                        .memory()
                        .read_obj::<u64>(data_desc_addr)
                        .map_err(Error::GuestMemory)?;
                    let ok = if u32::from(ctrl_hdr.cmd) == VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET {
                        let mut ok = true;
                        for tap in self.taps.iter_mut() {
                            info!("Reprogramming tap offload with features: {features}");
                            tap.set_offload(virtio_features_to_tap_offload(features))
                                .map_err(|e| {
                                    error!("Error programming tap offload: {e:?}");
                                    ok = false;
                                })
                                .ok();
                        }
                        ok
                    } else {
                        warn!("Unsupported command: {}", ctrl_hdr.cmd);
                        false
                    };

                    (ok, status_desc)
                }
                VIRTIO_NET_CTRL_ANNOUNCE => {
                    let status_desc = desc_chain.next().ok_or(Error::NoStatusDescriptor)?;
                    let ok = if u32::from(ctrl_hdr.cmd) == VIRTIO_NET_CTRL_ANNOUNCE_ACK {
                        self.announce_pending.store(false, Ordering::Release);
                        true
                    } else {
                        warn!("Unsupported command: {}", ctrl_hdr.cmd);
                        false
                    };

                    (ok, status_desc)
                }
                _ => {
                    let _data_desc = desc_chain.next().ok_or(Error::NoDataDescriptor)?;
                    let status_desc = desc_chain.next().ok_or(Error::NoStatusDescriptor)?;
                    let ok = if is_tolerated_ctrl_command(ctrl_hdr) {
                        debug!("Ignoring unsupported but tolerated control command {ctrl_hdr:?}");
                        true
                    } else {
                        warn!("Unsupported command {ctrl_hdr:?}");
                        false
                    };
                    (ok, status_desc)
                }
            };

            desc_chain
                .memory()
                .write_obj(
                    if ok { VIRTIO_NET_OK } else { VIRTIO_NET_ERR } as u8,
                    status_desc
                        .addr()
                        .translate_gva(access_platform, status_desc.len() as usize)
                        .map_err(|e| Error::GuestMemory(GuestMemoryError::IOError(e)))?,
                )
                .map_err(Error::GuestMemory)?;
            queue
                .add_used(desc_chain.memory(), desc_chain.head_index(), 1)
                .map_err(Error::QueueAddUsed)?;

            if !queue
                .enable_notification(mem)
                .map_err(Error::QueueEnableNotification)?
            {
                break;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod unit_tests {
    use std::mem::size_of;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use virtio_bindings::virtio_net::{VIRTIO_NET_CTRL_ANNOUNCE, VIRTIO_NET_CTRL_ANNOUNCE_ACK};
    use virtio_bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
    use vm_memory::{Bytes, GuestAddress};
    use vm_virtio::queue::testing::VirtQueue as GuestQ;

    use super::*;

    #[test]
    fn test_process_announce_ack() {
        // The guest acknowledges the post-migration request on the control
        // queue, which clears the pending announce state in the device model.
        // This test builds the minimal virtqueue request for that command:
        // one readable descriptor for the control header, followed by one
        // writable descriptor where the device stores the command status.
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let guest_q = GuestQ::new(GuestAddress(0), &mem, 16);
        let mut queue = guest_q.create_queue();

        let ctrl_hdr = ControlHeader {
            class: VIRTIO_NET_CTRL_ANNOUNCE as u8,
            cmd: VIRTIO_NET_CTRL_ANNOUNCE_ACK as u8,
        };
        let ctrl_addr = GuestAddress(0x1000);
        let status_addr = GuestAddress(0x1100);
        mem.write_obj(ctrl_hdr, ctrl_addr).unwrap();

        // Descriptor 0 contains the control header and points to descriptor 1.
        guest_q.dtable[0].set(
            ctrl_addr.0,
            size_of::<ControlHeader>() as u32,
            VRING_DESC_F_NEXT.try_into().unwrap(),
            1,
        );
        // Descriptor 1 is the writable status byte returned by the device.
        guest_q.dtable[1].set(status_addr.0, 1, VRING_DESC_F_WRITE.try_into().unwrap(), 0);

        // Publish the two-descriptor request to the available ring so
        // CtrlQueue::process() can pop and handle it.
        guest_q.avail.ring[0].set(0);
        guest_q.avail.idx.set(1);

        // Start from the state reached after post_migration(): the guest still
        // owes us an ANNOUNCE_ACK on the control queue.
        let announce_pending = Arc::new(AtomicBool::new(true));
        let mut ctrl_q = CtrlQueue::new(Vec::new(), Arc::clone(&announce_pending));

        ctrl_q.process(&mem, &mut queue, None).unwrap();

        // A successful ANNOUNCE_ACK clears the pending flag and reports
        // VIRTIO_NET_OK in the guest-provided status buffer.
        assert!(!announce_pending.load(Ordering::Acquire));
        assert_eq!(
            mem.read_obj::<u8>(status_addr).unwrap(),
            VIRTIO_NET_OK as u8
        );
    }
}
