// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io::{self, Read, Write};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::thread::JoinHandle;
use std::time::Duration;
use std::{result, thread};

use vm_memory::bitmap::BitmapSlice;
use vm_memory::{ReadVolatile, VolatileMemoryError, VolatileSlice, WriteVolatile};

use crate::protocol::Request;

/// The `KeepAliveStream` is a stream that is intended to be used for the main
/// connection of live migrations. If the `KeepAliveStream` does not read or
/// write often enough, it will send keep alive messages on the given stream.
/// The `KeepAliveStream` should not be used to send or receive memory, because
/// the `read_volatile()` and `write_volatile()` functions will be very slow.
///
/// The `KeepAliveStream` is designed to be compatible with the `SocketStream`
/// enum, and thus it should be really easy to use it.
///
/// The `KeepAliveStream` consists of a thread (the `KeepAliveWorker`) that owns
/// the given stream, and channels to send messages to said thread, and receive
/// answers from it.
// The messages that will be sent to the `KeepAliveWorker`.
#[derive(Debug)]
enum KeepAliveStreamMessage {
    // Read `len` bytes from `stream`.
    Read(usize /* len */),
    // Write `buf` to `stream`.
    Write(Vec<u8> /* buf */),
    // Flush `stream`.
    Flush,
    // Stop listening for messages, i.e. stop the worker.
    Disconnect,
}

// The answer we will get from the `KeepAliveWorker`.
#[derive(Debug)]
enum KeepAliveStreamAnswer {
    // Result of reading from `stream`.
    Read(io::Result<(Vec<u8>, usize)>),
    // Result of writing to `stream`.
    Write(io::Result<usize>),
    // Result of flushing `stream`.
    Flush(io::Result<()>),
}

// The [`KeepAliveStream`] should only be used by the sender, not the receiver.
// Thus it doesn't have to implement `AsFd`.
struct KeepAliveWorker<S: Read + Write> {
    stream: S,
}

impl<S> KeepAliveWorker<S>
where
    S: Read + Write,
{
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    pub fn read(&mut self, len: usize) -> io::Result<(Vec<u8>, usize)> {
        let mut buf: Vec<u8> = vec![0u8; len];
        let n = Read::read(&mut self.stream, &mut buf)?;
        Ok((buf, n))
    }

    pub fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Write::write(&mut self.stream, buf)
    }

    pub fn flush(&mut self) -> io::Result<()> {
        Write::flush(&mut self.stream)
    }
}

pub struct KeepAliveStream {
    /// The `KeepAliveWorker`.
    thread: Option<JoinHandle<()>>,

    /// Used to send messages to the worker.
    message_tx: SyncSender<KeepAliveStreamMessage>,
    /// Used to receive answers from the worker.
    answer_rx: Receiver<KeepAliveStreamAnswer>,
}

impl KeepAliveStream {
    pub fn new<T: Read + Write + Send + 'static>(
        stream: T,
        timeout: Duration,
    ) -> result::Result<Self, io::Error> {
        // We want to block on send and on recv if nobody listens. Thus we set the bound to 0.
        let (message_tx, message_rx) = sync_channel::<KeepAliveStreamMessage>(0);
        let (answer_tx, answer_rx) = sync_channel::<KeepAliveStreamAnswer>(0);

        let thread = thread::Builder::new()
            .name("keep_alive_sender_thread".to_string())
            .spawn(move || {
                let mut worker = KeepAliveWorker::new(stream);
                loop {
                    // The idea is to always send a keep alive message when this times out.
                    match message_rx.recv_timeout(timeout) {
                        Ok(message) => match message {
                            KeepAliveStreamMessage::Read(payload) => {
                                if answer_tx
                                    .send(KeepAliveStreamAnswer::Read(worker.read(payload)))
                                    .is_err()
                                {
                                    // We simply break the loop and thus stop the thread if anything bad happens.
                                    // The main thread will notice next time it tries to send a message to the thread.
                                    break;
                                }
                            }
                            KeepAliveStreamMessage::Write(payload) => {
                                if answer_tx
                                    .send(KeepAliveStreamAnswer::Write(worker.write(&payload)))
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            KeepAliveStreamMessage::Flush => {
                                if answer_tx
                                    .send(KeepAliveStreamAnswer::Flush(worker.flush()))
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            KeepAliveStreamMessage::Disconnect => break,
                        },
                        Err(RecvTimeoutError::Timeout) => {
                            let keep_alive = Request::keep_alive();
                            let _ = keep_alive.write_to(&mut worker.stream);
                        }
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                }
            })?;

        Ok(Self {
            thread: Some(thread),
            message_tx,
            answer_rx,
        })
    }
}

impl Drop for KeepAliveStream {
    fn drop(&mut self) {
        let _ = self.message_tx.send(KeepAliveStreamMessage::Disconnect);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

impl Read for KeepAliveStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.message_tx
            .send(KeepAliveStreamMessage::Read(buf.len()))
            .map_err(|e| {
                io::Error::other(format!("Unable to send message to KeepAliveWorker: {e}"))
            })?;

        match self.answer_rx.recv() {
            Ok(KeepAliveStreamAnswer::Read(result)) => match result {
                Ok((recv_buf, len)) => {
                    buf[..len].copy_from_slice(&recv_buf[..len]);
                    Ok(len)
                }
                Err(e) => Err(e),
            },
            Ok(a) => Err(io::Error::other(format!(
                "Received unexpected answer: {a:?}. This is most likely a bug!"
            ))),
            Err(e) => Err(io::Error::other(format!(
                "Unable to receive answer from KeepAliveWorker: {e}"
            ))),
        }
    }
}

impl Write for KeepAliveStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.message_tx
            .send(KeepAliveStreamMessage::Write(Vec::from(buf)))
            .map_err(|e| {
                io::Error::other(format!("Unable to send message to KeepAliveWorker: {e}"))
            })?;

        match self.answer_rx.recv() {
            Ok(KeepAliveStreamAnswer::Write(result)) => result,
            Ok(a) => Err(io::Error::other(format!(
                "Received unexpected answer: {a:?}. This is most likely a bug!",
            ))),
            Err(e) => Err(io::Error::other(format!(
                "Unable to receive answer from KeepAliveWorker: {e}"
            ))),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.message_tx
            .send(KeepAliveStreamMessage::Flush)
            .map_err(|e| {
                io::Error::other(format!("Unable to send message to KeepAliveWorker: {e}"))
            })?;
        match self.answer_rx.recv() {
            Ok(KeepAliveStreamAnswer::Flush(result)) => result,
            Ok(a) => Err(io::Error::other(format!(
                "Received unexpected answer: {a:?}. This is most likely a bug!",
            ))),
            Err(e) => Err(io::Error::other(format!(
                "Unable to receive answer from KeepAliveWorker: {e}"
            ))),
        }
    }
}

impl ReadVolatile for KeepAliveStream {
    fn read_volatile<B: BitmapSlice>(
        &mut self,
        buf: &mut VolatileSlice<B>,
    ) -> result::Result<usize, VolatileMemoryError> {
        self.message_tx
            .send(KeepAliveStreamMessage::Read(buf.len()))
            .map_err(|e| {
                io::Error::other(format!("Unable to send message to KeepAliveWorker: {e}"))
            })
            .map_err(VolatileMemoryError::IOError)?;

        match self.answer_rx.recv() {
            Ok(KeepAliveStreamAnswer::Read(result)) => match result {
                Ok((recv_buf, len)) => {
                    buf.copy_from(&recv_buf[..len]);
                    Ok(len)
                }
                Err(e) => Err(VolatileMemoryError::IOError(e)),
            },
            Ok(a) => Err(VolatileMemoryError::IOError(io::Error::other(format!(
                "Received unexpected answer: {a:?}. This is most likely a bug!",
            )))),
            Err(e) => Err(VolatileMemoryError::IOError(io::Error::other(format!(
                "Unable to receive answer from KeepAliveWorker: {e}"
            )))),
        }
    }
}

impl WriteVolatile for KeepAliveStream {
    fn write_volatile<B: BitmapSlice>(
        &mut self,
        buf: &VolatileSlice<B>,
    ) -> result::Result<usize, VolatileMemoryError> {
        let mut send_buf = vec![0u8; buf.len()];
        buf.copy_to(&mut send_buf);
        self.message_tx
            .send(KeepAliveStreamMessage::Write(send_buf))
            .map_err(|e| {
                io::Error::other(format!("Unable to send message to KeepAliveWorker: {e}"))
            })
            .map_err(VolatileMemoryError::IOError)?;

        match self.answer_rx.recv() {
            Ok(KeepAliveStreamAnswer::Write(result)) => {
                result.map_err(VolatileMemoryError::IOError)
            }
            Ok(a) => Err(VolatileMemoryError::IOError(io::Error::other(format!(
                "Received unexpected answer: {a:?}. This is most likely a bug!",
            )))),
            Err(e) => Err(VolatileMemoryError::IOError(io::Error::other(format!(
                "Unable to receive answer from KeepAliveWorker: {e}"
            )))),
        }
    }
}
