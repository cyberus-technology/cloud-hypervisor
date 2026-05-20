// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::thread::JoinHandle;
use std::time::Duration;
use std::{result, thread};

use vm_memory::bitmap::BitmapSlice;
use vm_memory::{ReadVolatile, VolatileMemoryError, VolatileSlice, WriteVolatile};

use crate::protocol::{Request, Response};

/// The `KeepAliveStream` is a stream that is intended to be used for the main
/// connection of live migrations. If the `KeepAliveStream` does not read or
/// write often enough, it will send keep alive messages on the given stream.
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
    // Read `len` bytes into `buf` from `stream`.
    Read { len: usize, buf: Vec<u8> },
    // Write `buf[..len]` to `stream`.
    Write { len: usize, buf: Vec<u8> },
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
    Write(io::Result<(Vec<u8>, usize)>),
    // Result of flushing `stream`.
    Flush(io::Result<()>),
}

struct KeepAliveWorker<S: Read + Write + AsFd> {
    stream: S,
    /// Is this running on the sender or receiver side?
    is_sender: bool,
}

impl<S> KeepAliveWorker<S>
where
    S: Read + Write + AsFd,
{
    pub fn new(stream: S, is_sender: bool) -> Self {
        Self { stream, is_sender }
    }

    pub fn read(&mut self, mut buf: Vec<u8>, len: usize) -> io::Result<(Vec<u8>, usize)> {
        if buf.len() < len {
            buf.resize(len, 0);
        }

        let n = Read::read(&mut self.stream, &mut buf[..len])?;
        Ok((buf, n))
    }

    pub fn write(&mut self, buf: Vec<u8>, len: usize) -> io::Result<(Vec<u8>, usize)> {
        debug_assert!(len <= buf.len());
        let n = Write::write(&mut self.stream, &buf[..len])?;
        Ok((buf, n))
    }

    pub fn flush(&mut self) -> io::Result<()> {
        Write::flush(&mut self.stream)
    }
}

pub struct KeepAliveStream {
    /// The `KeepAliveWorker`.
    thread: Option<JoinHandle<()>>,
    /// Duplicated file descriptor for `AsFd`.
    fd: OwnedFd,

    /// Used to send messages to the worker.
    message_tx: SyncSender<KeepAliveStreamMessage>,
    /// Used to receive answers from the worker.
    answer_rx: Receiver<KeepAliveStreamAnswer>,
    /// Scratch buffer that gets moved to/from the worker for reads.
    read_buf: Vec<u8>,
    /// Scratch buffer that gets moved to/from the worker for writes.
    write_buf: Vec<u8>,
}

impl KeepAliveStream {
    pub fn new<T: Read + Write + Send + AsFd + 'static>(
        stream: T,
        timeout: Duration,
        is_sender: bool,
    ) -> result::Result<Self, io::Error> {
        let fd = stream.as_fd().try_clone_to_owned()?;

        // We want to block on send and on recv if nobody listens. Thus we set the bound to 0.
        let (message_tx, message_rx) = sync_channel::<KeepAliveStreamMessage>(0);
        let (answer_tx, answer_rx) = sync_channel::<KeepAliveStreamAnswer>(0);

        let thread = thread::Builder::new()
            .name("migration_keep_alive_thread".to_string())
            .spawn(move || {
                let mut worker = KeepAliveWorker::new(stream, is_sender);
                loop {
                    // The idea is to always send a keep alive message when this times out.
                    match message_rx.recv_timeout(timeout) {
                        Ok(message) => match message {
                            KeepAliveStreamMessage::Read { len, buf } => {
                                if answer_tx
                                    .send(KeepAliveStreamAnswer::Read(worker.read(buf, len)))
                                    .is_err()
                                {
                                    // We simply break the loop and thus stop the thread if anything bad happens.
                                    // The main thread will notice next time it tries to send a message to the thread.
                                    break;
                                }
                            }
                            KeepAliveStreamMessage::Write { len, buf } => {
                                if answer_tx
                                    .send(KeepAliveStreamAnswer::Write(worker.write(buf, len)))
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
                            if worker.is_sender {
                                let keep_alive = Request::keep_alive();
                                let _ = keep_alive.write_to(&mut worker.stream);
                            } else {
                                let keep_alive = Response::keep_alive();
                                let _ = keep_alive.write_to(&mut worker.stream);
                            }
                        }
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                }
            })?;

        Ok(Self {
            thread: Some(thread),
            fd,
            message_tx,
            answer_rx,
            read_buf: Vec::new(),
            write_buf: Vec::new(),
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

impl AsFd for KeepAliveStream {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl Read for KeepAliveStream {
    fn read(&mut self, out_buf: &mut [u8]) -> io::Result<usize> {
        let len = out_buf.len();
        // Move the buffer to avoid lifetime or ownership issues.
        let read_buf = std::mem::take(&mut self.read_buf);

        self.message_tx
            .send(KeepAliveStreamMessage::Read { len, buf: read_buf })
            .map_err(|e| {
                io::Error::other(format!("Unable to send message to KeepAliveWorker: {e}"))
            })?;

        match self.answer_rx.recv() {
            Ok(KeepAliveStreamAnswer::Read(result)) => match result {
                Ok((buf, len)) => {
                    self.read_buf = buf;
                    out_buf[..len].copy_from_slice(&self.read_buf[..len]);
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
    fn write(&mut self, in_buf: &[u8]) -> io::Result<usize> {
        let len = in_buf.len();
        if self.write_buf.len() < len {
            self.write_buf.resize(len, 0);
        }

        self.write_buf[..len].copy_from_slice(in_buf);
        // Move the buffer to avoid lifetime or ownership issues.
        let write_buf = std::mem::take(&mut self.write_buf);

        self.message_tx
            .send(KeepAliveStreamMessage::Write {
                len,
                buf: write_buf,
            })
            .map_err(|e| {
                io::Error::other(format!("Unable to send message to KeepAliveWorker: {e}"))
            })?;

        match self.answer_rx.recv() {
            Ok(KeepAliveStreamAnswer::Write(result)) => match result {
                Ok((buf, len)) => {
                    self.write_buf = buf;
                    Ok(len)
                }
                Err(e) => Err(e),
            },
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
        vs: &mut VolatileSlice<B>,
    ) -> result::Result<usize, VolatileMemoryError> {
        let len = vs.len();
        // Move the buffer to avoid lifetime or ownership issues.
        let read_buf = std::mem::take(&mut self.read_buf);

        self.message_tx
            .send(KeepAliveStreamMessage::Read { len, buf: read_buf })
            .map_err(|e| {
                io::Error::other(format!("Unable to send message to KeepAliveWorker: {e}"))
            })
            .map_err(VolatileMemoryError::IOError)?;

        match self.answer_rx.recv() {
            Ok(KeepAliveStreamAnswer::Read(result)) => match result {
                Ok((buf, len)) => {
                    self.read_buf = buf;
                    vs.copy_from(&self.read_buf[..len]);
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
        vs: &VolatileSlice<B>,
    ) -> result::Result<usize, VolatileMemoryError> {
        let len = vs.len();
        if self.write_buf.len() < len {
            self.write_buf.resize(len, 0);
        }

        let len = vs.copy_to(&mut self.write_buf[..len]);
        // Move the buffer to avoid lifetime or ownership issues.
        let write_buf = std::mem::take(&mut self.write_buf);

        self.message_tx
            .send(KeepAliveStreamMessage::Write {
                len,
                buf: write_buf,
            })
            .map_err(|e| {
                io::Error::other(format!("Unable to send message to KeepAliveWorker: {e}"))
            })
            .map_err(VolatileMemoryError::IOError)?;

        match self.answer_rx.recv() {
            Ok(KeepAliveStreamAnswer::Write(result)) => match result {
                Ok((buf, len)) => {
                    self.write_buf = buf;
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
