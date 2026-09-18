// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::VecDeque;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_BUFFER_SIZE: usize = 1 << 20;

// Circular buffer implementation for serial output.
// Read from head; push to tail
pub struct SerialBuffer {
    buffer: VecDeque<u8>,
    out: Box<dyn Write + Send>,
    write_out: Arc<AtomicBool>,
}

impl SerialBuffer {
    pub fn new(out: Box<dyn Write + Send>, write_out: Arc<AtomicBool>) -> Self {
        Self {
            buffer: VecDeque::new(),
            out,
            write_out,
        }
    }

    fn fill_buffer(&mut self, buf: &[u8]) {
        if buf.len() >= MAX_BUFFER_SIZE {
            let offset = buf.len() - MAX_BUFFER_SIZE;
            self.buffer = VecDeque::from(buf[offset..].to_vec());
            return;
        }

        let num_allowed_bytes = MAX_BUFFER_SIZE - buf.len();
        if self.buffer.len() > num_allowed_bytes {
            let num_bytes_to_remove = self.buffer.len() - num_allowed_bytes;
            self.buffer.drain(..num_bytes_to_remove);
        }

        self.buffer.extend(buf);
    }
}

impl Write for SerialBuffer {
    fn write(&mut self, data: &[u8]) -> Result<usize, std::io::Error> {
        // Simply fill the buffer if we're not allowed to write to the out
        // device.
        if !self.write_out.load(Ordering::Acquire) {
            self.fill_buffer(data);
            return Ok(data.len());
        }

        // In case we're allowed to write to the out device, we flush the
        // content of the buffer.
        self.flush()?;

        // If after flushing the buffer, it's still not empty, that means
        // only a subset of the bytes was written and we should fill the buffer
        // with what's coming from the serial.
        if !self.buffer.is_empty() {
            self.fill_buffer(data);
            return Ok(data.len());
        }

        // First try writing directly to the output device; if that fails,
        // buffer the data in memory for later.
        let mut offset = 0;
        while offset < data.len() {
            match self.out.write(&data[offset..]) {
                Ok(0) => {
                    self.fill_buffer(&data[offset..]);
                    break;
                }
                Ok(written) => {
                    offset += written;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    self.fill_buffer(&data[offset..]);
                    break;
                }
                Err(e) => return Err(e),
            }
        }

        // Make sure we flush anything that might have been written to the
        // out device.
        self.out.flush()?;

        Ok(data.len())
    }

    // This function flushes the content of the buffer to the out device if
    // it is allowed to, otherwise this is a no-op.
    fn flush(&mut self) -> Result<(), std::io::Error> {
        if !self.write_out.load(Ordering::Acquire) {
            return Ok(());
        }

        while let Some(byte) = self.buffer.pop_front() {
            if self.out.write_all(&[byte]).is_err() {
                self.buffer.push_front(byte);
                break;
            }
        }
        self.out.flush()
    }
}
