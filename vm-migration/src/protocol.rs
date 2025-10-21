// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io::{Read, Write};

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use vm_memory::ByteValued;

use crate::MigratableError;
use crate::bitpos_iterator::BitposIteratorExt;

// Migration protocol
// 1: Source establishes communication with destination (file socket or TCP connection.)
// (The establishment is out of scope.)
// 2: Source -> Dest : send "start command"
// 3: Dest -> Source : sends "ok response" when read to accept state data
// 4: Source -> Dest : sends "config command" followed by config data, length
//                     in command is length of config data
// 5: Dest -> Source : sends "ok response" when ready to accept memory data
// 6: Source -> Dest : send "memory command" followed by table of u64 pairs (GPA, size)
//                     followed by the memory described in those pairs.
//                     !! length is size of table i.e. 16 * number of ranges !!
// 7: Dest -> Source : sends "ok response" when ready to accept more memory data
// 8..(n-4): Repeat steps 6 and 7 until source has no more memory to send
// (n-3): Source -> Dest : sends "state command" followed by state data, length
//                     in command is length of config data
// (n-2): Dest -> Source : sends "ok response"
// (n-1): Source -> Dest : send "complete command"
// n: Dest -> Source: sends "ok response"
//
// "Local version": (Handing FDs across socket for memory)
// 1: Source establishes communication with destination (file socket or TCP connection.)
// (The establishment is out of scope.)
// 2: Source -> Dest : send "start command"
// 3: Dest -> Source : sends "ok response" when read to accept state data
// 4: Source -> Dest : sends "config command" followed by config data, length
//                     in command is length of config data
// 5: Dest -> Source : sends "ok response" when ready to accept memory data
// 6: Source -> Dest : send "memory fd command" followed by u16 slot ID and FD for memory
// 7: Dest -> Source : sends "ok response" when received
// 8..(n-4): Repeat steps 6 and 7 until source has no more memory to send
// (n-3): Source -> Dest : sends "state command" followed by state data, length
//                     in command is length of config data
// (n-2): Dest -> Source : sends "ok response"
// (n-1): Source -> Dest : send "complete command"
// n: Dest -> Source: sends "ok response"
//
// The destination can at any time send an "error response" to cancel
// The source can at any time send an "abandon request" to cancel

#[repr(u16)]
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub enum Command {
    #[default]
    Invalid,
    Start,
    Config,
    State,
    Memory,
    Complete,
    Abandon,
    MemoryFd,
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct Request {
    command: Command,
    padding: [u8; 6],
    length: u64, // Length of payload for command excluding the Request struct
}

// SAFETY: Request contains a series of integers with no implicit padding
unsafe impl ByteValued for Request {}

impl Request {
    pub fn new(command: Command, length: u64) -> Self {
        Self {
            command,
            length,
            ..Default::default()
        }
    }

    pub fn start() -> Self {
        Self::new(Command::Start, 0)
    }

    pub fn state(length: u64) -> Self {
        Self::new(Command::State, length)
    }

    pub fn config(length: u64) -> Self {
        Self::new(Command::Config, length)
    }

    pub fn memory(length: u64) -> Self {
        Self::new(Command::Memory, length)
    }

    pub fn memory_fd(length: u64) -> Self {
        Self::new(Command::MemoryFd, length)
    }

    pub fn complete() -> Self {
        Self::new(Command::Complete, 0)
    }

    pub fn abandon() -> Self {
        Self::new(Command::Abandon, 0)
    }

    pub fn command(&self) -> Command {
        self.command
    }

    pub fn length(&self) -> u64 {
        self.length
    }

    pub fn read_from(fd: &mut dyn Read) -> Result<Request, MigratableError> {
        let mut request = Request::default();
        fd.read_exact(Self::as_mut_slice(&mut request))
            .map_err(MigratableError::MigrateSocket)?;

        Ok(request)
    }

    pub fn write_to(&self, fd: &mut dyn Write) -> Result<(), MigratableError> {
        fd.write_all(Self::as_slice(self))
            .map_err(MigratableError::MigrateSocket)
    }
}

#[repr(u16)]
#[derive(Copy, Clone, PartialEq, Eq, Default)]
pub enum Status {
    #[default]
    Invalid,
    Ok,
    Error,
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct Response {
    status: Status,
    padding: [u8; 6],
    length: u64, // Length of payload for command excluding the Response struct
}

// SAFETY: Response contains a series of integers with no implicit padding
unsafe impl ByteValued for Response {}

impl Response {
    pub fn new(status: Status, length: u64) -> Self {
        Self {
            status,
            length,
            ..Default::default()
        }
    }

    pub fn ok() -> Self {
        Self::new(Status::Ok, 0)
    }

    pub fn error() -> Self {
        Self::new(Status::Error, 0)
    }

    pub fn status(&self) -> Status {
        self.status
    }

    pub fn length(&self) -> u64 {
        self.length
    }

    pub fn read_from(fd: &mut dyn Read) -> Result<Response, MigratableError> {
        let mut response = Response::default();
        fd.read_exact(Self::as_mut_slice(&mut response))
            .map_err(MigratableError::MigrateSocket)?;

        Ok(response)
    }

    pub fn ok_or_abandon<T>(
        self,
        fd: &mut T,
        error: MigratableError,
    ) -> Result<Response, MigratableError>
    where
        T: Read + Write,
    {
        if self.status != Status::Ok {
            Request::abandon().write_to(fd)?;
            Response::read_from(fd)?;
            return Err(error);
        }
        Ok(self)
    }

    pub fn write_to(&self, fd: &mut dyn Write) -> Result<(), MigratableError> {
        fd.write_all(Self::as_slice(self))
            .map_err(MigratableError::MigrateSocket)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryRange {
    pub gpa: u64,
    pub length: u64,
}

impl MemoryRange {
    /// Turn an iterator over the dirty bitmap into an iterator of dirty ranges.
    pub fn dirty_ranges(
        bitmap: impl IntoIterator<Item = u64>,
        start_addr: u64,
        page_size: u64,
    ) -> impl Iterator<Item = Self> {
        bitmap
            .into_iter()
            .bit_positions()
            // Turn them into single-element ranges for coalesce.
            .map(|b| b..(b + 1))
            // Merge adjacent ranges.
            .coalesce(|prev, curr| {
                if prev.end == curr.start {
                    Ok(prev.start..curr.end)
                } else {
                    Err((prev, curr))
                }
            })
            .map(move |r| Self {
                gpa: start_addr + r.start * page_size,
                length: (r.end - r.start) * page_size,
            })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryRangeTable {
    data: Vec<MemoryRange>,
}

#[derive(Debug, Clone, Default)]
struct MemoryRangeTableIterator {
    chunk_size: u64,
    data: Vec<MemoryRange>,
}

impl MemoryRangeTableIterator {
    pub fn new(table: &MemoryRangeTable, chunk_size: u64) -> Self {
        MemoryRangeTableIterator {
            chunk_size,
            data: table.data.clone(),
        }
    }
}

impl Iterator for MemoryRangeTableIterator {
    type Item = MemoryRangeTable;

    /// Return the next memory range in the table, making sure that
    /// the returned range is not larger than `chunk_size`.
    ///
    /// **Note**: Do not rely on the order of the ranges returned by this
    /// iterator. This allows for a more efficient implementation.
    fn next(&mut self) -> Option<Self::Item> {
        let mut ranges: Vec<MemoryRange> = vec![];
        let mut ranges_size: u64 = 0;

        loop {
            assert!(ranges_size <= self.chunk_size);

            if ranges_size == self.chunk_size || self.data.is_empty() {
                break;
            }

            if let Some(range) = self.data.pop() {
                let next_range: MemoryRange = if ranges_size + range.length > self.chunk_size {
                    // How many bytes we need to put back into the table.
                    let leftover_bytes = ranges_size + range.length - self.chunk_size;
                    assert!(leftover_bytes <= range.length);
                    let returned_bytes = range.length - leftover_bytes;
                    assert!(returned_bytes <= range.length);
                    assert!(leftover_bytes + returned_bytes == range.length);

                    self.data.push(MemoryRange {
                        gpa: range.gpa + returned_bytes,
                        length: leftover_bytes,
                    });
                    MemoryRange {
                        gpa: range.gpa,
                        length: returned_bytes,
                    }
                } else {
                    range
                };

                ranges_size += next_range.length;
                ranges.push(next_range);
            }
        }

        if ranges.is_empty() {
            None
        } else {
            Some(MemoryRangeTable { data: ranges })
        }
    }
}

impl MemoryRangeTable {
    /// Partitions the table into chunks of at most `chunk_size` bytes.
    pub fn partition(&self, chunk_size: u64) -> impl Iterator<Item = MemoryRangeTable> {
        MemoryRangeTableIterator::new(self, chunk_size)
    }

    pub fn from_bitmap(
        bitmap: impl IntoIterator<Item = u64>,
        start_addr: u64,
        page_size: u64,
    ) -> Self {
        Self {
            data: MemoryRange::dirty_ranges(bitmap, start_addr, page_size).collect(),
        }
    }

    pub fn regions(&self) -> &[MemoryRange] {
        &self.data
    }

    pub fn push(&mut self, range: MemoryRange) {
        self.data.push(range)
    }

    pub fn read_from(fd: &mut dyn Read, length: u64) -> Result<MemoryRangeTable, MigratableError> {
        assert!((length as usize).is_multiple_of(size_of::<MemoryRange>()));

        let mut data: Vec<MemoryRange> = Vec::new();
        data.resize_with(
            length as usize / (std::mem::size_of::<MemoryRange>()),
            Default::default,
        );
        // SAFETY: the slice is constructed with the correct arguments
        fd.read_exact(unsafe {
            std::slice::from_raw_parts_mut(
                data.as_ptr() as *mut MemoryRange as *mut u8,
                length as usize,
            )
        })
        .map_err(MigratableError::MigrateSocket)?;

        Ok(Self { data })
    }

    pub fn length(&self) -> u64 {
        (std::mem::size_of::<MemoryRange>() * self.data.len()) as u64
    }

    pub fn write_to(&self, fd: &mut dyn Write) -> Result<(), MigratableError> {
        // SAFETY: the slice is constructed with the correct arguments
        fd.write_all(unsafe {
            std::slice::from_raw_parts(self.data.as_ptr() as *const u8, self.length() as usize)
        })
        .map_err(MigratableError::MigrateSocket)
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn extend(&mut self, table: Self) {
        self.data.extend(table.data)
    }

    pub fn new_from_tables(tables: Vec<Self>) -> Self {
        let mut data = Vec::new();
        for table in tables {
            data.extend(table.data);
        }
        Self { data }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_range_table() {
        let mut table = MemoryRangeTable::default();
        // Test blocks that are shorter than the chunk size.
        table.push(MemoryRange {
            gpa: 0,
            length: 1 << 10,
        });
        // Test blocks that are longer than the chunk size.
        table.push(MemoryRange {
            gpa: 0x1000,
            length: 3 << 20,
        });
        // And add another blocks, so we get a chunk that spans two memory
        // ranges.
        table.push(MemoryRange {
            gpa: 4 << 20,
            length: 1 << 20,
        });

        let table = table; // drop mut

        let chunks = table
            .partition(2 << 20)
            .map(|table| table.data)
            .collect::<Vec<_>>();

        // The implementation currently returns the ranges in reverse order. If
        // this tests becomes more complex, we can compare everything as sets.
        assert_eq!(
            chunks,
            vec![
                vec![
                    MemoryRange {
                        gpa: 4 << 20,
                        length: 1 << 20
                    },
                    MemoryRange {
                        gpa: 0x1000,
                        length: 1 << 20
                    }
                ],
                vec![MemoryRange {
                    gpa: 0x1000 + (1 << 20),
                    length: 2 << 20
                },],
                vec![MemoryRange {
                    gpa: 0,
                    length: 1 << 10
                }]
            ]
        );
    }
}
