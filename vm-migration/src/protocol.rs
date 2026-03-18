// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! # Migration Protocol
//!
//! ## Cross-Host Migration
//!
//! A traditional network-based live migration where all resources are
//! transmitted over the wire. Externally-provided FDs must be opened and
//! managed by the management software on the destination side.
//!
//! **Supported migration modes**:
//! - TCP (currently one single connection)
//!
//! The following mermaid sequence diagram shows a brief overview:
//!
//! <!-- Best viewed and edited here: https://mermaid.live/edit -->
//! ```mermaid
//! sequenceDiagram
//!    Source<<->>Destination: Establish connection
//!    Source->>Destination: Start
//!    Destination-->>Source: OK
//!    Source->>Destination: Config
//!      Note right of Destination: Payload: VM Config
//!    Destination-->>Source: OK
//!      Note right of Source: Start Dirty Logging
//!    loop Dirty Memory Ranges (until handover decision was made)
//!      Source->>Destination: Memory
//!        Note right of Destination: Payload: Memory Range Table
//!        Note right of Destination: Payload: Memory Content
//!      Destination-->>Source: OK
//!      Note right of Source: VM is paused after last OK
//!    end
//!    Source->>Destination: Memory
//!      Note right of Destination: Payload: Final Memory Range Table
//!      Note right of Destination: Payload: Final Memory Content
//!    Destination-->>Source: OK
//!    Source->>Destination: State
//!      Note right of Destination: Final VM State (vCPU, devices)
//!    Destination-->>Source: OK
//!    Source->>Destination: Complete
//!    Destination-->>Source: OK
//! ```
//!
//! ## Local Migration
//!
//! A simplified migration taking a few shortcuts and only working on the
//! same host. The VM memory is not transferred over the wire but instead
//! passed as memory FD.
//!
//! The following mermaid sequence diagram shows a brief overview:
//!
//! <!-- Best viewed and edited here: https://mermaid.live/edit -->
//! ```mermaid
//! sequenceDiagram
//!    Source<<->>Destination: Establish connection
//!    Source->>Destination: Start
//!    Destination-->>Source: OK
//!    loop For each Memory FD
//!      Source->>Destination: Memory FD (1/n)
//!        Note right of Destination: Payload: (slot: u32, fd: u32)
//!      Destination-->>Source: OK
//!    end
//!    Source->>Destination: Config
//!      Note right of Destination: Payload: VM Config
//!    Destination-->>Source: OK
//!      Note right of Source: VM is paused
//!    Source->>Destination: State
//!      Note right of Destination: Payload: Final VM State (vCPU, devices)
//!    Destination-->>Source: OK
//!    Source->>Destination: Complete
//!    Destination-->>Source: OK
//! ```

use std::io::{Read, Write};

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use vm_memory::{Address, ByteValued, GuestAddress, GuestAddressSpace, GuestMemory};

use crate::MigratableError;
use crate::bitpos_iterator::BitposIteratorExt;

/// The commands of the [live-migration protocol].
///
/// ### Sender State Machine
///
/// TODO refactor sender into state machine and add diagram
///
/// ### Receiver State Machine
///
/// <!-- Best viewed and edited here: https://mermaid.live/edit -->
/// ```mermaid
/// stateDiagram-v2
///     direction TB
///     [*] --> Started: Start
///     Started --> MemoryFdsReceived: MemoryFd
///     MemoryFdsReceived --> MemoryFdsReceived: MemoryFd
///     Started --> Configured: Config
///     MemoryFdsReceived --> Configured: Config
///     Configured --> Configured: Memory
///     Configured --> StateReceived: State
///     StateReceived --> Completed: Complete
/// ```
///
/// [live-migration protocol]: super::protocol
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
    KeepAlive,
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

    pub fn keep_alive() -> Self {
        Self::new(Command::KeepAlive, 0)
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRange {
    pub gpa: u64,
    pub length: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryRangeTable {
    data: Vec<MemoryRange>,
}

/// Iterator that returns the next memory range in the table,
/// making sure that the returned range is not larger than `chunk_size`.
///
/// If the iterator was configured to remove zero pages,
/// memory pages filled with only zeroes are omitted to reduce the
/// amount of data to be transmitted in a migration.
/// This relies on the migration receiver to initialize the guest
/// memory with zeroed pages.
///
/// **Note**: Do not rely on the order of the ranges returned by this
/// iterator. This allows for a more efficient implementation.
#[derive(Debug, Clone)]
struct MemoryRangeTableIterator<'a, M>
where
    M: GuestAddressSpace,
{
    /// Maximum size of a [`MemoryRange`] returned by the iterator.
    chunk_size: u64,
    /// A zero filled vector of the size of one memory page.
    /// Used to compare guest memory pages to via [`libc::memcmp`].
    zero_page: Vec<u8>,
    /// [`MemoryRange`]s that haven't been checked for zero pages yet.
    /// Only used if `self.skip_zero_pages == true`.
    unprocessed_data: Vec<MemoryRange>,
    /// Indicates whether zero pages should be skipped or not.
    skip_zero_pages: bool,
    /// [`MemoryRange`]s to be given out by the iterator.
    /// Depending on whether zero pages should be skipped, this contains all or just zero page
    /// removed [`MemoryRange`]s.
    processed_data: Vec<MemoryRange>,
    /// A reference to the memory of the guest.
    /// Used to check whether a [`MemoryRange`] contains zero pages.
    guest_memory: &'a M,
}

impl<'a, M> MemoryRangeTableIterator<'a, M>
where
    M: GuestAddressSpace,
{
    /// Creates a new [`MemoryRangeTableIterator`].
    ///
    /// The size of [`MemoryRangeTable`]s returned by the iterator is limited by `chunk_size`.
    ///
    /// If `skip_zero_pages == true`, the iterator checks whether a memory
    /// page is filled with zeroes and omits all zero filled pages.
    pub fn new(
        table: &MemoryRangeTable,
        chunk_size: u64,
        page_size: u64,
        skip_zero_pages: bool,
        guest_memory: &'a M,
    ) -> Self {
        if skip_zero_pages {
            MemoryRangeTableIterator {
                chunk_size,
                zero_page: vec![0; page_size as usize],
                unprocessed_data: table.data.clone(),
                skip_zero_pages,
                processed_data: Vec::new(),
                guest_memory,
            }
        } else {
            MemoryRangeTableIterator {
                chunk_size,
                zero_page: Vec::new(),
                unprocessed_data: Vec::new(),
                skip_zero_pages,
                processed_data: table.data.clone(),
                guest_memory,
            }
        }
    }

    /// Removes all-zero-pages from [`MemoryRangeTableIterator::data`] and populates
    /// [`MemoryRangeTableIterator::zero_removed_data`] with the non-zero-pages.
    ///
    /// # Panics
    ///
    /// Panics if a memory range is not valid for [`MemoryRangeTableIterator::guest_memory`].
    fn fill_zero_removed_data(&mut self) -> bool {
        /// Checks whether a memory region completely equal to the provided `comparison_memory`.
        ///
        /// # Panics:
        ///
        /// Panics if the `guest_memory_start` and the `comparison_memory.len()` are not valid for
        /// `guest_memory`.
        fn memory_is_equal<M>(
            guest_memory_start: u64,
            comparison_memory: &[u8],
            guest_memory: &M,
        ) -> bool
        where
            M: GuestAddressSpace,
        {
            let page_size = comparison_memory.len();
            let mem = guest_memory.memory();
            let volatile_slice = mem
                .get_slice(GuestAddress::new(guest_memory_start), page_size)
                .unwrap();
            let slice_ptr = volatile_slice.ptr_guard();
            // Shadow `slice_ptr` so the guard cannot be dropped until the end of the scope.
            let slice_ptr = slice_ptr.as_ptr().cast();
            let zero_page_ptr = comparison_memory.as_ptr().cast();

            // Potential data races between the guest writing to memory and the check whether
            // a page is all zero are handled by the page dirty logging.
            // SAFETY: Both pointers point to valid memory of length `PAGE_SIZE` and
            // neither are modified by `memcmp`.
            // See: https://man7.org/linux/man-pages/man3/memcmp.3.html
            let page_is_zero = unsafe { libc::memcmp(slice_ptr, zero_page_ptr, page_size) };
            page_is_zero == 0
        }

        if !self.skip_zero_pages {
            return false;
        }

        if let Some(memory_range) = self.unprocessed_data.pop() {
            let page_size = self.zero_page.len();
            // Avoids a bunch of `as u64` in the code.
            let page_size_u64 = page_size as u64;

            // As far as I can tell, `MemoryRange` should always start and end on page boundaries,
            // but there are not type-level guarantees, so we handle page boundaries and overshoot
            // to be safe.

            // Amount of bytes by which the gpa undershoots the page boundary.
            let gpa_page_undershoot = {
                // Amount of bytes by which the gpa overshoots the page boundary.
                let offset = memory_range.gpa % page_size_u64;
                if offset > 0 {
                    page_size_u64 - offset
                } else {
                    0
                }
            };

            // Amount of bytes by which the length overshoots the page boundary.
            let length_page_overshoot = (memory_range.length - gpa_page_undershoot) % page_size_u64;

            let first_page_boundary = memory_range.gpa + gpa_page_undershoot;
            let last_page_boundary = memory_range.gpa + memory_range.length - length_page_overshoot;
            let page_amount = (last_page_boundary - first_page_boundary) / page_size_u64;

            // The gpa of the memory range currently being built.
            let mut current_gpa = memory_range.gpa;
            // The length of memory range currently being built.
            // Initially set to the gpa page overshoot, which will be combined with the first
            // page if it is non-zero or added to `zero_removed_data` if the next page is zero.
            let mut current_length = 0;

            if gpa_page_undershoot != 0
                && !memory_is_equal(
                    current_gpa,
                    &self.zero_page[..gpa_page_undershoot as usize],
                    self.guest_memory,
                )
            {
                current_length += gpa_page_undershoot;
            }

            for page_start in
                (0..page_amount).map(|page_index| page_index * page_size_u64 + first_page_boundary)
            {
                // If the current page is zero, we push all previous non-zero pages to
                // `zero_removed_data` and set `current_gpa` to the end of the zero page while
                // resetting the length.
                if memory_is_equal(page_start, self.zero_page.as_slice(), self.guest_memory) {
                    if current_length != 0 {
                        self.processed_data.push(MemoryRange {
                            gpa: current_gpa,
                            length: current_length,
                        });
                    }
                    current_gpa += current_length + page_size_u64;
                    current_length = 0;
                } else {
                    current_length += page_size_u64;
                }
            }

            if length_page_overshoot != 0
                && !memory_is_equal(
                    current_gpa,
                    &self.zero_page[..length_page_overshoot as usize],
                    self.guest_memory,
                )
            {
                current_length += length_page_overshoot;
            }

            // If the current length is zero, the last page was a zero page.
            if current_length != 0 {
                self.processed_data.push(MemoryRange {
                    gpa: current_gpa,
                    length: current_length,
                });
            }

            true
        } else {
            false
        }
    }
}

impl<'a, M> Iterator for MemoryRangeTableIterator<'a, M>
where
    M: GuestAddressSpace,
{
    type Item = MemoryRangeTable;

    fn next(&mut self) -> Option<Self::Item> {
        let mut ranges: Vec<MemoryRange> = vec![];
        let mut ranges_size: u64 = 0;

        loop {
            assert!(ranges_size <= self.chunk_size);

            if self.processed_data.is_empty() && !self.fill_zero_removed_data() {
                break;
            }

            if ranges_size == self.chunk_size {
                break;
            }

            if let Some(range) = self.processed_data.pop() {
                let next_range: MemoryRange = if ranges_size + range.length > self.chunk_size {
                    // How many bytes we need to put back into the table.
                    let leftover_bytes = ranges_size + range.length - self.chunk_size;
                    assert!(leftover_bytes <= range.length);
                    let returned_bytes = range.length - leftover_bytes;
                    assert!(returned_bytes <= range.length);
                    assert_eq!(leftover_bytes + returned_bytes, range.length);

                    self.processed_data.push(MemoryRange {
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
    pub fn ranges(&self) -> &[MemoryRange] {
        &self.data
    }

    /// Partitions the table into chunks of at most `chunk_size` bytes.
    pub fn partition<M>(
        &self,
        chunk_size: u64,
        page_size: u64,
        skip_zero_pages: bool,
        guest_memory: &M,
    ) -> impl Iterator<Item = MemoryRangeTable>
    where
        M: GuestAddressSpace,
    {
        MemoryRangeTableIterator::new(self, chunk_size, page_size, skip_zero_pages, guest_memory)
    }

    /// Converts an iterator over a dirty bitmap into an iterator of dirty
    /// [`MemoryRange`]s, merging consecutive dirty pages into contiguous ranges.
    ///
    /// A memory page (i.e., a range) is marked dirty when its corresponding bit
    /// is set.
    fn dirty_ranges_iter(
        bitmap: impl IntoIterator<Item = u64>,
        start_addr: u64,
        page_size: u64,
    ) -> impl Iterator<Item = MemoryRange> {
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
            .map(move |r| MemoryRange {
                gpa: start_addr + r.start * page_size,
                length: (r.end - r.start) * page_size,
            })
    }

    /// Creates a new [`MemoryRangeTable`] from a bitmap (represented as
    /// multiple `u64`) where each bit corresponds to a dirty memory page.
    ///
    /// Only dirty ranges are represented in the resulting bitmap.
    pub fn from_dirty_bitmap(
        bitmap: impl IntoIterator<Item = u64>,
        start_addr: u64,
        page_size: u64,
    ) -> Self {
        Self {
            data: Self::dirty_ranges_iter(bitmap, start_addr, page_size).collect(),
        }
    }

    pub fn regions(&self) -> &[MemoryRange] {
        &self.data
    }

    pub fn push(&mut self, range: MemoryRange) {
        self.data.push(range);
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
        self.data.extend(table.data);
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
mod unit_tests {
    use vm_memory::bitmap::AtomicBitmap;
    use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryAtomic, GuestMemoryMmap};

    use crate::protocol::{MemoryRange, MemoryRangeTable};

    #[test]
    fn test_memory_range_table_from_dirty_ranges_iter() {
        let input = [0b1111_1110_1110, 0b1_0000];

        let start_gpa = 0x1000;
        let page_size = 0x1000;

        let range = MemoryRangeTable::from_dirty_bitmap(input, start_gpa, page_size);
        assert_eq!(
            range.regions(),
            &[
                MemoryRange {
                    gpa: start_gpa + page_size,
                    length: page_size * 3,
                },
                MemoryRange {
                    gpa: start_gpa + 5 * page_size,
                    length: page_size * 7,
                },
                MemoryRange {
                    gpa: start_gpa + (64 + 4) * page_size,
                    length: page_size,
                }
            ]
        );
    }

    #[test]
    fn test_memory_range_table_partition() {
        // We start the test similar as the one above, but with a input that is simpler to parse for
        // developers.
        let input = [0b11_0011_0011_0011];

        let start_gpa = 0x1000;
        let page_size = 0x1000;

        let table = MemoryRangeTable::from_dirty_bitmap(input, start_gpa, page_size);
        let expected_regions = [
            MemoryRange {
                gpa: start_gpa,
                length: page_size * 2,
            },
            MemoryRange {
                gpa: start_gpa + 4 * page_size,
                length: page_size * 2,
            },
            MemoryRange {
                gpa: start_gpa + 8 * page_size,
                length: page_size * 2,
            },
            MemoryRange {
                gpa: start_gpa + 12 * page_size,
                length: page_size * 2,
            },
        ];
        assert_eq!(table.regions(), &expected_regions);

        let ranges = expected_regions
            .clone()
            .map(|range| (GuestAddress::new(range.gpa), range.length as usize));
        let guest_memory_map: GuestMemoryMmap<AtomicBitmap> =
            GuestMemoryMmap::from_ranges(&ranges).unwrap();
        let atomic_guest_memory_map = GuestMemoryAtomic::new(guest_memory_map);

        // In the first test, we expect to see the exact same result as above, as we use the length
        // of every region (which is fixed!).
        {
            let chunks = table
                .partition(page_size * 2, page_size, false, &atomic_guest_memory_map)
                .map(|table| table.data)
                .collect::<Vec<_>>();

            // The implementation currently returns the ranges in reverse order.
            // For better testability, we reverse it.
            let chunks = chunks
                .into_iter()
                .map(|vec| vec.into_iter().rev().collect::<Vec<_>>())
                .rev()
                .collect::<Vec<_>>();

            assert_eq!(
                chunks,
                &[
                    [expected_regions[0].clone()].to_vec(),
                    [expected_regions[1].clone()].to_vec(),
                    [expected_regions[2].clone()].to_vec(),
                    [expected_regions[3].clone()].to_vec(),
                ]
            );
        }

        let ranges = expected_regions
            .clone()
            .map(|range| (GuestAddress(range.gpa), range.length as usize));

        let guest_memory_map: GuestMemoryMmap<AtomicBitmap> =
            GuestMemoryMmap::from_ranges(&ranges).unwrap();
        let atomic_guest_memory_map = GuestMemoryAtomic::new(guest_memory_map);

        // Next, we have a more sophisticated test with a chunk size of 5 pages.
        {
            let chunks = table
                .partition(page_size * 5, page_size, false, &atomic_guest_memory_map)
                .map(|table| table.data)
                .collect::<Vec<_>>();

            // The implementation currently returns the ranges in reverse order.
            // For better testability, we reverse it.
            let chunks = chunks
                .into_iter()
                .map(|vec| vec.into_iter().rev().collect::<Vec<_>>())
                .collect::<Vec<_>>();

            assert_eq!(
                chunks,
                &[
                    vec![
                        MemoryRange {
                            gpa: start_gpa + 4 * page_size,
                            length: page_size
                        },
                        MemoryRange {
                            gpa: start_gpa + 8 * page_size,
                            length: 2 * page_size
                        },
                        MemoryRange {
                            gpa: start_gpa + 12 * page_size,
                            length: 2 * page_size
                        }
                    ],
                    vec![
                        MemoryRange {
                            gpa: start_gpa,
                            length: 2 * page_size
                        },
                        MemoryRange {
                            gpa: start_gpa + 5 * page_size,
                            length: page_size
                        }
                    ]
                ]
            );
        }
    }

    #[test]
    fn test_memory_range_table_iter_skip_zero_pages_all() {
        let input = [0b11_0011_0011_0011];

        let start_gpa = 0x1000;
        let page_size = 0x1000;

        let table = MemoryRangeTable::from_dirty_bitmap(input, start_gpa, page_size);
        let expected_regions = [
            MemoryRange {
                gpa: start_gpa,
                length: page_size * 2,
            },
            MemoryRange {
                gpa: start_gpa + 4 * page_size,
                length: page_size * 2,
            },
            MemoryRange {
                gpa: start_gpa + 8 * page_size,
                length: page_size * 2,
            },
            MemoryRange {
                gpa: start_gpa + 12 * page_size,
                length: page_size * 2,
            },
        ];
        assert_eq!(table.regions(), &expected_regions);

        let ranges = expected_regions
            .clone()
            .map(|range| (GuestAddress::new(range.gpa), range.length as usize));
        let guest_memory_map: GuestMemoryMmap<AtomicBitmap> =
            GuestMemoryMmap::from_ranges(&ranges).unwrap();
        let atomic_guest_memory_map = GuestMemoryAtomic::new(guest_memory_map);

        let chunks = table
            .partition(page_size * 2, page_size, true, &atomic_guest_memory_map)
            .map(|table| table.data)
            .collect::<Vec<_>>();

        assert!(chunks.is_empty());
    }

    #[test]
    fn test_memory_range_table_iter_skip_zero_pages_some() {
        let input = [0b11_0011_0011_0011];

        let start_gpa = 0x1000;
        let page_size = 0x1000;

        let table = MemoryRangeTable::from_dirty_bitmap(input, start_gpa, page_size);
        let expected_regions = [
            MemoryRange {
                gpa: start_gpa,
                length: page_size * 2,
            },
            MemoryRange {
                gpa: start_gpa + 4 * page_size,
                length: page_size * 2,
            },
            MemoryRange {
                gpa: start_gpa + 8 * page_size,
                length: page_size * 2,
            },
            MemoryRange {
                gpa: start_gpa + 12 * page_size,
                length: page_size * 2,
            },
        ];
        assert_eq!(table.regions(), &expected_regions);

        let ranges = expected_regions
            .clone()
            .map(|range| (GuestAddress(range.gpa), range.length as usize));

        let guest_memory_map: GuestMemoryMmap<AtomicBitmap> =
            GuestMemoryMmap::from_ranges(&ranges).unwrap();

        expected_regions.iter().step_by(2).for_each(|memory_range| {
            let buffer = vec![1_u8; memory_range.length as usize];
            guest_memory_map
                .read_volatile_from(
                    GuestAddress::new(memory_range.gpa),
                    &mut buffer.as_slice(),
                    memory_range.length as usize,
                )
                .unwrap();
        });

        let atomic_guest_memory_map = GuestMemoryAtomic::new(guest_memory_map);

        // Use a large chunk_size to only return one vector.
        let chunks = table
            .partition(page_size * 20, page_size, true, &atomic_guest_memory_map)
            .map(|table| table.data)
            .collect::<Vec<_>>();

        assert_eq!(
            chunks,
            &[vec![
                MemoryRange {
                    gpa: start_gpa + 8 * page_size,
                    length: page_size * 2,
                },
                MemoryRange {
                    gpa: start_gpa,
                    length: page_size * 2,
                },
            ],]
        );
    }

    #[test]
    fn test_memory_range_table_iter_skip_zero_pages_within_range_table() {
        let input = [0b0111];

        let start_gpa = 0x1000;
        let page_size = 0x1000;

        let table = MemoryRangeTable::from_dirty_bitmap(input, start_gpa, page_size);
        let expected_regions = [MemoryRange {
            gpa: start_gpa,
            length: page_size * 3,
        }];
        assert_eq!(table.regions(), &expected_regions);

        let ranges = expected_regions
            .clone()
            .map(|range| (GuestAddress(range.gpa), range.length as usize));

        let guest_memory_map: GuestMemoryMmap<AtomicBitmap> =
            GuestMemoryMmap::from_ranges(&ranges).unwrap();

        let buffer = vec![1_u8; page_size as usize];

        guest_memory_map
            .read_volatile_from(
                GuestAddress::new(expected_regions[0].gpa),
                &mut buffer.as_slice(),
                page_size as usize,
            )
            .unwrap();

        guest_memory_map
            .read_volatile_from(
                GuestAddress::new(expected_regions[0].gpa + 2 * page_size),
                &mut buffer.as_slice(),
                page_size as usize,
            )
            .unwrap();

        let atomic_guest_memory_map = GuestMemoryAtomic::new(guest_memory_map);

        // Use a large chunk_size to only return one vector.
        let chunks = table
            .partition(page_size * 20, page_size, true, &atomic_guest_memory_map)
            .map(|table| table.data)
            .collect::<Vec<_>>();

        assert_eq!(
            chunks,
            &[vec![
                MemoryRange {
                    gpa: start_gpa + 2 * page_size,
                    length: page_size
                },
                MemoryRange {
                    gpa: start_gpa,
                    length: page_size
                }
            ],]
        );
    }

    #[test]
    fn test_memory_range_table_iter_skip_zero_pages_non_page_boundaries_all_zero() {
        let input = [0b11_0011_0000_1111];

        let start_gpa = 0x1000;
        let page_size = 0x1000;

        let mut table = MemoryRangeTable::from_dirty_bitmap(input, start_gpa, page_size);
        table.data.iter_mut().for_each(|entry| {
            entry.gpa += 10;
        });
        let expected_regions = [
            MemoryRange {
                gpa: start_gpa + 10,
                length: page_size * 4,
            },
            MemoryRange {
                gpa: start_gpa + 8 * page_size + 10,
                length: page_size * 2,
            },
            MemoryRange {
                gpa: start_gpa + 12 * page_size + 10,
                length: page_size * 2,
            },
        ];
        assert_eq!(table.regions(), &expected_regions);

        let ranges = expected_regions
            .clone()
            .map(|range| (GuestAddress(range.gpa), range.length as usize));

        let guest_memory_map: GuestMemoryMmap<AtomicBitmap> =
            GuestMemoryMmap::from_ranges(&ranges).unwrap();
        let atomic_guest_memory_map = GuestMemoryAtomic::new(guest_memory_map);

        // Use a large chunk_size to only return one vector.
        let chunks = table
            .partition(page_size * 20, page_size, true, &atomic_guest_memory_map)
            .map(|table| table.data)
            .collect::<Vec<_>>();

        assert!(chunks.is_empty());
    }

    #[test]
    fn test_memory_range_table_iter_skip_zero_pages_non_page_boundaries_all_non_zero() {
        let input = [0b11_0011_0000_1111];

        let start_gpa = 0x1000;
        let page_size = 0x1000;

        let mut table = MemoryRangeTable::from_dirty_bitmap(input, start_gpa, page_size);
        table.data.iter_mut().for_each(|entry| {
            entry.gpa += 10;
        });
        let expected_regions = [
            MemoryRange {
                gpa: start_gpa + 10,
                length: page_size * 4,
            },
            MemoryRange {
                gpa: start_gpa + 8 * page_size + 10,
                length: page_size * 2,
            },
            MemoryRange {
                gpa: start_gpa + 12 * page_size + 10,
                length: page_size * 2,
            },
        ];
        assert_eq!(table.regions(), &expected_regions);

        let ranges = expected_regions
            .clone()
            .map(|range| (GuestAddress(range.gpa), range.length as usize));

        let guest_memory_map: GuestMemoryMmap<AtomicBitmap> =
            GuestMemoryMmap::from_ranges(&ranges).unwrap();

        expected_regions.iter().for_each(|memory_range| {
            let buffer = vec![1_u8; memory_range.length as usize];

            guest_memory_map
                .read_volatile_from(
                    GuestAddress::new(memory_range.gpa),
                    &mut buffer.as_slice(),
                    memory_range.length as usize,
                )
                .unwrap();
        });

        let atomic_guest_memory_map = GuestMemoryAtomic::new(guest_memory_map);

        // Use a large chunk_size to only return one vector.
        let chunks = table
            .partition(page_size * 20, page_size, true, &atomic_guest_memory_map)
            .map(|table| table.data)
            .collect::<Vec<_>>();

        let mut expected_chunks = expected_regions.clone();
        expected_chunks.reverse();
        assert_eq!(chunks, &[expected_chunks]);
    }
}
