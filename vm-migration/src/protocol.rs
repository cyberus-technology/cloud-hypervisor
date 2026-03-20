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

use anyhow::anyhow;
use arch::PAGE_SIZE;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use vm_memory::{Address, GuestAddress, GuestAddressSpace, GuestMemory};
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes};

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
#[derive(
    Debug, Copy, Clone, Default, PartialEq, Eq, Immutable, IntoBytes, KnownLayout, TryFromBytes,
)]
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
#[derive(Default, Copy, Clone, Immutable, IntoBytes, KnownLayout, TryFromBytes)]
pub struct Request {
    command: Command,
    padding: [u8; 6],
    length: u64, // Length of payload for command excluding the Request struct
}

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
        /// A byte buffer that matches `Self` in size and alignment to allow deserializing `Self` into.
        #[repr(C, align(8))]
        struct RequestBuffer([u8; const { size_of::<Request>() }]);
        const _: () = const {
            // Check that the alignment of the buffer matches `Self`.
            assert!(align_of::<RequestBuffer>() == align_of::<Request>());
        };
        let mut buffer = RequestBuffer([0; size_of::<Self>()]);
        let RequestBuffer(request) = &mut buffer;

        loop {
            fd.read_exact(request)
                .map_err(MigratableError::MigrateSocket)?;

            let request = Self::try_mut_from_bytes(request)
                .map_err(|error| MigratableError::DeserializeError(anyhow!("{error:?}")))?;

            // If we read a keep alive message, we throw it away and keep reading.
            if request.command() == Command::KeepAlive {
                *request = Request::default();
                continue;
            }
            return Ok(*request);
        }
    }

    pub fn write_to(&self, fd: &mut dyn Write) -> Result<(), MigratableError> {
        fd.write_all(self.as_bytes())
            .map_err(MigratableError::MigrateSocket)
    }
}

#[repr(u16)]
#[derive(Copy, Clone, PartialEq, Eq, Default, Immutable, IntoBytes, KnownLayout, TryFromBytes)]
pub enum Status {
    #[default]
    Invalid,
    Ok,
    Error,
    KeepAlive,
}

#[repr(C)]
#[derive(Default, Copy, Clone, Immutable, IntoBytes, KnownLayout, TryFromBytes)]
pub struct Response {
    status: Status,
    padding: [u8; 6],
    length: u64, // Length of payload for command excluding the Response struct
}

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

    pub fn keep_alive() -> Self {
        Self::new(Status::KeepAlive, 0)
    }

    pub fn status(&self) -> Status {
        self.status
    }

    pub fn length(&self) -> u64 {
        self.length
    }

    pub fn read_from(fd: &mut dyn Read) -> Result<Response, MigratableError> {
        /// A byte buffer that matches `Self` in size and alignment to allow deserializing `Self` into.
        #[repr(C, align(8))]
        struct ResponseBuffer([u8; const { size_of::<Response>() }]);
        const _: () = const {
            // Check that the alignment of the buffer matches `Self`.
            assert!(align_of::<ResponseBuffer>() == align_of::<Response>());
        };
        let mut buffer = ResponseBuffer([0; size_of::<Self>()]);
        let ResponseBuffer(response) = &mut buffer;

        loop {
            fd.read_exact(response)
                .map_err(MigratableError::MigrateSocket)?;

            let response = Self::try_mut_from_bytes(response)
                .map_err(|error| MigratableError::DeserializeError(anyhow!("{error:?}")))?;

            // If we read a keep alive message, we throw it away and keep reading.
            if response.status() == Status::KeepAlive {
                *response = Response::default();
                continue;
            }
            return Ok(*response);
        }
    }

    /// Return the response if its status is `Ok`; return the caller-provided error for any other status.
    pub fn ok_or_error(self, error: MigratableError) -> Result<Response, MigratableError> {
        if self.status != Status::Ok {
            return Err(error);
        }
        Ok(self)
    }

    pub fn write_to(&self, fd: &mut dyn Write) -> Result<(), MigratableError> {
        fd.write_all(self.as_bytes())
            .map_err(MigratableError::MigrateSocket)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRange {
    pub gpa: u64,
    pub length: u64,
}

/// Checks whether a guest memory region is equal to the provided `comparison_memory`.
fn guest_memory_is_equal<M>(
    guest_memory_start: u64,
    comparison_memory: &[u8],
    guest_memory: &M,
) -> Result<bool, vm_memory::guest_memory::Error>
where
    M: GuestAddressSpace,
{
    let cmp_mem_length = comparison_memory.len();
    let guest_memory = guest_memory.memory();
    let volatile_slice =
        guest_memory.get_slice(GuestAddress::new(guest_memory_start), cmp_mem_length)?;
    let slice_ptr = volatile_slice.ptr_guard();
    // Shadow `slice_ptr` so the guard cannot be dropped until the end of the scope.
    let slice_ptr = slice_ptr.as_ptr().cast();
    let comparison_memory_ptr = comparison_memory.as_ptr().cast();

    // Potential data races between the guest writing to memory and the check whether
    // a page is all zero are handled by the page dirty logging.
    // SAFETY: Both pointers point to valid memory of length `cmp_mem_length` and
    // neither are modified by `memcmp`.
    // See: https://man7.org/linux/man-pages/man3/memcmp.3.html
    let memory_is_equal = unsafe { libc::memcmp(slice_ptr, comparison_memory_ptr, cmp_mem_length) };
    Ok(memory_is_equal == 0)
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
                    assert_eq!(leftover_bytes + returned_bytes, range.length);

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
    pub fn ranges(&self) -> &[MemoryRange] {
        &self.data
    }

    /// Partitions the table into chunks of at most `chunk_size` bytes.
    pub fn partition(&self, chunk_size: u64) -> impl Iterator<Item = MemoryRangeTable> {
        MemoryRangeTableIterator::new(self, chunk_size)
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

    /// Creates a new `MemoryRangeTable` from `Self` with all zero-pages removed.
    ///
    /// Also removes non-page aligned parts of any `MemoryRange` that is zero-filled in the
    /// `guest_memory`.
    pub fn remove_zero_pages<M>(
        &self,
        guest_memory: &M,
    ) -> Result<Self, vm_memory::guest_memory::Error>
    where
        M: GuestAddressSpace,
    {
        let mut processed_data = Vec::new();
        const ZERO_PAGE: [u8; PAGE_SIZE] = [0_u8; PAGE_SIZE];

        self.data
            .iter()
            .try_for_each::<_, Result<(), vm_memory::guest_memory::Error>>(|memory_range| {
                // Avoids a bunch of `as u64` in the code.
                let page_size_u64 = PAGE_SIZE as u64;

                // As far as I can tell, `MemoryRange` should always start and end on page boundaries,
                // but there are no type-level guarantees, so we handle page boundaries and overshoot
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
                let length_page_overshoot =
                    (memory_range.length - gpa_page_undershoot) % page_size_u64;

                let first_page_boundary = memory_range.gpa + gpa_page_undershoot;
                let last_page_boundary =
                    memory_range.gpa + memory_range.length - length_page_overshoot;
                let page_amount = (last_page_boundary - first_page_boundary) / page_size_u64;

                // The gpa of the memory range currently being built.
                let mut current_gpa = memory_range.gpa;
                // The length of memory range currently being built.
                // Initially set to the gpa page overshoot, which will be combined with the first
                // page if it is non-zero or added to `processed_data` if the next page is zero.
                let mut current_length = 0;

                if gpa_page_undershoot != 0 {
                    if guest_memory_is_equal(
                        current_gpa,
                        &ZERO_PAGE[..gpa_page_undershoot as usize],
                        guest_memory,
                    )? {
                        current_gpa += gpa_page_undershoot;
                    } else {
                        current_length += gpa_page_undershoot;
                    }
                }

                for page_start in (0..page_amount)
                    .map(|page_index| page_index * page_size_u64 + first_page_boundary)
                {
                    // If the current page is zero, we push all previous non-zero pages to
                    // `processed_data` and set `current_gpa` to the end of the zero page while
                    // resetting the length.
                    if guest_memory_is_equal(page_start, &ZERO_PAGE, guest_memory)? {
                        if current_length != 0 {
                            processed_data.push(MemoryRange {
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
                    && !guest_memory_is_equal(
                        current_gpa,
                        &ZERO_PAGE[..length_page_overshoot as usize],
                        guest_memory,
                    )?
                {
                    current_length += length_page_overshoot;
                }

                // If the current length is zero, the last page was a zero page.
                if current_length != 0 {
                    processed_data.push(MemoryRange {
                        gpa: current_gpa,
                        length: current_length,
                    });
                }
                Ok(())
            })?;

        Ok(Self {
            data: processed_data,
        })
    }
}

#[cfg(test)]
mod unit_tests {
    use arch::PAGE_SIZE;
    use vm_memory::bitmap::AtomicBitmap;
    use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryAtomic, GuestMemoryMmap};

    use crate::protocol::{MemoryRange, MemoryRangeTable, guest_memory_is_equal};

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

        // In the first test, we expect to see the exact same result as above, as we use the length
        // of every region (which is fixed!).
        {
            let chunks = table
                .partition(page_size * 2)
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

        // Next, we have a more sophisticated test with a chunk size of 5 pages.
        {
            let chunks = table
                .partition(page_size * 5)
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
    fn test_guest_memory_is_equal_success() {
        let start_gpa = 0x1000;
        let page_size = PAGE_SIZE as u64;

        let expected_regions = vec![MemoryRange {
            gpa: start_gpa,
            length: page_size * 2,
        }];

        let memory_range_table = MemoryRangeTable {
            data: expected_regions,
        };

        let ranges: Vec<_> = memory_range_table
            .ranges()
            .iter()
            .map(|range| (GuestAddress(range.gpa), range.length as usize))
            .collect();

        let guest_memory_map: GuestMemoryMmap<AtomicBitmap> =
            GuestMemoryMmap::from_ranges(&ranges).unwrap();

        let atomic_guest_memory_map = GuestMemoryAtomic::new(guest_memory_map);

        let result = guest_memory_is_equal(
            start_gpa,
            &vec![0; page_size as usize],
            &atomic_guest_memory_map,
        )
        .unwrap();

        assert!(result);
    }

    #[test]
    fn test_guest_memory_is_equal_invalid_memory_range() {
        let start_gpa = 0x1000;
        let page_size = PAGE_SIZE as u64;

        let memory_ranges = vec![MemoryRange {
            gpa: start_gpa,
            length: page_size * 2,
        }];

        let memory_range_table = MemoryRangeTable {
            data: memory_ranges,
        };

        let ranges: Vec<_> = memory_range_table
            .ranges()
            .iter()
            .map(|range| (GuestAddress(range.gpa), range.length as usize))
            .collect();

        let guest_memory_map: GuestMemoryMmap<AtomicBitmap> =
            GuestMemoryMmap::from_ranges(&ranges).unwrap();
        let atomic_guest_memory_map = GuestMemoryAtomic::new(guest_memory_map);

        let result = guest_memory_is_equal(
            start_gpa - 10,
            &vec![0; page_size as usize],
            &atomic_guest_memory_map,
        )
        .unwrap_err();

        if let vm_memory::guest_memory::Error::InvalidGuestAddress(GuestAddress(guest_address)) =
            result
        {
            assert_eq!(guest_address, 4086);
        } else {
            panic!("`guest_memory_is_equal` returned wrong error")
        }
    }

    #[test]
    fn test_memory_range_table_remove_zero_pages() {
        let start_gpa = 0x1000;
        let page_size = PAGE_SIZE as u64;

        let expected_regions = vec![MemoryRange {
            gpa: start_gpa,
            length: page_size * 2,
        }];

        let memory_range_table = MemoryRangeTable {
            data: expected_regions,
        };

        let ranges: Vec<_> = memory_range_table
            .ranges()
            .iter()
            .map(|range| (GuestAddress(range.gpa), range.length as usize))
            .collect();

        let guest_memory_map: GuestMemoryMmap<AtomicBitmap> =
            GuestMemoryMmap::from_ranges(&ranges).unwrap();
        let atomic_guest_memory_map = GuestMemoryAtomic::new(guest_memory_map);

        let result = memory_range_table.remove_zero_pages(&atomic_guest_memory_map);

        assert!(result.unwrap().ranges().is_empty());
    }

    #[test]
    fn test_memory_range_table_remove_zero_pages_all() {
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

        assert!(
            table
                .remove_zero_pages(&atomic_guest_memory_map)
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn test_memory_range_table_remove_zero_pages_some() {
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

        assert_eq!(
            table
                .remove_zero_pages(&atomic_guest_memory_map)
                .unwrap()
                .ranges(),
            &[
                MemoryRange {
                    gpa: start_gpa,
                    length: page_size * 2,
                },
                MemoryRange {
                    gpa: start_gpa + 8 * page_size,
                    length: page_size * 2,
                },
            ]
        );
    }

    #[test]
    fn test_memory_range_table_remove_zero_pages_within_range_table() {
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

        assert_eq!(
            table
                .remove_zero_pages(&atomic_guest_memory_map)
                .unwrap()
                .ranges(),
            &[
                MemoryRange {
                    gpa: start_gpa,
                    length: page_size
                },
                MemoryRange {
                    gpa: start_gpa + 2 * page_size,
                    length: page_size
                },
            ]
        );
    }

    #[test]
    fn test_memory_range_table_remove_zero_pages_non_page_boundaries_all_zero() {
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

        assert!(
            table
                .remove_zero_pages(&atomic_guest_memory_map)
                .unwrap()
                .ranges()
                .is_empty()
        );
    }

    #[test]
    fn test_memory_range_table_remove_zero_pages_non_page_boundaries_all_non_zero() {
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

        assert_eq!(
            table
                .remove_zero_pages(&atomic_guest_memory_map)
                .unwrap()
                .ranges(),
            expected_regions
        );
    }

    #[test]
    fn test_memory_range_table_remove_zero_pages_within_memory_range() {
        let start_gpa = 0x1000;
        let page_size = 0x1000;

        let table = MemoryRangeTable {
            data: vec![MemoryRange {
                gpa: start_gpa - 0x800,
                length: 0x800 + 2 * page_size,
            }],
        };

        let ranges: Vec<(GuestAddress, usize)> = table
            .ranges()
            .iter()
            .clone()
            .map(|range| (GuestAddress(range.gpa), range.length as usize))
            .collect();

        let guest_memory_map: GuestMemoryMmap<AtomicBitmap> =
            GuestMemoryMmap::from_ranges(&ranges).unwrap();

        let buffer = vec![1_u8; page_size as usize];

        guest_memory_map
            .read_volatile_from(
                GuestAddress::new(start_gpa),
                &mut buffer.as_slice(),
                page_size as usize,
            )
            .unwrap();

        let atomic_guest_memory_map = GuestMemoryAtomic::new(guest_memory_map);

        assert_eq!(
            table
                .remove_zero_pages(&atomic_guest_memory_map)
                .unwrap()
                .ranges(),
            [MemoryRange {
                gpa: start_gpa,
                length: page_size,
            },]
        );
    }
}
