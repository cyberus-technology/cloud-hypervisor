// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

#[cfg(target_arch = "x86_64")]
use std::collections::btree_map::BTreeMap;
use std::result::Result;

use thiserror::Error;

/// GsiApic
#[cfg(target_arch = "x86_64")]
#[derive(Copy, Clone)]
pub struct GsiApic {
    base: u32,
    irqs: u32,
}

#[cfg(target_arch = "x86_64")]
impl GsiApic {
    /// New GSI APIC
    pub fn new(base: u32, irqs: u32) -> Self {
        GsiApic { base, irqs }
    }
}

// This interrupt allocator is a simple bitmap that stores which interrupt
// vectors are currently in use. The allocator has an offset, e.g. if you want
// to have vectors in the range of [512, 1024), you should choose an offset and
// a size of 512.
#[derive(Debug)]
struct InterruptAllocator {
    // Although this is used as a bitmap, it is a collection of `usize`. Thus the
    // name `words`.
    words: Box<[usize]>,
    size: u32,
    offset: u32,
}

/// Errors that may happen while allocating or freeing an interrupt.
#[derive(Error, Debug, PartialEq)]
pub enum InterruptAllocError {
    /// Interrupt allocator is exhausted, i.e. out of interrupt vectors.
    #[error("Interrupt allocator is exhausted (capacity: {0})")]
    ExhaustedError(u32 /* capacity/size */),

    /// Tried to free an interrupt that wasn't allocated.
    #[error("Interrupt was not allocated: {0}")]
    AlreadyFree(u32 /* vector */),

    /// Tried to free an interrupt that is not in range of the interrupt allocator.
    #[error("Interrupt vector is out of range: {0} (range: [{1},{2})")]
    OutOfRange(
        u32, /* vector */
        u32, /* lower bound */
        u32, /* upper bound */
    ),
}

// Maximum number of IRQ routes according to the kernel code.
const KVM_MAX_IRQ_ROUTES: u32 = 4096;

impl InterruptAllocator {
    fn new(size: u32, offset: u32) -> Self {
        assert_ne!(size, 0);
        let num_words = (size + usize::BITS - 1).div_euclid(usize::BITS);

        let mut words = vec![0usize; num_words as usize].into_boxed_slice();
        words[(num_words - 1) as usize] = Self::last_word(size);

        Self {
            words,
            size,
            offset,
        }
    }

    // Returns the mask of the last word. E.g. if our words would be of type u8, and
    // we want a size of (n * 8 + 4) (e.g. 12), this would return 0b11110000.
    fn last_word(size: u32) -> usize {
        let rem = size % usize::BITS;
        if rem == 0 {
            0usize
        } else {
            !((1usize << rem) - 1)
        }
    }

    fn free(&mut self, vector: u32) -> Result<(), InterruptAllocError> {
        // At first we make sure that the vector is not out of range.
        if !(self.offset..self.offset + self.size).contains(&vector) {
            return Err(InterruptAllocError::OutOfRange(
                vector,
                self.offset,
                self.offset + self.size,
            ));
        }

        let idx = vector.abs_diff(self.offset);
        let (w, b) = Self::word_and_bit(idx);

        let mask = 1usize << b;

        // Let's first check whether the bit is set.
        if self.words[w] & mask == 0usize {
            return Err(InterruptAllocError::AlreadyFree(vector));
        }
        // Clear the bit and we are done!
        self.words[w] &= !mask;
        Ok(())
    }

    fn word_and_bit(
        vector: u32,
    ) -> (
        usize, /* index into `words` */
        usize, /* index into `words[w]` */
    ) {
        let idx = vector as usize;
        let bits = usize::BITS as usize;
        (idx / bits, idx % bits)
    }

    fn alloc(&mut self) -> Result<u32, InterruptAllocError> {
        let bits = usize::BITS as usize;
        if let Some(idx) = self.words.iter().position(|&w| w != usize::MAX) {
            let word: &mut usize = &mut self.words[idx];
            // Find lowest free bit.
            let bit = (!*word).trailing_zeros() as usize;
            // Set the bit.
            *word |= 1usize << bit;
            // Calculate index, add offset and return.
            let vector = idx * bits + bit;
            return Ok(vector as u32 + self.offset);
        }
        Err(InterruptAllocError::ExhaustedError(self.size))
    }

    fn size(&self) -> u32 {
        self.size
    }
}

/// GsiAllocator
pub struct GsiAllocator {
    #[cfg(target_arch = "x86_64")]
    apics: BTreeMap<u32, u32>,
    irqs: InterruptAllocator,
    gsis: InterruptAllocator,
}

impl GsiAllocator {
    #[cfg(target_arch = "x86_64")]
    /// New GSI allocator
    pub fn new(apics: &[GsiApic]) -> Self {
        let mut allocator_apics = BTreeMap::new();
        let mut next_irq = 0xffff_ffffu32;
        let mut next_gsi = 0u32;

        for apic in apics {
            if apic.base < next_irq {
                next_irq = apic.base;
            }

            if apic.base + apic.irqs > next_gsi {
                next_gsi = apic.base + apic.irqs;
            }

            allocator_apics.insert(apic.base, apic.irqs);
        }

        Self {
            apics: allocator_apics,
            irqs: InterruptAllocator::new(KVM_MAX_IRQ_ROUTES - next_irq, next_irq),
            gsis: InterruptAllocator::new(KVM_MAX_IRQ_ROUTES - next_gsi, next_gsi),
        }
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    /// New GSI allocator
    pub fn new() -> Self {
        GsiAllocator {
            irqs: InterruptAllocator::new(KVM_MAX_IRQ_ROUTES - arch::IRQ_BASE, arch::IRQ_BASE),
            gsis: InterruptAllocator::new(KVM_MAX_IRQ_ROUTES - arch::IRQ_BASE, arch::IRQ_BASE),
        }
    }

    /// Allocate a GSI
    pub fn allocate_gsi(&mut self) -> Result<u32, InterruptAllocError> {
        self.gsis.alloc()
    }

    /// Frees a GSI
    pub fn free_gsi(&mut self, vector: u32) -> Result<(), InterruptAllocError> {
        self.gsis.free(vector)
    }

    #[cfg(target_arch = "x86_64")]
    /// Allocate an IRQ
    pub fn allocate_irq(&mut self) -> Result<u32, InterruptAllocError> {
        let next_irq = self.irqs.alloc()?;
        for (base, irqs) in self.apics.iter() {
            // HACKHACK - This only works with 1 single IOAPIC...
            if next_irq >= *base && next_irq < *base + *irqs {
                return Ok(next_irq);
            }
        }

        self.irqs.free(next_irq)?;
        Err(InterruptAllocError::ExhaustedError(self.irqs.size()))
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    /// Allocate an IRQ
    pub fn allocate_irq(&mut self) -> Result<u32, InterruptAllocError> {
        self.irqs.alloc()
    }
}

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
impl Default for GsiAllocator {
    fn default() -> Self {
        GsiAllocator::new()
    }
}

#[cfg(test)]
mod unit_tests {
    use super::{InterruptAllocError, InterruptAllocator};

    #[test]
    // Checks that the allocator can only allocate as many vectors as configured.
    fn test_allocator_respects_size() {
        for size in [1, 8, 16, 17, 32, 64, 65, 128] {
            let mut allocator = InterruptAllocator::new(size, 0);
            let mut num_vectors = 0u32;

            loop {
                let vec = allocator.alloc();
                match vec {
                    Ok(_) => {
                        num_vectors += 1;
                        continue;
                    }
                    Err(e) => match e {
                        InterruptAllocError::ExhaustedError(_) => {
                            assert_eq!(size, num_vectors);
                            break;
                        }
                        _ => panic!(),
                    },
                }
            }
            assert_eq!(size, num_vectors);
        }
    }

    #[test]
    // Checks that the allocator starts allocating vectors at the given offset.
    fn test_allocator_respects_offset() {
        for offset in [1, 8, 16, 17, 32, 64, 65, 128] {
            let mut allocator = InterruptAllocator::new(1, offset);
            let vec = allocator.alloc().unwrap();

            assert_eq!(offset, vec);
            allocator.free(vec).unwrap();
        }
    }

    #[test]
    // Checks that the calculations in alloc and free are correct.
    fn test_allocator_alloc_and_free_all_vectors() {
        for size in [1, 8, 16, 17, 32, 64, 65, 128, 4096] {
            let mut allocator = InterruptAllocator::new(size, 0);
            let mut num_vectors = 0u32;

            while allocator.alloc().is_ok() {
                num_vectors += 1;
            }

            assert_eq!(size, num_vectors);
            num_vectors -= 1;

            loop {
                if let Err(e) = allocator.free(num_vectors) {
                    println!("Could not free {num_vectors}: {e}");
                    break;
                }
                if let Some(v) = num_vectors.checked_sub(1) {
                    num_vectors = v;
                } else {
                    break;
                }
            }
        }
    }

    #[test]
    // Checks that freeing a vector that isn't allocated results in an error.
    fn test_can_only_free_allocated_vectors() {
        let mut allocator = InterruptAllocator::new(1, 0);

        let vec = allocator.alloc().unwrap();
        allocator.free(vec).unwrap();

        let e = allocator.free(vec);
        assert_eq!(e, Err(InterruptAllocError::AlreadyFree(vec)));
    }

    #[test]
    // Checks that freeing a vector that is not in range of the allocator results
    // in an error.
    fn test_can_only_free_vectors_in_range() {
        let size = 1u32;
        let offset = 0u32;
        let mut allocator = InterruptAllocator::new(size, 0);

        // The allocator has vectors from `0 .. size - 1`, this `size` should be
        // out of range.
        let e = allocator.free(size);
        assert_eq!(
            e,
            Err(InterruptAllocError::OutOfRange(size, offset, offset + size))
        );
    }
}
