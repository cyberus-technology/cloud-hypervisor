// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0

// The following is a 1:1 copy from https://github.com/phip1611/bit_ops/blob/ee5f576fae6e78ec036646977641a457bdf8bf8e/src/bitpos_iter.rs#L1

//! Module providing iterators to iterate over set bits in unsigned integers.
//!
//! See [`BitsIter`] and [`BitmapIter`]. The latter is included into Rust's
//! [`Iterator`] API via [`BitposIteratorExt`].
//!
//! # Performance
//!
//! These iterators have been trimmed for performance and were benchmarked. See
//! the project's README on GitHub for more details.

use core::fmt::Debug;
use core::ops::{Add, BitAndAssign, Sub};

/// **Internal helper** trait for [`BitsIter`].
pub trait Uint:
Copy + Eq + Add<Output = Self> + Sub<Output = Self> + Sized + BitAndAssign + TryInto<usize>
{
    /// Number of bits of that type.
    const BITS: usize;
    /// `0` value of the underlying primitive type.
    const ZERO: Self;
    /// `1` value of the underlying primitive type.
    const ONE: Self;
    /// Number of trailing zeroes.
    fn trailing_zeros(self) -> Self;
}

/// Implements the relevant bit operations for the specified primitive type.
///
/// Note that the bit positions start at `0`. The highest `bit` position thus
/// is `BITS - 1`.
macro_rules! impl_uint_trait {
    ($primitive_ty:ty) => {
        impl Uint for $primitive_ty {
            const BITS: usize = <$primitive_ty>::BITS as usize;
            const ZERO: Self = 0;
            const ONE: Self = 1;

            #[inline(always)]
            fn trailing_zeros(self) -> Self {
                <$primitive_ty>::trailing_zeros(self) as Self
            }
        }
    };
}

impl_uint_trait!(u8);
impl_uint_trait!(u16);
impl_uint_trait!(u32);
impl_uint_trait!(u64);
impl_uint_trait!(u128);
impl_uint_trait!(usize);

/// Iterator over set bits of an unsigned integer.
///
/// The index / bit position starts at `0`, the last bit position is
/// `n_bits - 1`.
///
/// The iterator can be used with [`u8`], [`u16`], [`u32`], [`u64`], [`u128`],
/// and [`usize`].
///
/// # Example
/// ```rust
/// # use bit_ops::BitsIter;
/// // also works with u16, u32, u64, u128, and usize
/// let iter = BitsIter::<u8>::new(0);
/// assert_eq!(&iter.collect::<Vec<_>>(), &[]);
///
/// let iter = BitsIter::<u8>::new(1);
/// assert_eq!(&iter.collect::<Vec<_>>(), &[0]);
///
/// let iter = BitsIter::<u8>::new(0b1010_1010);
/// assert_eq!(&iter.collect::<Vec<_>>(), &[1, 3, 5, 7]);
/// ```
#[derive(Debug)]
pub struct BitsIter<U> {
    value: U,
}

impl<U: Uint> BitsIter<U>
where
    <U as TryInto<usize>>::Error: Debug,
{
    /// Creates a new iterator.
    pub const fn new(value: U) -> Self {
        Self { value }
    }
}

impl<U: Uint> Iterator for BitsIter<U>
where
    <U as TryInto<usize>>::Error: Debug,
{
    type Item = U;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.value == U::ZERO {
            return None;
        }
        let tz = self.value.trailing_zeros();
        self.value &= self.value - U::ONE; // clear lowest set bit
        Some(tz)
    }
}

/// Iterator over set bits in (large) bitmaps, i.e., collection of unsigned
/// integers.
///
/// This wraps an iterator emitting corresponding unsigned integers and
/// uses [`BitsIter`] on each element. While doing so, [`BitmapIter`] keeps
/// track of consumed elements to properly report the bit position relative to
/// the very first bit. We basically treat the incoming [`Uint`]s as one
/// gigantic integer and just spit out which bits are set.
///
/// The iterator can be used with [`u8`], [`u16`], [`u32`], [`u64`], [`u128`],
/// and [`usize`]. The [`BitposIteratorExt`] offers a convenient way to
/// integrate this iterator in typical iterator chains.
///
/// # Example
///
/// ## Direct Usage of Iterator
/// ```rust
/// use bit_ops::BitmapIter;
///
/// // also works with u16, u32, u64, u128, and usize
/// let iter = BitmapIter::<u8, _>::new([0b1111_0010, 0b1000, 1].into_iter());
/// assert_eq!(&iter.collect::<Vec<_>>(), &[1, 4, 5, 6, 7, 11, 16]);
/// ```
///
/// ## Use via Iterator Trait Extension
/// ```rust
/// use bit_ops::BitposIteratorExt;
///
/// // also works with u16, u32, u64, u128, and usize
/// let bit_pos = [0b1111_0010_u8, 0b1000, 1].into_iter()
///     .bit_positions()
///     .collect::<Vec<_>>();
/// assert_eq!(&bit_pos, &[1, 4, 5, 6, 7, 11, 16]);
/// ```
#[derive(Debug)]
pub struct BitmapIter<U, I> {
    bitmap_iter: I,
    consumed_bits: usize,
    current_element_it: BitsIter<U>,
}

impl<U: Uint, I: Iterator<Item = U>> BitmapIter<U, I>
where
    <U as TryInto<usize>>::Error: Debug,
{
    /// Creates a new iterator.
    ///
    /// This consumes everything that implements [`IntoIterator`] for an
    /// [`Iterator`] of the corresponding [`Uint`].
    ///
    /// # Example
    /// ```rust
    /// # use bit_ops::BitmapIter;
    /// let _ = BitmapIter::<u8, _>::new([0_u8]);
    /// let _ = BitmapIter::<u16, _>::new([0_u16].iter().copied());
    /// let _ = BitmapIter::<u16, _>::new((&[0_u16]).iter().copied());
    /// let _ = BitmapIter::<usize, _>::new((vec![42_usize]));
    /// ```
    pub fn new<In: IntoIterator<IntoIter = I>>(bitmap_iter: In) -> Self {
        let mut bitmap_iter = bitmap_iter.into_iter();
        let current_element_it = BitsIter::new(bitmap_iter.next().unwrap_or(U::ZERO));
        Self {
            bitmap_iter,
            consumed_bits: 0,
            current_element_it,
        }
    }
}

impl<U: Uint, I: Iterator<Item = U>> Iterator for BitmapIter<U, I>
where
    <U as TryInto<usize>>::Error: Debug,
{
    type Item = usize;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        // PERFORMANCE: For performance-reasons, I refrain from a checked
        // addition. 2^61 bytes / 2^64 bits (usize on a 64-bit system) are more
        // than enough, and it is unlikely that users will ever have bitmaps
        // that large.
        loop {
            // We return here, if we currently have an element.
            if let Some(bit) = self.current_element_it.next() {
                // Compiled will optimize this check in most cases away.
                let bit: usize = bit.try_into().unwrap();
                // Unchecked add: see performance comment above
                return Some(self.consumed_bits + bit);
            }

            // Current byte exhausted: load next one or return `None` / exit.
            let next_byte = self.bitmap_iter.next()?;
            // Unchecked add: see performance comment above
            self.consumed_bits += U::BITS;
            self.current_element_it = BitsIter::new(next_byte);
        }
    }
}

/// Extension for the Rust standard libraries [`Iterator`] for convenient
/// integration of [`BitmapIter`].
pub trait BitposIteratorExt<U: Uint>: Iterator<Item = U> + Sized
where
    <U as TryInto<usize>>::Error: Debug,
{
    /// Creates an iterator that emits which bits are set.
    ///
    /// See [`BitmapIter`] for more details.
    ///
    /// # Example
    /// ```rust
    /// use bit_ops::BitposIteratorExt;
    /// let ones = [0b101_u64, 0, 1].into_iter()
    ///     .bit_positions()
    ///     .collect::<Vec<_>>();
    /// assert_eq!(&ones, &[0, 2, 2*64]);
    /// ```
    fn bit_positions(self) -> BitmapIter<U, Self> {
        BitmapIter::new(self)
    }
}

// Blanked implementation for all matching iterators.
impl<U: Uint, I: Iterator<Item = U> + Sized> BitposIteratorExt<U> for I where
    <U as TryInto<usize>>::Error: Debug
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    #[test]
    fn bits_iter() {
        let iter = BitsIter::<u8>::new(0);
        assert_eq!(&iter.collect::<Vec<_>>(), &[]);

        let iter = BitsIter::<u8>::new(1);
        assert_eq!(&iter.collect::<Vec<_>>(), &[0]);

        let iter = BitsIter::<u8>::new(0b1010_1010);
        assert_eq!(&iter.collect::<Vec<_>>(), &[1, 3, 5, 7]);

        let iter = BitsIter::<u8>::new(0b1111_1111);
        assert_eq!(&iter.collect::<Vec<_>>(), &[0, 1, 2, 3, 4, 5, 6, 7]);

        let iter = BitsIter::<u128>::new(0b1111_1111);
        assert_eq!(&iter.collect::<Vec<_>>(), &[0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn bitmap_iter() {
        let iter = BitmapIter::<u8, _>::new([0_u8]);
        assert_eq!(&iter.collect::<Vec<_>>(), &[]);

        let iter = BitmapIter::<u8, _>::new([0b1111_0010, 0b1000, 1]);
        assert_eq!(&iter.collect::<Vec<_>>(), &[1, 4, 5, 6, 7, 11, 16]);

        let iter = BitmapIter::<u128, _>::new([0b10, 0b10, 0b11]);
        assert_eq!(&iter.collect::<Vec<_>>(), &[1, 129, 256, 257]);
    }
}
