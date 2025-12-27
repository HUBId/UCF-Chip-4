// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE.md for licensing terms.

//! # Primitives Module
//!
//! This module contains the primitives for the nodestore, including a list of valid
//! area sizes, `AreaIndex` that uniquely identifies a valid area size, and
//! `LinearAddress` that points to a specific location in the linear storage space.

use crate::TrieHash;

use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{Error, ErrorKind};
use std::iter::FusedIterator;
use std::num::NonZeroU64;
use std::sync::OnceLock;

/// [`super::NodeStore`] divides the linear store into blocks of different sizes.
/// [`AREA_SIZES`] is every valid block size.
const AREA_SIZES: [u64; 23] = [
    16, // Min block size
    32,
    64,
    96,
    128,
    256,
    512,
    768,
    1024,
    1024 << 1,
    1024 << 2,
    1024 << 3,
    1024 << 4,
    1024 << 5,
    1024 << 6,
    1024 << 7,
    1024 << 8,
    1024 << 9,
    1024 << 10,
    1024 << 11,
    1024 << 12,
    1024 << 13,
    1024 << 14,
];

/// Iterator over all valid area sizes paired with their [`AreaIndex`].
#[derive(Clone, Debug, Default)]
pub struct AreaSizes {
    start: u8,
    end: u8,
}

impl AreaSizes {
    /// Creates a new iterator that yields each area size in order.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            start: 0,
            end: AreaIndex::NUM_AREA_SIZES as u8,
        }
    }
}

impl Iterator for AreaSizes {
    type Item = (AreaIndex, u64);

    fn next(&mut self) -> Option<Self::Item> {
        if self.start >= self.end {
            return None;
        }

        let index = self.start;
        self.start += 1;
        #[expect(clippy::indexing_slicing)]
        let size = AREA_SIZES[index as usize];
        Some((AreaIndex(index), size))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.len();
        (remaining, Some(remaining))
    }
}

impl DoubleEndedIterator for AreaSizes {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.start >= self.end {
            return None;
        }

        self.end -= 1;
        let index = self.end;
        #[expect(clippy::indexing_slicing)]
        let size = AREA_SIZES[index as usize];
        Some((AreaIndex(index), size))
    }
}

impl ExactSizeIterator for AreaSizes {
    fn len(&self) -> usize {
        usize::from(self.end.saturating_sub(self.start))
    }
}

impl FusedIterator for AreaSizes {}

/// Returns an iterator over all valid area sizes.
#[must_use]
pub fn area_size_iter() -> AreaSizes {
    AreaSizes::new()
}

pub fn area_size_hash() -> TrieHash {
    let mut hasher = Sha256::new();
    for size in AREA_SIZES {
        hasher.update(size.to_ne_bytes());
    }
    hasher.finalize().into()
}

fn area_size_names() -> &'static [&'static str] {
    static NAMES: OnceLock<&'static [&'static str]> = OnceLock::new();

    NAMES.get_or_init(|| {
        let names: Vec<&'static str> = AREA_SIZES
            .iter()
            .map(|size| {
                let s = size.to_string();
                Box::leak(s.into_boxed_str()) as &'static str
            })
            .collect();
        let boxed: Box<[&'static str]> = names.into_boxed_slice();
        Box::leak(boxed)
    })
}

/// Returns the decimal string representation of the area size at `index`.
pub fn index_name(index: AreaIndex) -> &'static str {
    area_size_names()
        .get(index.as_usize())
        .copied()
        .unwrap_or("unknown")
}

#[cfg(test)]
mod tests {
    use super::{area_size_iter, index_name, AreaIndex, AreaSizes, AREA_SIZES};

    #[test]
    fn area_sizes_iterates_in_order() {
        let collected: Vec<(AreaIndex, u64)> = area_size_iter().collect();
        let expected: Vec<(AreaIndex, u64)> = AREA_SIZES
            .iter()
            .enumerate()
            .map(|(i, &size)| (AreaIndex::from_u8_unchecked(i as u8), size))
            .collect();

        assert_eq!(collected, expected);
    }

    #[test]
    fn area_sizes_supports_double_ended_iteration() {
        let mut iter = AreaSizes::new();

        assert_eq!(
            iter.next(),
            Some((AreaIndex::from_u8_unchecked(0), AREA_SIZES[0]))
        );
        let last_index = AREA_SIZES.len() - 1;
        assert_eq!(
            iter.next_back(),
            Some((
                AreaIndex::from_u8_unchecked(last_index as u8),
                AREA_SIZES[last_index],
            ))
        );
        assert_eq!(iter.len(), AREA_SIZES.len().saturating_sub(2));
    }

    #[test]
    fn index_names_match_area_sizes() {
        for (i, size) in AREA_SIZES.iter().enumerate() {
            let index = AreaIndex::from_u8_unchecked(i as u8);
            assert_eq!(index_name(index), size.to_string());
        }
    }
}

/// The type that uniquely identifies a valid area size.
/// This is not usize because we store this as a single byte
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct AreaIndex(u8);

impl AreaIndex {
    /// The number of different area sizes available.
    pub const NUM_AREA_SIZES: usize = AREA_SIZES.len();

    /// The minimum area index (0).
    pub const MIN: AreaIndex = AreaIndex(0);

    /// The maximum area index (22).
    pub const MAX: AreaIndex = AreaIndex(Self::NUM_AREA_SIZES as u8 - 1);

    /// The minimum area size available for allocation.
    pub const MIN_AREA_SIZE: u64 = AREA_SIZES[0];

    /// The maximum area size available for allocation.
    pub const MAX_AREA_SIZE: u64 = AREA_SIZES[Self::NUM_AREA_SIZES - 1];

    /// Create a new `AreaIndex` from a u8 value, returns None if value is out of range.
    #[inline]
    #[must_use]
    pub const fn new(index: u8) -> Option<Self> {
        if index < Self::NUM_AREA_SIZES as u8 {
            Some(AreaIndex(index))
        } else {
            None
        }
    }

    /// Create an `AreaIndex` from a size in bytes.
    /// Returns the index of the smallest area size >= `n`.
    ///
    /// # Errors
    ///
    /// Returns an error if the size is too large.
    pub fn from_size(n: u64) -> Result<Self, Error> {
        if n > Self::MAX_AREA_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Node size {n} is too large"),
            ));
        }

        if n <= Self::MIN_AREA_SIZE {
            return Ok(AreaIndex(0));
        }

        AREA_SIZES
            .iter()
            .position(|&size| size >= n)
            .map(|index| AreaIndex(index as u8))
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("Node size {n} is too large"),
                )
            })
    }

    /// Get the underlying index as u8.
    #[inline]
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    /// Get the underlying index as usize.
    #[inline]
    #[must_use]
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }

    /// Returns the number of different area sizes available.
    #[inline]
    #[must_use]
    pub const fn num_area_sizes() -> usize {
        Self::NUM_AREA_SIZES
    }

    /// Create an `AreaIndex` from a u8 value without bounds checking.
    #[inline]
    #[must_use]
    #[cfg(test)]
    pub const fn from_u8_unchecked(index: u8) -> Self {
        AreaIndex(index)
    }

    /// Get the size of an area index (used by the checker)
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of bounds for the `AREA_SIZES` array.
    #[must_use]
    pub const fn size(self) -> u64 {
        #[expect(clippy::indexing_slicing)]
        AREA_SIZES[self.as_usize()]
    }
}

impl TryFrom<u8> for AreaIndex {
    type Error = Error;

    fn try_from(index: u8) -> Result<Self, Self::Error> {
        AreaIndex::new(index).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                format!("Area index out of bounds: {index}"),
            )
        })
    }
}

impl From<AreaIndex> for u8 {
    fn from(area_index: AreaIndex) -> Self {
        area_index.get()
    }
}

impl TryFrom<usize> for AreaIndex {
    type Error = Error;

    fn try_from(index: usize) -> Result<Self, Self::Error> {
        let index_u8: Result<u8, _> = index.try_into();
        index_u8.map(AreaIndex).map_err(|_| {
            Error::new(
                ErrorKind::InvalidData,
                format!("Area index out of bounds: {index}"),
            )
        })
    }
}

impl From<AreaIndex> for usize {
    fn from(area_index: AreaIndex) -> Self {
        area_index.as_usize()
    }
}

impl fmt::Display for AreaIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        std::fmt::Display::fmt(&self.get(), f)
    }
}

/// A linear address in the nodestore storage.
///
/// This represents a non-zero address in the linear storage space.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct LinearAddress(NonZeroU64);

#[expect(unsafe_code)]
// SAFETY: `LinearAddress` is a wrapper around `NonZeroU64` which is also `ZeroableInOption`.
unsafe impl bytemuck::ZeroableInOption for LinearAddress {}
#[expect(unsafe_code)]
// SAFETY: `LinearAddress` is a wrapper around `NonZeroU64` which is also `PodInOption`.
unsafe impl bytemuck::PodInOption for LinearAddress {}

impl LinearAddress {
    /// Create a new `LinearAddress`, returns None if value is zero.
    #[inline]
    #[must_use]
    pub const fn new(addr: u64) -> Option<Self> {
        match NonZeroU64::new(addr) {
            Some(addr) => Some(LinearAddress(addr)),
            None => None,
        }
    }

    /// Get the underlying address as u64.
    #[inline]
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Check if the address is 8-byte aligned.
    #[inline]
    #[must_use]
    pub const fn is_aligned(self) -> bool {
        self.0.get() % Self::MIN_AREA_SIZE == 0
    }

    /// The maximum area size available for allocation.
    pub const MAX_AREA_SIZE: u64 = *AREA_SIZES.last().unwrap();

    /// The minimum area size available for allocation.
    pub const MIN_AREA_SIZE: u64 = *AREA_SIZES.first().unwrap();

    /// Returns the number of different area sizes available.
    #[inline]
    #[must_use]
    pub const fn num_area_sizes() -> usize {
        const { AREA_SIZES.len() }
    }

    /// Returns the inner `NonZeroU64`
    #[inline]
    #[must_use]
    pub const fn into_nonzero(self) -> NonZeroU64 {
        self.0
    }

    /// Advances a `LinearAddress` by `n` bytes.
    ///
    /// Returns `None` if the result overflows a u64
    /// Some(LinearAddress) otherwise
    ///
    #[inline]
    #[must_use]
    pub const fn advance(self, n: u64) -> Option<Self> {
        match self.0.checked_add(n) {
            // overflowed
            None => None,

            // It is impossible to add a non-zero positive number to a u64 and get 0 without
            // overflowing, so we don't check for that here, and panic instead.
            Some(sum) => Some(LinearAddress(sum)),
        }
    }

    /// Returns the number of bytes between `other` and `self` if `other` is less than or equal to `self`.
    /// Otherwise, returns `None`.
    #[inline]
    #[must_use]
    pub const fn distance_from(self, other: Self) -> Option<u64> {
        self.0.get().checked_sub(other.0.get())
    }
}

impl std::ops::Deref for LinearAddress {
    type Target = NonZeroU64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for LinearAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        std::fmt::Display::fmt(&self.get(), f)
    }
}

impl fmt::LowerHex for LinearAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        std::fmt::LowerHex::fmt(&self.get(), f)
    }
}
impl From<LinearAddress> for u64 {
    fn from(addr: LinearAddress) -> Self {
        addr.get()
    }
}

impl From<NonZeroU64> for LinearAddress {
    fn from(addr: NonZeroU64) -> Self {
        LinearAddress(addr)
    }
}
