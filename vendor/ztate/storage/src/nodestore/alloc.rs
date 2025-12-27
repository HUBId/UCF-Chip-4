// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE.md for licensing terms.

#![allow(clippy::expect_used)] // Allocator helpers rely on expect to loudly flag impossible storage layouts.

//! # Allocation Module
//!
//! This module handles memory allocation and space management for nodes in the nodestore's
//! linear storage, implementing a malloc-like free space management system.
//!
//! ### Area Sizes
//! Storage is divided into 23 predefined area sizes from 16 bytes to 16MB:
//! - Small sizes (16, 32, 64, 96, 128, 256, 512, 768, 1024 bytes) for common nodes
//! - Power-of-two larger sizes (2KB, 4KB, 8KB, ..., 16MB) for larger data
//!
//! ### Storage Format
//! Each stored area follows this layout:
//! ```text
//! [AreaIndex:1][AreaType:1][NodeData:n]
//! ```
//! - **`AreaIndex`** - Index into `AREA_SIZES` array (1 byte)
//! - **`AreaType`** - 0xFF for free areas, otherwise node type data (1 byte)
//! - **`NodeData`** - Serialized node content

use super::area_index_and_size;
use super::primitives::{index_name, AreaIndex, LinearAddress};
use crate::linear::FileIoError;
use crate::logger::{trace, warn};
use crate::node::branch::{ReadSerializable, Serializable};
use crate::node::extend_vec_with_varint;
use crate::nodestore::NodeStoreHeader;
use integer_encoding::VarIntReader;

use std::io::{Error, ErrorKind, Read};
use std::iter::FusedIterator;

use crate::{
    firewood_counter, firewood_gauge, FreeListParent, MaybePersistedNode, ReadableStorage,
    WritableStorage,
};

/// Returns the maximum size needed to encode a `VarInt`.
const fn var_int_max_size<VI>() -> usize {
    const { (size_of::<VI>() * 8 + 7) / 7 }
}

/// `FreeLists` is an array of `Option<LinearAddress>` for each area size.
pub type FreeLists = [Option<LinearAddress>; AreaIndex::NUM_AREA_SIZES];

/// A [`FreeArea`] is stored at the start of the area that contained a node that
/// has been freed.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct FreeArea {
    next_free_block: Option<LinearAddress>,
}

impl Serializable for FreeArea {
    fn write_to_vec(&self, vec: &mut Vec<u8>) {
        vec.push(0xff); // 0xff indicates a free area
        extend_vec_with_varint(vec, self.next_free_block.map_or(0, LinearAddress::get));
    }

    /// Parse a [`FreeArea`].
    ///
    /// The old serde generate code that unintentionally encoded [`FreeArea`]s
    /// incorrectly. Integers were encoded as variable length integers, but
    /// expanded to fixed-length below:
    ///
    /// ```text
    /// [
    ///     0x01, // LE u32 begin -- field index of the old `StoredArea` struct (#1)
    ///     0x00,
    ///     0x00,
    ///     0x00, // LE u32 end
    ///     0x01, // `Option` discriminant, 1 Indicates `Some(_)` from `Option<LinearAddress>`
    ///           // because serde does not handle the niche optimization of
    ///           // `Option<NonZero<_>>`
    ///     0x2a, // LinearAddress(LE u64) start
    ///     0x00,
    ///     0x00,
    ///     0x00,
    ///     0x00,
    ///     0x00,
    ///     0x00,
    ///     0x00, // LE u64 end
    /// ]
    /// ```
    ///
    /// Our manual encoding format is (with variable int, but expanded below):
    ///
    /// ```text
    /// [
    ///     0xff, // FreeArea marker
    ///     0x2a, // LinearAddress(LE u64) start
    ///     0x00,
    ///     0x00,
    ///     0x00,
    ///     0x00,
    ///     0x00,
    ///     0x00,
    ///     0x00, // LE u64 end
    /// ]
    /// ```
    fn from_reader<R: Read>(mut reader: R) -> std::io::Result<Self> {
        match reader.read_byte()? {
            0x01 => {
                // might be old format, look for option discriminant
                match reader.read_byte()? {
                    0x00 => {
                        // serde encoded `Option::None` as 0 with no following data
                        Ok(Self {
                            next_free_block: None,
                        })
                    }
                    0x01 => {
                        // encoded `Some(_)` as 1 with the data following
                        let addr = LinearAddress::new(read_bincode_varint_u64_le(&mut reader)?)
                            .ok_or_else(|| {
                                Error::new(
                                    ErrorKind::InvalidData,
                                    "Option::<LinearAddress> was Some(0) which is invalid",
                                )
                            })?;
                        Ok(Self {
                            next_free_block: Some(addr),
                        })
                    }
                    option_discriminant => Err(Error::new(
                        ErrorKind::InvalidData,
                        format!("Invalid Option discriminant: {option_discriminant}"),
                    )),
                }
            }
            0xFF => {
                // new format: read the address directly (zero is allowed here to indicate None)
                Ok(Self {
                    next_free_block: LinearAddress::new(reader.read_varint()?),
                })
            }
            first_byte => Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Invalid FreeArea marker, expected 0xFF (or 0x01 for old format), found {first_byte:#04x}"
                ),
            )),
        }
    }
}

impl FreeArea {
    /// Create a new `FreeArea`
    pub const fn new(next_free_block: Option<LinearAddress>) -> Self {
        Self { next_free_block }
    }

    /// Get the next free block address
    pub const fn next_free_block(self) -> Option<LinearAddress> {
        self.next_free_block
    }

    pub fn from_storage<S: ReadableStorage>(
        storage: &S,
        address: LinearAddress,
    ) -> Result<(Self, AreaIndex), FileIoError> {
        let free_area_addr = address.get();
        let stored_area_stream = storage.stream_from(free_area_addr)?;
        Self::from_storage_reader(stored_area_stream).map_err(|e| {
            storage.file_io_error(
                e,
                free_area_addr,
                Some("FreeArea::from_storage".to_string()),
            )
        })
    }

    pub fn as_bytes(self, area_index: AreaIndex, encoded: &mut Vec<u8>) {
        const RESERVE_SIZE: usize = size_of::<u8>() + var_int_max_size::<u64>();

        encoded.reserve(RESERVE_SIZE);
        encoded.push(area_index.get());
        self.write_to_vec(encoded);
    }

    fn from_storage_reader(mut reader: impl Read) -> std::io::Result<(Self, AreaIndex)> {
        let area_index = AreaIndex::try_from(reader.read_byte()?)?;
        let free_area = reader.next_value()?;
        Ok((free_area, area_index))
    }
}

/// A [`StoredArea`] represents the metadata header of an allocated area that
/// stores a node in linear storage. Unlike [`FreeArea`], a stored area is
/// identified by any marker other than `0xff` in the second byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StoredArea {
    area_index: AreaIndex,
}

impl StoredArea {
    /// Returns the [`AreaIndex`] encoded in the stored area's header.
    pub const fn area_index(self) -> AreaIndex {
        self.area_index
    }

    /// Reads the stored area metadata from storage.
    pub fn from_storage<S: ReadableStorage>(
        storage: &S,
        address: LinearAddress,
    ) -> Result<Self, FileIoError> {
        let stored_area_addr = address.get();
        let mut stream = storage.stream_from(stored_area_addr)?;
        Self::from_storage_reader(&mut stream).map_err(|e| {
            storage.file_io_error(
                e,
                stored_area_addr,
                Some("StoredArea::from_storage".to_string()),
            )
        })
    }

    fn from_storage_reader(mut reader: impl Read) -> std::io::Result<Self> {
        let area_index = AreaIndex::try_from(reader.read_byte()?)?;
        let area_size = area_index.size();

        let mut payload_available =
            usize::try_from(area_size.checked_sub(1).ok_or_else(|| {
                Error::new(ErrorKind::InvalidData, "Stored area is missing payload")
            })?)
            .map_err(|_| {
                Error::new(
                    ErrorKind::InvalidData,
                    "Stored area size exceeds usize range",
                )
            })?;

        if payload_available == 0 {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "Stored area missing node marker",
            ));
        }

        let marker = reader.read_byte()?;
        payload_available -= 1;

        if marker == 0xff {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Stored area marker indicates a free area",
            ));
        }

        let min_payload = Self::minimum_payload_size(marker, &mut reader)?;
        if payload_available < min_payload {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Stored area payload too small: requires at least {min_payload} bytes, found {payload_available}"
                ),
            ));
        }

        Ok(Self { area_index })
    }

    fn minimum_payload_size(marker: u8, reader: &mut impl Read) -> std::io::Result<usize> {
        if marker & 1 == 1 {
            Self::minimum_leaf_payload(marker)
        } else {
            Self::minimum_branch_payload(marker, reader)
        }
    }

    fn minimum_leaf_payload(marker: u8) -> std::io::Result<usize> {
        const LEAF_PARTIAL_PATH_LEN_OVERFLOW: usize = (1 << 7) - 2;

        let partial_path_nibbles = usize::from(marker >> 1);
        let mut min_payload = 0usize;

        if partial_path_nibbles == LEAF_PARTIAL_PATH_LEN_OVERFLOW {
            // Overflow encoding includes a varint length and the actual path bytes.
            min_payload += 1; // minimum varint encoding for length 0
        } else {
            min_payload += (partial_path_nibbles + 1) / 2;
        }

        // Leaf values are encoded as <varint length><bytes>.
        min_payload += 1; // minimum varint encoding for zero-length value

        Ok(min_payload)
    }

    fn minimum_branch_payload(marker: u8, reader: &mut impl Read) -> std::io::Result<usize> {
        const HASH_AND_ADDRESS_LEN: usize = size_of::<u64>() + size_of::<crate::HashType>();

        #[cfg(not(feature = "branch_factor_256"))]
        const BRANCH_PARTIAL_PATH_LEN_OVERFLOW: usize = (1 << 2) - 1;
        #[cfg(feature = "branch_factor_256")]
        const BRANCH_PARTIAL_PATH_LEN_OVERFLOW: usize = (1 << 6) - 1;

        let has_value = (marker >> 1) & 1 == 1;

        #[cfg(not(feature = "branch_factor_256"))]
        let childcount = {
            let encoded = ((marker >> 2) & 0x0f) as usize;
            if encoded == 0 {
                crate::node::BranchNode::MAX_CHILDREN
            } else {
                encoded
            }
        };

        #[cfg(feature = "branch_factor_256")]
        let childcount = {
            let mut buf = [0u8; 1];
            reader.read_exact(&mut buf)?;
            if buf[0] == 0 {
                crate::node::BranchNode::MAX_CHILDREN
            } else {
                usize::from(buf[0])
            }
        };

        #[cfg(not(feature = "branch_factor_256"))]
        let partial_path_nibbles = usize::from(marker >> 6);
        #[cfg(feature = "branch_factor_256")]
        let partial_path_nibbles = usize::from((marker >> 2) & 0x3f);

        let mut min_payload = 0usize;

        #[cfg(feature = "branch_factor_256")]
        {
            // We consumed an explicit child count byte above.
            min_payload += 1;
        }

        if partial_path_nibbles == BRANCH_PARTIAL_PATH_LEN_OVERFLOW {
            min_payload += 1; // minimum varint encoding for overflow length
        } else {
            min_payload += (partial_path_nibbles + 1) / 2;
        }

        if has_value {
            min_payload += 1; // minimum varint encoding for zero-length value
        }

        if childcount > crate::node::BranchNode::MAX_CHILDREN {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Branch child count {childcount} exceeds maximum {}",
                    crate::node::BranchNode::MAX_CHILDREN
                ),
            ));
        }

        if childcount == crate::node::BranchNode::MAX_CHILDREN {
            min_payload += crate::node::BranchNode::MAX_CHILDREN * HASH_AND_ADDRESS_LEN;
        } else {
            min_payload += childcount * (1 + HASH_AND_ADDRESS_LEN);
        }

        Ok(min_payload)
    }
}

// Re-export the NodeStore types we need
use super::NodeStore;

/// Writable allocator for allocating and deleting nodes
#[derive(Debug)]
pub struct NodeAllocator<'a, S> {
    storage: &'a S,
    header: &'a mut NodeStoreHeader,
}

impl<'a, S: WritableStorage> NodeAllocator<'a, S> {
    pub const fn new(storage: &'a S, header: &'a mut NodeStoreHeader) -> Self {
        Self { storage, header }
    }

    /// Returns the `AreaIndex` for the stored area at `addr`.
    /// Use [`AreaIndex::size`] to recover the stored area's length.
    ///
    /// # Errors
    ///
    /// Returns a [`FileIoError`] if the area cannot be read.
    pub fn area_index_and_size(&self, addr: LinearAddress) -> Result<AreaIndex, FileIoError> {
        area_index_and_size(self.storage, addr)
    }

    /// Attempts to allocate `n` bytes from the free lists.
    /// If successful returns the address of the newly allocated area
    /// and the index of the free list that was used.
    /// If there are no free areas big enough for `n` bytes, returns None.
    /// TODO Consider splitting the area if we return a larger area than requested.
    fn allocate_from_freed(
        &mut self,
        n: u64,
    ) -> Result<Option<(LinearAddress, AreaIndex)>, FileIoError> {
        // Find the smallest free list that can fit this size.
        let requested_index = AreaIndex::from_size(n).map_err(|e| {
            self.storage
                .file_io_error(e, 0, Some("allocate_from_freed".to_string()))
        })?;

        let mut current_index_u8 = requested_index.get();
        'outer: while current_index_u8 <= AreaIndex::MAX.get() {
            let current_index = AreaIndex::try_from(current_index_u8)
                .expect("current_index_u8 is less than AreaIndex::NUM_AREA_SIZES");

            let mut maybe_address = None;
            {
                let free_lists = self.header.free_lists_mut();
                let free_stored_area_addr = free_lists
                    .get_mut(current_index.as_usize())
                    .expect("index is less than AreaIndex::NUM_AREA_SIZES");

                if let Some(address) = *free_stored_area_addr {
                    let cached_next = self.storage.free_list_cache(address).flatten();
                    match FreeArea::from_storage(self.storage, address) {
                        Ok((free_head, read_index)) => {
                            debug_assert_eq!(read_index, current_index);
                            let has_cached_next = cached_next.is_some();
                            let next_free = cached_next.or(free_head.next_free_block);

                            *free_stored_area_addr = next_free;
                            if !has_cached_next {
                                self.storage.add_to_free_list_cache(address, next_free);
                            }

                            trace!("free_head@{address}: {next_free:?} size:{current_index}");
                            maybe_address = Some(address);
                        }
                        Err(err) => {
                            if matches!(
                                err.kind(),
                                ErrorKind::InvalidData | ErrorKind::UnexpectedEof
                            ) {
                                *free_stored_area_addr = cached_next;
                                warn!(
                                    "Corrupt free list entry at {address:?} (size {current_index}): {err}"
                                );
                                firewood_counter!(
                                    "firewood.freelist.corrupt_header",
                                    "Free list entries skipped due to invalid headers",
                                    "index" => index_name(current_index)
                                )
                                .increment(1);
                                continue 'outer;
                            }

                            return Err(err);
                        }
                    }
                }
            }

            if let Some(address) = maybe_address {
                let was_split = current_index.get() > requested_index.get();
                if was_split {
                    self.split_free_block(address, current_index, requested_index)?;
                }

                firewood_counter!(
                    "firewood.allocations.reused",
                    "Node allocations served from free lists by index",
                    "index" => index_name(requested_index)
                )
                .increment(1);
                if was_split {
                    firewood_counter!(
                        "firewood.allocations.reused.split",
                        "Node allocations that split larger free-list entries by target size",
                        "area_size" => index_name(requested_index)
                    )
                    .increment(1);
                } else {
                    firewood_counter!(
                        "firewood.allocations.reused.whole",
                        "Node allocations served by exact free-list entries by target size",
                        "area_size" => index_name(requested_index)
                    )
                    .increment(1);
                }
                firewood_gauge!(
                    "firewood.freelist.available",
                    "Free list entries available by area size",
                    "index" => index_name(current_index)
                )
                .decrement(1.0);

                trace!("Allocating from free list: addr: {address:?}, size: {requested_index}");
                firewood_counter!(
                    "firewood.space.reused",
                    "Bytes reused from free list by index",
                    "index" => index_name(requested_index)
                )
                .increment(requested_index.size());
                firewood_counter!(
                    "firewood.space.wasted",
                    "Bytes wasted from free list by index",
                    "index" => index_name(requested_index)
                )
                .increment(requested_index.size().saturating_sub(n));

                return Ok(Some((address, requested_index)));
            }

            current_index_u8 = current_index_u8
                .checked_add(1)
                .expect("current_index_u8 never exceeds AreaIndex::MAX");
        }

        trace!("No free blocks of sufficient size {requested_index} found");
        firewood_counter!(
            "firewood.space.from_end",
            "Space allocated from end of nodestore",
            "index" => index_name(requested_index)
        )
        .increment(requested_index.size());
        Ok(None)
    }

    fn allocate_from_end(&mut self, n: u64) -> Result<(LinearAddress, AreaIndex), FileIoError> {
        let index = AreaIndex::from_size(n).map_err(|e| {
            self.storage
                .file_io_error(e, 0, Some("allocate_from_end".to_string()))
        })?;
        let area_size = index.size();
        let addr = LinearAddress::new(self.header.size()).expect("node store size can't be 0");
        self.header
            .set_size(self.header.size().saturating_add(area_size));
        debug_assert!(addr.is_aligned());
        trace!("Allocating from end: addr: {addr:?}, size: {index}");
        firewood_counter!(
            "firewood.allocations.from_end",
            "Node allocations that extend the nodestore size",
            "index" => index_name(index)
        )
        .increment(1);
        Ok((addr, index))
    }

    /// Returns an address that can be used to store the given `node` and updates
    /// `self.header` to reflect the allocation. Doesn't actually write the node to storage.
    /// Also returns the index of the free list the node was allocated from.
    ///
    /// # Errors
    ///
    /// Returns a [`FileIoError`] if the node cannot be allocated.
    pub fn allocate_node(
        &mut self,
        node: &[u8],
    ) -> Result<(LinearAddress, AreaIndex), FileIoError> {
        let stored_area_size = node.len() as u64;

        if stored_area_size > AreaIndex::MAX_AREA_SIZE {
            let error = Error::new(
                ErrorKind::InvalidData,
                format!("Node size {stored_area_size} is too large"),
            );
            return Err(self
                .storage
                .file_io_error(error, 0, Some("allocate_node".to_string())));
        }

        // Attempt to allocate from a free list.
        // If we can't allocate from a free list, allocate past the existing
        // of the ReadableStorage.
        let (addr, index) = match self.allocate_from_freed(stored_area_size)? {
            Some((addr, index)) => (addr, index),
            None => self.allocate_from_end(stored_area_size)?,
        };

        Ok((addr, index))
    }
}

impl<S: WritableStorage> NodeAllocator<'_, S> {
    /// Deletes the `Node` and updates the header of the allocator.
    /// Nodes that are not persisted are just dropped.
    ///
    /// # Errors
    ///
    /// Returns a [`FileIoError`] if the area cannot be read or written.
    #[expect(clippy::indexing_slicing)]
    pub fn delete_node(&mut self, node: MaybePersistedNode) -> Result<(), FileIoError> {
        let Some(addr) = node.as_linear_address() else {
            return Ok(());
        };
        debug_assert!(addr.is_aligned());

        let area_size_index = self.area_index_and_size(addr)?;
        let area_size = area_size_index.size();
        trace!("Deleting node at {addr:?} of size {area_size_index}");
        firewood_counter!(
            "firewood.delete_node",
            "Nodes deleted",
            "index" => index_name(area_size_index)
        )
        .increment(1);
        firewood_counter!(
            "firewood.space.freed",
            "Bytes freed in nodestore",
            "index" => index_name(area_size_index)
        )
        .increment(area_size);

        self.add_free_block(addr, area_size_index)?;

        Ok(())
    }
}

impl<'a, S: WritableStorage> NodeAllocator<'a, S> {
    fn split_free_block(
        &mut self,
        address: LinearAddress,
        mut current_index: AreaIndex,
        target_index: AreaIndex,
    ) -> Result<(), FileIoError> {
        while current_index.get() > target_index.get() {
            let prev_index = AreaIndex::try_from(current_index.get() - 1)
                .expect("current_index is greater than AreaIndex::MIN");
            let current_size = current_index.size();
            let prev_size = prev_index.size();
            let remainder_size = current_size - prev_size;
            let remainder_index = AreaIndex::from_size(remainder_size).map_err(|e| {
                self.storage
                    .file_io_error(e, address.get(), Some("split_free_block".to_string()))
            })?;

            firewood_counter!(
                "firewood.freelist.split",
                "Free list blocks split to satisfy allocations",
                "from_index" => index_name(current_index),
                "target_index" => index_name(target_index)
            )
            .increment(1);

            let remainder_addr = address
                .advance(prev_size)
                .expect("remainder address should be non-zero");
            self.add_free_block(remainder_addr, remainder_index)?;

            current_index = prev_index;
        }

        Ok(())
    }

    pub(crate) fn add_free_block(
        &mut self,
        address: LinearAddress,
        area_index: AreaIndex,
    ) -> Result<(), FileIoError> {
        let next = self.header.free_lists()[area_index.as_usize()];
        let mut stored_area_bytes = Vec::new();
        FreeArea::new(next).as_bytes(area_index, &mut stored_area_bytes);
        self.storage.write(address.get(), &stored_area_bytes)?;
        self.storage.add_to_free_list_cache(address, next);
        self.header.free_lists_mut()[area_index.as_usize()] = Some(address);
        firewood_gauge!(
            "firewood.freelist.available",
            "Free list entries available by area size",
            "index" => index_name(area_index)
        )
        .increment(1.0);
        Ok(())
    }
}

/// Iterator over free lists in the nodestore
struct FreeListIterator<'a, S: ReadableStorage> {
    storage: &'a S,
    id: AreaIndex,
    next_addr: Option<LinearAddress>,
    parent: FreeListParent,
}

impl<'a, S: ReadableStorage> FreeListIterator<'a, S> {
    const fn new(
        storage: &'a S,
        free_list_id: AreaIndex,
        next_addr: Option<LinearAddress>,
        src_ptr: FreeListParent,
    ) -> Self {
        Self {
            storage,
            id: free_list_id,
            next_addr,
            parent: src_ptr,
        }
    }

    fn next_with_metadata(
        &mut self,
    ) -> Option<(Result<FreeAreaWithMetadata, FileIoError>, FreeListParent)> {
        let parent = self.parent;
        let next_addr = self.next()?;
        let next_with_metadata = next_addr.map(|(addr, area_index)| FreeAreaWithMetadata {
            addr,
            area_index,
            free_list_id: self.id,
        });
        Some((next_with_metadata, parent))
    }
}

impl<S: ReadableStorage> Iterator for FreeListIterator<'_, S> {
    type Item = Result<(LinearAddress, AreaIndex), FileIoError>;

    fn next(&mut self) -> Option<Self::Item> {
        let next_addr = self.next_addr?;

        // read the free area, propagate any IO error if it occurs
        let (free_area, stored_area_index) = match FreeArea::from_storage(self.storage, next_addr) {
            Ok(free_area) => free_area,
            Err(e) => {
                // if the read fails, we cannot proceed with the current freelist
                self.next_addr = None;
                return Some(Err(e));
            }
        };

        // update the next address to the next free block
        self.parent = FreeListParent::PrevFreeArea {
            area_size_idx: stored_area_index,
            parent_addr: next_addr,
        };
        self.next_addr = free_area.next_free_block();
        Some(Ok((next_addr, stored_area_index)))
    }
}

impl<S: ReadableStorage> FusedIterator for FreeListIterator<'_, S> {}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FreeAreaWithMetadata {
    pub addr: LinearAddress,
    pub area_index: AreaIndex,
    pub free_list_id: AreaIndex,
}

pub(crate) struct FreeListsIterator<'a, S: ReadableStorage> {
    storage: &'a S,
    free_lists_iter: std::iter::Skip<
        std::iter::Enumerate<std::slice::Iter<'a, std::option::Option<LinearAddress>>>,
    >,
    current_free_list: Option<(AreaIndex, FreeListIterator<'a, S>)>,
}

impl<'a, S: ReadableStorage> FreeListsIterator<'a, S> {
    pub(crate) fn new(
        storage: &'a S,
        free_lists: &'a FreeLists,
        start_area_index: AreaIndex,
    ) -> Self {
        let mut free_lists_iter = free_lists
            .iter()
            .enumerate()
            .skip(start_area_index.as_usize());
        let current_free_list = free_lists_iter.next().map(|(id, head)| {
            let free_list_id =
                AreaIndex::try_from(id).expect("id is less than AreaIndex::NUM_AREA_SIZES");
            let free_list_iter = FreeListIterator::new(
                storage,
                free_list_id,
                *head,
                FreeListParent::FreeListHead(free_list_id),
            );
            (free_list_id, free_list_iter)
        });
        Self {
            storage,
            free_lists_iter,
            current_free_list,
        }
    }

    pub(crate) fn next_with_metadata(
        &mut self,
    ) -> Option<(Result<FreeAreaWithMetadata, FileIoError>, FreeListParent)> {
        self.next_inner(FreeListIterator::next_with_metadata)
    }

    fn next_inner<T, F: FnMut(&mut FreeListIterator<'a, S>) -> Option<T>>(
        &mut self,
        mut next_fn: F,
    ) -> Option<T> {
        loop {
            let Some((_, free_list_iter)) = &mut self.current_free_list else {
                return None;
            };
            if let Some(next) = next_fn(free_list_iter) {
                // the current free list is not exhausted, return the next free area
                return Some(next);
            }

            self.move_to_next_free_list();
        }
    }

    pub(crate) fn move_to_next_free_list(&mut self) {
        let Some((next_free_list_id, next_free_list_head)) = self.free_lists_iter.next() else {
            self.current_free_list = None;
            return;
        };
        let next_free_list_id = AreaIndex::try_from(next_free_list_id)
            .expect("next_free_list_id is less than AreaIndex::NUM_AREA_SIZES");
        let next_free_list_iter = FreeListIterator::new(
            self.storage,
            next_free_list_id,
            *next_free_list_head,
            FreeListParent::FreeListHead(next_free_list_id),
        );
        self.current_free_list = Some((next_free_list_id, next_free_list_iter));
    }
}

impl<S: ReadableStorage> Iterator for FreeListsIterator<'_, S> {
    type Item = Result<(LinearAddress, AreaIndex), FileIoError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_inner(FreeListIterator::next)
    }
}

/// Extension methods for `NodeStore` to provide free list iteration capabilities
impl<T, S: ReadableStorage> NodeStore<T, S> {
    // Returns an iterator over the free lists of size no smaller than the size corresponding to `start_area_index`.
    // The iterator returns a tuple of the address and the area index of the free area.
    // Since this is a low-level iterator, we avoid safe conversion to AreaIndex for performance
    pub(crate) fn free_list_iter(&self, start_area_index: AreaIndex) -> FreeListsIterator<'_, S> {
        FreeListsIterator::new(self.storage.as_ref(), self.freelists(), start_area_index)
    }
}

// Functionalities use by the checker
impl<T, S: WritableStorage> NodeStore<T, S> {
    pub(crate) fn truncate_free_list(
        &mut self,
        free_list_parent: FreeListParent,
    ) -> Result<(), FileIoError> {
        match free_list_parent {
            FreeListParent::FreeListHead(area_size_index) => {
                *self
                    .freelists_mut()
                    .get_mut(area_size_index.as_usize())
                    .expect("area_size_index is less than AreaIndex::NUM_AREA_SIZES") = None;
                Ok(())
            }
            FreeListParent::PrevFreeArea {
                area_size_idx,
                parent_addr,
            } => {
                let free_area = FreeArea::new(None);
                let mut stored_area_bytes = Vec::new();
                free_area.as_bytes(area_size_idx, &mut stored_area_bytes);
                self.storage.write(parent_addr.into(), &stored_area_bytes)?;
                Ok(())
            }
        }
    }
}

fn read_bincode_varint_u64_le(reader: &mut impl Read) -> std::io::Result<u64> {
    // See https://github.com/ava-labs/chain/issues/1146 for full details.
    // emulate this behavior: https://github.com/bincode-org/bincode/blob/c44b5e364e7084cdbabf9f94b63a3c7f32b8fb68/src/config/int.rs#L241-L258

    const SINGLE_BYTE_MAX: u8 = 250;
    const U16_BYTE: u8 = 251;
    const U32_BYTE: u8 = 252;
    const U64_BYTE: u8 = 253;

    match reader.read_byte()? {
        byte @ 0..=SINGLE_BYTE_MAX => Ok(u64::from(byte)),
        U16_BYTE => {
            let mut buf = [0u8; 2];
            reader.read_exact(&mut buf)?;
            Ok(u64::from(u16::from_le_bytes(buf)))
        }
        U32_BYTE => {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf)?;
            Ok(u64::from(u32::from_le_bytes(buf)))
        }
        U64_BYTE => {
            let mut buf = [0u8; 8];
            reader.read_exact(&mut buf)?;
            Ok(u64::from_le_bytes(buf))
        }
        byte => Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "Invalid bincode varint byte, expected 0-250, 251, 252, or 253, found {byte:#04x}"
            ),
        )),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test utilities unwrap to build deliberately invalid storage layouts.
#[allow(clippy::expect_used)] // Test utilities call expect when constructing invariant-breaking fixtures.
pub mod test_utils {
    use super::*;

    use crate::node::Node;
    use crate::nodestore::{Committed, NodeStore, NodeStoreHeader};

    // Helper function to wrap the node in a StoredArea and write it to the given offset. Returns the size of the area on success.
    pub fn test_write_new_node<S: WritableStorage>(
        nodestore: &NodeStore<Committed, S>,
        node: &Node,
        offset: u64,
    ) -> (u64, u64) {
        let mut encoded_node = Vec::new();
        node.as_bytes(AreaIndex::MIN, &mut encoded_node);
        let encoded_node_len = encoded_node.len() as u64;
        let area_size_index = AreaIndex::from_size(encoded_node_len).unwrap();
        let mut stored_area_bytes = Vec::new();
        node.as_bytes(area_size_index, &mut stored_area_bytes);
        let bytes_written = stored_area_bytes.len() as u64;
        nodestore
            .storage
            .write(offset, stored_area_bytes.as_slice())
            .unwrap();
        (bytes_written, area_size_index.size())
    }

    // Helper function to write a free area to the given offset.
    pub fn test_write_free_area<S: WritableStorage>(
        nodestore: &NodeStore<Committed, S>,
        next_free_block: Option<LinearAddress>,
        area_size_index: AreaIndex,
        offset: u64,
    ) {
        let mut stored_area_bytes = Vec::new();
        FreeArea::new(next_free_block).as_bytes(area_size_index, &mut stored_area_bytes);
        nodestore.storage.write(offset, &stored_area_bytes).unwrap();
    }

    // Helper function to write the NodeStoreHeader
    pub fn test_write_header<S: WritableStorage>(
        nodestore: &mut NodeStore<Committed, S>,
        size: u64,
        root_addr: Option<LinearAddress>,
        free_lists: FreeLists,
    ) {
        let mut header = NodeStoreHeader::new();
        header.set_size(size);
        header.set_root_address(root_addr);
        *header.free_lists_mut() = free_lists;
        let header_bytes = bytemuck::bytes_of(&header);
        nodestore.header = header;
        nodestore.storage.write(0, header_bytes).unwrap();
    }

    // Helper function to write a random stored area to the given offset.
    pub(crate) fn test_write_zeroed_area<S: WritableStorage>(
        nodestore: &NodeStore<Committed, S>,
        size: u64,
        offset: u64,
    ) {
        let area_content = vec![0u8; size as usize];
        nodestore.storage.write(offset, &area_content).unwrap();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests unwrap to highlight allocator invariant violations immediately.
#[allow(clippy::expect_used)] // Tests call expect while synthesizing intentionally invalid free lists.
#[allow(clippy::indexing_slicing)] // Tests index deterministic buffers to encode synthetic storage artefacts.
mod tests {
    use super::*;
    use crate::area_index;
    use crate::linear::memory::MemStore;
    use crate::noop_storage_metrics;
    use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
    use rand::seq::IteratorRandom;
    use std::collections::HashMap;
    use std::sync::OnceLock;
    use test_case::test_case;
    use test_utils::{test_write_free_area, test_write_header};

    fn prometheus_handle() -> &'static PrometheusHandle {
        static PROMETHEUS: OnceLock<PrometheusHandle> = OnceLock::new();
        PROMETHEUS.get_or_init(|| {
            PrometheusBuilder::new()
                .install_recorder()
                .expect("install metrics")
        })
    }

    fn parse_labels(segment: &str) -> HashMap<&str, &str> {
        segment
            .split(',')
            .filter_map(|pair| {
                let mut parts = pair.split('=');
                let key = parts.next()?.trim();
                let value = parts
                    .next()
                    .and_then(|raw| raw.trim().strip_prefix('"'))
                    .and_then(|raw| raw.strip_suffix('"'))?;
                Some((key, value))
            })
            .collect()
    }

    fn metric_value(metrics: &str, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
        metrics.lines().find_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || !line.starts_with(name) {
                return None;
            }

            let (label_segment, value_segment) = match line.find('{') {
                Some(start) => {
                    let end = line.find('}')?;
                    (&line[start + 1..end], line[end + 1..].trim())
                }
                None => ("", line[name.len()..].trim()),
            };

            let parsed_labels = parse_labels(label_segment);
            if labels
                .iter()
                .all(|(key, value)| parsed_labels.get(key).copied() == Some(*value))
            {
                value_segment.split_whitespace().last()?.parse().ok()
            } else {
                None
            }
        })
    }

    fn metric_delta(before: &str, after: &str, name: &str, labels: &[(&str, &str)]) -> f64 {
        let before_value = metric_value(before, name, labels).unwrap_or_default();
        let after_value = metric_value(after, name, labels).unwrap_or_default();
        after_value - before_value
    }

    #[test]
    fn allocation_metrics_cover_multiple_area_sizes() {
        let prometheus = prometheus_handle();

        let memstore = MemStore::new(vec![]);
        let mut nodestore =
            NodeStore::new_empty_committed(memstore.into(), noop_storage_metrics()).unwrap();
        let mut allocator = NodeAllocator::new(nodestore.storage.as_ref(), &mut nodestore.header);

        let small_index = area_index!(1);
        let large_index = area_index!(3);

        let base_addr = LinearAddress::new(NodeStoreHeader::SIZE).unwrap();
        allocator
            .add_free_block(base_addr, large_index)
            .expect("seed large free block");
        let small_addr = base_addr
            .advance(large_index.size())
            .expect("small block address");
        allocator
            .add_free_block(small_addr, small_index)
            .expect("seed small free block");

        let seeded_metrics = prometheus.render();

        let (first_addr, first_index) = allocator
            .allocate_from_freed(small_index.size())
            .expect("free list traversal succeeds")
            .expect("first allocation should reuse seed block");
        assert_eq!(first_index, small_index);
        assert_eq!(first_addr, small_addr);

        let (split_addr, split_index) = allocator
            .allocate_from_freed(small_index.size())
            .expect("split traversal succeeds")
            .expect("second allocation should split larger block");
        assert_eq!(split_index, small_index);
        assert_eq!(split_addr, base_addr);

        let final_metrics = prometheus.render();

        let reused_small = metric_delta(
            &seeded_metrics,
            &final_metrics,
            "firewood_allocations_reused",
            &[("index", index_name(small_index))],
        );
        assert_eq!(reused_small, 2.0);

        let reused_whole = metric_delta(
            &seeded_metrics,
            &final_metrics,
            "firewood_allocations_reused_whole",
            &[("area_size", index_name(small_index))],
        );
        assert_eq!(reused_whole, 1.0);

        let reused_split = metric_delta(
            &seeded_metrics,
            &final_metrics,
            "firewood_allocations_reused_split",
            &[("area_size", index_name(small_index))],
        );
        assert_eq!(reused_split, 1.0);

        let split_from_large = metric_delta(
            &seeded_metrics,
            &final_metrics,
            "firewood_freelist_split",
            &[
                ("from_index", index_name(large_index)),
                ("target_index", index_name(small_index)),
            ],
        );
        assert_eq!(split_from_large, 1.0);

        let split_from_prev = metric_delta(
            &seeded_metrics,
            &final_metrics,
            "firewood_freelist_split",
            &[
                (
                    "from_index",
                    index_name(AreaIndex::try_from(large_index.get() - 1).unwrap()),
                ),
                ("target_index", index_name(small_index)),
            ],
        );
        assert_eq!(split_from_prev, 1.0);

        let available_small = metric_value(
            &final_metrics,
            "firewood_freelist_available",
            &[("index", index_name(small_index))],
        )
        .expect("gauge present for small index");
        let available_large = metric_value(
            &final_metrics,
            "firewood_freelist_available",
            &[("index", index_name(large_index))],
        )
        .expect("gauge present for large index");

        assert_eq!(available_small, 2.0);
        assert_eq!(available_large, 0.0);
    }

    #[test_case(&[0x01, 0x01, 0x01, 0x2a], Some((area_index!(1), 42)); "old format")]
    // StoredArea::new(12, Area::<Node, _>::Free(FreeArea::new(None)));
    #[test_case(&[0x02, 0x01, 0x00], Some((area_index!(2), 0)); "none")]
    #[test_case(&[0x03, 0xff, 0x2b], Some((area_index!(3), 43)); "new format")]
    #[test_case(&[0x03, 0x44, 0x55], None; "garbage")]
    #[test_case(
        &[0x03, 0x01, 0x01, 0xfd, 0xe0, 0xa2, 0x6d, 0x27, 0x6e, 0x00, 0x00, 0x00, 0x0d, 0x09, 0x03, 0x00],
        Some((area_index!(3), 0x6e_276d_a2e0));
        "old format with u64 address (issue #1146)"
    )]
    fn test_free_list_format(reader: &[u8], expected: Option<(AreaIndex, u64)>) {
        let expected =
            expected.map(|(index, addr)| (FreeArea::new(LinearAddress::new(addr)), index));
        let result = FreeArea::from_storage_reader(reader).ok();
        assert_eq!(result, expected, "Failed to parse FreeArea from {reader:?}");
    }

    #[test]
    // Create a random free list and test that `FreeListIterator` is able to traverse all the free areas
    fn free_list_iterator() {
        let mut rng = crate::SeededRng::from_env_or_random();
        let memstore = MemStore::new(vec![]);
        let nodestore =
            NodeStore::new_empty_committed(memstore.into(), noop_storage_metrics()).unwrap();

        let area_index = rng.random_range(0..AreaIndex::NUM_AREA_SIZES as u8);
        let area_index_type = AreaIndex::try_from(area_index).unwrap();
        let area_size = area_index_type.size();

        // create a random free list scattered across the storage
        let offsets = (1..100u64)
            .map(|i| i * area_size)
            .choose_multiple(&mut rng, 10);
        for (cur, next) in offsets.iter().zip(offsets.iter().skip(1)) {
            test_utils::test_write_free_area(
                &nodestore,
                Some(LinearAddress::new(*next).unwrap()),
                area_index_type,
                *cur,
            );
        }
        test_utils::test_write_free_area(
            &nodestore,
            None,
            area_index_type,
            *offsets.last().unwrap(),
        );

        // test iterator from a random starting point
        let skip = rng.random_range(0..offsets.len());
        let mut iterator = offsets.into_iter().skip(skip);
        let start = iterator.next().unwrap();
        let mut free_list_iter = FreeListIterator::new(
            nodestore.storage.as_ref(),
            area_index_type,
            LinearAddress::new(start),
            FreeListParent::FreeListHead(area_index_type),
        );
        assert_eq!(
            free_list_iter.next().unwrap().unwrap(),
            (LinearAddress::new(start).unwrap(), area_index_type)
        );

        for offset in iterator {
            assert_eq!(
                free_list_iter.next().unwrap().unwrap(),
                (LinearAddress::new(offset).unwrap(), area_index_type)
            );
        }

        assert!(free_list_iter.next().is_none());
    }

    // Create two free lists and check that `free_list_iter_with_metadata` correctly returns the free areas and their parents
    #[test]
    fn free_list_iter_with_metadata() {
        let rng = crate::SeededRng::from_env_or_random();
        let memstore = MemStore::new(vec![]);
        let mut nodestore =
            NodeStore::new_empty_committed(memstore.into(), noop_storage_metrics()).unwrap();

        let mut free_lists = FreeLists::default();
        let mut offset = NodeStoreHeader::SIZE;

        // first free list
        let area_index1 =
            AreaIndex::try_from(rng.random_range(0..AreaIndex::NUM_AREA_SIZES as u8)).unwrap();
        let area_size1 = area_index1.size();
        let mut next_free_block1 = None;

        test_write_free_area(&nodestore, next_free_block1, area_index1, offset);
        let free_list1_area2 = LinearAddress::new(offset).unwrap();
        next_free_block1 = Some(free_list1_area2);
        offset += area_size1;

        test_write_free_area(&nodestore, next_free_block1, area_index1, offset);
        let free_list1_area1 = LinearAddress::new(offset).unwrap();
        next_free_block1 = Some(free_list1_area1);
        offset += area_size1;

        free_lists[area_index1.as_usize()] = next_free_block1;

        // second free list
        let area_index2 = AreaIndex::new(
            (area_index1.get() + rng.random_range(1..AreaIndex::NUM_AREA_SIZES as u8))
                % AreaIndex::NUM_AREA_SIZES as u8,
        )
        .unwrap(); // make sure the second free list is different from the first
        assert_ne!(area_index1, area_index2);
        let area_size2 = area_index2.size();
        let mut next_free_block2 = None;

        test_write_free_area(&nodestore, next_free_block2, area_index2, offset);
        let free_list2_area2 = LinearAddress::new(offset).unwrap();
        next_free_block2 = Some(free_list2_area2);
        offset += area_size2;

        test_write_free_area(&nodestore, next_free_block2, area_index2, offset);
        let free_list2_area1 = LinearAddress::new(offset).unwrap();
        next_free_block2 = Some(free_list2_area1);
        offset += area_size2;

        free_lists[area_index2.as_usize()] = next_free_block2;

        // write header
        test_write_header(&mut nodestore, offset, None, free_lists);

        // test iterator
        let mut free_list_iter = nodestore.free_list_iter(AreaIndex::MIN);

        // expected
        let expected_free_list1 = vec![
            (
                FreeAreaWithMetadata {
                    addr: free_list1_area1,
                    area_index: area_index1,
                    free_list_id: area_index1,
                },
                FreeListParent::FreeListHead(area_index1),
            ),
            (
                FreeAreaWithMetadata {
                    addr: free_list1_area2,
                    area_index: area_index1,
                    free_list_id: area_index1,
                },
                FreeListParent::PrevFreeArea {
                    area_size_idx: area_index1,
                    parent_addr: free_list1_area1,
                },
            ),
        ];

        let expected_free_list2 = vec![
            (
                FreeAreaWithMetadata {
                    addr: free_list2_area1,
                    area_index: area_index2,
                    free_list_id: area_index2,
                },
                FreeListParent::FreeListHead(area_index2),
            ),
            (
                FreeAreaWithMetadata {
                    addr: free_list2_area2,
                    area_index: area_index2,
                    free_list_id: area_index2,
                },
                FreeListParent::PrevFreeArea {
                    area_size_idx: area_index2,
                    parent_addr: free_list2_area1,
                },
            ),
        ];

        let mut expected_iterator = if area_index1 < area_index2 {
            expected_free_list1.into_iter().chain(expected_free_list2)
        } else {
            expected_free_list2.into_iter().chain(expected_free_list1)
        };

        loop {
            let next = free_list_iter.next_with_metadata();
            let Some((expected, expected_parent)) = expected_iterator.next() else {
                assert!(next.is_none());
                break;
            };

            let (next, next_parent) = next.unwrap();
            assert_eq!(next.unwrap(), expected);
            assert_eq!(next_parent, expected_parent);
        }
    }

    #[test]
    #[expect(clippy::arithmetic_side_effects)]
    fn free_lists_iter_skip_to_next_free_list() {
        use test_utils::{test_write_free_area, test_write_header};

        const AREA_INDEX1: AreaIndex = area_index!(3);
        const AREA_INDEX1_PLUS_1: AreaIndex = area_index!(4);
        const AREA_INDEX2: AreaIndex = area_index!(5);
        const AREA_INDEX2_PLUS_1: AreaIndex = area_index!(6);

        let memstore = MemStore::new(vec![]);
        let mut nodestore =
            NodeStore::new_empty_committed(memstore.into(), noop_storage_metrics()).unwrap();

        let mut free_lists = FreeLists::default();
        let mut offset = NodeStoreHeader::SIZE;

        // first free list
        let area_size1 = AREA_INDEX1.size();
        let mut next_free_block1 = None;

        test_write_free_area(&nodestore, next_free_block1, AREA_INDEX1, offset);
        let free_list1_area2 = LinearAddress::new(offset).unwrap();
        next_free_block1 = Some(free_list1_area2);
        offset += area_size1;

        test_write_free_area(&nodestore, next_free_block1, AREA_INDEX1, offset);
        let free_list1_area1 = LinearAddress::new(offset).unwrap();
        next_free_block1 = Some(free_list1_area1);
        offset += area_size1;

        free_lists[AREA_INDEX1.as_usize()] = next_free_block1;

        // second free list
        assert_ne!(AREA_INDEX1, AREA_INDEX2);
        let area_size2 = AREA_INDEX2.size();
        let mut next_free_block2 = None;

        test_write_free_area(&nodestore, next_free_block2, AREA_INDEX2, offset);
        let free_list2_area2 = LinearAddress::new(offset).unwrap();
        next_free_block2 = Some(free_list2_area2);
        offset += area_size2;

        test_write_free_area(&nodestore, next_free_block2, AREA_INDEX2, offset);
        let free_list2_area1 = LinearAddress::new(offset).unwrap();
        next_free_block2 = Some(free_list2_area1);
        offset += area_size2;

        free_lists[AREA_INDEX2.as_usize()] = next_free_block2;

        // write header
        test_write_header(&mut nodestore, offset, None, free_lists);

        // test iterator
        let mut free_list_iter = nodestore.free_list_iter(AreaIndex::MIN);

        // start at the first free list
        assert_eq!(
            free_list_iter.current_free_list.as_ref().unwrap().0,
            AreaIndex::MIN
        );
        let (next, next_parent) = free_list_iter.next_with_metadata().unwrap();
        assert_eq!(
            next.unwrap(),
            FreeAreaWithMetadata {
                addr: free_list1_area1,
                area_index: AREA_INDEX1,
                free_list_id: AREA_INDEX1,
            },
        );
        assert_eq!(next_parent, FreeListParent::FreeListHead(AREA_INDEX1));
        // `next_with_metadata` moves the iterator to the first free list that is not empty
        assert_eq!(
            free_list_iter.current_free_list.as_ref().unwrap().0,
            AREA_INDEX1
        );
        free_list_iter.move_to_next_free_list();
        // `move_to_next_free_list` moves the iterator to the next free list
        assert_eq!(
            free_list_iter.current_free_list.as_ref().unwrap().0,
            AREA_INDEX1_PLUS_1
        );
        let (next, next_parent) = free_list_iter.next_with_metadata().unwrap();
        assert_eq!(
            next.unwrap(),
            FreeAreaWithMetadata {
                addr: free_list2_area1,
                area_index: AREA_INDEX2,
                free_list_id: AREA_INDEX2,
            },
        );
        assert_eq!(next_parent, FreeListParent::FreeListHead(AREA_INDEX2));
        // `next_with_metadata` moves the iterator to the first free list that is not empty
        assert_eq!(
            free_list_iter.current_free_list.as_ref().unwrap().0,
            AREA_INDEX2
        );
        free_list_iter.move_to_next_free_list();
        // `move_to_next_free_list` moves the iterator to the next free list
        assert_eq!(
            free_list_iter.current_free_list.as_ref().unwrap().0,
            AREA_INDEX2_PLUS_1
        );
        assert!(free_list_iter.next_with_metadata().is_none());
        // since no more non-empty free lists, `move_to_next_free_list` moves the iterator to the end
        assert!(free_list_iter.current_free_list.is_none());
        free_list_iter.move_to_next_free_list();
        // `move_to_next_free_list` will do nothing since we are already at the end
        assert!(free_list_iter.current_free_list.is_none());
        assert!(free_list_iter.next_with_metadata().is_none());
    }

    #[test]
    const fn la_const_expr_tests() {
        // these are const expr
        let _ = const { LinearAddress::new(0) };
        let _ = const { LinearAddress::new(1).unwrap().advance(1u64) };
    }

    #[test]
    const fn ai_const_expr_tests() {
        let _ = const { AreaIndex::new(1) };
        let _ = const { area_index!(1) };
    }
}
