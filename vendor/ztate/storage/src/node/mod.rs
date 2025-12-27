// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE.md for licensing terms.

#![expect(
    clippy::indexing_slicing,
    reason = "Found 1 occurrences after enabling the lint."
)]
#![expect(
    clippy::items_after_statements,
    reason = "Found 2 occurrences after enabling the lint."
)]
#![expect(
    clippy::missing_errors_doc,
    reason = "Found 1 occurrences after enabling the lint."
)]
#![expect(
    clippy::missing_panics_doc,
    reason = "Found 1 occurrences after enabling the lint."
)]
#![allow(clippy::expect_used)] // Node serialization relies on expect when detecting structurally invalid encodings.

use crate::node::branch::ReadSerializable;
use crate::nodestore::AreaIndex;
use crate::{HashType, LinearAddress, Path, SharedNode};
use bitfield::bitfield;
use branch::Serializable as _;
pub use branch::{BranchNode, Child, Children};
use enum_as_inner::EnumAsInner;
use integer_encoding::{VarInt, VarIntReader as _};
pub use leaf::LeafNode;
use std::fmt::Debug;
use std::io::{Error, Read};
use std::mem::size_of;

pub mod branch;
mod leaf;
pub mod path;
pub mod persist;
/// A node, either a Branch or Leaf
//
// The [`BranchNode`] variant is boxed because branch nodes are several orders of
// magnitude larger than leaves: `size_of::<BranchNode>()` is 1,752 bytes with the
// default 16-way branching factor, while `size_of::<LeafNode>()` is only 88 bytes
// (a [`Path`] plus the boxed value). Storing branch nodes inline would inflate
// the `Node` enum itself to the branch size (≈1.7 KiB), making every move,
// clone, or `Option<Node>` allocation pay for an entire branch payload even when
// the variant holds a leaf. Boxing keeps `Node` at 96 bytes so branch-heavy
// traversals copy just the pointer-sized handle, and matches the persistence
// layout described in the Firewood storage architecture notes. See
// `docs/storage/firewood.md` for a detailed breakdown of the node layout and
// allocation trade-offs.
#[derive(PartialEq, Eq, Clone, Debug, EnumAsInner)]
#[repr(C)]
pub enum Node {
    /// This node is a [`BranchNode`]
    Branch(Box<BranchNode>),
    /// This node is a [`LeafNode`]
    Leaf(LeafNode),
}

impl Default for Node {
    fn default() -> Self {
        Node::Leaf(LeafNode {
            partial_path: Path::new(),
            value: Box::default(),
        })
    }
}

impl From<BranchNode> for Node {
    fn from(branch: BranchNode) -> Self {
        Node::Branch(Box::new(branch))
    }
}

impl From<LeafNode> for Node {
    fn from(leaf: LeafNode) -> Self {
        Node::Leaf(leaf)
    }
}

#[cfg(not(feature = "branch_factor_256"))]
bitfield! {
    struct BranchFirstByte(u8);
    impl Debug;
    impl new;
    u8;
    has_value, set_has_value: 1, 1;
    number_children, set_number_children: 5, 2;
    partial_path_length, set_partial_path_length: 7, 6;
}
#[cfg(not(feature = "branch_factor_256"))]
const BRANCH_PARTIAL_PATH_LEN_OVERFLOW: u8 = (1 << 2) - 1; // 3 nibbles

#[cfg(feature = "branch_factor_256")]
bitfield! {
    struct BranchFirstByte(u8);
    impl Debug;
    impl new;
    u8;
    has_value, set_has_value: 1, 1;
    partial_path_length, set_partial_path_length: 7, 2;
}
#[cfg(feature = "branch_factor_256")]
const BRANCH_PARTIAL_PATH_LEN_OVERFLOW: u8 = (1 << 6) - 1; // 63 nibbles

bitfield! {
    struct LeafFirstByte(u8);
    impl Debug;
    impl new;
    u8;
    is_leaf, set_is_leaf: 0, 0;
    partial_path_length, set_partial_path_length: 7, 1;
}

const LEAF_PARTIAL_PATH_LEN_OVERFLOW: u8 = (1 << 7) - 2; // 126 nibbles (-1 for indicating Free Area (0xff))

impl Default for LeafFirstByte {
    fn default() -> Self {
        LeafFirstByte(1)
    }
}

/// Maximum number of bytes required to encode a [`VarInt`].
const MAX_VARINT_LENGTH: usize = 10;

/// Append the varint-encoded representation of `value` to `buffer` without allocating
/// temporary storage on the heap.
///
/// We reserve the maximum encoded length up-front so that callers can provide capacity
/// hints and avoid reallocations even though we use a stack buffer for encoding.
#[inline]
pub(crate) fn extend_vec_with_varint<VI: VarInt>(buffer: &mut Vec<u8>, value: VI) {
    buffer.reserve(MAX_VARINT_LENGTH);

    #[expect(clippy::indexing_slicing)]
    {
        let mut scratch = [0u8; MAX_VARINT_LENGTH];
        let written = VarInt::encode_var(value, &mut scratch);
        buffer.extend_from_slice(&scratch[..written]);
    }
}

fn packed_nibble_len(nibbles: usize) -> usize {
    nibbles / 2 + nibbles % 2
}

fn extend_with_packed_nibbles(buffer: &mut Vec<u8>, path: &Path) {
    let mut iter = path.iter().copied();
    while let Some(high) = iter.next() {
        debug_assert!(high <= 0x0f, "partial path nibble overflow: {high}");
        match iter.next() {
            Some(low) => {
                debug_assert!(low <= 0x0f, "partial path nibble overflow: {low}");
                buffer.push((high << 4) | (low & 0x0f));
            }
            None => buffer.push(high << 4),
        }
    }
}

fn path_from_packed_bytes(bytes: Vec<u8>, nibble_len: usize) -> Path {
    if nibble_len == 0 {
        return Path::new();
    }

    let mut nibbles = Vec::with_capacity(nibble_len);
    for byte in bytes {
        if nibbles.len() == nibble_len {
            break;
        }
        nibbles.push(byte >> 4);
        if nibbles.len() == nibble_len {
            break;
        }
        nibbles.push(byte & 0x0f);
    }

    Path::from(nibbles)
}

impl Node {
    /// Returns the partial path of the node.
    #[must_use]
    pub fn partial_path(&self) -> &Path {
        match self {
            Node::Branch(b) => &b.partial_path,
            Node::Leaf(l) => &l.partial_path,
        }
    }

    /// Updates the partial path of the node to `partial_path`.
    pub fn update_partial_path(&mut self, partial_path: Path) {
        match self {
            Node::Branch(b) => b.partial_path = partial_path,
            Node::Leaf(l) => l.partial_path = partial_path,
        }
    }

    /// Updates the value of the node to `value`.
    pub fn update_value(&mut self, value: Box<[u8]>) {
        match self {
            Node::Branch(b) => b.value = Some(value),
            Node::Leaf(l) => l.value = value,
        }
    }

    /// Returns Some(value) inside the node, or None if the node is a branch
    /// with no value.
    #[must_use]
    pub fn value(&self) -> Option<&[u8]> {
        match self {
            Node::Branch(b) => b.value.as_deref(),
            Node::Leaf(l) => Some(&l.value),
        }
    }

    /// Returns the length in bytes of the serialized representation of this node,
    /// including the leading area-size prefix byte.
    #[must_use]
    pub fn serialized_length(&self) -> usize {
        match self {
            Node::Branch(branch) => Self::branch_serialized_length(branch),
            Node::Leaf(leaf) => Self::leaf_serialized_length(leaf),
        }
    }

    fn branch_serialized_length(branch: &BranchNode) -> usize {
        let mut length = 1; // area index prefix
        length += 1; // branch marker byte

        #[cfg(feature = "branch_factor_256")]
        {
            length += 1; // child count byte for branch_factor_256 encoding
        }

        let partial_path_len = branch.partial_path.len();
        if partial_path_len >= BRANCH_PARTIAL_PATH_LEN_OVERFLOW as usize {
            length += Self::varint_length(partial_path_len);
        }
        length += packed_nibble_len(partial_path_len);

        if let Some(value) = &branch.value {
            length += Self::varint_length(value.len());
            length += value.len();
        }

        let childcount = branch
            .children
            .iter()
            .filter(|child| child.is_some())
            .count();

        if childcount == BranchNode::MAX_CHILDREN {
            for child in branch.children.iter().filter_map(|child| child.as_ref()) {
                length += Self::child_serialized_length(child);
            }
        } else {
            for (position, child) in branch.children.iter().enumerate() {
                if let Some(child) = child.as_ref() {
                    length += Self::varint_length(position);
                    length += Self::child_serialized_length(child);
                }
            }
        }

        length
    }

    fn leaf_serialized_length(leaf: &LeafNode) -> usize {
        let mut length = 1; // area index prefix
        length += 1; // leaf marker byte

        let partial_path_len = leaf.partial_path.len();
        if partial_path_len >= LEAF_PARTIAL_PATH_LEN_OVERFLOW as usize {
            length += Self::varint_length(partial_path_len);
        }
        length += packed_nibble_len(partial_path_len);

        length += Self::varint_length(leaf.value.len());
        length += leaf.value.len();

        length
    }

    fn child_serialized_length(child: &Child) -> usize {
        let hash_len = match child {
            Child::AddressWithHash(_, hash) => Self::hash_serialized_len(hash),
            Child::MaybePersisted(_, hash) => Self::hash_serialized_len(hash),
            Child::Node(_) => {
                debug_assert!(false, "unhashed child when computing serialized length");
                0
            }
        };

        size_of::<u64>() + hash_len
    }

    #[cfg(feature = "ethhash")]
    fn hash_serialized_len(hash: &HashType) -> usize {
        match hash {
            crate::node::branch::ethhash::HashOrRlp::Hash(h) => 1 + h.as_ref().len(),
            crate::node::branch::ethhash::HashOrRlp::Rlp(r) => 1 + r.len(),
        }
    }

    #[cfg(not(feature = "ethhash"))]
    fn hash_serialized_len(hash: &HashType) -> usize {
        hash.as_ref().len()
    }

    fn varint_length(value: usize) -> usize {
        let mut length = 1;
        let mut value = value as u64;
        while value >= 0x80 {
            value >>= 7;
            length += 1;
        }
        length
    }

    /// Given a [Node], returns a set of bytes to write to storage
    /// The format is as follows:
    ///
    /// For a branch:
    ///  - Byte 0:
    ///   - Bit 0: always 0
    ///   - Bit 1: indicates if the branch has a value
    ///   - Bits 2-5: the number of children (unless `branch_factor_256`, which stores it in the next byte)
    ///   - Bits 6-7: 0: empty `partial_path`, 1: 1 nibble, 2: 2 nibbles, 3: length is encoded in the next byte
    ///     (for `branch_factor_256`, bits 2-7 are used for `partial_path` length, up to 63 nibbles)
    ///
    /// The remaining bytes are in the following order:
    ///   - The partial path packed as pairs of nibbles (two per byte, with an odd trailing nibble padded)
    ///     and preceded by a varint length when longer than 3 nibbles
    ///   - The number of children, if the branch factor is 256
    ///   - The children. If the number of children == [`BranchNode::MAX_CHILDREN`], then the children are just
    ///     addresses with hashes. Otherwise, they are offset, address, hash tuples.
    ///
    /// For a leaf:
    ///  - Byte 0:
    ///    - Bit 0: always 1
    ///    - Bits 1-7: the length of the partial path. If the partial path is longer than 126 nibbles, this is set to
    ///      126 and the length is encoded in the next byte.
    ///
    /// The remaining bytes are in the following order:
    ///    - The partial path packed as pairs of nibbles (two per byte, with an odd trailing nibble padded)
    ///      and preceded by a varint length when longer than 126 nibbles
    ///    - The value, always preceeded by the length, varint encoded
    ///
    /// Note that this means the first byte cannot be 255, which would be a leaf with 127 nibbles. We save this extra
    /// value to mark this as a freed area.
    ///
    /// Note that there is a "prefix" byte which is the size of the area when serializing this object. Since
    /// we always have one of those, we include it as a parameter for serialization.
    pub fn as_bytes(&self, prefix: AreaIndex, encoded: &mut Vec<u8>) {
        match self {
            Node::Branch(b) => {
                let child_iter = b
                    .children
                    .iter()
                    .enumerate()
                    .filter_map(|(offset, child)| child.as_ref().map(|c| (offset, c)));
                let childcount = child_iter.clone().count();

                // encode the first byte
                let pp_len = match b.partial_path.len() {
                    // less than 3 or 62 nibbles
                    len if len < BRANCH_PARTIAL_PATH_LEN_OVERFLOW as usize => len as u8,
                    _ => BRANCH_PARTIAL_PATH_LEN_OVERFLOW,
                };

                #[cfg(not(feature = "branch_factor_256"))]
                let first_byte: BranchFirstByte = BranchFirstByte::new(
                    u8::from(b.value.is_some()),
                    (childcount % BranchNode::MAX_CHILDREN) as u8,
                    pp_len,
                );
                #[cfg(feature = "branch_factor_256")]
                let first_byte: BranchFirstByte =
                    BranchFirstByte::new(u8::from(b.value.is_some()), pp_len);

                // create an output stack item, which can overflow to memory for very large branch nodes
                const OPTIMIZE_BRANCHES_FOR_SIZE: usize = 1024;
                encoded.reserve(OPTIMIZE_BRANCHES_FOR_SIZE);
                encoded.push(prefix.get());
                encoded.push(first_byte.0);
                #[cfg(feature = "branch_factor_256")]
                encoded.push((childcount % BranchNode::MAX_CHILDREN) as u8);

                // encode the partial path, including the length if it didn't fit above
                if pp_len == BRANCH_PARTIAL_PATH_LEN_OVERFLOW {
                    extend_vec_with_varint(encoded, b.partial_path.len());
                }
                extend_with_packed_nibbles(encoded, &b.partial_path);

                // encode the value. For tries that have the same length keys, this is always empty
                if let Some(v) = &b.value {
                    extend_vec_with_varint(encoded, v.len());
                    encoded.extend_from_slice(v);
                }

                // encode the children
                if childcount == BranchNode::MAX_CHILDREN {
                    for (_, child) in child_iter {
                        let (address, hash) = child
                            .persist_info()
                            .expect("child must be hashed when serializing");
                        encoded.extend_from_slice(&address.get().to_ne_bytes());
                        hash.write_to_vec(encoded);
                    }
                } else {
                    for (position, child) in child_iter {
                        extend_vec_with_varint(encoded, position);
                        let (address, hash) = child
                            .persist_info()
                            .expect("child must be hashed when serializing");
                        encoded.extend_from_slice(&address.get().to_ne_bytes());
                        hash.write_to_vec(encoded);
                    }
                }
            }
            Node::Leaf(l) => {
                let pp_len = match l.partial_path.len() {
                    // less than 126 nibbles
                    len if len < LEAF_PARTIAL_PATH_LEN_OVERFLOW as usize => len as u8,
                    _ => LEAF_PARTIAL_PATH_LEN_OVERFLOW,
                };
                let first_byte: LeafFirstByte = LeafFirstByte::new(1, pp_len);

                const OPTIMIZE_LEAVES_FOR_SIZE: usize = 128;
                encoded.reserve(OPTIMIZE_LEAVES_FOR_SIZE);
                encoded.push(prefix.get());
                encoded.push(first_byte.0);

                // encode the partial path, including the length if it didn't fit above
                if pp_len == LEAF_PARTIAL_PATH_LEN_OVERFLOW {
                    extend_vec_with_varint(encoded, l.partial_path.len());
                }
                extend_with_packed_nibbles(encoded, &l.partial_path);

                // encode the value
                extend_vec_with_varint(encoded, l.value.len());
                encoded.extend_from_slice(&l.value);
            }
        }
    }

    /// Given a reader, return a [Node] from those bytes
    pub fn from_reader(mut serialized: &mut impl Read) -> Result<Self, Error> {
        match serialized.read_byte()? {
            255 => {
                // this is a freed area
                Err(Error::other("attempt to read freed area"))
            }
            first_byte if first_byte & 1 == 1 => {
                let partial_path = read_path_with_overflow_length(
                    &mut serialized,
                    first_byte >> 1,
                    LEAF_PARTIAL_PATH_LEN_OVERFLOW,
                )?;
                let value_len = serialized.read_varint()?;
                let value = serialized.read_fixed_len(value_len)?;
                Ok(Node::Leaf(LeafNode {
                    partial_path,
                    value: value.into(),
                }))
            }
            branch_first_byte => {
                let branch_first_byte = BranchFirstByte(branch_first_byte);

                let has_value = branch_first_byte.has_value() == 1;
                #[cfg(not(feature = "branch_factor_256"))]
                let childcount = branch_first_byte.number_children() as usize;
                #[cfg(feature = "branch_factor_256")]
                let childcount = serialized.read_byte()? as usize;

                let partial_path = read_path_with_overflow_length(
                    &mut serialized,
                    branch_first_byte.partial_path_length(),
                    BRANCH_PARTIAL_PATH_LEN_OVERFLOW,
                )?;

                let value = if has_value {
                    let value_len = serialized.read_varint()?;
                    let value = serialized.read_fixed_len(value_len)?;
                    Some(value.into())
                } else {
                    None
                };

                let mut children = BranchNode::empty_children();
                if childcount == 0 {
                    // branch is full of all children
                    #[cfg(feature = "ethhash")]
                    {
                        for child in &mut children {
                            let mut address_buf = [0u8; 8];
                            serialized.read_exact(&mut address_buf)?;
                            let address = u64::from_ne_bytes(address_buf);

                            let hash = HashType::from_reader(&mut serialized)?;

                            *child = Some(Child::AddressWithHash(
                                LinearAddress::new(address)
                                    .ok_or(Error::other("zero address in child"))?,
                                hash,
                            ));
                        }
                    }

                    #[cfg(not(feature = "ethhash"))]
                    {
                        const ADDRESS_BYTES: usize = size_of::<u64>();
                        const HASH_BYTES: usize = size_of::<HashType>();
                        const CHILD_BYTES: usize = ADDRESS_BYTES + HASH_BYTES;

                        let mut child_bytes = vec![0u8; BranchNode::MAX_CHILDREN * CHILD_BYTES];
                        serialized.read_exact(&mut child_bytes)?;

                        for (child, chunk) in children
                            .iter_mut()
                            .zip(child_bytes.chunks_exact(CHILD_BYTES))
                        {
                            let (address_slice, hash_slice) = chunk.split_at(ADDRESS_BYTES);

                            let mut address_buf = [0u8; ADDRESS_BYTES];
                            address_buf.copy_from_slice(address_slice);
                            let address = u64::from_ne_bytes(address_buf);

                            let mut hash_buf = [0u8; HASH_BYTES];
                            hash_buf.copy_from_slice(hash_slice);
                            let hash = HashType::from(hash_buf);

                            *child = Some(Child::AddressWithHash(
                                LinearAddress::new(address)
                                    .ok_or(Error::other("zero address in child"))?,
                                hash,
                            ));
                        }
                    }
                } else {
                    for _ in 0..childcount {
                        let mut position_buf = [0u8; 1];
                        serialized.read_exact(&mut position_buf)?;
                        let position = position_buf[0] as usize;

                        let mut address_buf = [0u8; 8];
                        serialized.read_exact(&mut address_buf)?;
                        let address = u64::from_ne_bytes(address_buf);

                        let hash = HashType::from_reader(&mut serialized)?;

                        children[position] = Some(Child::AddressWithHash(
                            LinearAddress::new(address)
                                .ok_or(Error::other("zero address in child"))?,
                            hash,
                        ));
                    }
                }

                Ok(Node::Branch(Box::new(BranchNode {
                    partial_path,
                    value,
                    children,
                })))
            }
        }
    }
}

/// A path iterator item, which has the key nibbles up to this point,
/// a node, the address of the node, and the nibble that points to the
/// next child down the list
#[derive(Debug)]
pub struct PathIterItem {
    /// The key of the node at `address` as nibbles.
    pub key_nibbles: Box<[u8]>,
    /// A reference to the node
    pub node: SharedNode,
    /// The next item returned by the iterator is a child of `node`.
    /// Specifically, it's the child at index `next_nibble` in `node`'s
    /// children array.
    /// None if `node` is the last node in the path.
    pub next_nibble: Option<u8>,
}

fn read_path_with_overflow_length(
    reader: &mut impl Read,
    value: u8,
    overflow: u8,
) -> std::io::Result<Path> {
    if value < overflow {
        // the value is less than the overflow, so we can read it directly
        read_path_with_provided_length(reader, value as usize)
    } else {
        read_path_with_prefix_length(reader)
    }
}

#[cold]
#[inline(never)]
fn read_path_with_prefix_length(reader: &mut impl Read) -> std::io::Result<Path> {
    let len = reader.read_varint()?;
    read_path_with_provided_length(reader, len)
}

#[inline]
fn read_path_with_provided_length(reader: &mut impl Read, len: usize) -> std::io::Result<Path> {
    if len == 0 {
        return Ok(Path::new());
    }

    let packed_len = packed_nibble_len(len);
    reader
        .read_fixed_len(packed_len)
        .map(|bytes| path_from_packed_bytes(bytes, len))
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)] // Tests unwrap to exercise encoding paths that intentionally violate invariants.
    #![allow(clippy::expect_used)] // Tests call expect while mutating synthetic nodes to expose encoding regressions.

    use super::extend_vec_with_varint;
    use crate::node::{BranchNode, LeafNode, Node};
    use crate::nodestore::AreaIndex;
    use crate::{Child, HashType, LinearAddress, NibblesIterator, Path};
    use std::io::{Cursor, ErrorKind};
    use test_case::test_case;

    #[test_case(
        Node::Leaf(LeafNode {
            partial_path: Path::from(vec![0, 1, 2, 3]),
            value: vec![4, 5, 6, 7].into()
        }), 9; "leaf node with value")]
    #[test_case(
        Node::Leaf(LeafNode {
            partial_path: Path::from(vec![0, 1, 2]),
            value: vec![4, 5].into()
        }), 7; "leaf node with odd partial path")]
    #[test_case(
        Node::Leaf(LeafNode {
            partial_path: Path::from_nibbles_iterator(NibblesIterator::new(b"this is a really long partial path, like so long it's more than 63 nibbles long which triggers #1056.")),
            value: vec![4, 5, 6, 7].into()
        }), 110; "leaf node obnoxiously long partial path")]
    #[test_case(Node::Branch(Box::new(BranchNode {
        partial_path: Path::from(vec![0, 1]),
        value: None,
        children: std::array::from_fn(|i| {
            if i == 15 {
                Some(Child::AddressWithHash(LinearAddress::new(1).unwrap(), std::array::from_fn::<u8, 32, _>(|i| i as u8).into()))
            } else {
                None
            }
        })})), 44; "one child branch node with short partial path and no value"
    )]
    #[test_case(Node::Branch(Box::new(BranchNode {
        partial_path: Path::from(vec![0, 1, 2]),
        value: None,
        children: std::array::from_fn(|i| {
            if i == 15 {
                Some(Child::AddressWithHash(LinearAddress::new(1).unwrap(), std::array::from_fn::<u8, 32, _>(|i| i as u8).into()))
            } else {
                None
            }
        })})), 46; "one child branch node with odd partial path and no value"
    )]
    #[test_case(Node::Branch(Box::new(BranchNode {
        partial_path: Path::from(vec![0, 1, 2, 3]),
        value: Some(vec![4, 5, 6, 7].into()),
        children: std::array::from_fn(|_|
                Some(Child::AddressWithHash(LinearAddress::new(1).unwrap(), std::array::from_fn::<u8, 32, _>(|i| i as u8).into()))
        )})), 650; "full branch node with long partial path and value"
    )]
    #[test_case(Node::Branch(Box::new(BranchNode {
        partial_path: Path::from_nibbles_iterator(NibblesIterator::new(b"this is a really long partial path, like so long it's more than 63 nibbles long which triggers #1056.")),
        value: Some(vec![4, 5, 6, 7].into()),
        children: std::array::from_fn(|_|
                Some(Child::AddressWithHash(LinearAddress::new(1).unwrap(), std::array::from_fn::<u8, 32, _>(|i| i as u8).into()))
        )})), 750; "full branch node with obnoxiously long partial path"
    )]
    #[test_case(Node::Branch(Box::new(BranchNode {
        partial_path: Path::from_nibbles_iterator(NibblesIterator::new(b"this is a really long partial path, like so long it's more than 63 nibbles long which triggers #1056.")),
        value: Some((*br"
We also need to test values that have a length longer than 255 bytes so that we
verify that we decode the entire value every time. previously, we would only read
the first byte for the value length, which is incorrect if the length is greater
than 126 bytes as the length would be encoded in multiple bytes.
        ").into()),
        children: std::array::from_fn(|_|
                Some(Child::AddressWithHash(LinearAddress::new(1).unwrap(), std::array::from_fn::<u8, 32, _>(|i| i as u8).into()))
        )})), 1064; "full branch node with obnoxiously long partial path and long value"
    )]
    // When ethhash is enabled, we don't actually check the `expected_length`
    fn test_serialize_deserialize(
        node: Node,
        #[cfg_attr(
            any(feature = "branch_factor_256", feature = "ethhash"),
            expect(unused_variables)
        )]
        expected_length: usize,
    ) {
        use crate::node::Node;
        use std::io::Cursor;

        let mut serialized = Vec::new();
        node.as_bytes(AreaIndex::MIN, &mut serialized);
        #[cfg(not(any(feature = "branch_factor_256", feature = "ethhash")))]
        assert_eq!(serialized.len(), expected_length);
        let mut cursor = Cursor::new(&serialized);
        cursor.set_position(1);
        let deserialized = Node::from_reader(&mut cursor).unwrap();

        assert_eq!(node, deserialized);
    }

    #[test]
    fn extend_vec_with_varint_reuses_allocation() {
        let mut buffer = Vec::with_capacity(32);
        let ptr = buffer.as_ptr();

        extend_vec_with_varint(&mut buffer, 1u64);

        assert_eq!(
            ptr,
            buffer.as_ptr(),
            "varint encoding should not reallocate when spare capacity is available"
        );
        assert_eq!(buffer.as_slice(), &[1]);
    }

    #[test]
    fn branch_serialization_reuses_capacity() {
        let node = Node::Branch(Box::new(BranchNode {
            partial_path: Path::from(vec![0, 1, 2, 3]),
            value: Some(vec![4, 5, 6, 7].into()),
            children: std::array::from_fn(|i| {
                if i == 7 {
                    Some(Child::AddressWithHash(
                        LinearAddress::new(1).unwrap(),
                        std::array::from_fn::<u8, 32, _>(|j| (j + 1) as u8).into(),
                    ))
                } else {
                    None
                }
            }),
        }));

        let mut buffer = Vec::with_capacity(1024);
        let ptr = buffer.as_ptr();

        node.as_bytes(AreaIndex::MIN, &mut buffer);
        assert_eq!(ptr, buffer.as_ptr());

        let serialized_len = buffer.len();
        buffer.clear();

        node.as_bytes(AreaIndex::MIN, &mut buffer);
        assert_eq!(ptr, buffer.as_ptr());
        assert_eq!(buffer.len(), serialized_len);
    }

    #[test]
    fn leaf_serialization_reuses_capacity() {
        let node = Node::Leaf(LeafNode {
            partial_path: Path::from(vec![0, 1, 2, 3, 4, 5]),
            value: vec![10; 256].into(),
        });

        let mut buffer = Vec::with_capacity(512);
        let ptr = buffer.as_ptr();

        node.as_bytes(AreaIndex::MIN, &mut buffer);
        assert_eq!(ptr, buffer.as_ptr());

        let serialized_len = buffer.len();
        buffer.clear();

        node.as_bytes(AreaIndex::MIN, &mut buffer);
        assert_eq!(ptr, buffer.as_ptr());
        assert_eq!(buffer.len(), serialized_len);
    }

    #[test]
    fn full_branch_with_truncated_addresses_returns_unexpected_eof() {
        let node = Node::Branch(Box::new(BranchNode {
            partial_path: Path::new(),
            value: None,
            children: std::array::from_fn(|i| {
                Some(Child::AddressWithHash(
                    LinearAddress::new((i + 1) as u64).unwrap(),
                    HashType::from([i as u8; 32]),
                ))
            }),
        }));

        let mut serialized = Vec::new();
        node.as_bytes(AreaIndex::MIN, &mut serialized);

        let header_len = 2 + if cfg!(feature = "branch_factor_256") {
            1
        } else {
            0
        };
        let truncated_len = header_len + BranchNode::MAX_CHILDREN * size_of::<u64>() - 1;
        assert!(truncated_len < serialized.len());

        let mut cursor = Cursor::new(serialized[..truncated_len].to_vec());
        cursor.set_position(1);

        let error = Node::from_reader(&mut cursor).expect_err("deserialization should fail");
        assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
    }
}
