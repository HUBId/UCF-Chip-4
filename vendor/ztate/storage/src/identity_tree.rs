// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE.md for licensing terms.

//! Identity tree re-exports maintained for backwards compatibility.
//!
//! The identity tree implementation now lives in the `rpp-identity-tree` crate.
//! This module simply re-exports the public API so existing downstream users
//! that depend on `firewood-storage` continue to compile without code changes.

pub use rpp_identity_tree::{
    IdentityCommitmentProof, IdentityCommitmentTree, IdentityTreeError, IdentityTreeResult,
    IDENTITY_TREE_DEPTH,
};
