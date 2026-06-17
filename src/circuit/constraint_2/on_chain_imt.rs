use anyhow::{Error, Result};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use solana_poseidon::{Endianness, Parameters};

use crate::circuit::{
    constraint_2::imt_utils::{EMPTY_VALUE, generate_zero_values_for_levels},
    utils::{fr_from_le_bytes, fr_to_le_bytes},
};

// const TREE_DEPTH: usize = 10;

// This limits only how many deposit can happen in between you generate a proof for withdrawal
// and actually sending the withdrawal transaction as each new deposit changes the root.
// The on-chain program keeps a ring buffer of the last ROOT_HISTORY_LENGTH roots.
//
// The circuit proves membership against ONE root, supplied as a public input by the prover (root observed during proof generation).
// After verifying the proof, the program checks that this public root is present in the
// ring buffer. If it has already rolled off (more than ROOT_HISTORY_LENGTH deposits landed
// since the proof was made), the program rejects it — regenerate the proof against a more
// recent root and resubmit.
const ROOT_HISTORY_LENGTH: usize = 10;

const TREE_DEPTH_MAX: usize = 20; // 1M leafs and total size of full tree  64MB (32 bytes per leaf)

/// # Fields
///
/// - `root` - current root of the tree (root level == TREE_DEPTH, leaf level == 0)
///
/// - `frontiers` - also called filledSubtrees. It stores exactly one hash per level — the hash of the
///   most recently updated left subtree at that level.
///   One value per level (no need to store it for root level)
///
/// - `zero_values` - Z_k for each level k (precomputed). Contains TREE_DEPTH values (we do not need it on root level)
///
/// - `roots_history` - old roots history. Represented as ring buffer.
///
/// - `last_root_idx` - index of the last root in the roots_history
///
/// - `next_leaf_idx` - Index of the next leaf to be inserted (0.. 2^TREE_DEPTH)
///   First level depth == 0 and amount of leafs at this level is 2^TREE_DEPTH
struct OnChainImt<const TREE_DEPTH: usize> {
    root: Fr,
    frontiers: [Fr; TREE_DEPTH],
    zero_values: [Fr; TREE_DEPTH],
    roots_history: [Fr; ROOT_HISTORY_LENGTH],
    last_root_idx: usize,
    next_leaf_idx: usize,
}

impl<const TREE_DEPTH: usize> OnChainImt<TREE_DEPTH> {
    pub fn new() -> Self {
        assert!(TREE_DEPTH <= TREE_DEPTH_MAX, "Tree depth is too large");

        // init tree values when tree is empty (no leaves inserted yet) -  but still need to be correct Merkle tree (hashing tree)
        let zero_values: [Fr; TREE_DEPTH] =
            generate_zero_values_for_levels(TREE_DEPTH).try_into().unwrap();
        let root = Self::hash(zero_values[TREE_DEPTH - 1], zero_values[TREE_DEPTH - 1]);
        let mut roots_history = [EMPTY_VALUE; ROOT_HISTORY_LENGTH];
        roots_history[0] = root;
        
        Self {
            root,
            frontiers: [EMPTY_VALUE; TREE_DEPTH], // initial values do not matter (will be first filled during first insert)
            zero_values,
            roots_history,
            last_root_idx: 0,
            next_leaf_idx: 0,
        }
    }

    pub fn insert(&mut self, leaf: Fr) -> Result<()> {
        if self.next_leaf_idx >= 1 << TREE_DEPTH {
            return Err(Error::msg("Tree is full"));
        }

        // traverse tree from leaf to root (current leaf index in leaf level == next_leaf_index)
        let mut current_idx = self.next_leaf_idx;
        let mut current_node_value = leaf;
        for current_level in 0..TREE_DEPTH {
            let is_left_leaf = current_idx % 2 == 0;

            // go level up add calculate upper node value
            if is_left_leaf {
                self.frontiers[current_level] = current_node_value;
                current_node_value = Self::hash(current_node_value, self.zero_values[current_level])
            } else {
                current_node_value = Self::hash(self.frontiers[current_level], current_node_value)
            };
            current_idx /= 2;
        }
        self.root = current_node_value;
        self.next_leaf_idx += 1;
        self.inc_last_root_idx();
        self.roots_history[self.last_root_idx] = self.root;

        Ok(())
    }

    // root_history is a ring buffer (cyclic array)
    fn inc_last_root_idx(&mut self) {
        if self.last_root_idx == ROOT_HISTORY_LENGTH - 1 {
            self.last_root_idx = 0;
        } else {
            self.last_root_idx += 1;
        }
    }

    fn hash(left: Fr, right: Fr) -> Fr {
        let hash = solana_poseidon::hashv(
            Parameters::Bn254X5,
            Endianness::LittleEndian,
            &[&fr_to_le_bytes(left), &fr_to_le_bytes(right)],
        )
        .unwrap();

        fr_from_le_bytes(hash.to_bytes())
    }
}
