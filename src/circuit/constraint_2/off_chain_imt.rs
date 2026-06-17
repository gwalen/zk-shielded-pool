use crate::circuit::constraint_2::imt_utils::{
    EMPTY_VALUE, TREE_DEPTH_MAX, Z_0, generate_zero_values_for_levels, poseidon_hash,
};
use anyhow::{Error, Result};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

// ********************
// This is memory heavy full IMT tree builder that will be used off-chain on the client side
// to reconstruct the tree and build the Merkle proof of inclusion for give leaf node (commitment hash)
//
// It stores hash, Fr::zero and Fr::one are not possible values
// ********************

pub struct OffChainImtBuilder {
    pub nodes: Vec<Fr>,
    pub zero_values: Vec<Fr>,
    pub first_leaf_idx: usize,
    pub next_free_leaf_idx: usize,
    pub tree_depth: u32,
}

impl OffChainImtBuilder {
    pub fn new(tree_depth: u32) -> Self {
        assert!(tree_depth > 0, "Tree depth must be greater than 0");
        assert!(tree_depth <= TREE_DEPTH_MAX as u32, "Tree depth is too large");

        // For tree_depth = 20 node_code ~= 2M
        let node_count = 2usize.pow(tree_depth + 1) - 1;
        let nodes = vec![EMPTY_VALUE; node_count];

        let zero_values = generate_zero_values_for_levels(tree_depth as usize);
        // We need to skip all the nodes on levels above the zero level where leaves are stored
        let first_leaf_idx = 2usize.pow(tree_depth as u32) - 1;

        let mut builder = Self {
            nodes,
            zero_values,
            first_leaf_idx,
            next_free_leaf_idx: first_leaf_idx,
            tree_depth,
        };
        // build the empty tree with zero values
        builder.build_tree();
        builder
    }

    pub fn root(&self) -> Fr {
        self.nodes[0]
    }

    // Insert leaf on next unused leaf position, do not recalculate the full tree
    pub fn insert_leaf_lazy(&mut self, leaf: Fr) -> Result<()> {
        if leaf == EMPTY_VALUE || leaf == Z_0 {
            return Err(Error::msg("Leaf value is not valid"));
        }
        if self.next_free_leaf_idx >= self.nodes.len() {
            return Err(Error::msg("Tree is full"));
        }
        self.nodes[self.next_free_leaf_idx] = leaf;
        self.next_free_leaf_idx += 1;
        Ok(())
    }

    pub fn build_tree(&mut self) {
        // first fill the leaf level
        for i in self.first_leaf_idx..self.nodes.len() {
            self.nodes[i] = self.node(i);
        }

        let mut last_level_start_idx = self.first_leaf_idx;
        // fill other levels
        for level in 1..=self.tree_depth {
            let level_start_idx = 2usize.pow(self.tree_depth - level) - 1;
            for i in level_start_idx..last_level_start_idx {
                let left_child = self.node(i * 2 + 1);
                let right_child = self.node(i * 2 + 2);
                self.nodes[i] = poseidon_hash(left_child, right_child)
            }
            last_level_start_idx = level_start_idx;
        }
    }

    fn node(&self, idx: usize) -> Fr {
        if self.nodes[idx] == EMPTY_VALUE {
            // unset node, fetch zero value based on level
            let node_level = self.calculate_level(idx);
            self.zero_values[node_level]
        } else {
            self.nodes[idx]
        }
    }

    /**
     * Example tree indexes for depth = 3 :
     *            0               - level 3 (root)
     *      1            2        - level 2
     *   3    4      5      6     - level 1
     *  7 8  9 10  11 12  13 14   - level 0 (leafs)
     */
    fn calculate_level(&self, node_idx: usize) -> usize {
        // ilog2 - does integer bit logic, not floating-point logarithms. It asks: “what is the position of the highest set bit?”
        let depth_from_root = (node_idx + 1).ilog2();
        (self.tree_depth - depth_from_root) as usize
    }
}
