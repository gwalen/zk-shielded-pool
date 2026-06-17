use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use solana_poseidon::{Endianness, Parameters};

use crate::circuit::utils::{fr_from_le_bytes, fr_to_le_bytes};

// We use Fr::zero and Fr::one as no each element in our tree is a 32 byte hash,
// so we know for sure that zero and one will never be used (as hashes much bigger)
pub const Z_0: Fr = Fr::zero();
// tree node value that was not updated yet 
pub const EMPTY_VALUE: Fr = Fr::one();

pub fn generate_zero_values_for_levels(tree_depth: usize) -> Vec<Fr> {
    // zero values for each level (except root level) 
    // Example for depth 3: 0 (leaf) -> 1 (level 1) -> 2 (level 2) -> 3 (root)
    //                         Z_0   ->    Z_1      ->  Z_2        ->  this we do not need to store in zero_values (used only for root calculation)
    let mut zero_values = Vec::<Fr>::with_capacity(tree_depth);
    
    zero_values.push(Z_0);

    for i in 1..tree_depth {
        let z_prev = zero_values[i - 1];
        let z_prev_bytes = fr_to_le_bytes(z_prev);
        let hash = solana_poseidon::hashv(
            Parameters::Bn254X5,
            Endianness::LittleEndian,
            &[&z_prev_bytes, &z_prev_bytes],
        )
        .unwrap();

        zero_values.push(fr_from_le_bytes(hash.to_bytes()));
    }

    zero_values
}
