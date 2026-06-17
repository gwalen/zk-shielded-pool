use halo2_base::halo2_proofs::dev::VerifyFailure;
use halo2_base::poseidon::hasher::PoseidonSponge;
use halo2_base::{
    AssignedValue, Context,
    gates::{GateChip, GateInstructions, circuit::builder::BaseCircuitBuilder},
    halo2_proofs::{arithmetic::Field, dev::MockProver, halo2curves::bn256::Fr},
};

// *** Pool membership constraint ***

// TODO:
// 1. on-chain IMT insert that holds just root and frontier values (as Fr) and precomputed Z_k empty leafs values for each level.
// 2. off-chain IMT tree builder for whole tree at given time (after all inserts) that will be used to create the Merkle proof of inclusion for given commitment.
// 3. circuit IMT Merkle proof checker to assert that given commitment is in the tree.
//
// - For hashing we use Solana Poseidon.
// - All elements of IMT are Fr.
