use halo2_base::halo2_proofs::dev::VerifyFailure;
use halo2_base::poseidon::hasher::PoseidonSponge;
use halo2_base::{
    AssignedValue, Context,
    gates::{GateChip, GateInstructions, circuit::builder::BaseCircuitBuilder},
    halo2_proofs::{arithmetic::Field, dev::MockProver, halo2curves::bn256::Fr},
};

// *** Pool membership constraint ***