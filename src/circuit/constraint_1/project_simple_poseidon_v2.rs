use halo2_base::halo2_proofs::halo2curves::group::ff::PrimeField;
use halo2_base::{
    AssignedValue, Context,
    QuantumCell::{Constant, Existing},
    gates::{GateChip, GateInstructions, circuit::builder::BaseCircuitBuilder},
    halo2_proofs::{
        arithmetic::Field, dev::MockProver, dev::VerifyFailure, halo2curves::bn256::Fr,
    },
};
use pse_poseidon::Spec;
use solana_poseidon::{Endianness, Parameters, hashv};

// *** Commitment reconstruction constraint, Solana-compatible Poseidon shape ***
//
// Exploration summary:
// 1. A ready-made Halo2 gadget would need to explicitly match
//    `light_poseidon::Poseidon::new_circom(n)` / Solana `sol_poseidon`.
//    The local `halo2-base` Poseidon gadget is a sponge and is not that gadget.
// 2. This file uses a small fixed-arity gadget for this project's current
//    9-field-element commitment.
//
// Solana `Parameters::Bn254X5` for 9 inputs:
//   width/state T = inputs + 1 = 10
//   full rounds R_F = 8
//   partial rounds R_P = 60
//   S-box alpha = 5
//   domain tag = 0
//   output = state[0]
const SOLANA_POSEIDON_INPUTS: usize = 9;
const SOLANA_POSEIDON_WIDTH: usize = SOLANA_POSEIDON_INPUTS + 1;
const SOLANA_POSEIDON_R_F: usize = 8;
const SOLANA_POSEIDON_R_P: usize = 60;

// Max length of the list of addresses and chunks.
const MAX_CHUNKS: usize = 3;

pub struct SolanaPoseidonChip {
    gate: GateChip<Fr>,
}

impl SolanaPoseidonChip {
    pub fn new() -> Self {
        Self { gate: GateChip::default() }
    }

    pub fn hash_commitment(
        &self,
        ctx: &mut Context<Fr>,
        s: AssignedValue<Fr>,
        total_amount: AssignedValue<Fr>,
        chunks: &[AssignedValue<Fr>; MAX_CHUNKS],
        addresses: &[AssignedValue<Fr>; MAX_CHUNKS],
    ) -> AssignedValue<Fr> {
        let assigned_m = ctx.load_constant(Fr::from(MAX_CHUNKS as u64));
        let inputs = [
            s,
            total_amount,
            chunks[0],
            chunks[1],
            chunks[2],
            addresses[0],
            addresses[1],
            addresses[2],
            assigned_m,
        ];

        let mut sum_of_chunks = ctx.load_zero();
        for chunk in chunks {
            sum_of_chunks = self.gate.add(ctx, *chunk, sum_of_chunks);
        }
        ctx.constrain_equal(&sum_of_chunks, &total_amount);

        solana_poseidon_9(ctx, &self.gate, inputs)
    }
}

fn solana_poseidon_9(
    ctx: &mut Context<Fr>,
    gate: &impl GateInstructions<Fr>,
    inputs: [AssignedValue<Fr>; SOLANA_POSEIDON_INPUTS],
) -> AssignedValue<Fr> {
    let spec = Spec::<Fr, SOLANA_POSEIDON_WIDTH, SOLANA_POSEIDON_INPUTS>::new(
        SOLANA_POSEIDON_R_F,
        SOLANA_POSEIDON_R_P,
    );

    let domain_tag = ctx.load_zero();
    let mut state: [AssignedValue<Fr>; SOLANA_POSEIDON_WIDTH] =
        std::array::from_fn(|i| if i == 0 { domain_tag } else { inputs[i - 1] });

    let constants = spec.constants();
    let mds_matrices = spec.mds_matrices();
    let r_f_half = SOLANA_POSEIDON_R_F / 2;

    add_constants(ctx, gate, &mut state, &constants.start()[0]);
    for round_constants in constants.start().iter().skip(1).take(r_f_half - 1) {
        sbox_full(ctx, gate, &mut state);
        add_constants(ctx, gate, &mut state, round_constants);
        apply_mds(ctx, gate, &mut state, &mds_matrices.mds().rows());
    }
    sbox_full(ctx, gate, &mut state);
    add_constants(ctx, gate, &mut state, constants.start().last().unwrap());
    apply_mds(ctx, gate, &mut state, &mds_matrices.pre_sparse_mds().rows());

    for (round_constant, sparse_mds) in
        constants.partial().iter().zip(mds_matrices.sparse_matrices())
    {
        state[0] = sbox_5(ctx, gate, state[0]);
        state[0] = add_constant(ctx, gate, state[0], *round_constant);

        let old = state;
        state[0] = gate.inner_product(
            ctx,
            old.iter().copied(),
            sparse_mds.row().iter().map(|c| Constant(*c)),
        );
        for i in 1..SOLANA_POSEIDON_WIDTH {
            state[i] = gate.mul_add(ctx, old[0], Constant(sparse_mds.col_hat()[i - 1]), old[i]);
        }
    }

    for round_constants in constants.end() {
        sbox_full(ctx, gate, &mut state);
        add_constants(ctx, gate, &mut state, round_constants);
        apply_mds(ctx, gate, &mut state, &mds_matrices.mds().rows());
    }
    sbox_full(ctx, gate, &mut state);
    apply_mds(ctx, gate, &mut state, &mds_matrices.mds().rows());

    state[0]
}

fn sbox_full(
    ctx: &mut Context<Fr>,
    gate: &impl GateInstructions<Fr>,
    state: &mut [AssignedValue<Fr>; SOLANA_POSEIDON_WIDTH],
) {
    for value in state.iter_mut() {
        *value = sbox_5(ctx, gate, *value);
    }
}

fn sbox_5(
    ctx: &mut Context<Fr>,
    gate: &impl GateInstructions<Fr>,
    value: AssignedValue<Fr>,
) -> AssignedValue<Fr> {
    let value_squared = gate.mul(ctx, value, value);
    let value_fourth = gate.mul(ctx, value_squared, value_squared);
    gate.mul(ctx, value, value_fourth)
}

fn add_constants(
    ctx: &mut Context<Fr>,
    gate: &impl GateInstructions<Fr>,
    state: &mut [AssignedValue<Fr>; SOLANA_POSEIDON_WIDTH],
    constants: &[Fr; SOLANA_POSEIDON_WIDTH],
) {
    for (value, constant) in state.iter_mut().zip(constants.iter()) {
        *value = add_constant(ctx, gate, *value, *constant);
    }
}

fn add_constant(
    ctx: &mut Context<Fr>,
    gate: &impl GateInstructions<Fr>,
    value: AssignedValue<Fr>,
    constant: Fr,
) -> AssignedValue<Fr> {
    if constant == Fr::ZERO { value } else { gate.add(ctx, value, Constant(constant)) }
}

fn apply_mds(
    ctx: &mut Context<Fr>,
    gate: &impl GateInstructions<Fr>,
    state: &mut [AssignedValue<Fr>; SOLANA_POSEIDON_WIDTH],
    rows: &[[Fr; SOLANA_POSEIDON_WIDTH]; SOLANA_POSEIDON_WIDTH],
) {
    let old = *state;
    for (value, row) in state.iter_mut().zip(rows.iter()) {
        *value = gate.inner_product(
            ctx,
            old.iter().map(|x| Existing(*x)),
            row.iter().map(|c| Constant(*c)),
        );
    }
}

fn fr_to_le_bytes(value: Fr) -> [u8; 32] {
    value.to_repr()
}

fn fr_from_le_bytes(bytes: [u8; 32]) -> Fr {
    Fr::from_repr(bytes).unwrap()
}

fn solana_poseidon_hash_native_rust(inputs: &[Fr; SOLANA_POSEIDON_INPUTS]) -> Fr {
    let input_bytes = inputs.map(fr_to_le_bytes);
    let input_refs: [&[u8]; SOLANA_POSEIDON_INPUTS] =
        input_bytes.each_ref().map(|bytes| &bytes[..]);
    let hash = hashv(Parameters::Bn254X5, Endianness::LittleEndian, &input_refs).unwrap();
    fr_from_le_bytes(hash.to_bytes())
}

fn commitment_inputs(
    s: Fr,
    total_amount: Fr,
    chunks: &[Fr; MAX_CHUNKS],
    addresses: &[Fr; MAX_CHUNKS],
) -> [Fr; SOLANA_POSEIDON_INPUTS] {
    [
        s,
        total_amount,
        chunks[0],
        chunks[1],
        chunks[2],
        addresses[0],
        addresses[1],
        addresses[2],
        Fr::from(MAX_CHUNKS as u64),
    ]
}

pub fn build_solana_poseidon_circuit(
    builder: &mut BaseCircuitBuilder<Fr>,
    s: Fr,
    total_amount: Fr,
    chunks: &[Fr; MAX_CHUNKS],
    addresses: &[Fr; MAX_CHUNKS],
) {
    let chip = SolanaPoseidonChip::new();
    let ctx = builder.main(0);

    let s_witness = ctx.load_witness(s);
    let total_amount_witness = ctx.load_witness(total_amount);
    let chunks_witness: [AssignedValue<Fr>; MAX_CHUNKS] =
        std::array::from_fn(|i| ctx.load_witness(chunks[i]));
    let addresses_witness: [AssignedValue<Fr>; MAX_CHUNKS] =
        std::array::from_fn(|i| ctx.load_witness(addresses[i]));

    let poseidon_hash = chip.hash_commitment(
        ctx,
        s_witness,
        total_amount_witness,
        &chunks_witness,
        &addresses_witness,
    );

    builder.assigned_instances[0].push(poseidon_hash);
}

pub fn run_constraint_1_solana_poseidon_test_ok() -> Result<(), Vec<VerifyFailure>> {
    let k = 16;

    let s = Fr::from(1234567890);
    let total_amount = Fr::from(7);
    let chunks = [Fr::from(2), Fr::from(2), Fr::from(3)];
    // Demo addresses are already field elements. Raw Solana pubkeys need a
    // separate, identical field-mapping step in both the circuit and program.
    let addresses = [Fr::from(1001), Fr::from(1002), Fr::from(1003)];

    let poseidon_hash =
        solana_poseidon_hash_native_rust(&commitment_inputs(s, total_amount, &chunks, &addresses));
    println!("Solana-compatible Poseidon hash: {:?}", poseidon_hash);

    let mut builder =
        BaseCircuitBuilder::<Fr>::new(false).use_k(k as usize).use_instance_columns(1);

    build_solana_poseidon_circuit(&mut builder, s, total_amount, &chunks, &addresses);
    builder.calculate_params(Some(9));

    let instances = vec![vec![poseidon_hash]];
    let verification_result = MockProver::run(k, &builder, instances).unwrap().verify();
    match &verification_result {
        Ok(()) => println!("Solana-compatible Poseidon verification successful"),
        Err(e) => println!("Solana-compatible Poseidon verification failed: {e:?}"),
    }
    verification_result
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn test_solana_poseidon_v2_circuit() {
        let verification_result = run_constraint_1_solana_poseidon_test_ok();
        assert!(verification_result.is_ok());
    }

    // test containing 12 test vectors for different inputs
    #[test]
    fn test_solana_poseidon_matches_reference_vectors() {
        let k = 18;
        let mut rng = StdRng::seed_from_u64(0x5eed);
        let mut vectors = vec![
            // All-zero vector
            (Fr::ZERO, [Fr::ZERO; MAX_CHUNKS], [Fr::ZERO; MAX_CHUNKS]),
            // Vector containing -1
            (-Fr::ONE, [Fr::ONE, Fr::from(2), Fr::from(3)], [-Fr::ONE, Fr::ZERO, Fr::ONE]),
        ];

        for _ in 0..10 {
            vectors.push((
                Fr::random(&mut rng),
                std::array::from_fn(|_| Fr::random(&mut rng)),
                std::array::from_fn(|_| Fr::random(&mut rng)),
            ));
        }

        let mut builder = BaseCircuitBuilder::<Fr>::new(false).use_k(k).use_instance_columns(1);
        let mut expected_hashes = Vec::with_capacity(vectors.len());

        for (s, chunks, addresses) in vectors {
            let total_amount = chunks.iter().copied().sum();
            expected_hashes.push(solana_poseidon_hash_native_rust(&commitment_inputs(
                s,
                total_amount,
                &chunks,
                &addresses,
            )));
            build_solana_poseidon_circuit(&mut builder, s, total_amount, &chunks, &addresses);
        }

        builder.calculate_params(Some(9));
        MockProver::run(k as u32, &builder, vec![expected_hashes]).unwrap().assert_satisfied();
    }

    // test rejecting wrong public hash
    #[test]
    fn test_solana_poseidon_rejects_wrong_public_hash() {
        let k = 16;
        let s = Fr::from(1234567890);
        let total_amount = Fr::from(7);
        let chunks = [Fr::from(2), Fr::from(2), Fr::from(3)];
        let addresses = [Fr::from(1001), Fr::from(1002), Fr::from(1003)];

        let expected_hash = solana_poseidon_hash_native_rust(&commitment_inputs(
            s,
            total_amount,
            &chunks,
            &addresses,
        ));
        let wrong_hash = expected_hash + Fr::ONE;

        let mut builder = BaseCircuitBuilder::<Fr>::new(false).use_k(k).use_instance_columns(1);
        build_solana_poseidon_circuit(&mut builder, s, total_amount, &chunks, &addresses);
        builder.calculate_params(Some(9));

        assert!(
            MockProver::run(k as u32, &builder, vec![vec![wrong_hash]]).unwrap().verify().is_err()
        );
    }
}
