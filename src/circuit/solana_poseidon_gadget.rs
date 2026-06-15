use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::{
    AssignedValue, Context,
    QuantumCell::{Constant, Existing},
    gates::{GateChip, GateInstructions},
    halo2_proofs::arithmetic::Field,
};
use pse_poseidon::Spec;
use solana_poseidon::{Endianness, Parameters, hashv};

use crate::circuit::utils::{fr_from_le_bytes, fr_to_le_bytes};

// Solana `Parameters::Bn254X5` for 9 inputs:
//   width/state T = inputs + 1 = 10
//   full rounds R_F = 8
//   partial rounds R_P = 60
//   S-box alpha = 5
//   domain tag = 0
//   output = state[0]
pub const SOLANA_POSEIDON_INPUTS: usize = 9;
const SOLANA_POSEIDON_WIDTH: usize = SOLANA_POSEIDON_INPUTS + 1;
const SOLANA_POSEIDON_R_F: usize = 8;
const SOLANA_POSEIDON_R_P: usize = 60;

pub fn solana_poseidon_hash_native_rust(inputs: &[Fr; SOLANA_POSEIDON_INPUTS]) -> Fr {
    let input_bytes = inputs.map(fr_to_le_bytes);
    let input_refs: [&[u8]; SOLANA_POSEIDON_INPUTS] =
        input_bytes.each_ref().map(|bytes| &bytes[..]);
    let hash = hashv(Parameters::Bn254X5, Endianness::LittleEndian, &input_refs).unwrap();
    fr_from_le_bytes(hash.to_bytes())
}

pub struct SolanaPoseidonChip<const MAX_CHUNKS: usize> {
    gate: GateChip<Fr>,
}

impl<const MAX_CHUNKS: usize> SolanaPoseidonChip<MAX_CHUNKS> {
    pub fn new() -> Self {
        Self { gate: GateChip::default() }
    }

    pub fn commitment_inputs(
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

    pub fn hash_commitment_9_inputs(
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

#[cfg(test)]
mod tests {
    use crate::circuit::constraint_1::project_simple_poseidon_v2::MAX_CHUNKS;

    use super::*;
    use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
    use halo2_base::halo2_proofs::dev::MockProver;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn test_solana_poseidon_matches_reference_vectors() {
        let k = 18;
        let mut rng = StdRng::seed_from_u64(0x5eed);
        let mut vectors = vec![
            (Fr::ZERO, [Fr::ZERO; MAX_CHUNKS], [Fr::ZERO; MAX_CHUNKS]),
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
            expected_hashes.push(solana_poseidon_hash_native_rust(
                &SolanaPoseidonChip::commitment_inputs(
                    s,
                    total_amount,
                    &chunks,
                    &addresses,
                ),
            ));

            let ctx = builder.main(0);
            let s = ctx.load_witness(s);
            let total_amount = ctx.load_witness(total_amount);
            let chunks = chunks.map(|chunk| ctx.load_witness(chunk));
            let addresses = addresses.map(|address| ctx.load_witness(address));
            let hash = SolanaPoseidonChip::new().hash_commitment_9_inputs(
                ctx,
                s,
                total_amount,
                &chunks,
                &addresses,
            );
            builder.assigned_instances[0].push(hash);
        }

        builder.calculate_params(Some(9));
        MockProver::run(k as u32, &builder, vec![expected_hashes]).unwrap().assert_satisfied();
    }
}
