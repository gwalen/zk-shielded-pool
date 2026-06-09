use halo2_base::poseidon::hasher::PoseidonSponge;
use halo2_base::{
    AssignedValue, Context,
    gates::{GateChip, GateInstructions, circuit::builder::BaseCircuitBuilder},
    halo2_proofs::{arithmetic::Field, dev::MockProver, halo2curves::bn256::Fr},
};
use hex_literal::hex;
use pse_poseidon::Poseidon;


/*
Poseidon parameters (given by AI):
  T = 3       state width
  RATE = 2    two input elements absorbed per permutation
  R_F = 8     full rounds
  R_P = 57    partial rounds
*/
const T: usize = 3;
const RATE: usize = 2;
const R_F: usize = 8;
const R_P: usize = 57;

// Max length of the list of addresses and chunks
const MAX_CHUNKS: usize = 3;

pub struct PoseidonChip {
    gate: GateChip<Fr>,
}

impl PoseidonChip {
    pub fn new() -> Self {
        Self {
            gate: GateChip::default(),
        }
    }

    pub fn hash(
        &self,
        ctx: &mut Context<Fr>,
        s: AssignedValue<Fr>,
        total_amount: AssignedValue<Fr>,
        chunks: &[AssignedValue<Fr>; MAX_CHUNKS],
        addresses: &[AssignedValue<Fr>; MAX_CHUNKS],
    ) -> AssignedValue<Fr> {
        // TODO: do we need to check that total amount and chunks are in the u64 range?

        let mut sponge = PoseidonSponge::<Fr, T, RATE>::new::<R_F, R_P, 0>(ctx);
        // update only buffers AssignedValues
        sponge.update(&[s, total_amount]);
        sponge.update(chunks);
        sponge.update(addresses);

        // This is only a normal Rust value outside the circuit
        let m = Fr::from(MAX_CHUNKS as u64);
        // creates a circuit value constrained to equal that constant - adds to execution trace
        let assigned_m = ctx.load_constant(m);
        sponge.update(&[assigned_m]);

        let mut sum_of_chunks = ctx.load_zero();
        for chunk in chunks {
            sum_of_chunks = self.gate.add(ctx, *chunk, sum_of_chunks);
        }
        // add constraint that sum of chunks equals total_amount
        ctx.constrain_equal(&sum_of_chunks, &total_amount);

        // squeeze() performs the actual constrained arithmetic of Poseidon, will affect execution trace
        sponge.squeeze(ctx, &self.gate)
    }
}

// Native rust implementation of Poseidon hash for tests verification
fn poseidon_hash_native_rust(
    s: Fr,
    total_amount: Fr,
    chunks: &[Fr; MAX_CHUNKS],
    addresses: &[Fr; MAX_CHUNKS],
) -> Fr {
    let mut sponge = Poseidon::<Fr, T, RATE>::new(R_F, R_P);

    sponge.update(&[s, total_amount]);
    sponge.update(chunks);
    sponge.update(addresses);
    sponge.update(&[Fr::from(MAX_CHUNKS as u64)]);

    sponge.squeeze()
}

pub fn poseidon_circuit(
    builder: &mut BaseCircuitBuilder<Fr>,
    s: Fr,
    total_amount: Fr,
    chunks: &[Fr; MAX_CHUNKS],
    addresses: &[Fr; MAX_CHUNKS],
) {
    let chip = PoseidonChip::new();
    let ctx = builder.main(0);

    let s_witness = ctx.load_witness(s);
    let total_amount_witness = ctx.load_witness(total_amount);
    let chunks_witness: Vec<AssignedValue<Fr>> = chunks
        .iter()
        .map(|&chunk| ctx.load_witness(chunk))
        .collect();
    let addresses_witness: Vec<AssignedValue<Fr>> = addresses
        .iter()
        .map(|&addr| ctx.load_witness(addr))
        .collect();

    // NOTE:
    // - cleaner way with no try_into() Vec to array conversion:
    // let addresses_witness_v2: [AssignedValue<Fr>; MAX_CHUNKS] =
    //     std::array::from_fn(|i| ctx.load_witness(addresses[i]));

    let poseidon_hash = chip.hash(
        ctx,
        s_witness,
        total_amount_witness,
        &chunks_witness.try_into().unwrap(),
        &addresses_witness.try_into().unwrap(),
    );

    // input values are private we only check if output hash which is public is correct
    builder.assigned_instances[0].push(poseidon_hash);
}

// TODO: this will be converted to a test function
fn main() {
    println!("Hello, world!");

    let k = 10; // domain size, max 2^k rows in execution trace

    // private values used to calulate the hash
    let s = 1234567890;
    let total_amount = 7;
    let chunks = [2, 2, 3];
    let addr_hex: [u8; 32] =
        hex!("fc91f35435da1610a33bc390ba7f94227e0ac863b3c4ddf49349f0a8406114d3");
    let addresses = [addr_hex, addr_hex, addr_hex];

    // TODO: how to convert 32 byte array to Fr?
    // let poseidon_hash = poseidon_hash_native_rust(
    //     s,
    //     total_amount,
    //     &chunks.try_into().unwrap(),
    //     &addresses.try_into().unwrap(),
    // );
    // println!("Poseidon hash: {}", poseidon_hash);
}
