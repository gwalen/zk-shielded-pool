use halo2_base::halo2_proofs::dev::VerifyFailure;
use halo2_base::poseidon::hasher::PoseidonSponge;
use halo2_base::{
    AssignedValue, Context,
    gates::{GateChip, GateInstructions, circuit::builder::BaseCircuitBuilder},
    halo2_proofs::{arithmetic::Field, dev::MockProver, halo2curves::bn256::Fr},
};
use hex_literal::hex;
use pse_poseidon::Poseidon;

// *** Commitment reconstruction constraint ***

// Poseidon parameters (given by AI):
//   T = 3       state width
//   RATE = 2    two input elements absorbed per permutation
//   R_F = 8     full rounds
//   R_P = 57    partial rounds
const T: usize = 3;
const RATE: usize = 2;
const R_F: usize = 8;
const R_P: usize = 57;

// Max length of the list of addresses and chunks
const MAX_CHUNKS: usize = 3;

pub struct PoseidonChip {
    gate: GateChip<Fr>,
}

/*
TODO:
Double hashing to prevent fake proof (with forged total_amount):
H_user = Poseidon(s, 7.0, 2.0, 3.5, 1.5, A0, A1, A2, M=3)
H = Poseidon(H_user, 7.0) -> calculated by program on-chain, a 7 to value taken directly from transaction
*/

impl PoseidonChip {
    pub fn new() -> Self {
        Self { gate: GateChip::default() }
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

// TODO: dodaj range check dla chunks

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

fn split_into_u64_limbs(bytes: [u8; 32]) -> [u64; 4] {
    std::array::from_fn(|i| {
        let start = i * 8;
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&bytes[start..start + 8]);
        u64::from_be_bytes(limb)
    })
}

// TODO: write cheaper version of this conversion : Hash the whole 32bytes array and just take 254 bits that will fit in Fr (drop last two)
// sponge already does incremental ordered hashing, so I don't need to hand-roll the hashing chain
fn convert_32bytes_to_fr(bytes: [u8; 32]) -> Fr {
    let limbs: [Fr; 4] = split_into_u64_limbs(bytes).map(Fr::from);
    let mut sponge = Poseidon::<Fr, T, RATE>::new(R_F, R_P);
    sponge.update(&limbs);
    sponge.squeeze()
}

pub fn build_poseidon_circuit(
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
    let chunks_witness: Vec<AssignedValue<Fr>> =
        chunks.iter().map(|&chunk| ctx.load_witness(chunk)).collect();
    let addresses_witness: Vec<AssignedValue<Fr>> =
        addresses.iter().map(|&addr| ctx.load_witness(addr)).collect();

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
pub fn run_constraint_1_test_ok() -> Result<(), Vec<VerifyFailure>> {
    let k = 10; // domain size, max 2^k rows in execution trace

    // private values used to calculate the hash
    let s = Fr::from(1234567890);
    let total_amount = Fr::from(7);
    let chunks = [Fr::from(2), Fr::from(2), Fr::from(3)];
    let addr_hex: [u8; 32] =
        hex!("fc91f35435da1610a33bc390ba7f94227e0ac863b3c4ddf49349f0a8406114d3");
    let addresses = [addr_hex, addr_hex, addr_hex];

    let addresses_fr: [Fr; MAX_CHUNKS] = addresses.map(convert_32bytes_to_fr);

    let poseidon_hash = poseidon_hash_native_rust(s, total_amount, &chunks, &addresses_fr);
    println!("Poseidon hash: {:?}", poseidon_hash);

    let mut builder =
        BaseCircuitBuilder::<Fr>::new(false).use_k(k as usize).use_instance_columns(1);

    build_poseidon_circuit(&mut builder, s, total_amount, &chunks, &addresses_fr);
    // amount of rows reserved for blinding, 9 is value used in halo2 examples/tests
    builder.calculate_params(Some(9)); // TODO: this is magic number - for prod circuit it must be chosen consciously

    // public values
    let instances = vec![vec![poseidon_hash]];

    let verification_result = MockProver::run(k, &builder, instances).unwrap().verify();
    match &verification_result {
        Ok(()) => println!("Verification Successful"),
        Err(e) => println!("Verification Failed: {e:?}"),
    }
    verification_result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_circuit() {
        let verification_result = run_constraint_1_test_ok();
        assert!(verification_result.is_ok());
    }

    #[test]
    pub fn run_constraint_1_test_fail() {
        let k = 10; // domain size, max 2^k rows in execution trace

        // private values used to calculate the hash
        let s = Fr::from(1234567890);
        let total_amount = Fr::from(7);
        let chunks = [Fr::from(2), Fr::from(2), Fr::from(3)];
        let addr_hex: [u8; 32] =
            hex!("fc91f35435da1610a33bc390ba7f94227e0ac863b3c4ddf49349f0a8406114d3");
        let addresses = [addr_hex, addr_hex, addr_hex];

        let addresses_fr: [Fr; MAX_CHUNKS] = addresses.map(convert_32bytes_to_fr);

        let poseidon_hash = poseidon_hash_native_rust(s, total_amount, &chunks, &addresses_fr);

        let mut builder =
            BaseCircuitBuilder::<Fr>::new(false).use_k(k as usize).use_instance_columns(1);

        let fake_s = Fr::from(666);

        build_poseidon_circuit(&mut builder, fake_s, total_amount, &chunks, &addresses_fr);
        // amount of rows reserved for blinding, 9 is value used in halo2 examples/tests
        builder.calculate_params(Some(9)); // TODO: this is magic number - for prod circuit it must be chosen consciously

        // public values
        let instances = vec![vec![poseidon_hash]];

        let verification_result = MockProver::run(k, &builder, instances).unwrap().verify();
        match &verification_result {
            Ok(()) => println!("Verification Successful"),
            Err(e) => println!("Verification Failed: {e:?}"),
        }

        assert!(verification_result.is_err());
    }
}
