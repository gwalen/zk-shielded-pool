use crate::circuit::poseidon::solana_poseidon_chip::{
    SOLANA_POSEIDON_INPUTS_2, SolanaPoseidonChip, commitment_9_inputs,
};
use crate::circuit::poseidon::solana_poseidon_native;
use crate::circuit::utils::{convert_pubkey_32bytes_to_fr, fr_to_le_bytes};
use halo2_base::Context;
use halo2_base::gates::{GateChip, GateInstructions, RangeChip, RangeInstructions};
use halo2_base::{
    AssignedValue,
    gates::circuit::builder::BaseCircuitBuilder,
    halo2_proofs::{dev::MockProver, dev::VerifyFailure, halo2curves::bn256::Fr},
};
use hex_literal::hex;

pub const MAX_CHUNKS: usize = 3;
pub const MAX_CHUNK_AMOUNT: u64 = u64::MAX;
pub const U64_RANGE_CHECK_BITS: usize = 64; // 2^64 - 1

/*
 Private inputs:
 - s — the user's secret
 - [2, 3, 2] —  chunks
 - [A0, A1, A2] —  addresses
 - total_amount = 7.0 — the deposited total

 Public inputs (verifier and chain see):
 - root — the root user path climbs to (the program will check it's recent root)
 - nullifier_0 = Poseidon(s, 0) — derived from her secret and step 0
 - step = 0 — the step the user wants to withdraw
 - chunk_amount = 2.0 — what to transfer
 - destination = A0 — where to send it
*/

pub struct AdditionalConstraintsChip {
    gate: GateChip<Fr>,
    range: RangeChip<Fr>,
    poseidon: SolanaPoseidonChip<SOLANA_POSEIDON_INPUTS_2>,
}

impl AdditionalConstraintsChip {
    pub fn new(
        range: RangeChip<Fr>,
        poseidon: SolanaPoseidonChip<SOLANA_POSEIDON_INPUTS_2>,
    ) -> Self {
        Self { gate: GateChip::default(), range, poseidon }
    }

    // TODO: (!) should we pass values to chip as Fr or AssignedValues(as witnesses)
    pub fn step_in_range(
        &self,
        ctx: &mut Context<Fr>,
        // witness and instance // TODO: check if this comment is correct
        step_w: AssignedValue<Fr>,
    ) {
        // check if step is in the array bounds
        self.range.check_less_than_safe(ctx, step_w, MAX_CHUNKS as u64); // < MAX_CHUNKS
    }

    // check if chunk_amount == chunks[step]
    pub fn chunk_selection_and_amount_in_range(
        &self,
        ctx: &mut Context<Fr>,
        // witness
        chunks: &[AssignedValue<Fr>; MAX_CHUNKS],
        // instances and also witnesses
        chunk_amount_w: AssignedValue<Fr>,
        step_w: AssignedValue<Fr>,
    ) {
        // check if chunk_amount is in the range of u64 // TODO: this might be redundant - not sure (we just need to check is chunk_amount as in the initial array)
        self.range.check_less_than_safe(ctx, chunk_amount_w, MAX_CHUNK_AMOUNT); // < MAX_CHUNK_AMOUNT

        // check if chunk_amount == chunks[step]
        let selected_chunk = self.gate.select_from_idx(ctx, chunks.iter().copied(), step_w);
        ctx.constrain_equal(&chunk_amount_w, &selected_chunk);
    }

    pub fn destination_selection(
        &self,
        ctx: &mut Context<Fr>,
        // witness
        addresses: &[AssignedValue<Fr>; MAX_CHUNKS],
        // instances and also witnesses
        dest_address_w: AssignedValue<Fr>,
        step_w: AssignedValue<Fr>,
    ) {
        // TODO: should I load step as witness every time (in each method, or just once and pass it as an argument from main method)
        // check if chunk_amount == chunks[step]
        let selected_address = self.gate.select_from_idx(ctx, addresses.iter().copied(), step_w);
        ctx.constrain_equal(&dest_address_w, &selected_address);
    }

    pub fn chunks_sum_to_total(
        &self,
        ctx: &mut Context<Fr>,
        // witness
        chunks: &[AssignedValue<Fr>; MAX_CHUNKS],
        total_amount: Fr,
    ) {
        let total_amount_w = ctx.load_witness(total_amount);
        let sum_of_chunks = self.gate.sum(ctx, chunks.iter().copied());
        ctx.constrain_equal(&total_amount_w, &sum_of_chunks);
    }

    pub fn nullifier_derivation(
        &self,
        ctx: &mut Context<Fr>,
        // witness
        s: Fr,
        // instances and also witnesses
        nullifier_w: AssignedValue<Fr>,
        step_w: AssignedValue<Fr>,
    ) {
        let s_w = ctx.load_witness(s);
        let nullifier_hash = self.poseidon.hash_commitment_2_inputs(ctx, s_w, step_w);

        ctx.constrain_equal(&nullifier_hash, &nullifier_w);
    }

    // fn fr_to_usize(v: Fr) -> usize {
    //     let bytes = fr_to_le_bytes(v);
    //     u64::from_le_bytes(bytes[..8].try_into().unwrap()) as usize
    // }
}

pub fn build_additional_constraints_circuit(
    builder: &mut BaseCircuitBuilder<Fr>,
    // private witness(advice) values
    chunks: &[Fr; MAX_CHUNKS],
    addresses: &[Fr; MAX_CHUNKS],
    s: Fr,
    total_amount: Fr,
    // instances (public) and witnesses (advice columns)
    step: Fr,
    chunk_amount: Fr,
    dest_address: Fr,
    nullifier: Fr,
) {
    let solana_poseidon = SolanaPoseidonChip::<SOLANA_POSEIDON_INPUTS_2>::new();
    let range: RangeChip<Fr> = builder.range_chip();
    let additional_constraints = AdditionalConstraintsChip::new(range, solana_poseidon);
    let ctx = builder.main(0); // TODO: again, what is does, is this should always be at the start of the circuit ?

    let step_w = ctx.load_witness(step);
    let chunk_amount_w = ctx.load_witness(chunk_amount);
    let dest_address_w = ctx.load_witness(dest_address);
    let nullifier_w = ctx.load_witness(nullifier);

    let chunks_witness: [AssignedValue<Fr>; MAX_CHUNKS] =
        std::array::from_fn(|i| ctx.load_witness(chunks[i]));
    let addresses_witness: [AssignedValue<Fr>; MAX_CHUNKS] =
        std::array::from_fn(|i| ctx.load_witness(addresses[i]));

    additional_constraints.step_in_range(ctx, step_w);
    additional_constraints.chunk_selection_and_amount_in_range(ctx, &chunks_witness, chunk_amount_w, step_w);
    additional_constraints.destination_selection(ctx, &addresses_witness, dest_address_w, step_w);
    additional_constraints.chunks_sum_to_total(ctx, &chunks_witness, total_amount);
    additional_constraints.nullifier_derivation(ctx, s, nullifier_w, step_w);

    builder.assigned_instances[0].push(step_w);
    builder.assigned_instances[0].push(chunk_amount_w);
    builder.assigned_instances[0].push(dest_address_w);
    builder.assigned_instances[0].push(nullifier_w);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_additional_constraints_ok() {
        let k: usize = 16;

        let s = Fr::from(1234567890);
        let total_amount = Fr::from(7);
        let chunks = [Fr::from(2), Fr::from(2), Fr::from(3)];
        let addr_hex: [u8; 32] =
            hex!("fc91f35435da1610a33bc390ba7f94227e0ac863b3c4ddf49349f0a8406114d3");
        let addresses = [addr_hex, addr_hex, addr_hex];
        let addresses_fr: [Fr; MAX_CHUNKS] = addresses.map(convert_pubkey_32bytes_to_fr);

        let step = Fr::from(0);
        let chunk_amount = chunks[0];
        let dest_address = addresses_fr[0];
        let nullifier = solana_poseidon_native::hash2(&[s, step]);

        let mut builder =
            BaseCircuitBuilder::<Fr>::new(false).use_k(k).use_instance_columns(1);
        
        // In constraints we check against the max value u64
        // But lookup_bits = 15 does not conflict with checking a 64-bit u64 range
        // lookup_bits is the size of each lookup limb, not the max value being checked. 
        // For a 64-bit check, halo2-base decomposes the value into multiple 15-bit limbs:
        //   64 bits / 15 bits = 5 limbs, rounded up
        //   range_bits = 75
        // So with lookup_bits = 15, the range chip can still check 64-bit values by splitting them up.
        builder.set_lookup_bits(k - 1);

        build_additional_constraints_circuit(
            &mut builder,
            &chunks,
            &addresses_fr,
            s,
            total_amount,
            step,
            chunk_amount,
            dest_address,
            nullifier,
        );
        builder.calculate_params(Some(9));

        let public_instances = vec![vec![step, chunk_amount, dest_address, nullifier]];
        assert!(MockProver::run(k as u32, &builder, public_instances)
            .unwrap()
            .verify()
            .is_ok());
    }
}
