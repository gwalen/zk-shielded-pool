use crate::circuit::solana_poseidon_chip::{SolanaPoseidonChip, commitment_9_inputs};
use crate::circuit::solana_poseidon_native;
use crate::circuit::utils::convert_pubkey_32bytes_to_fr;
use halo2_base::{
    AssignedValue,
    gates::circuit::builder::BaseCircuitBuilder,
    halo2_proofs::{dev::MockProver, dev::VerifyFailure, halo2curves::bn256::Fr},
};
use hex_literal::hex;

pub const MAX_CHUNKS: usize = 3;

pub fn build_solana_poseidon_circuit(
    builder: &mut BaseCircuitBuilder<Fr>,
    s: Fr,
    total_amount: Fr,
    chunks: &[Fr; MAX_CHUNKS],
    addresses: &[Fr; MAX_CHUNKS],
) {
    let chip = SolanaPoseidonChip::<MAX_CHUNKS>::new();
    let ctx = builder.main(0);

    let s_witness = ctx.load_witness(s);
    let total_amount_witness = ctx.load_witness(total_amount);
    let chunks_witness: [AssignedValue<Fr>; MAX_CHUNKS] =
        std::array::from_fn(|i| ctx.load_witness(chunks[i]));
    let addresses_witness: [AssignedValue<Fr>; MAX_CHUNKS] =
        std::array::from_fn(|i| ctx.load_witness(addresses[i]));

    let poseidon_hash = chip.hash_commitment_9_inputs(
        ctx,
        s_witness,
        total_amount_witness,
        &chunks_witness,
        &addresses_witness,
    );

    builder.assigned_instances[0].push(poseidon_hash);
}

pub fn run_constraint_1_solana_poseidon_test_ok() -> Result<(), Vec<VerifyFailure>> {
    let k: usize = 16;

    // --- private proof values
    let s = Fr::from(1234567890);
    let total_amount = Fr::from(7);
    let chunks = [Fr::from(2), Fr::from(2), Fr::from(3)];
    // Demo addresses are already field elements. Raw Solana pubkeys need a
    // separate, identical field-mapping step in both the circuit and program.
    let addr_hex: [u8; 32] =
        hex!("fc91f35435da1610a33bc390ba7f94227e0ac863b3c4ddf49349f0a8406114d3");
    let addresses = [addr_hex, addr_hex, addr_hex];

    let addresses_fr: [Fr; MAX_CHUNKS] = addresses.map(convert_pubkey_32bytes_to_fr);
    // ---

    let commitment_inputs = &commitment_9_inputs(s, total_amount, &chunks, &addresses_fr);
    let poseidon_hash = solana_poseidon_native::hash9(commitment_inputs);
    println!("Solana-compatible Poseidon hash: {:?}", poseidon_hash);

    let mut builder =
        BaseCircuitBuilder::<Fr>::new(false).use_k(k).use_instance_columns(1);

    build_solana_poseidon_circuit(&mut builder, s, total_amount, &chunks, &addresses_fr);
    builder.calculate_params(Some(9)); // TODO: how to decide that value on prod ? (this is default)

    let public_instances = vec![vec![poseidon_hash]];
    let verification_result =
        MockProver::run(k as u32, &builder, public_instances).unwrap().verify();
    match &verification_result {
        Ok(()) => println!("Solana-compatible Poseidon verification successful"),
        Err(e) => println!("Solana-compatible Poseidon verification failed: {e:?}"),
    }
    verification_result
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_base::halo2_proofs::arithmetic::Field;

    #[test]
    fn test_solana_poseidon_v2_circuit() {
        let verification_result = run_constraint_1_solana_poseidon_test_ok();
        assert!(verification_result.is_ok());
    }

    // test rejecting wrong public hash
    #[test]
    fn test_solana_poseidon_rejects_wrong_public_hash() {
        // --- private proof values
        let k = 16;
        let s = Fr::from(1234567890);
        let total_amount = Fr::from(7);
        let chunks = [Fr::from(2), Fr::from(2), Fr::from(3)];
        let addresses = [Fr::from(1001), Fr::from(1002), Fr::from(1003)];
        // ---

        let expected_hash = solana_poseidon_native::hash9(&commitment_9_inputs(
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
