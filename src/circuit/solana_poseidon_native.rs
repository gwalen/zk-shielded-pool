use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use solana_poseidon::{Endianness, Parameters, hashv};
use crate::circuit::solana_poseidon_chip::{SOLANA_POSEIDON_INPUTS_2, SOLANA_POSEIDON_INPUTS_9};
use crate::circuit::utils::{fr_from_le_bytes, fr_to_le_bytes};

pub fn hash9(inputs: &[Fr; SOLANA_POSEIDON_INPUTS_9]) -> Fr {
    let input_bytes = inputs.map(fr_to_le_bytes);
    let input_refs: [&[u8]; SOLANA_POSEIDON_INPUTS_9] =
        input_bytes.each_ref().map(|bytes| &bytes[..]);
    let hash = hashv(Parameters::Bn254X5, Endianness::LittleEndian, &input_refs).unwrap();
    fr_from_le_bytes(hash.to_bytes())
}

pub fn hash2(inputs: &[Fr; SOLANA_POSEIDON_INPUTS_2]) -> Fr {
    let input_bytes = inputs.map(fr_to_le_bytes);
    let input_refs: [&[u8]; SOLANA_POSEIDON_INPUTS_2] =
        input_bytes.each_ref().map(|bytes| &bytes[..]);
    let hash = hashv(Parameters::Bn254X5, Endianness::LittleEndian, &input_refs).unwrap();
    fr_from_le_bytes(hash.to_bytes())
}

pub fn hash1(seed: u64) -> Fr {
    let h = solana_poseidon::hash(
        Parameters::Bn254X5,
        Endianness::LittleEndian,
        &fr_to_le_bytes(Fr::from(seed)),
    )
    .unwrap();
    fr_from_le_bytes(h.to_bytes())
}
