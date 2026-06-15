use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::group::ff::PrimeField;

pub fn fr_to_le_bytes(value: Fr) -> [u8; 32] {
    value.to_repr()
}

pub fn fr_from_le_bytes(bytes: [u8; 32]) -> Fr {
    Fr::from_repr(bytes).unwrap()
}

pub fn split_into_u64_limbs(bytes: [u8; 32]) -> [u64; 4] {
    std::array::from_fn(|i| {
        let start = i * 8;
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&bytes[start..start + 8]);
        u64::from_be_bytes(limb)
    })
}