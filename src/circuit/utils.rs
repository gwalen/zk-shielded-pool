
pub fn split_into_u64_limbs(bytes: [u8; 32]) -> [u64; 4] {
    std::array::from_fn(|i| {
        let start = i * 8;
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&bytes[start..start + 8]);
        u64::from_be_bytes(limb)
    })
}