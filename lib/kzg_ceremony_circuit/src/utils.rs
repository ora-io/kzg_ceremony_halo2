/*
  The implementation is ported from https://github.com/DelphinusLab/halo2ecc-s
*/

use crate::circuit_utils::range_chip::{COMMON_RANGE_BITS, MAX_CHUNKS};
use halo2_proofs::arithmetic::BaseExt;
use halo2_proofs::pairing::bls12_381;
use halo2_proofs::pairing::bn256::Fr;
use num_bigint::BigUint;

pub fn field_to_bn<F: BaseExt>(f: &F) -> BigUint {
    let mut bytes: Vec<u8> = Vec::new();
    f.write(&mut bytes).unwrap();
    BigUint::from_bytes_le(&bytes[..])
}

pub fn bn_to_field<F: BaseExt>(bn: &BigUint) -> F {
    let modulus = field_to_bn(&-F::one()) + 1u64;
    let bn = bn % &modulus;
    let mut bytes = bn.to_bytes_le();
    bytes.resize((modulus.bits() as usize + 7) / 8, 0);
    let mut bytes = &bytes[..];
    F::read(&mut bytes).unwrap()
}

fn split_fp(el: bls12_381::Fq) -> Vec<Fr> {
    let bits = COMMON_RANGE_BITS * MAX_CHUNKS;
    let bit_mask = (BigUint::from(1u64) << bits) - 1u64;

    let bu = field_to_bn(&el);
    (0..4)
        .map(|i| bn_to_field::<Fr>(&((&bu >> (i * bits)) & &bit_mask)))
        .collect()
}

pub fn split_g1_point(point: &bls12_381::G1Affine) -> Vec<Fr> {
    let mut limbs = vec![];
    for el in vec![point.x, point.y].iter() {
        limbs.extend_from_slice(&split_fp(*el));
    }

    limbs
}

pub fn split_g2_point(point: &bls12_381::G2Affine) -> Vec<Fr> {
    let mut limbs = vec![];
    for el in vec![point.x.c0, point.x.c1, point.y.c0, point.y.c1].iter() {
        limbs.extend_from_slice(&split_fp(*el));
    }

    limbs
}
