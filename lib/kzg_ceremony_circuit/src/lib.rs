pub mod assign;
pub mod circuit_g1_mul;
pub mod circuit_g2_mul;
pub mod circuit_utils;
pub mod context;
pub mod range_info;
pub mod utils;

pub use halo2_proofs;
use halo2_proofs::pairing::bn256;
use halo2_proofs::pairing::bn256::Bn256;
use halo2_proofs::poly::commitment::Params;

pub const K: u32 = 23;

// This is just for test.
#[test]
fn test_untrusted_setup() {
    let params = Params::<bn256::G1Affine>::unsafe_setup::<Bn256>(K);

    let mut params_buffer = vec![];
    params.write(&mut params_buffer).unwrap();
    std::fs::write(format!("params_{}.bin", K), &params_buffer).expect("Write params failed");
}
