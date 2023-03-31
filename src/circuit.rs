use ark_std::{end_timer, start_timer};
use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;

use halo2_proofs::arithmetic::{CurveAffine, Field, FieldExt};
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::pairing::bls12_381;
use halo2_proofs::pairing::bn256::{self, Bn256, Fr};
use halo2_proofs::pairing::group::Curve;
use halo2_proofs::plonk::{self, ConstraintSystem, Error, SingleVerifier};
use halo2_proofs::poly::commitment::{Params, ParamsVerifier};
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use rand::rngs::OsRng;

use crate::circuit_utils::base_chip::{BaseChip, BaseChipConfig};
use crate::circuit_utils::ecc_chip::{EccChipBaseOps, EccChipScalarOps};
use crate::circuit_utils::integer_chip::IntegerChipOps;
use crate::circuit_utils::range_chip::{RangeChip, RangeChipConfig, RangeChipOps};
use crate::context::{Context, GeneralScalarEccContext};
use crate::utils::field_to_bn;

const LENGTH: usize = 16;
const K: u32 = 22;

#[derive(Clone, Debug)]
pub struct Config {
    base_chip_config: BaseChipConfig,
    range_chip_config: RangeChipConfig,
}

#[derive(Clone, Debug)]
pub struct Circuit<C: CurveAffine, N: FieldExt> {
    pub from_index: Option<u16>,
    pub tau: Option<C::ScalarExt>,
    pub points: Vec<Option<C>>,
    _mark: PhantomData<N>,
}

impl<C: CurveAffine, N: FieldExt> Default for Circuit<C, N> {
    fn default() -> Self {
        Self {
            from_index: None,
            tau: None,
            points: vec![None; LENGTH],
            _mark: Default::default(),
        }
    }
}

impl<C: CurveAffine, N: FieldExt> plonk::Circuit<N> for Circuit<C, N> {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
        Config {
            base_chip_config: BaseChip::configure(meta),
            range_chip_config: RangeChip::<N>::configure(meta),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<N>,
    ) -> Result<(), Error> {
        let base_chip: BaseChip<N> = BaseChip::new(config.base_chip_config);
        let range_chip = RangeChip::<N>::new(config.range_chip_config);
        range_chip.init_table(&mut layouter)?;

        let ctx = Rc::new(RefCell::new(Context::new()));
        let mut ctx = GeneralScalarEccContext::<C, N>::new(ctx);

        // load tau and check pubkey
        let tau = ctx
            .scalar_integer_ctx
            .assign_w(&field_to_bn(&self.tau.unwrap_or_default()));
        let generator = ctx.assign_constant_point(&C::generator());
        // todo: make pubkey public
        let pubkey = ctx.ecc_mul(&generator, tau.clone());

        // load points
        assert_eq!(self.points.len(), LENGTH);
        let points = self
            .points
            .iter()
            .map(|x| {
                let x = x.unwrap_or(C::identity());
                ctx.assign_point(&x)
            })
            .collect::<Vec<_>>();

        // process scalars
        let scalars = {
            // cal {tau^((from_index*COUNT)+i)| i=0,1,...,COUNT-1
            let pow_bits_be = {
                let from_index = ctx
                    .scalar_integer_ctx
                    .assign_small_number(self.from_index.unwrap_or_default(), 16);
                let length = ctx
                    .scalar_integer_ctx
                    .base_chip()
                    .assign_constant(N::from(LENGTH as u64));

                let pow = ctx.scalar_integer_ctx.base_chip().mul(&from_index, &length);
                let pow_bn = field_to_bn(&pow.val);

                let mut bits_le = (0..16)
                    .map(|i| {
                        ctx.scalar_integer_ctx
                            .base_chip()
                            .assign_bit(pow_bn.bit(i).into())
                    })
                    .collect::<Vec<_>>();
                {
                    let schema = bits_le
                        .iter()
                        .enumerate()
                        .map(|(i, el)| (&el.0, N::from(1 << i)))
                        .collect::<Vec<_>>();

                    let sum = ctx
                        .scalar_integer_ctx
                        .base_chip()
                        .sum_with_constant(schema, None);
                    ctx.scalar_integer_ctx.base_chip().assert_equal(&pow, &sum);
                }

                bits_le.reverse();

                bits_le
            };

            let mut acc = ctx
                .scalar_integer_ctx
                .assign_int_constant(C::ScalarExt::one());

            for (i, bit) in pow_bits_be.iter().enumerate() {
                if i != 0 {
                    acc = ctx.scalar_integer_ctx.int_mul(&acc, &acc);
                }
                let acc_tmp = ctx.scalar_integer_ctx.int_mul(&acc, &tau);
                acc = ctx.scalar_integer_ctx.bisec_int(bit, &acc_tmp, &acc);
            }
            let mut scalars = vec![acc.clone()];
            for _ in 1..LENGTH {
                acc = ctx.scalar_integer_ctx.int_mul(&acc, &tau);
                scalars.push(acc.clone());
            }

            scalars
        };

        let mut powers_of_tau = vec![];
        for (p, s) in points.iter().zip(scalars.into_iter()) {
            powers_of_tau.push(ctx.ecc_mul(p, s));
        }

        let ctx = Context::<N>::from(ctx);
        println!("rows: range {}, base {}", ctx.range_offset, ctx.base_offset);

        let records = Arc::try_unwrap(ctx.records).unwrap().into_inner().unwrap();
        layouter.assign_region(
            || "base",
            |mut region| {
                records.assign_all(&mut region, &base_chip, &range_chip)?;
                Ok(())
            },
        )?;

        Ok(())
    }
}

/// The verifying key for the Orchard Action circuit.
#[derive(Debug)]
pub struct VerifyingKey {
    pub vk: plonk::VerifyingKey<bn256::G1Affine>,
}

impl VerifyingKey {
    /// Builds the verifying key.
    pub fn build(params: &Params<bn256::G1Affine>) -> Self {
        // TODO: use trusted setup.
        let circuit: Circuit<bls12_381::G1Affine, Fr> = Default::default();

        let vk = plonk::keygen_vk(&params, &circuit).unwrap();

        VerifyingKey { vk }
    }
}

/// The proving key for the Orchard Action circuit.
#[derive(Debug)]
pub struct ProvingKey {
    pk: plonk::ProvingKey<bn256::G1Affine>,
}

impl ProvingKey {
    /// Builds the proving key.
    pub fn build(params: &Params<bn256::G1Affine>) -> Self {
        // TODO: use trusted setup.
        let circuit: Circuit<bls12_381::G1Affine, Fr> = Default::default();

        let vk = plonk::keygen_vk(&params, &circuit).unwrap();
        let pk = plonk::keygen_pk(&params, vk, &circuit).unwrap();

        ProvingKey { pk }
    }
}

pub fn create_proof(
    params: &Params<bn256::G1Affine>,
    circuit: Circuit<bls12_381::G1Affine, Fr>,
    pk: &ProvingKey,
) -> Vec<u8> {
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

    let timer = start_timer!(|| "create proof");
    plonk::create_proof(&params, &pk.pk, &[circuit], &[&[]], OsRng, &mut transcript)
        .expect("proof generation should not fail");
    end_timer!(timer);

    let proof = transcript.finalize();
    proof
}

pub fn verify_proof(params: &Params<bn256::G1Affine>, vk: &VerifyingKey, proof: &Vec<u8>) {
    let params_verifier: ParamsVerifier<Bn256> = params.verifier(0).unwrap();

    let strategy = SingleVerifier::new(&params_verifier);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

    let timer = start_timer!(|| "verify proof");
    plonk::verify_proof(&params_verifier, &vk.vk, strategy, &[&[]], &mut transcript).unwrap();
    end_timer!(timer);
}

#[test]
fn test_proof() {
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    let mut rng = XorShiftRng::seed_from_u64(0x0102030405060708);
    let tau = bls12_381::Fr::random(&mut rng);

    let circuit = Circuit::<bls12_381::G1Affine, Fr> {
        from_index: Some(0),
        tau: Some(tau),
        points: (0..LENGTH)
            .map(|_| {
                let s = bls12_381::Fr::random(&mut rng);
                let p = bls12_381::G1Affine::generator() * s;
                Some(p.to_affine())
            })
            .collect::<Vec<_>>(),
        _mark: Default::default(),
    };

    let params = Params::<bn256::G1Affine>::unsafe_setup::<Bn256>(K);
    let pk = ProvingKey::build(&params);
    let proof = create_proof(&params, circuit, &pk);

    let vk = VerifyingKey::build(&params);
    verify_proof(&params, &vk, &proof);
}
