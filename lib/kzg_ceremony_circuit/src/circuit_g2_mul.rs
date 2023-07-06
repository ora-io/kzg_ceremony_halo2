use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;

use ark_std::{end_timer, start_timer};
use num_bigint::BigUint;
use rand::rngs::OsRng;

use halo2_proofs::arithmetic::{Field, FieldExt};
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::pairing::bls12_381;
use halo2_proofs::pairing::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::plonk::{self, ConstraintSystem, Error, SingleVerifier};
use halo2_proofs::poly::commitment::{Params, ParamsVerifier};
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};

use crate::circuit_utils::base_chip::{BaseChip, BaseChipConfig};
use crate::circuit_utils::ecc_chip::{EccChipBaseOps, EccChipScalarOps};
use crate::circuit_utils::fq2::Fq2ChipOps;
use crate::circuit_utils::integer_chip::IntegerChipOps;
use crate::circuit_utils::range_chip::{RangeChip, RangeChipConfig, RangeChipOps};
use crate::context::{Context, GeneralScalarEccContext};
use crate::utils::{bn_to_field, field_to_bn, split_g2_point};

pub const LENGTH: usize = 16;
const INSTANCE_NUM: usize = 1 + 16 + 8 * 2 * 2 * LENGTH;

#[derive(Clone, Debug)]
pub struct Config {
    base_chip_config: BaseChipConfig,
    range_chip_config: RangeChipConfig,
}

#[derive(Clone, Debug)]
pub struct Circuit<N: FieldExt> {
    pub from_index: Option<usize>,
    pub tau: Option<bls12_381::Fr>,
    pub pubkey: Option<bls12_381::G2Affine>,
    pub points: Vec<Option<bls12_381::G2Affine>>,
    pub new_points: Vec<Option<bls12_381::G2Affine>>,
    pub _mark: PhantomData<N>,
}

impl<N: FieldExt> Default for Circuit<N> {
    fn default() -> Self {
        Self {
            from_index: None,
            tau: None,
            pubkey: None,
            points: vec![None; LENGTH],
            new_points: vec![None; LENGTH],
            _mark: Default::default(),
        }
    }
}

impl<N: FieldExt> plonk::Circuit<N> for Circuit<N> {
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
        let base_chip = BaseChip::new(config.base_chip_config.clone());
        let range_chip = RangeChip::<N>::new(config.range_chip_config);
        range_chip.init_table(&mut layouter)?;

        let ctx = Rc::new(RefCell::new(Context::new()));
        let mut ctx = GeneralScalarEccContext::<bls12_381::G1Affine, N>::new(ctx);
        let mut instances = vec![];

        // load from_index
        let from_index = ctx
            .scalar_integer_ctx
            .assign_small_number(self.from_index.unwrap_or_default(), 16);
        instances.push(from_index.clone());

        // load pubkey
        let pubkey = self.pubkey.unwrap_or(bls12_381::G2Affine::generator());
        let four = bls12_381::Fq::one().double().double();
        let b = ctx.fq2_assign_constant((four, four));
        let pubkey = ctx.assign_non_identity_g2(
            &((pubkey.x.c0, pubkey.x.c1), (pubkey.y.c0, pubkey.y.c1)),
            b.clone(),
        );

        instances.extend_from_slice(&pubkey.x.0.limbs_le);
        instances.extend_from_slice(&pubkey.x.1.limbs_le);
        instances.extend_from_slice(&pubkey.y.0.limbs_le);
        instances.extend_from_slice(&pubkey.y.1.limbs_le);

        // load tau and check pubkey
        let tau = ctx
            .scalar_integer_ctx
            .assign_w(&field_to_bn(&self.tau.unwrap_or_default()));
        let generator = ctx.assign_non_identity_constant_g2({
            let g = bls12_381::G2Affine::generator();
            &((g.x.c0, g.x.c1), (g.y.c0, g.y.c1))
        });

        let expected_pubkey = ctx.ecc_g2_mul(&generator, &tau);
        ctx.ecc_assert_g2_equal(&pubkey, &expected_pubkey);

        // load points
        assert_eq!(self.points.len(), LENGTH);
        let points = self
            .points
            .iter()
            .map(|x| {
                let x = x.unwrap_or(bls12_381::G2Affine::generator());
                let p =
                    ctx.assign_non_identity_g2(&((x.x.c0, x.x.c1), (x.y.c0, x.y.c1)), b.clone());
                instances.extend_from_slice(&p.x.0.limbs_le);
                instances.extend_from_slice(&p.x.1.limbs_le);
                instances.extend_from_slice(&p.y.0.limbs_le);
                instances.extend_from_slice(&p.y.1.limbs_le);

                p
            })
            .collect::<Vec<_>>();

        let new_points = self
            .new_points
            .iter()
            .map(|x| {
                let x = x.unwrap_or(bls12_381::G2Affine::generator());
                let p =
                    ctx.assign_non_identity_g2(&((x.x.c0, x.x.c1), (x.y.c0, x.y.c1)), b.clone());
                instances.extend_from_slice(&p.x.0.limbs_le);
                instances.extend_from_slice(&p.x.1.limbs_le);
                instances.extend_from_slice(&p.y.0.limbs_le);
                instances.extend_from_slice(&p.y.1.limbs_le);

                p
            })
            .collect::<Vec<_>>();

        // process scalars
        let scalars = {
            // cal {tau^(from_index+i)| i=0,1,...,LENGTH-1
            let pow_bits_be = {
                let pow_bn = field_to_bn(&from_index.val);

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
                    ctx.scalar_integer_ctx
                        .base_chip()
                        .assert_equal(&from_index, &sum);
                }

                bits_le.reverse();

                bits_le
            };

            let mut acc = ctx
                .scalar_integer_ctx
                .assign_int_constant(bls12_381::Fr::one());

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

        for (point, (new_point, scalar)) in points
            .iter()
            .zip(new_points.iter().zip(scalars.into_iter()))
        {
            let p = ctx.ecc_g2_mul(point, &scalar);
            ctx.ecc_assert_g2_equal(&p, &new_point);
        }
        assert_eq!(instances.len(), INSTANCE_NUM);

        let ctx = Context::<N>::from(ctx);
        let mut records = Arc::try_unwrap(ctx.records).unwrap().into_inner().unwrap();

        for instance in instances.iter() {
            records.enable_permute(&instance.cell);
        }

        let mut assigned_instance_cells = vec![];
        layouter.assign_region(
            || "base",
            |mut region| {
                let cells = records.assign_all(&mut region, &base_chip, &range_chip)?;
                assigned_instance_cells = instances
                    .iter()
                    .map(|ist| {
                        let cell = cells[ist.cell.region as usize][ist.cell.col][ist.cell.row]
                            .clone()
                            .unwrap();

                        cell.cell()
                    })
                    .collect::<Vec<_>>();
                Ok(())
            },
        )?;

        // Constrain public input
        for (offset, instance) in assigned_instance_cells.into_iter().enumerate() {
            layouter.constrain_instance(instance, config.base_chip_config.primary, offset)?;
        }

        Ok(())
    }
}

/// The verifying key for the Orchard Action circuit.
#[derive(Debug)]
pub struct VerifyingKey {
    pub vk: plonk::VerifyingKey<G1Affine>,
}

impl VerifyingKey {
    /// Builds the verifying key.
    pub fn build(params: &Params<G1Affine>) -> Self {
        let circuit: Circuit<Fr> = Default::default();

        let vk = plonk::keygen_vk(&params, &circuit).unwrap();

        VerifyingKey { vk }
    }
}

#[derive(Debug)]
pub struct ProvingKey {
    pk: plonk::ProvingKey<G1Affine>,
}

impl ProvingKey {
    /// Builds the proving key.
    pub fn build(params: &Params<G1Affine>) -> Self {
        let circuit: Circuit<Fr> = Default::default();

        let vk = plonk::keygen_vk(&params, &circuit).unwrap();
        let pk = plonk::keygen_pk(&params, vk, &circuit).unwrap();

        ProvingKey { pk }
    }
}

#[derive(Clone, Debug)]
pub struct Instance {
    pub from_index: usize,
    pub pubkey: bls12_381::G2Affine,
    pub old_points: Vec<bls12_381::G2Affine>,
    pub new_points: Vec<bls12_381::G2Affine>,
}

pub fn generate_instance(instance: &Instance) -> Vec<Fr> {
    let mut halo2_instances = vec![bn_to_field::<Fr>(&BigUint::from(instance.from_index))];

    halo2_instances.extend_from_slice(&split_g2_point(&instance.pubkey));

    let _ = instance
        .old_points
        .iter()
        .chain(instance.new_points.iter())
        .map(|p| halo2_instances.extend_from_slice(&split_g2_point(&p)))
        .collect::<Vec<_>>();

    assert_eq!(halo2_instances.len(), INSTANCE_NUM);

    halo2_instances
}

pub fn create_proofs(
    params: &Params<G1Affine>,
    circuit: Circuit<Fr>,
    pk: &ProvingKey,
    instance: &Vec<Fr>,
) -> Vec<u8> {
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

    let timer = start_timer!(|| "create proof");
    plonk::create_proof(
        &params,
        &pk.pk,
        &[circuit],
        &[&[&instance]],
        OsRng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    end_timer!(timer);

    transcript.finalize()
}

pub fn verify_proof(
    params: &Params<G1Affine>,
    vk: &VerifyingKey,
    proof: &Vec<u8>,
    instance: &Vec<Fr>,
) -> Result<(), Error> {
    let params_verifier: ParamsVerifier<Bn256> = params.verifier(INSTANCE_NUM).unwrap();

    let strategy = SingleVerifier::new(&params_verifier);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

    let result = plonk::verify_proof(
        &params_verifier,
        &vk.vk,
        strategy,
        &[&[&instance]],
        &mut transcript,
    );

    result
}

mod tests {
    use crate::circuit_g2_mul::{
        create_proofs, generate_instance, verify_proof, Circuit, Instance, ProvingKey,
        VerifyingKey, LENGTH,
    };
    use crate::K;
    use halo2_proofs::arithmetic::Field;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::pairing::bn256::{Bn256, Fr};
    use halo2_proofs::pairing::group::ff::PrimeField;
    use halo2_proofs::pairing::group::Curve;
    use halo2_proofs::pairing::{bls12_381, bn256};
    use halo2_proofs::poly::commitment::Params;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    fn random_circuit() -> (Circuit<Fr>, Vec<Fr>) {
        let mut rng = XorShiftRng::seed_from_u64(0x0102030405060708);
        let tau = bls12_381::Fr::random(&mut rng);
        let from_index = 1;
        let old_points = (0..LENGTH)
            .map(|_| {
                let s = bls12_381::Fr::random(&mut rng);
                let p = bls12_381::G2Affine::generator() * s;

                p.to_affine()
            })
            .collect::<Vec<_>>();
        let mut scalar = tau.pow_vartime(&[from_index as u64, 0, 0, 0]);
        let mut new_points = vec![];
        for p in old_points.iter() {
            let new_p = p * scalar;
            new_points.push(new_p.to_affine());
            scalar = scalar * tau;
        }

        let circuit = Circuit::<Fr> {
            from_index: Some(from_index),
            tau: Some(tau),
            pubkey: Some((bls12_381::G2Affine::generator() * tau).to_affine()),
            points: old_points.iter().map(|p| Some(*p)).collect::<Vec<_>>(),
            new_points: new_points.iter().map(|p| Some(*p)).collect::<Vec<_>>(),
            _mark: Default::default(),
        };

        let instance = generate_instance(&Instance {
            from_index,
            pubkey: (bls12_381::G2Affine::generator() * tau).to_affine(),
            old_points,
            new_points,
        });

        (circuit, instance)
    }

    #[test]
    fn mock_prover() {
        let (circuit, instance) = random_circuit();
        let prover = match MockProver::run(K, &circuit, vec![instance]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn prover() {
        let (circuit, instance) = random_circuit();

        let params = match std::fs::read(format!("params_{}.bin", K)) {
            Ok(params) => Params::<bn256::G1Affine>::read(&params[..]).expect("Read params failed"),
            Err(_) => {
                println!("Setup");
                let params = Params::<bn256::G1Affine>::unsafe_setup::<Bn256>(K);
                let mut params_buffer = vec![];
                params.write(&mut params_buffer).unwrap();
                std::fs::write(format!("params_{}.bin", K), &params_buffer)
                    .expect("Write params failed");

                params
            }
        };

        let pk = ProvingKey::build(&params);
        let proof = create_proofs(&params, circuit, &pk, &instance);

        let vk = VerifyingKey::build(&params);
        verify_proof(&params, &vk, &proof, &instance).unwrap();

        let mut instance = instance;
        instance[0] = Fr::from_str_vartime("2").unwrap();
        verify_proof(&params, &vk, &proof, &instance).unwrap_err();
    }
}
