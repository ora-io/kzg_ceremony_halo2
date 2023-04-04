/*
  The implementation is ported from https://github.com/DelphinusLab/halo2ecc-s
*/

use halo2_proofs::arithmetic::BaseExt;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::arithmetic::FieldExt;
use num_bigint::BigUint;

use super::integer_chip::IntegerChipOps;
use crate::assign::{
    AssignedCondition, AssignedCurvature, AssignedExtCurvature, AssignedFq2, AssignedG2Affine,
    AssignedG2WithCurvature, AssignedPoint,
};
use crate::assign::{AssignedPointWithCurvature, AssignedValue};
use crate::circuit_utils::fq2::Fq2ChipOps;
use crate::utils::{bn_to_field, field_to_bn};

pub trait EccChipScalarOps<C: CurveAffine, N: FieldExt>: EccChipBaseOps<C, N> {
    type AssignedScalar: Clone;
    fn decompose_scalar<const WINDOW_SIZE: usize>(
        &mut self,
        s: &Self::AssignedScalar,
    ) -> Vec<[AssignedCondition<N>; WINDOW_SIZE]>;
    // like pippenger
    fn msm_batch_on_group(
        &mut self,
        points: &Vec<AssignedPoint<C, N>>,
        scalars: &Vec<Self::AssignedScalar>,
    ) -> AssignedPoint<C, N> {
        let best_group_size = 3;
        let n_group = (points.len() + best_group_size - 1) / best_group_size;
        let group_size = (points.len() + n_group - 1) / n_group;

        let identity = self.assign_identity();

        let mut candidates = vec![];
        for chunk in points.chunks(group_size) {
            candidates.push(vec![identity.clone()]);
            let cl = candidates.last_mut().unwrap();
            for i in 1..1u32 << chunk.len() {
                let pos = 32 - i.leading_zeros() - 1;
                let other = i - (1 << pos);
                let p = self.ecc_add(&cl[other as usize], &chunk[pos as usize]);
                let p = self.to_point_with_curvature(p);
                cl.push(p);
            }
        }

        let pick_candidate = |ops: &mut Self, gi: usize, group_bits: &Vec<AssignedCondition<N>>| {
            let mut curr_candidates: Vec<_> = candidates[gi].clone();
            for bit in group_bits {
                let mut next_candidates = vec![];

                for it in curr_candidates.chunks(2) {
                    let a0 = &it[0];
                    let a1 = &it[1];

                    let cell = ops.bisec_point_with_curvature(&bit, a1, a0);
                    next_candidates.push(cell);
                }
                curr_candidates = next_candidates;
            }

            assert_eq!(curr_candidates.len(), 1);
            curr_candidates[0].clone()
        };

        let bits = scalars
            .into_iter()
            .map(|s| self.decompose_scalar::<1>(s))
            .collect::<Vec<Vec<[AssignedCondition<_>; 1]>>>();

        let groups = bits.chunks(group_size).collect::<Vec<_>>();

        let mut acc = None;

        for wi in 0..bits[0].len() {
            let mut inner_acc = None;
            for gi in 0..groups.len() {
                let group_bits = groups[gi].iter().map(|bits| bits[wi][0]).collect();
                let ci = pick_candidate(self, gi, &group_bits);

                match inner_acc {
                    None => inner_acc = Some(ci.to_point()),
                    Some(_inner_acc) => {
                        let p = self.ecc_add(&ci, &_inner_acc);
                        inner_acc = Some(p);
                    }
                }
            }

            match acc {
                None => acc = inner_acc,
                Some(_acc) => {
                    let p = self.to_point_with_curvature(_acc);
                    let p = self.ecc_double(&p);
                    let p = self.to_point_with_curvature(p);
                    acc = Some(self.ecc_add(&p, &inner_acc.unwrap()));
                }
            }
        }

        acc.unwrap()
    }

    //like shamir
    fn msm_batch_on_window(
        &mut self,
        points: &Vec<AssignedPoint<C, N>>,
        scalars: &Vec<Self::AssignedScalar>,
    ) -> AssignedPoint<C, N> {
        const WINDOW_SIZE: usize = 4;
        assert!(points.len() == scalars.len());

        // TODO: can be parallel
        let windows_in_be = scalars
            .into_iter()
            .map(|s| self.decompose_scalar(s))
            .collect::<Vec<Vec<[AssignedCondition<_>; WINDOW_SIZE]>>>();

        let identity = self.assign_identity();

        // TODO: can be parallel
        let point_candidates: Vec<Vec<AssignedPointWithCurvature<_, _>>> = points
            .iter()
            .map(|a| {
                let mut candidates =
                    vec![identity.clone(), self.to_point_with_curvature(a.clone())];
                for i in 2..(1 << WINDOW_SIZE) {
                    let ai = self.ecc_add(&candidates[i - 1], a);
                    let ai = self.to_point_with_curvature(ai);
                    candidates.push(ai)
                }
                candidates
            })
            .collect::<Vec<_>>();

        let pick_candidate =
            |ops: &mut Self, pi: usize, bits_in_le: &[AssignedCondition<N>; WINDOW_SIZE]| {
                let mut curr_candidates: Vec<_> = point_candidates[pi].clone();
                for bit in bits_in_le {
                    let mut next_candidates = vec![];

                    for it in curr_candidates.chunks(2) {
                        let a0 = &it[0];
                        let a1 = &it[1];

                        let cell = ops.bisec_point_with_curvature(&bit, a1, a0);
                        next_candidates.push(cell);
                    }
                    curr_candidates = next_candidates;
                }
                assert_eq!(curr_candidates.len(), 1);
                curr_candidates[0].clone()
            };

        let mut acc = None;

        for wi in 0..windows_in_be[0].len() {
            let mut inner_acc = None;
            // TODO: can be parallel
            for pi in 0..points.len() {
                let ci = pick_candidate(self, pi, &windows_in_be[pi][wi]);
                match inner_acc {
                    None => inner_acc = Some(ci.to_point()),
                    Some(_inner_acc) => {
                        let p = self.ecc_add(&ci, &_inner_acc);
                        inner_acc = Some(p);
                    }
                }
            }

            match acc {
                None => acc = inner_acc,
                Some(mut _acc) => {
                    for _ in 0..WINDOW_SIZE {
                        let p = self.to_point_with_curvature(_acc);
                        _acc = self.ecc_double(&p);
                    }
                    let p = self.to_point_with_curvature(inner_acc.unwrap());
                    _acc = self.ecc_add(&p, &_acc);
                    acc = Some(_acc);
                }
            }
        }

        acc.unwrap()
    }

    fn msm(
        &mut self,
        points: &Vec<AssignedPoint<C, N>>,
        scalars: &Vec<Self::AssignedScalar>,
    ) -> AssignedPoint<C, N> {
        if points.len() >= 3 {
            self.msm_batch_on_group(points, scalars)
        } else {
            self.msm_batch_on_window(points, scalars)
        }
    }

    fn ecc_mul(&mut self, a: &AssignedPoint<C, N>, s: Self::AssignedScalar) -> AssignedPoint<C, N> {
        self.msm(&vec![a.clone()], &vec![s.clone()])
    }

    fn ecc_g2_mul(
        &mut self,
        point: &AssignedG2Affine<C, N>,
        scalar: &Self::AssignedScalar,
    ) -> AssignedG2Affine<C, N> {
        const WINDOW_SIZE: usize = 4;

        // TODO: can be parallel
        let windows_in_be = self.decompose_scalar::<WINDOW_SIZE>(scalar);

        let identity = self.assign_g2_identity();
        // {0,P, 2P, 3P,...15P}
        let point_candidates = {
            let mut candidates = vec![
                identity.clone(),
                self.to_g2_point_with_curvature(point.clone()),
            ];
            for i in 2..(1 << WINDOW_SIZE) {
                let ai = self.ecc_g2_add(&candidates[i - 1], point);
                let ai = self.to_g2_point_with_curvature(ai);
                candidates.push(ai)
            }
            candidates
        };

        let pick_candidate = |ops: &mut Self, bits_in_le: &[AssignedCondition<N>; WINDOW_SIZE]| {
            let mut curr_candidates: Vec<_> = point_candidates.clone();
            for bit in bits_in_le {
                let mut next_candidates = vec![];

                for it in curr_candidates.chunks(2) {
                    let a0 = &it[0];
                    let a1 = &it[1];

                    let cell = ops.bisec_g2_with_curvature(&bit, a1, a0);
                    next_candidates.push(cell);
                }
                curr_candidates = next_candidates;
            }
            assert_eq!(curr_candidates.len(), 1);

            curr_candidates[0].clone()
        };

        let mut acc = None;

        // for each window
        for wi in 0..windows_in_be.len() {
            let mut inner_acc = None;

            // TODO: can be parallel
            let ci = pick_candidate(self, &windows_in_be[wi]);
            match inner_acc {
                None => inner_acc = Some(ci.to_point()),
                Some(_inner_acc) => {
                    let p = self.ecc_g2_add(&ci, &_inner_acc);
                    inner_acc = Some(p);
                }
            }

            match acc {
                None => acc = inner_acc,
                Some(mut _acc) => {
                    for _ in 0..WINDOW_SIZE {
                        let p = self.to_g2_point_with_curvature(_acc);
                        _acc = self.ecc_g2_double(&p);
                    }
                    let p = self.to_g2_point_with_curvature(inner_acc.unwrap());
                    _acc = self.ecc_g2_add(&p, &_acc);
                    acc = Some(_acc);
                }
            }
        }

        acc.unwrap()
    }
}

pub trait EccBaseIntegerChipWrapper<W: BaseExt, N: FieldExt> {
    fn base_integer_chip(&mut self) -> &mut dyn IntegerChipOps<W, N>;
}

pub trait EccChipBaseOps<C: CurveAffine, N: FieldExt>: Fq2ChipOps<C::Base, N> {
    fn assign_constant_point(&mut self, c: &C) -> AssignedPoint<C, N> {
        let coordinates = c.coordinates();
        let t: Option<_> = coordinates.map(|v| (v.x().clone(), v.y().clone())).into();
        let (x, y) = t.unwrap_or((C::Base::zero(), C::Base::zero()));
        let z = if c.is_identity().into() {
            N::one()
        } else {
            N::zero()
        };

        let x = self.base_integer_chip().assign_int_constant(x);
        let y = self.base_integer_chip().assign_int_constant(y);
        let z = self.base_integer_chip().base_chip().assign_constant(z);

        AssignedPoint::new(x, y, AssignedCondition(z))
    }

    fn assign_point(&mut self, c: &C) -> AssignedPoint<C, N> {
        let coordinates = c.coordinates();
        let t: Option<_> = coordinates.map(|v| (v.x().clone(), v.y().clone())).into();
        let (x, y) = t.unwrap_or((C::Base::zero(), C::Base::zero()));
        // TODO: fix identity.
        let z = if c.is_identity().into() {
            N::one()
        } else {
            N::zero()
        };

        let x = self.base_integer_chip().assign_w(&field_to_bn(&x));
        let y = self.base_integer_chip().assign_w(&field_to_bn(&y));
        let z = self.base_integer_chip().base_chip().assign_bit(z);

        // Constrain y^2 = x^3 + b
        // TODO: Optimize b
        let b = self.base_integer_chip().assign_int_constant(C::b());
        let y2 = self.base_integer_chip().int_square(&y);
        let x2 = self.base_integer_chip().int_square(&x);
        let x3 = self.base_integer_chip().int_mul(&x2, &x);
        let right = self.base_integer_chip().int_add(&x3, &b);

        let eq = self.base_integer_chip().is_int_equal(&y2, &right);
        let eq_or_identity = self.base_integer_chip().base_chip().or(&eq, &z);
        self.base_integer_chip()
            .base_chip()
            .assert_true(&eq_or_identity);

        AssignedPoint::new(x, y, z)
    }

    fn assign_identity(&mut self) -> AssignedPointWithCurvature<C, N> {
        let zero = self
            .base_integer_chip()
            .assign_int_constant(C::Base::zero());
        let one = self
            .base_integer_chip()
            .base_chip()
            .assign_constant(N::one());

        AssignedPointWithCurvature::new(
            zero.clone(),
            zero.clone(),
            AssignedCondition(one),
            AssignedCurvature(zero, AssignedCondition(one)),
        )
    }

    fn bisec_point(
        &mut self,
        cond: &AssignedCondition<N>,
        a: &AssignedPoint<C, N>,
        b: &AssignedPoint<C, N>,
    ) -> AssignedPoint<C, N> {
        let x = self.base_integer_chip().bisec_int(cond, &a.x, &b.x);
        let y = self.base_integer_chip().bisec_int(cond, &a.y, &b.y);
        let z = self
            .base_integer_chip()
            .base_chip()
            .bisec_cond(cond, &a.z, &b.z);

        AssignedPoint::new(x, y, z)
    }

    fn bisec_curvature(
        &mut self,
        cond: &AssignedCondition<N>,
        a: &AssignedCurvature<C, N>,
        b: &AssignedCurvature<C, N>,
    ) -> AssignedCurvature<C, N> {
        let v = self.base_integer_chip().bisec_int(cond, &a.0, &b.0);
        let z = self
            .base_integer_chip()
            .base_chip()
            .bisec_cond(cond, &a.1, &b.1);

        AssignedCurvature(v, z)
    }

    fn bisec_point_with_curvature(
        &mut self,
        cond: &AssignedCondition<N>,
        a: &AssignedPointWithCurvature<C, N>,
        b: &AssignedPointWithCurvature<C, N>,
    ) -> AssignedPointWithCurvature<C, N> {
        let x = self.base_integer_chip().bisec_int(cond, &a.x, &b.x);
        let y = self.base_integer_chip().bisec_int(cond, &a.y, &b.y);
        let z = self
            .base_integer_chip()
            .base_chip()
            .bisec_cond(cond, &a.z, &b.z);

        let c = self.bisec_curvature(cond, &a.curvature, &b.curvature);

        AssignedPointWithCurvature::new(x, y, z, c)
    }

    fn lambda_to_point(
        &mut self,
        lambda: &AssignedCurvature<C, N>,
        a: &AssignedPoint<C, N>,
        b: &AssignedPoint<C, N>,
    ) -> AssignedPoint<C, N> {
        let l = &lambda.0;

        // cx = lambda ^ 2 - a.x - b.x
        let cx = {
            let l_square = self.base_integer_chip().int_square(l);
            let t = self.base_integer_chip().int_sub(&l_square, &a.x);
            let t = self.base_integer_chip().int_sub(&t, &b.x);
            t
        };

        let cy = {
            let t = self.base_integer_chip().int_sub(&a.x, &cx);
            let t = self.base_integer_chip().int_mul(&t, l);
            let t = self.base_integer_chip().int_sub(&t, &a.y);
            t
        };

        AssignedPoint::new(cx, cy, lambda.1)
    }

    fn ecc_add(
        &mut self,
        a: &AssignedPointWithCurvature<C, N>,
        b: &AssignedPoint<C, N>,
    ) -> AssignedPoint<C, N> {
        let diff_x = self.base_integer_chip().int_sub(&a.x, &b.x);
        let diff_y = self.base_integer_chip().int_sub(&a.y, &b.y);
        let (x_eq, tangent) = self.base_integer_chip().int_div(&diff_y, &diff_x);

        let y_eq = self.base_integer_chip().is_int_zero(&diff_y);
        let eq = self.base_integer_chip().base_chip().and(&x_eq, &y_eq);

        let tangent = AssignedCurvature(tangent, x_eq);
        let mut lambda = self.bisec_curvature(&eq, &a.curvature, &tangent);

        let a_p = a.clone().to_point();

        let p = self.lambda_to_point(&mut lambda, &a_p, b);
        let p = self.bisec_point(&a.z, b, &p);
        let p = self.bisec_point(&b.z, &a_p, &p);

        p
    }

    fn ecc_double(&mut self, a: &AssignedPointWithCurvature<C, N>) -> AssignedPoint<C, N> {
        let a_p = a.clone().to_point();
        let mut p = self.lambda_to_point(&a.curvature, &a_p, &a_p);
        p.z = self
            .base_integer_chip()
            .base_chip()
            .bisec_cond(&a.z, &a.z, &p.z);

        p
    }

    fn to_point_with_curvature(
        &mut self,
        a: AssignedPoint<C, N>,
    ) -> AssignedPointWithCurvature<C, N> {
        // 3 * x ^ 2 / 2 * y
        let x_square = self.base_integer_chip().int_square(&a.x);
        let numerator = self
            .base_integer_chip()
            .int_mul_small_constant(&x_square, 3);
        let denominator = self.base_integer_chip().int_mul_small_constant(&a.y, 2);

        let (z, v) = self.base_integer_chip().int_div(&numerator, &denominator);
        AssignedPointWithCurvature::new(a.x, a.y, a.z, AssignedCurvature(v, z))
    }

    // c: ((x.c0, x.c1),(y.c0, y.c1))
    fn assign_non_identity_constant_g2(
        &mut self,
        c: &((C::Base, C::Base), (C::Base, C::Base)),
    ) -> AssignedG2Affine<C, N> {
        let x = self.fq2_assign_constant(c.0);
        let y = self.fq2_assign_constant(c.1);

        let z = self
            .base_integer_chip()
            .base_chip()
            .assign_constant(N::zero());

        AssignedG2Affine::new(x, y, AssignedCondition(z))
    }

    fn assign_non_identity_g2(
        &mut self,
        c: &((C::Base, C::Base), (C::Base, C::Base)),
        b: AssignedFq2<C::Base, N>,
    ) -> AssignedG2Affine<C, N> {
        let x = self.fq2_assign(c.0);
        let y = self.fq2_assign(c.1);
        let z = self
            .base_integer_chip()
            .base_chip()
            .assign_constant(N::zero());

        // Constrain y^2 = x^3 + b
        let y2 = self.fq2_mul(&y, &y);
        let x2 = self.fq2_mul(&x, &x);
        let x3 = self.fq2_mul(&x2, &x);
        let right = self.fq2_add(&x3, &b);

        self.fq2_assert_equal(&y2, &right);

        AssignedG2Affine::new(x, y, AssignedCondition(z))
    }

    fn assign_g2_identity(&mut self) -> AssignedG2WithCurvature<C, N> {
        let zero = self.fq2_assign_zero();
        let one = self.fq2_assign_one();
        let z = self
            .base_integer_chip()
            .base_chip()
            .assign_constant(N::one());

        AssignedG2WithCurvature::new(
            zero.clone(),
            one,
            AssignedCondition(z),
            AssignedExtCurvature(zero, AssignedCondition(z)),
        )
    }

    fn bisec_g2_point(
        &mut self,
        cond: &AssignedCondition<N>,
        a: &AssignedG2Affine<C, N>,
        b: &AssignedG2Affine<C, N>,
    ) -> AssignedG2Affine<C, N> {
        let x = self.fq2_bisec(cond, &a.x, &b.x);
        let y = self.fq2_bisec(cond, &a.y, &b.y);
        let z = self
            .base_integer_chip()
            .base_chip()
            .bisec_cond(cond, &a.z, &b.z);

        AssignedG2Affine::new(x, y, z)
    }

    fn bisec_ext_curvature(
        &mut self,
        cond: &AssignedCondition<N>,
        a: &AssignedExtCurvature<C, N>,
        b: &AssignedExtCurvature<C, N>,
    ) -> AssignedExtCurvature<C, N> {
        let v = self.fq2_bisec(cond, &a.0, &b.0);
        let z = self
            .base_integer_chip()
            .base_chip()
            .bisec_cond(cond, &a.1, &b.1);

        AssignedExtCurvature(v, z)
    }

    fn bisec_g2_with_curvature(
        &mut self,
        cond: &AssignedCondition<N>,
        a: &AssignedG2WithCurvature<C, N>,
        b: &AssignedG2WithCurvature<C, N>,
    ) -> AssignedG2WithCurvature<C, N> {
        let x = self.fq2_bisec(cond, &a.x, &b.x);
        let y = self.fq2_bisec(cond, &a.y, &b.y);
        let z = self
            .base_integer_chip()
            .base_chip()
            .bisec_cond(cond, &a.z, &b.z);

        let c = self.bisec_ext_curvature(cond, &a.curvature, &b.curvature);

        AssignedG2WithCurvature::new(x, y, z, c)
    }

    fn lambda_to_g2_point(
        &mut self,
        lambda: &AssignedExtCurvature<C, N>,
        a: &AssignedG2Affine<C, N>,
        b: &AssignedG2Affine<C, N>,
    ) -> AssignedG2Affine<C, N> {
        let l = &lambda.0;

        // cx = lambda ^ 2 - a.x - b.x
        let cx = {
            let l_square = self.fq2_square(l);
            let t = self.fq2_sub(&l_square, &a.x);
            let t = self.fq2_sub(&t, &b.x);
            t
        };

        let cy = {
            let t = self.fq2_sub(&a.x, &cx);
            let t = self.fq2_mul(&t, l);
            let t = self.fq2_sub(&t, &a.y);
            t
        };

        AssignedG2Affine::new(cx, cy, lambda.1)
    }

    fn ecc_g2_add(
        &mut self,
        a: &AssignedG2WithCurvature<C, N>,
        b: &AssignedG2Affine<C, N>,
    ) -> AssignedG2Affine<C, N> {
        let diff_x = self.fq2_sub(&a.x, &b.x);
        let diff_y = self.fq2_sub(&a.y, &b.y);
        let (x_eq, tangent) = self.fq2_div(&diff_y, &diff_x);

        let y_eq = self.fq2_is_zero(&diff_y);
        let eq = self.base_integer_chip().base_chip().and(&x_eq, &y_eq);

        let tangent = AssignedExtCurvature(tangent, x_eq);
        let mut lambda = self.bisec_ext_curvature(&eq, &a.curvature, &tangent);

        let a_p = a.clone().to_point();

        let p = self.lambda_to_g2_point(&mut lambda, &a_p, b);
        let p = self.bisec_g2_point(&a.z, b, &p);
        let p = self.bisec_g2_point(&b.z, &a_p, &p);

        p
    }

    fn ecc_g2_double(&mut self, a: &AssignedG2WithCurvature<C, N>) -> AssignedG2Affine<C, N> {
        let a_p = a.clone().to_point();
        let mut p = self.lambda_to_g2_point(&a.curvature, &a_p, &a_p);
        p.z = self
            .base_integer_chip()
            .base_chip()
            .bisec_cond(&a.z, &a.z, &p.z);

        p
    }

    fn to_g2_point_with_curvature(
        &mut self,
        a: AssignedG2Affine<C, N>,
    ) -> AssignedG2WithCurvature<C, N> {
        // 3 * x ^ 2 / 2 * y
        let x_square = self.fq2_square(&a.x);
        let numerator = self.fq2_mul_small_constant(&x_square, 3);
        let denominator = self.fq2_mul_small_constant(&a.y, 2);

        let (z, v) = self.fq2_div(&numerator, &denominator);

        AssignedG2WithCurvature::new(a.x, a.y, a.z, AssignedExtCurvature(v, z))
    }
}
