use halo2_proofs::arithmetic::{BaseExt, FieldExt};

use crate::circuit_utils::ecc_chip::EccBaseIntegerChipWrapper;
use crate::circuits::assign::{AssignedCondition, AssignedFq2};
use crate::circuits::utils::field_to_bn;

pub trait Fq2ChipOps<W: BaseExt, N: FieldExt>: EccBaseIntegerChipWrapper<W, N> {
    fn fq2_reduce(&mut self, x: &AssignedFq2<W, N>) -> AssignedFq2<W, N> {
        (
            self.base_integer_chip().reduce(&x.0),
            self.base_integer_chip().reduce(&x.1),
        )
    }

    fn fq2_assert_equal(&mut self, x: &AssignedFq2<W, N>, y: &AssignedFq2<W, N>) {
        self.base_integer_chip().assert_int_equal(&x.0, &y.0);
        self.base_integer_chip().assert_int_equal(&x.1, &y.1);
    }

    fn fq2_is_zero(&mut self, x: &AssignedFq2<W, N>) -> AssignedCondition<N> {
        let is_c0_zero = self.base_integer_chip().is_int_zero(&x.0);
        let is_c1_zero = self.base_integer_chip().is_int_zero(&x.1);

        self.base_integer_chip()
            .base_chip()
            .and(&is_c0_zero, &is_c1_zero)
    }

    fn fq2_assign_zero(&mut self) -> AssignedFq2<W, N> {
        let fq2_zero = self.base_integer_chip().assign_int_constant(W::zero());
        (fq2_zero.clone(), fq2_zero)
    }

    fn fq2_assign_one(&mut self) -> AssignedFq2<W, N> {
        (
            self.base_integer_chip().assign_int_constant(W::one()),
            self.base_integer_chip().assign_int_constant(W::zero()),
        )
    }

    fn fq2_assign_constant(&mut self, c: (W, W)) -> AssignedFq2<W, N> {
        (
            self.base_integer_chip().assign_int_constant(c.0),
            self.base_integer_chip().assign_int_constant(c.1),
        )
    }

    fn fq2_assign(&mut self, c: (W, W)) -> AssignedFq2<W, N> {
        (
            self.base_integer_chip().assign_w(&field_to_bn(&c.0)),
            self.base_integer_chip().assign_w(&field_to_bn(&c.1)),
        )
    }

    fn fq2_add(&mut self, a: &AssignedFq2<W, N>, b: &AssignedFq2<W, N>) -> AssignedFq2<W, N> {
        (
            self.base_integer_chip().int_add(&a.0, &b.0),
            self.base_integer_chip().int_add(&a.1, &b.1),
        )
    }

    fn fq2_mul(&mut self, a: &AssignedFq2<W, N>, b: &AssignedFq2<W, N>) -> AssignedFq2<W, N> {
        let ab00 = self.base_integer_chip().int_mul(&a.0, &b.0);
        let ab11 = self.base_integer_chip().int_mul(&a.1, &b.1);
        let c0 = self.base_integer_chip().int_sub(&ab00, &ab11);

        let a01 = self.base_integer_chip().int_add(&a.0, &a.1);
        let b01 = self.base_integer_chip().int_add(&b.0, &b.1);
        let c1 = self.base_integer_chip().int_mul(&a01, &b01);
        let c1 = self.base_integer_chip().int_sub(&c1, &ab00);
        let c1 = self.base_integer_chip().int_sub(&c1, &ab11);

        (c0, c1)
    }

    fn fq2_sub(&mut self, a: &AssignedFq2<W, N>, b: &AssignedFq2<W, N>) -> AssignedFq2<W, N> {
        (
            self.base_integer_chip().int_sub(&a.0, &b.0),
            self.base_integer_chip().int_sub(&a.1, &b.1),
        )
    }

    fn fq2_double(&mut self, a: &AssignedFq2<W, N>) -> AssignedFq2<W, N> {
        (
            self.base_integer_chip().int_add(&a.0, &a.0),
            self.base_integer_chip().int_add(&a.1, &a.1),
        )
    }

    fn fq2_square(&mut self, a: &AssignedFq2<W, N>) -> AssignedFq2<W, N> {
        self.fq2_mul(a, a)
    }

    fn fq2_neg(&mut self, a: &AssignedFq2<W, N>) -> AssignedFq2<W, N> {
        (
            self.base_integer_chip().int_neg(&a.0),
            self.base_integer_chip().int_neg(&a.1),
        )
    }

    fn fq2_conjugate(&mut self, a: &AssignedFq2<W, N>) -> AssignedFq2<W, N> {
        (a.0.clone(), self.base_integer_chip().int_neg(&a.1))
    }

    fn fq2_unsafe_invert(&mut self, x: &AssignedFq2<W, N>) -> AssignedFq2<W, N> {
        let t0 = self.base_integer_chip().int_square(&x.0);
        let t1 = self.base_integer_chip().int_square(&x.1);
        let t0 = self.base_integer_chip().int_add(&t0, &t1);
        let t = self.base_integer_chip().int_unsafe_invert(&t0);
        let c0 = self.base_integer_chip().int_mul(&x.0, &t);
        let c1 = self.base_integer_chip().int_mul(&x.1, &t);
        let c1 = self.base_integer_chip().int_neg(&c1);
        (c0, c1)
    }

    fn fq2_invert(&mut self, x: &AssignedFq2<W, N>) -> (AssignedCondition<N>, AssignedFq2<W, N>) {
        let t0 = self.base_integer_chip().int_square(&x.0);
        let t1 = self.base_integer_chip().int_square(&x.1);
        let t0 = self.base_integer_chip().int_add(&t0, &t1);
        let one = self.base_integer_chip().assign_int_constant(W::one());
        let (z, t) = self.base_integer_chip().int_div(&one, &t0);
        let c0 = self.base_integer_chip().int_mul(&x.0, &t);
        let c1 = self.base_integer_chip().int_mul(&x.1, &t);
        let c1 = self.base_integer_chip().int_neg(&c1);
        (z, (c0, c1))
    }

    fn fq2_div(
        &mut self,
        a: &AssignedFq2<W, N>,
        b: &AssignedFq2<W, N>,
    ) -> (AssignedCondition<N>, AssignedFq2<W, N>) {
        let (z, b_inv) = self.fq2_invert(b);
        (z, self.fq2_mul(a, &b_inv))
    }

    // if cond == true, return a else b
    fn fq2_bisec(
        &mut self,
        cond: &AssignedCondition<N>,
        a: &AssignedFq2<W, N>,
        b: &AssignedFq2<W, N>,
    ) -> AssignedFq2<W, N> {
        (
            self.base_integer_chip().bisec_int(cond, &a.0, &b.0),
            self.base_integer_chip().bisec_int(cond, &a.1, &b.1),
        )
    }

    fn fq2_mul_small_constant(&mut self, a: &AssignedFq2<W, N>, b: u64) -> AssignedFq2<W, N> {
        (
            self.base_integer_chip().int_mul_small_constant(&a.0, b),
            self.base_integer_chip().int_mul_small_constant(&a.1, b),
        )
    }
}
