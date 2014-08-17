// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::{Bignum, Digit, Word};
use super::DIGIT_BITS;
use super::clamp;
use super::ops;

use std::cmp;

pub fn mul(out: &mut Bignum, a: &Bignum, b: &Bignum) {
    let mut c0: Digit = 0;
    let mut c1: Digit = 0;
    let mut c2: Digit = 0;

    let result_used = a.dp.len() + b.dp.len();

    // Probably faster:
    // out.dp.reserve(result_used);
    // unsafe { out.dp.set_len(result_used); }

    out.dp.clear();
    out.dp.grow(result_used, &0);

    for ix in range(0, result_used) {
        let ty = cmp::min(ix, b.dp.len() - 1);
        let tx = ix - ty;
        let iy = cmp::min(a.dp.len() - tx, ty + 1);

        c0 = c1;
        c1 = c2;
        c2 = 0;

        let mut tmpx = unsafe { a.dp.as_ptr().offset(tx as int) };
        let mut tmpy = unsafe { b.dp.as_ptr().offset(ty as int) };
        for iz in range(0, iy) {
            unsafe {
                let (_c0, _c1, _c2) = ops::op_muladd(*tmpx, *tmpy, c0, c1, c2);
                c0 = _c0;
                c1 = _c1;
                c2 = _c2;
                tmpx = tmpx.offset(1);
                tmpy = tmpy.offset(1);
            }
        }

        unsafe { *out.dp.as_mut_ptr().offset(ix as int) = c0; }
    }

    out.positive = if a.positive == b.positive { true } else { false };
    clamp(out);
}


/*
void fp_mul_comba(fp_int *A, fp_int *B, fp_int *C)
{
   int       ix, iy, iz, tx, ty, pa;
   fp_digit  c0, c1, c2, *tmpx, *tmpy;
   fp_int    tmp, *dst;

   c0 = c1 = c2 = 0;

   // get size of output and trim
   pa = A->used + B->used;
   if (pa >= FP_SIZE) {
      pa = FP_SIZE-1;
   }

   if (A == C || B == C) {
      fp_zero(&tmp);
      dst = &tmp;
   } else {
      fp_zero(C);
      dst = C;
   }

   for (ix = 0; ix < pa; ix++) {
      // get offsets into the two bignums
      ty = MIN(ix, B->used-1);
      tx = ix - ty;

      // setup temp aliases
      tmpx = A->dp + tx;
      tmpy = B->dp + ty;

      // this is the number of times the loop will iterrate, essentially its
      //   while (tx++ < a->used && ty-- >= 0) { ... }
      iy = MIN(A->used-tx, ty+1);

      // execute loop
      do { c0 = c1; c1 = c2; c2 = 0; } while (0);
      for (iz = 0; iz < iy; ++iz) {
          MULADD(*tmpx++, *tmpy--);
      }

      // store term
      dst->dp[ix] = c0;
  }

  dst->used = pa;
  dst->sign = A->sign ^ B->sign;
  fp_clamp(dst);
  fp_copy(dst, C);
}
*/
