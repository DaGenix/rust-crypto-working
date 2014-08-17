// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::{Bignum, Digit, Word};
use super::DIGIT_BITS;
use super::clamp;
use super::cmp::cmp_mag;
use super::ops;

pub fn add(out: &mut Bignum, a: &Bignum, b: &Bignum) {
    if (a.positive == b.positive) {
        out.positive = a.positive;
        ops::op_unsigned_add(out, a, b);
    } else {
        // one positive, the other negative
        // subtract the one with the greater magnitude from
        // the one of the lesser magnitude. The result gets
        // the sign of the one with the greater magnitude.
        if (cmp_mag(a, b) == -1) {
            out.positive = b.positive;
            ops::op_unsigned_sub(out, b, a);
        } else {
            out.positive = b.positive;
            ops::op_unsigned_sub(out, a, b);
        }
    }
}

pub fn sub(out: &mut Bignum, a: &Bignum, b: &Bignum) {
    // subtract a negative from a positive, OR
    // subtract a positive from a negative.
    // In either case, ADD their magnitudes,
    // and use the sign of the first number.
    if a.positive != b.positive {
        out.positive = a.positive;
        ops::op_unsigned_add(out, a, b);
    } else {
        // subtract a positive from a positive, OR
        // subtract a negative from a negative.
        // First, take the difference between their
        // magnitudes, then...
        if cmp_mag(a, b) >= 0 {
            out.positive = a.positive;
            // The first has a larger or equal magnitude
            ops::op_unsigned_sub(out, a, b);
        } else {
            // The result has the *opposite* sign from
            // the first number.
            out.positive = !a.positive;
            // The second has a larger magnitude
            ops::op_unsigned_sub(out, b, a);
        }
    }
}
