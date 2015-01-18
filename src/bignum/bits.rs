// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::Bignum;
use super::DIGIT_BITS;
use std::num::Int;

pub fn count_bits(a: &Bignum) -> uint {
    if a.is_zero() {
        return 0;
    }
    let mut bits = (a.dp.len() - 1) * DIGIT_BITS;
    bits += DIGIT_BITS - (a.dp[a.dp.len() - 1].leading_zeros());
    return bits;
}
