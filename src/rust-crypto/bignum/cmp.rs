// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::{Bignum, Digit};

/// Signed comparison
pub fn cmp(x: &Bignum, y: &Bignum) -> int {
    if (!x.positive && y.positive) {
        return -1;
    } else if (x.positive && y.positive) {
        return 1;
    } else {
        // compare digits
        if (!x.positive) {
            // if negative compare opposite direction
            return cmp_mag(y, x);
        } else {
            return cmp_mag(x, y);
        }
    }
}

/// Unsigned comparison
pub fn cmp_mag(x: &Bignum, y: &Bignum) -> int {
    if (x.dp.len() > y.dp.len()) {
        return 1;
    } else if (x.dp.len() < y.dp.len()) {
        return -1;
    } else {
        for (&tmpx, &tmpy) in x.dp.iter().rev().zip(y.dp.iter().rev()) {
            if tmpx > tmpy {
                return 1
            } else if tmpx < tmpy {
                return -1
            }
        }
        return 0;
    }
}
