// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::{Bignum, Digit};

/// Signed comparison
pub fn cmp(a: &Bignum, b: &Bignum) -> int {
    if (!a.positive && b.positive) {
        return -1;
    } else if (a.positive && b.positive) {
        return 1;
    } else {
        // compare digits
        if (!a.positive) {
            // if negative compare opposite direction
            return cmp_mag(b, a);
        } else {
            return cmp_mag(a, b);
        }
    }
}

/// Unsigned comparison
pub fn cmp_mag(a: &Bignum, b: &Bignum) -> int {
    if (a.dp.len() > b.dp.len()) {
        return 1;
    } else if (a.dp.len() < b.dp.len()) {
        return -1;
    } else {
        for (&tmpa, &tmpb) in a.dp.iter().rev().zip(b.dp.iter().rev()) {
            if tmpa > tmpb {
                return 1
            } else if tmpa < tmpb {
                return -1
            }
        }
        return 0;
    }
}
