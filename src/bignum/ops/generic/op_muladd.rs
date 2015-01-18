// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::super::{Digit, Word};
use super::super::DIGIT_BITS;

#[inline(always)]
pub fn op_muladd(i: Digit, j: Digit, mut c0: Digit, mut c1: Digit, mut c2: Digit)
        -> (Digit, Digit, Digit) {
    let mut t: Word;
    t = (c0 as Word) + ((i as Word) * (j as Word));
    c0 = t as Digit;
    t = (c1 as Word) + (t >> DIGIT_BITS);
    c1 = t as Digit;
    c2 += (t >> DIGIT_BITS) as Digit;
    (c0, c1, c2)
}

/*
#define MULADD(i, j)                                    \
   do { fp_word t;                                      \
   t = (fp_word)c0 + ((fp_word)i) * ((fp_word)j);       \
   c0 = t;                                              \
   t = (fp_word)c1 + (t >> DIGIT_BIT);                  \
   c1 = t;                                              \
   c2 += t >> DIGIT_BIT;                                \
   } while (0);
*/