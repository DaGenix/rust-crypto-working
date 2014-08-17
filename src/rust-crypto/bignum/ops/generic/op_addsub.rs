// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::super::{Bignum, Digit, Word};
use super::super::DIGIT_BITS;
use super::super::clamp;
use super::super::cmp::cmp_mag;

struct ZipWithDefault <T, A, B> {
    def: T,
    a: A,
    b: B
}

fn zip_with_default<T: Copy, A: Iterator<T>, B: Iterator<T>>(def: T, a: A, b: B)
        -> ZipWithDefault<T, A, B> {
    ZipWithDefault {
        def: def,
        a: a,
        b: b
    }
}

impl <T: Copy, A: Iterator<T>, B: Iterator<T>> Iterator<(T, T)> for ZipWithDefault<T, A, B> {
    #[inline]
    fn next(&mut self) -> Option<(T, T)> {
        let next_a = self.a.next();
        let next_b = self.b.next();
        match (next_a, next_b) {
            (Some(x), Some(y)) => Some((x, y)),
            (Some(x), None) => Some((x, self.def)),
            (None, Some(y)) => Some((self.def, y)),
            (None, None) => None
        }
    }
}

pub fn op_unsigned_add(out: &mut Bignum, a: &Bignum, b: &Bignum) {
    out.dp.clear();
    let mut t: Word = 0;
    for (tmpa, tmpb) in zip_with_default(0, a.dp.iter().map(|x| *x), b.dp.iter().map(|x| *x)) {
        t += tmpa as Word + tmpb as Word;
        out.dp.push(t as Digit);
        t = t >> DIGIT_BITS;
    }
    if t != 0 {
        out.dp.push(t as Digit);
    }
    clamp(out);
}

/// out = a - b; abs(a) >= abs(b)
pub fn op_unsigned_sub(out: &mut Bignum, a: &Bignum, b: &Bignum) {
    out.dp.clear();
    let mut t: Word = 0;
    let mut a_iter = a.dp.iter();
    for (&tmpa, &tmpb) in a_iter.by_ref().zip(b.dp.iter()) {
        t = (tmpa as Word) - ((tmpb as Word) + t);
        out.dp.push(t as Digit);
        t = (t >> DIGIT_BITS) & 1;
    }
    for &tmpa in a_iter {
        t = (tmpa as Word) - t;
        out.dp.push(t as Digit);
        t = (t >> DIGIT_BITS) & 1;
    }
    clamp(out);
}
