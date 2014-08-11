// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::{Bignum, Digit, Word};
use super::DIGIT_BITS;
use super::clamp;
use super::cmp::cmp_mag;

pub fn add(out: &mut Bignum, x: &Bignum, y: &Bignum) {
    if (x.positive == y.positive) {
        out.positive = x.positive;
        unsigned_add(out, x, y);
    } else {
        // one positive, the other negative
        // subtract the one with the greater magnitude from
        // the one of the lesser magnitude. The result gets
        // the sign of the one with the greater magnitude.
        if (cmp_mag(x, y) == -1) {
            out.positive = y.positive;
            unsigned_sub(out, y, x);
        } else {
            out.positive = y.positive;
            unsigned_sub(out, x, y);
        }
    }
}

pub fn sub(out: &mut Bignum, x: &Bignum, y: &Bignum) {
    // subtract a negative from a positive, OR
    // subtract a positive from a negative.
    // In either case, ADD their magnitudes,
    // and use the sign of the first number.
    if x.positive != y.positive {
        out.positive = x.positive;
        unsigned_add(out, x, y);
    } else {
        // subtract a positive from a positive, OR
        // subtract a negative from a negative.
        // First, take the difference between their
        // magnitudes, then...
        if cmp_mag(x, y) >= 0 {
            out.positive = x.positive;
            // The first has a larger or equal magnitude
            unsigned_sub(out, x, y);
        } else {
            // The result has the *opposite* sign from
            // the first number.
            out.positive = !x.positive;
            // The second has a larger magnitude
            unsigned_sub(out, y, x);
        }
    }
}

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

fn unsigned_add(out: &mut Bignum, x: &Bignum, y: &Bignum) {
    out.dp.clear();
    let mut t: Word = 0;
    for (tmpx, tmpy) in zip_with_default(0, x.dp.iter().map(|x| *x), y.dp.iter().map(|x| *x)) {
        t += tmpx as Word + tmpy as Word;
        out.dp.push(t as Digit);
        t = t >> DIGIT_BITS;
    }
    if t != 0 {
        out.dp.push(t as Digit);
    }
    clamp(out);
}

/// out = x - y; abs(x) >= abs(y)
fn unsigned_sub(out: &mut Bignum, x: &Bignum, y: &Bignum) {
    out.dp.clear();
    let mut t: Word = 0;
    let mut x_iter = x.dp.iter();
    for (&tmpx, &tmpy) in x_iter.by_ref().zip(y.dp.iter()) {
        t = (tmpx as Word) - ((tmpy as Word) + t);
        out.dp.push(t as Digit);
        t = (t >> DIGIT_BITS) & 1;
    }
    for &tmpx in x_iter {
        t = (tmpx as Word) - t;
        out.dp.push(t as Digit);
        t = (t >> DIGIT_BITS) & 1;
    }
    clamp(out);
}
