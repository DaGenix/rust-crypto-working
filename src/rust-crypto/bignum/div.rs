// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use num::bigint::BigInt;
use num::Integer;
use std::num::{Zero, One};

use super::Bignum;
use super::DIGIT_BITS;

fn from_bignum(x: &Bignum) -> BigInt {
    let mut out: BigInt = Zero::zero();
    for &d in x.dp.iter().rev() {
        out = out << DIGIT_BITS;
        let tmp: BigInt = FromPrimitive::from_u32(d).unwrap();
        out = out + tmp;
    }
    if !x.positive {
        out = out.neg();
    }
    out
}

fn to_bignum(out: &mut Bignum, mut x: BigInt) {
    out.dp.clear();
    let positive = if x.is_positive() {
        true
    } else {
        x.neg();
        false
    };
    let mut s: BigInt = One::one();
    s = s << DIGIT_BITS;
    while !x.is_zero() {
        let (q, r) = x.div_rem(&s);
        let d = r.to_u32().unwrap();
        out.dp.push(d);
        x = q;
    }
    out.positive = positive;
}

pub fn div_rem(
        quotient: Option<&mut Bignum>,
        remainder: Option<&mut Bignum>,
        a: &Bignum,
        b: &Bignum) {
    if b.is_zero() {
        fail!("Division by 0");
    }

    let tmpa = from_bignum(a);
    let tmpb = from_bignum(b);

    let (q, r) = tmpa.div_rem(&tmpb);

    match quotient {
        Some(x) => { to_bignum(x, q); }
        None => { }
    }
    match remainder {
        Some(x) => { to_bignum(x, r); }
        None => { }
    }
}
