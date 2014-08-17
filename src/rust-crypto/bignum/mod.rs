// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

mod addsub;
mod cmp;
mod mul;
mod div;
mod exp;
mod ops;

pub type Digit = u32;
pub type Word = u64;

pub static DIGIT_BITS: uint = 32;

pub struct Bignum {
    pub dp: Vec<Digit>,
    pub positive: bool
}

impl Bignum {
    pub fn new() -> Bignum {
        Bignum {
            dp: Vec::new(),
            positive: true
        }
    }
}

impl Bignum {
    pub fn set_add(&mut self, a: &Bignum, b: &Bignum) {
        addsub::add(self, a, b);
    }
    pub fn set_sub(&mut self, a: &Bignum, b: &Bignum) {
        addsub::sub(self, a, b);
    }
    pub fn set_mul(&mut self, a: &Bignum, b: &Bignum) {
        mul::mul(self, a, b);
    }
}

pub fn clamp(x: &mut Bignum) {
    while x.dp.last().map_or(false, |&tmp| tmp == 0) {
        x.dp.pop();
    }
    if x.dp.is_empty() {
        x.positive = true;
    }
}
