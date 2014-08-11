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

pub type Digit = u32;
pub type Word = u64;

pub static DIGIT_BITS: uint = 32;

pub struct Bignum {
    pub dp: Vec<Digit>,
    pub positive: bool
}

impl Bignum {
    pub fn zero() -> Bignum {
        Bignum {
            dp: Vec::new(),
            positive: true
        }
    }
}

impl Bignum {
    pub fn set_add(&mut self, x: &Bignum, y: &Bignum) {
        addsub::add(self, x, y);
    }
    pub fn set_sub(&mut self, x: &Bignum, y: &Bignum) {
        addsub::sub(self, x, y);
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
