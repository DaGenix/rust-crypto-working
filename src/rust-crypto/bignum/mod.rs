// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// pub use self::div::div_rem;

mod addsub;
mod bits;
mod cmp;
mod mul;
// mod div;
mod exp;
// mod radix;
mod ops;

pub type Digit = u32;
pub type Word = u64;

pub static DIGIT_BITS: uint = 32;

#[deriving(Clone)]
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
    pub fn new_d(a: Digit) -> Bignum {
        let mut x = Bignum::new();
        x.dp.push(a);
        x
    }
/*    pub fn new_from_str(v: &str) -> Result<Bignum, &'static str> {
        let mut x = Bignum::new();
        if radix::read_str(&mut x, v) {
            Ok(x)
        } else {
            Err("Invalid string")
        }
    }
*/
}

impl Bignum {
    pub fn is_zero(&self) -> bool {
        self.dp.len() == 0
    }
    pub fn set_d(&mut self, a: Digit) {
        self.dp.clear();
        self.dp.push(a);
        self.positive == a >= 0;
    }
    pub fn set(&mut self, a: &Bignum) {
        self.dp.clear();
        self.dp.push_all(a.dp.as_slice());
        self.positive = a.positive;
    }
}

impl Bignum {
//    pub fn to_string(&self) -> String {
//        radix::to_str(self)
//    }
    pub fn count_bits(&self) -> uint {
        bits::count_bits(self)
    }
    pub fn set_add(&mut self, a: &Bignum, b: &Bignum) {
        addsub::add(self, a, b);
    }
    pub fn set_sub(&mut self, a: &Bignum, b: &Bignum) {
        addsub::sub(self, a, b);
    }
    pub fn set_mul(&mut self, a: &Bignum, b: &Bignum) {
        mul::mul(self, a, b);
    }
    pub fn set_div(&mut self, a: &Bignum, b: &Bignum) {
        // div::div_rem(Some(self), None, a, b);
    }
}

/*
impl FromStrRadix for BigInt {
    /// Creates and initializes a BigInt.
    #[inline]
    fn from_str_radix(s: &str, radix: uint) -> Option<BigInt> {
        BigInt::parse_bytes(s.as_bytes(), radix)
    }
}
*/

pub fn clamp(x: &mut Bignum) {
    while x.dp.last().map_or(false, |&tmp| tmp == 0) {
        x.dp.pop();
    }
    if x.dp.is_empty() {
        x.positive = true;
    }
}
