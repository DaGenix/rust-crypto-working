// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate num;

use std::{cmp, mem, ptr};
use std::fmt::{self, Display};
use std::num::Int;
use std::ops::{Deref, DerefMut, Add, Sub, Mul, Shl, Shr};

// Must by Copy so that we can do byte copies
pub trait Digit: Int + Copy + fmt::Display {
    type Word: Word<Digit = Self>;

    fn from_byte(x: u8) -> Self;
    fn to_byte(self) -> u8;

    fn to_word(self) -> Self::Word;

    fn bits() -> usize;
}

// Must by Copy so that we can do byte copies
pub trait Word: Int + Copy + fmt::Display {
    type Digit: Digit<Word = Self>;

    fn to_digit(self) -> Self::Digit;
}

impl Digit for u16 {
    type Word = u32;

    fn from_byte(x: u8) -> u16 { x as u16 }
    fn to_byte(self) -> u8 { self as u8 }

    fn to_word(self) -> u32 { self as u32 }

    fn bits() -> usize { 16 }
}

impl Digit for u8 {
    type Word = u16;

    fn from_byte(x: u8) -> u8 { x }
    fn to_byte(self) -> u8 { self }

    fn to_word(self) -> u16 { self as u16 }

    fn bits() -> usize { 8 }
}

impl Word for u32 {
    type Digit = u16;

    fn to_digit(self) -> u16 { self as u16 }
}

impl Word for u16 {
    type Digit = u8;

    fn to_digit(self) -> u8 { self as u8 }
}

pub trait Data {
    type Item; //=

    fn new() -> Self;
    fn len(&self) -> usize;
    fn capacity(&self) -> usize;
    fn clear(&mut self);
    unsafe fn grow_uninit(&mut self, additional: usize);
    fn shrink(&mut self, ammount: usize);
    fn pop(&mut self);
    fn push(&mut self, val: Self::Item);
    fn is_empty(&self) -> bool { self.len() == 0}

    fn as_ptr(&self) -> *const Self::Item;
    fn as_mut_ptr(&mut self) -> *mut Self::Item;
}

pub trait DigitVec<D>: Data<Item = D> + Deref<Target = [D]> + DerefMut { }

#[macro_export]
macro_rules! bignum_data(
    ($name:ident, $ty:ty, $size:expr) => {
        pub struct $name {
            len: usize,
            data: [$ty; $size]
        }

        impl Deref for $name {
            type Target = [$ty];
            fn deref(&self) -> &[$ty] { &self.data[..self.len] }
        }

        impl DerefMut for $name {
            fn deref_mut(&mut self) -> &mut [$ty] { &mut self.data[..self.len] }
        }

        impl Data for $name {
            type Item = $ty;

            fn new() -> $name {
                $name {
                    len: 0,
                    data: unsafe { mem::uninitialized() }
                }
            }

            fn len(&self) -> usize { self.len }

            fn capacity(&self) -> usize { $size }

            fn clear(&mut self) {
                self.len = 0;
            }

            fn pop(&mut self) {
                if self.len == 0 {
                    panic!("Can't pop empty data");
                }
                self.len -= 1;
            }

            fn push(&mut self, val: $ty) {
                let old_len = self.len();
                unsafe {
                    self.grow_uninit(1);
                    self[old_len] = val;
                }
            }

            unsafe fn grow_uninit(&mut self, additional: usize) {
                if self.len + additional > $size {
                    panic!("Size too big");
                }
                self.len += additional;
            }

            fn shrink(&mut self, ammount: usize) {
                if ammount > self.len {
                    panic!("Ammount too big");
                }
                self.len -= ammount;
            }

            fn as_ptr(&self) -> *const $ty {
                self.data.as_ptr()
            }

            fn as_mut_ptr(&mut self) -> *mut $ty {
                self.data.as_mut_ptr()
            }
        }

        impl DigitVec<$ty> for $name { }
    }
);

bignum_data!(DataU16x100, u16, 100);
bignum_data!(DataU8x200, u8, 200);

#[derive(Debug)]
pub struct Bignum<M> {
    pub pos: bool,
    pub data: M
}

impl <M> Bignum<M> where M: Data {
    pub fn new() -> Bignum<M> {
        Bignum {
            pos: true,
            data: Data::new()
        }
    }
}

pub fn clamp<D, M>(x: &mut Bignum<M>) where D: Digit, M: DigitVec<D> {
    while let Some(&tmp) = x.data[..].last() {
        if tmp == Int::zero() {
            x.data.pop();
        }
    }
    if x.data.is_empty() {
        x.pos = true;
    }
}


pub trait Ops<D, M>: Copy {
    fn unsigned_add(&self, out: &mut Bignum<M>, a: &Bignum<M>, b: &Bignum<M>);
    fn unsigned_sub(&self, out: &mut Bignum<M>, a: &Bignum<M>, b: &Bignum<M>);
    fn muladd(&self, i: D, j: D, mut c0: D, mut c1: D, mut c2: D) -> (D, D, D);
    fn sqradd(&self, i: D, j: D, mut c0: D, mut c1: D, mut c2: D) -> (D, D, D);
    fn sqradd2(&self, i: D, j: D, mut c0: D, mut c1: D, mut c2: D) -> (D, D, D);
}

#[derive(Copy)]
pub struct GenericOps;

struct ZipWithDefault <T, A, B> {
    def: T,
    a: A,
    b: B
}

fn zip_with_default<T: Copy, A: Iterator<Item = T>, B: Iterator<Item = T>>(def: T, a: A, b: B)
        -> ZipWithDefault<T, A, B> {
    ZipWithDefault {
        def: def,
        a: a,
        b: b
    }
}

impl <T: Copy, A: Iterator<Item = T>, B: Iterator<Item = T>> Iterator for ZipWithDefault<T, A, B> {
    type Item = (T, T);

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

impl <D, M> Ops<D, M> for GenericOps where D: Digit, M: DigitVec<D> {
    fn unsigned_add(&self, out: &mut Bignum<M>, a: &Bignum<M>, b: &Bignum<M>) {
        let digit_bits = <D as Digit>::bits();
        out.data.clear();
        let mut t: <D as Digit>::Word = Int::zero();
        for (&tmpa, &tmpb) in zip_with_default(&Int::zero(), a.data[..].iter(), b.data[..].iter()) {
            t = t + tmpa.to_word() + tmpb.to_word();
            out.data.push(t.to_digit());
            t = t >> digit_bits;
        }
        if t != Int::zero() {
            out.data.push(t.to_digit());
        }
        clamp(out);
    }

    /// out = a - b; abs(a) >= abs(b)
    fn unsigned_sub(&self, out: &mut Bignum<M>, a: &Bignum<M>, b: &Bignum<M>) {
        let digit_bits = <D as Digit>::bits();
        let mut t: <D as Digit>::Word = Int::zero();
        let mut a_iter = a.data[..].iter();
        let mut b_iter = b.data[..].iter();
        // This is similar to doing .zip() with the exception
        // that we are guaranteed not to call .next() on a_iter
        // after b_iter is exhausted.
        while let Some(&tmpb) = b_iter.next() {
            if let Some(&tmpa) = a_iter.next() {
                t = tmpa.to_word() - (tmpb.to_word() + t);
                out.data.push(t.to_digit());
                t = (t >> digit_bits) & Int::one();
            } else {
                panic!("a has lesser magnitude than b");
            }
        }
        for &tmpa in a_iter {
            t = tmpa.to_word() - t;
            out.data.push(t.to_digit());
            t = (t >> digit_bits) & Int::one();
        }
        clamp(out);
    }

    fn muladd(&self, i: D, j: D, mut c0: D, mut c1: D, mut c2: D) -> (D, D, D) {
        let digit_bits = <D as Digit>::bits();
        let mut t: <D as Digit>::Word;
        t = c0.to_word() + i.to_word() * j.to_word();
        c0 = t.to_digit();
        t = c1.to_word() + (t >> digit_bits);
        c1 = t.to_digit();
        c2 = c2 + (t >> digit_bits).to_digit();
        (c0, c1, c2)
    }

    // multiplies point i and j, updates carry "c1" and digit c2
    fn sqradd(&self, i: D, j: D, mut c0: D, mut c1: D, mut c2: D) -> (D, D, D) {
        let digit_bits = <D as Digit>::bits();
        let mut t = c0.to_word() + (i.to_word() * j.to_word());
        c0 = t.to_digit();
        t = c1.to_word() + (t >> digit_bits);
        c1 = t.to_digit();
        c2 = c2 + (t >> digit_bits).to_digit();
        (c0, c1, c2)
    }


    // for squaring some of the terms are doubled...
    fn sqradd2(&self, i: D, j: D, mut c0: D, mut c1: D, mut c2: D) -> (D, D, D) {
        let digit_bits = <D as Digit>::bits();
        let t = i.to_word() * j.to_word();
        let mut tt = c0.to_word() + t;
        c0 = tt.to_digit();
        tt = c1.to_word() + (tt >> digit_bits);
        c1 = tt.to_digit();
        c2 = c2 + (tt >> digit_bits).to_digit();
        tt = c0.to_word() + t;
        c0 = tt.to_digit();
        tt = c1.to_word() + (tt >> digit_bits);
        c1 = tt.to_digit();
        c2 = c2 + (tt >> digit_bits).to_digit();
        (c0, c1, c2)
    }
}

pub fn copy<D, M>(x: &mut Bignum<M>, a: &Bignum<M>) where D: Digit, M: DigitVec<D> {
    x.data.clear();
    unsafe {
        x.data.grow_uninit(a.data.len());
        ptr::copy_nonoverlapping_memory(
            x.data[..].as_mut_ptr(),
            a.data[..].as_ptr(),
            a.data.len());
    }
    x.pos = a.pos;
}

pub fn is_zero<D, M>(a: &Bignum<M>) -> bool where D: Digit, M: DigitVec<D> {
    a.data.is_empty()
}

pub fn zero<D, M>(a: &mut Bignum<M>) where D: Digit, M: DigitVec<D> {
    a.data.clear();
    a.pos = true;
}

/// Unsigned comparison
pub fn cmp_mag<D, M>(a: &Bignum<M>, b: &Bignum<M>) -> isize where D: Digit, M: DigitVec<D> {
    if a.data.len() > b.data.len() {
        return 1;
    } else if a.data.len() < b.data.len() {
        return -1;
    } else {
        for (&tmpa, &tmpb) in a.data[..].iter().rev().zip(b.data[..].iter().rev()) {
            if tmpa > tmpb {
                return 1
            } else if tmpa < tmpb {
                return -1
            }
        }
        return 0;
    }
}

/// Signed comparison
pub fn cmp<D, M>(a: &Bignum<M>, b: &Bignum<M>) -> isize where D: Digit, M: DigitVec<D> {
    if !a.pos && b.pos {
        return -1;
    } else if a.pos && b.pos {
        return 1;
    } else {
        // compare digits
        if !a.pos {
            // if negative compare opposite direction
            return cmp_mag(b, a);
        } else {
            return cmp_mag(a, b);
        }
    }
}

pub fn add<D, M, O>(out: &mut Bignum<M>, a: &Bignum<M>, b: &Bignum<M>, ops: O)
        where D: Digit, M: DigitVec<D>, O: Ops<D, M> {
    if a.pos == b.pos {
        out.pos = a.pos;
        ops.unsigned_add(out, a, b);
    } else {
        // one positive, the other negative
        // subtract the one with the greater magnitude from
        // the one of the lesser magnitude. The result gets
        // the sign of the one with the greater magnitude.
        if cmp_mag(a, b) == -1 {
            out.pos = b.pos;
            ops.unsigned_sub(out, b, a);
        } else {
            out.pos = b.pos;
            ops.unsigned_sub(out, a, b);
        }
    }
}

pub fn add_d<D, M, O>(out: &mut Bignum<M>, a: &Bignum<M>, b: D, ops: O)
        where D: Digit, M: DigitVec<D>, O: Ops<D, M> {
    let mut tmp: Bignum<M> = Bignum::new();
    unsafe {
        tmp.data.grow_uninit(1);
        tmp.data[0] = b;
    }
    add(out, a, &tmp, ops);
}

pub fn sub<D, M, O>(out: &mut Bignum<M>, a: &Bignum<M>, b: &Bignum<M>, ops: O)
        where D: Digit, M: DigitVec<D>, O: Ops<D, M> {
    // subtract a negative from a positive, OR
    // subtract a positive from a negative.
    // In either case, ADD their magnitudes,
    // and use the sign of the first number.
    if a.pos != b.pos {
        out.pos = a.pos;
        ops.unsigned_add(out, a, b);
    } else {
        // subtract a positive from a positive, OR
        // subtract a negative from a negative.
        // First, take the difference between their
        // magnitudes, then...
        if cmp_mag(a, b) >= 0 {
            out.pos = a.pos;
            // The first has a larger or equal magnitude
            ops.unsigned_sub(out, a, b);
        } else {
            // The result has the *opposite* sign from
            // the first number.
            out.pos = !a.pos;
            // The second has a larger magnitude
            ops.unsigned_sub(out, b, a);
        }
    }
}

pub fn mul<D, M, O>(out: &mut Bignum<M>, a: &Bignum<M>, b: &Bignum<M>, ops: O)
        where D: Digit, M: DigitVec<D>, O: Ops<D, M> {
    let mut c0;
    let mut c1: D = Int::zero();
    let mut c2: D = Int::zero();

    let result_used = a.data.len() + b.data.len();

    out.data.clear();

    // The entire contents of the data is potentially
    // uninitialized after this. However, every item will be set
    // in the following loop.
    unsafe { out.data.grow_uninit(result_used); }

    for ix in range(0, result_used) {
        let ty = cmp::min(ix, b.data.len() - 1);
        let tx = ix - ty;
        let iy = cmp::min(a.data.len() - tx, ty + 1);

        c0 = c1;
        c1 = c2;
        c2 = Int::zero();

        let mut tmpx = unsafe { a.data.as_ptr().offset(tx as isize) };
        let mut tmpy = unsafe { b.data.as_ptr().offset(ty as isize) };
        for _ in range(0, iy) {
            unsafe {
                let (_c0, _c1, _c2) = ops.muladd(*tmpx, *tmpy, c0, c1, c2);
                c0 = _c0;
                c1 = _c1;
                c2 = _c2;
                tmpx = tmpx.offset(1);
                tmpy = tmpy.offset(-1);
            }
        }

        unsafe { *out.data.as_mut_ptr().offset(ix as isize) = c0; }
    }

    out.pos = a.pos == b.pos;

    clamp(out);
}

// x = a * 2**b
pub fn mul_2d<D, M>(out: &mut Bignum<M>, mut b: usize) where D: Digit, M: DigitVec<D> {
    // let digit_bits = bits::<D>();
    let digit_bits = <D as Digit>::bits();

    // handle whole digits
    if b >= digit_bits {
        lsh_digits(out, b / digit_bits);
    }
    b %= digit_bits;

    // shift the digits
    if b != 0 {
        let mut carry: D = Int::zero();
        let shift = digit_bits - b;
        for x in range(0, out.data.len()) {
            let carrytmp = out.data[x] >> shift;
            out.data[x] = (out.data[x] << b) + carry;
            carry = carrytmp;
        }
        // store last carry if room
        if carry != Int::zero() && out.data.len() < out.data.capacity() {
            let t = out.data.len();
            unsafe {
                out.data.grow_uninit(1);
                out.data[t] = carry;
            }
        }
    }

    clamp(out);
}

// out = a * b
pub fn mul_d<D, M>(out: &mut Bignum<M>, a: &Bignum<M>, b: D) where D: Digit, M: DigitVec<D> {
    let digit_bits = <D as Digit>::bits();

    let old_len = out.data.len();
    out.data.clear();
    unsafe {
        out.data.grow_uninit(a.data.len());
        out.pos = a.pos;
        let mut w: <D as Digit>::Word = Int::zero();
        let mut x: usize = 0;
        while x < a.data.len() {
            w = a.data[x].to_word() * b.to_word() + w;
            out.data[x] = w.to_digit();
            w = w >> digit_bits;
            x += 1;
        }
        if w != Int::zero() && a.data.len() < a.data.capacity() {
            let tmp = out.data.len();
            out.data.grow_uninit(1);
            out.data[tmp] = w.to_digit();
            x += 1;
        }
        while x < old_len {
            out.data[x] = Int::zero();
            x += 1;
        }
        clamp(out);
    }
}

pub fn lsh_digits<D, M>(a: &mut Bignum<M>, x: usize) where D: Digit, M: DigitVec<D> {
    // move up and truncate as required
    let old_len = a.data.len();
    let new_len = cmp::min(old_len + x, a.data.capacity());

    unsafe {
        // set new size
        a.data.grow_uninit(new_len - old_len);

        // move digits
        for i in range(x, new_len).rev() {
            a.data[i] = a.data[i - x];
        }

        // zero lower digits
        for i in range(0, x) {
            a.data[i] = Int::zero();
        }
    }

    clamp(a);
}

pub fn rsh_digits<D, M>(a: &mut Bignum<M>, x: usize) where D: Digit, M: DigitVec<D> {
    // too many digits just zero and return
    if x > a.data.len() {
        zero(a);
        return;
    }

    // shift
    for y in range(0, a.data.len() - x) {
        a.data[y] = a.data[y + x];
    }

    // zero rest
    for y in range(0, a.data.len()) {
        a.data[y] = Int::zero();
    }

    // decrement count
    a.data.shrink(x);
    clamp(a);
}

pub fn count_bits<D, M>(a: &Bignum<M>) -> usize where D: Digit, M: DigitVec<D> {
    if a.data.len() == 0 {
        return 0;
    }

    let digit_bits = <D as Digit>::bits();

    // get number of digits and add that
    let mut r = (a.data.len() - 1) * digit_bits;

    // take the last digit and count the bits in it
    let mut q = a.data[a.data.len() - 1];
    while q > Int::zero() {
        r += 1;
        q = q >> 1;
    }

    r
}

// out = a mod 2**b
pub fn mod_2d<D, M>(out: &mut Bignum<M>, a: &Bignum<M>, b: usize) where D: Digit, M: DigitVec<D> {
    let digit_bits = <D as Digit>::bits();

    // zero if b is zero
    if b == 0 {
        zero(out);
        return;
    }

    copy(out, a);

    // if 2**b is larger then we just return
    if b > digit_bits * a.data.len() {
        return;
    }

    // zero digits above the last digit of the modulus
    let start = b / digit_bits + if b % digit_bits == 0 { 0 } else { 1 };
    for x in range(start, out.data.len()) {
        out.data[x] = Int::zero();
    }

    // clear the digit that is not completely outside/inside the modulus
    let zero: D = Int::zero();
    out.data[b / digit_bits] = out.data[b / digit_bits] & ((!zero) >> (digit_bits - b));

    clamp(out);
}

// (quotient, remainder) = a / 2**b
pub fn div_2d<D, M>(
        quotient: &mut Bignum<M>,
        remainder: Option<&mut Bignum<M>>,
        a: &Bignum<M>,
        b: usize) where D: Digit, M: DigitVec<D> {
    let digit_bits = <D as Digit>::bits();

    // if the shift count is == 0 then we do no work
    if b == 0 {
        copy(quotient, a);
        if let Some(r) = remainder {
            zero(r);
        }
        return;
    }

    let mut t: Bignum<M> = Bignum::new();

    // get the remainder
    if let Some(r) = remainder {
        mod_2d(&mut t, a, b);
    }

    copy(quotient, a);

    // shift by as many digits in the bit count
    if b >= digit_bits {
        rsh_digits(quotient, b / digit_bits);
    }

    // shift any bit count < digit_bits
    let D: usize = b % digit_bits;
    if D != 0 {
        let one: D = Int::one();
        let mask: D = (one << D) - Int::one();
        let shift = digit_bits - D;
        let mut tmpi = quotient.data.len() - 1;
        let mut r: D = Int::zero();
        for x in range(0, quotient.data.len()).rev() {
            let rr = quotient.data[tmpi] & mask;
            quotient.data[tmpi] = (quotient.data[tmpi] >> D) | (r << shift);
            tmpi -= 1;
            r = rr;
        }
    }

    clamp(quotient);
}

fn is_power_of_two<D>(b: D) -> (bool, Option<usize>) where D: Digit {
    // fast return if no power of two
    if b == Int::zero() || (b & (b - Int::one()) != Int::zero()) {
        return (false, None);
    }

    let digit_bits = <D as Digit>::bits();
    for x in (0..digit_bits) {
        let one: D = Int::one();
        if b == one << x {
            return (true, Some(x));
        }
    }
    return (false, None);
}

pub fn div_d<D, M, O>(
        quotient: Option<&mut Bignum<M>>,
        remainder: Option<&mut D>,
        a: &Bignum<M>,
        b: D,
        ops: O) where D: Digit, M: DigitVec<D>, O: Ops<D, M> { 
    // cannot divide by zero
    if b == Int::zero() {
        panic!("Divide by 0");
    }

    // quick outs
    if b == Int::one() || is_zero(a) {
        if let Some(rem) = remainder {
            *rem = Int::zero();
        }
        if let Some(quot) = quotient {
            copy(quot, a);
        }
        return;
    }

    // power of two ?
    let result = is_power_of_two(b);

    let digit_bits = <D as Digit>::bits();

    if let (true, Some(pos)) = result {
        // power of two
        if let Some(rem) = remainder {
            let one: D = Int::one();
            *rem = a.data[0] & ((one << pos) - one);
        }
        if let Some(quot) = quotient {
            div_2d(quot, None, a, pos);
        }
    } else {
        // not a power of is_power_of_two
        // no easy answer (c'est la vie).  Just division
        let mut q: Bignum<M> = Bignum::new();
        unsafe {
            q.data.grow_uninit(a.data.len());
            q.pos = a.pos;

            let mut w: <D as Digit>::Word = Int::zero();
            let mut t: D;
            for ix in (0..a.data.len()).rev() {
                w = (w << digit_bits) | a.data[ix].to_word();
                let mut t: D;
                if w >= b.to_word() {
                    t = (w / b.to_word()).to_digit();
                    w = w - t.to_word() * b.to_word();
                } else {
                    t = Int::zero();
                }
                q.data[ix] = t;
            }

            if let Some(rem) = remainder {
                *rem = w.to_digit();
            }
            if let Some(quot) = quotient {
                clamp(&mut q);
                copy(quot, &q);
            }
        }
    }
}

pub fn div_rem<D, M, O>(
        quotient: Option<&mut Bignum<M>>,
        remainder: Option<&mut Bignum<M>>,
        a: &Bignum<M>,
        b: &Bignum<M>,
        ops: O)
        where D: Digit, M: DigitVec<D>, O: Ops<D, M> {
    if is_zero(b) {
        panic!("Divide by 0");
    }

    // if a < b, then q = 0, r = a
    if cmp_mag(a, b) < 0 {
        if let Some(r) = remainder {
            copy(r, a);
        }
        if let Some(quot) = quotient {
            zero(quot);
        }
        return;
    }

    let digit_bits = <D as Digit>::bits();

    let neg = a.pos == b.pos;

    // temporary needed because most functions take distinct input and
    // output parameters. Making one of the inputs also an output might
    // allow for this to be eliminated.
    let mut tmp: Bignum<M> = Bignum::new();

    let mut t1: Bignum<M> = Bignum::new();
    let mut t2: Bignum<M> = Bignum::new();

    let mut q: Bignum<M> = Bignum::new();

    unsafe {
        q.data.grow_uninit(a.data.len() + 2);

        let mut x: Bignum<M> = Bignum::new();
        copy(&mut x, a);

        let mut y: Bignum<M> = Bignum::new();
        copy(&mut y, b);

        // fix the sign
        x.pos = true;
        y.pos = true;

        // normalize both x and y, ensure that y >= b/2, [b == 2**digit_bits]
        let norm = {
            let mut norm = count_bits(&y) % digit_bits;
            if norm < digit_bits - 1 {
                norm = (digit_bits - 1) - norm;
                mul_2d(&mut x, norm);
                mul_2d(&mut y, norm);
                norm
            } else {
                0
            }
        };

        // note hac does 0 based, so if used==5 then its 0,1,2,3,4, e.g. use 4
        let n = y.data.len() - 1;
        let t = y.data.len() - 1;

        lsh_digits(&mut y, n - t);

        while cmp(&x, &y) != -1 {
            q.data[n - t] = q.data[n - t] + Int::one();
            copy(&mut tmp, &x);
            sub(&mut x, &tmp, &y, ops);
        }

        // reset y by shifting it back down
        rsh_digits(&mut y, n - t);

        // step 3. for i from n down to (t + 1)
        for i in (t + 1 .. n + 1).rev() {
            if i > x.data.len() {
                continue;
            }

            /* step 3.1 if xi == yt then set q{i-t-1} to b-1,
            * otherwise set q{i-t-1} to (xi*b + x{i-1})/yt */
            if x.data[i] == y.data[i] {
                let zero: D = Int::zero();
                q.data[i - t - 1] = !zero;
            } else {
                let mut tmpword = x.data[i].to_word() << digit_bits;
                tmpword = tmpword | x.data[i - 1].to_word();
                tmpword = tmpword / y.data[t].to_word();
                q.data[i - t - 1] = tmpword.to_digit();
            }

            /* while (q{i-t-1} * (yt * b + y{t-1})) >
                    xi * b**2 + xi-1 * b + xi-2

            do q{i-t-1} -= 1;
            */
            q.data[i - t - 1] = q.data[i - t - 1] + Int::one();
            loop {
                q.data[i - t - 1] = q.data[i - t - 1] - Int::one();

                // find left hand
                zero(&mut t1);
                t1.data.grow_uninit(2);
                t1.data[0] = if t - 1 < 0 { Int::zero() } else { y.data[t - 1] };
                t1.data[1] = y.data[t];
                copy(&mut tmp, &t1);
                mul_d(&mut t1, &tmp, q.data[i - t - 1]);

                // find right hand
                zero(&mut t2);
                t2.data.grow_uninit(3);
                t2.data[0] = if i - 2 < 0 { Int::zero() } else { x.data[i - 2] };
                t2.data[1] = if i - 1 < 0 { Int::zero() } else { x.data[i - 1] };
                t2.data[2] = x.data[i];

                if cmp_mag(&t1, &t2) <= 0 {
                    break;
                }
            }

            // step 3.3 x = x - q{i-t-1} * y * b**{i-t-1}
            mul_d(&mut t1, &y, q.data[i - t - 1]);
            lsh_digits(&mut t1, i - t - 1);
            copy(&mut tmp, &x);
            sub(&mut x, &tmp, &t1, ops);

            // if x < 0 then { x = x + y*b**{i-t-1}; q{i-t-1} -= 1; }
            if !x.pos {
                copy(&mut t1, &y);
                lsh_digits(&mut t1, i - t - 1);
                copy(&mut tmp, &x);
                add(&mut x, &tmp, &t1, ops);
                q.data[i - t - 1] = q.data[i - t - 1] - Int::one();
            }
        }


        // now q is the quotient and x is the remainder (which we have to normalize)

        // get sign before writing to c
        x.pos = if x.data.len() == 0 { true } else { a.pos };

        if let Some(quot) = quotient {
            clamp(&mut q);
            copy(quot, &q);
            quot.pos = neg;
        }

        if let Some(rem) = remainder {
            copy(&mut tmp, &x);
            div_2d(&mut x, None, &tmp, norm);

            // the following is a kludge, essentially we were seeing the right remainder but
            // with excess digits that should have been zero
            for i in (b.data.len() .. x.data.len()) {
                x.data[i] = Int::zero();
            }
            clamp(&mut x);
            copy(rem, &x);
        }
    }
}

const radix_digits: &'static str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";

pub fn read_radix<D, M, O>(out: &mut Bignum<M>, text: &str, radix: usize, ops: O)
        where D: Digit, M: DigitVec<D>, O: Ops<D, M> {
    zero(out);

    // make sure the radix is ok
    if radix < 2 || radix > 64 {
        panic!("Invalid radix");
    }

    let mut chars = text.bytes().peekable();

    // if the leading digit is a minus set the sign to negative
    let sign = if let Some(&next) = chars.peek() {
        if next == '-' as u8 {
            chars.next();
            false
        } else {
            true
        }
    } else {
        true
    };

    let mut tmp: Bignum<M> = Bignum::new();

    // process each digit of the string
    for c in chars {
        // if the radix <= 36 the conversion is case insensitive
        // this allows numbers like 1AB and 1ab to represent the same value
        // (e.g. in hex)
        let c = if radix <= 36 { (c as char).to_uppercase() as u8 } else { c };

        let y = if let Some(pos) = radix_digits.bytes().position(|d| d == c) {
            pos
        } else {
            panic!("Invalid digit");
        };

        // if the char was found in the map
        // and is less than the given radix add it
        // to the number, otherwise exit the loop.
        copy(&mut tmp, out);
        mul_d(out, &tmp, Digit::from_byte(radix as u8));
        copy(&mut tmp, out);
        add_d(out, &tmp, Digit::from_byte(y as u8), ops);
    }

    // set the sign only if a != 0
    if !is_zero(out) {
        out.pos = sign;
    }
}

pub fn to_radix<D, M, O>(a: &Bignum<M>, radix: u8, ops: O) -> String
        where D: Digit, M: DigitVec<D>, O: Ops<D, M> {
    // check range of the radix
    if radix < 2 || radix > 64 {
        panic!("Invalid radix");
    }

    let mut result: String = String::new();

    // quick out if its zero
    if is_zero(a) {
        result.push('0');
        return result;
    }

    let mut t: Bignum<M> = Bignum::new();
    copy(&mut t, a);

    // if it is negative output a -
    if !t.pos {
        result.push('-');
        t.pos = true;
    }

    let mut d: D = Int::zero();
    let mut tmp: Bignum<M> = Bignum::new();
    while !is_zero(&t) {
        // println!("{:?}", &t);
        copy(&mut tmp, &t);
        div_d(Some(&mut t), Some(&mut d), &tmp, Digit::from_byte(radix), ops);
        // println!("{:?}", &t);
        // println!("{:?}", d);
        result.push(radix_digits.as_bytes()[d.to_byte() as usize] as char);
    }

    // reverse the string
    unsafe {
        result.as_mut_vec()[if a.pos { 0 } else { 1 }..].reverse()
    };

    result
}

// c = a mod b, 0 <= c < b
pub fn _mod<D, M, O>(out: &mut Bignum<M>, a: &Bignum<M>, b: &Bignum<M>, ops: O)
        where D: Digit, M: DigitVec<D>, O: Ops<D, M> {
    let mut t: Bignum<M> = Bignum::new();
    div_rem(None, Some(&mut t), a, b, ops);
    if t.pos != b.pos {
        add(out, &t, b, ops);
    } else {
        copy(out, &t);
    }
}

// d = a * b (mod c)
pub fn mulmod<D, M, O>(out: &mut Bignum<M>, a: &Bignum<M>, b: &Bignum<M>, c: &Bignum<M>, ops: O)
        where D: Digit, M: DigitVec<D>, O: Ops<D, M> {
    let mut tmp: Bignum<M> = Bignum::new();
    mul(&mut tmp, a, b, ops);
    _mod(out, &tmp, c, ops);
}

// generic comba squarer
pub fn sqr<D, M, O>(out: &mut Bignum<M>, a: &Bignum<M>, ops: O)
        where D: Digit, M: DigitVec<D>, O: Ops<D, M> {
    // get size of output and trim
    let pa = a.data.len() * 2;
    let pa = if pa >= a.data.capacity() {
        a.data.capacity() - 1
    } else {
        pa
    };

    let mut c0: D = Int::zero();
    let mut c1: D = Int::zero();
    let mut c2: D = Int::zero();

    unsafe {
        zero(out);
        out.data.grow_uninit(pa);

        for ix in (0..pa) {
            // get offsets into the two bignums
            let ty = cmp::min(a.data.len() - 1, ix);
            let tx = ix - ty;

            // setup temp aliases
            let mut tmpx = a.data.as_ptr().offset(tx as isize);
            let mut tmpy = a.data.as_ptr().offset(ty as isize);

            // this is the number of times the loop will iterrate:
            // while tx++ < a->used && ty-- >= 0 { ... }
            let mut iy = cmp::min(a.data.len() - tx, ty + 1);

            // now for squaring tx can never equal ty
            // we halve the distance since they approach
            // at a rate of 2x and we have to round because
            // odd cases need to be executed
            iy = cmp::min(iy, (ty - tx + 1) >> 1);

            // forward carries
            c0 = c1;
            c1 = c2;
            c2 = Int::zero();

            // execute loop
            for iz in (0..iy) {
                let (_c0, _c1, _c2) = ops.sqradd2(*tmpx, *tmpy, c0, c1, c2);
                c0 = _c0;
                c1 = _c1;
                c2 = _c2;
                tmpx = tmpx.offset(1);
                tmpy = tmpy.offset(-1);
            }

            // even columns have the square term in them
            if ix % 2 == 0 {
                let (_c0, _c1, _c2) = ops.sqradd(a.data[ix / 2], a.data[ix / 2], c0, c1, c2);
                c0 = _c0;
                c1 = _c1;
                c2 = _c2;
            }

            // store it
            out.data[ix] = c0;
        }
    }

    clamp(out);
}

// setup the montgomery reduction
pub fn montgomery_setup<D, M, O>(a: &mut Bignum<M>, rho: &mut D, ops: O)
        where D: Digit, M: DigitVec<D>, O: Ops<D, M> {
    let digit_bits = <D as Digit>::bits();

    let one: D = Int::one();
    let two: D = one + one;
    let four: D = two + two;

    /* fast inversion mod 2**k
    *
    * Based on the fact that
    *
    * XA = 1 (mod 2**n)  =>  (X(2-XA)) A = 1 (mod 2**2n)
    *                    =>  2*X*A - X*X*A*A = 1
    *                    =>  2*(1) - (1)     = 1
    */
    let b = a.data[0];

    if b % two == Int::zero() {
        panic!("Invalid value");
    }

    // here x * a == 1 mod 2**4
    let mut x = (((b + two) & four) << 1) + b;

    // here x * a == 1 mod 2**8
    x = x * (two - b * x);

    // here x * a == 1 mod 2**16
    if digit_bits >= 16 {
        x = x * (two - b * x);
    }
    // here x * a == 1 mod 2**32
    if digit_bits >= 32 {
        x = x * (two - b * x);
    }
    // here x * a == 1 mod 2**64
    if digit_bits == 64 {
        x = x * (two - b * x);
    }
    if digit_bits > 64 {
        panic!("Can't handle digits bigger than 64 bits");
    }

    *rho = ((one.to_word() << digit_bits) - x.to_word()).to_digit();
}

// computes a = 2**b
pub fn twoexpt<D, M>(out: &mut Bignum<M>, b: usize) where D: Digit, M: DigitVec<D> {
    let digit_bits = <D as Digit>::bits();

    // zero a as per default
    zero(out);

    let z = b / digit_bits;
    if z >= digit_bits {
        return;
    }

    unsafe {
        // set the used count of where the bit will go
        out.data.grow_uninit(z + 1);

        for x in out.data.iter_mut().take(z) {
            *x = Int::zero();
        }

        // put the single bit in its place
        let one: D = Int::one();
        out.data[z] = one << (b % digit_bits);
    }
}

// out = 2 * b
pub fn mul_2<D, M>(a: &mut Bignum<M>) where D: Digit, M: DigitVec<D> {
    let digit_bits = <D as Digit>::bits();

    let mut carry: D = Int::zero();
    for digit in a.data[..].iter_mut() {
        let next_carry = *digit >> (digit_bits - 1);
        *digit = (*digit << 1) | carry;
        carry = next_carry;
    }
    if carry != Int::zero() {
        a.data.push(carry);
    }
}

pub fn set<D, M>(out: &mut Bignum<M>, d: D) where D: Digit, M: DigitVec<D> {
    out.pos = true;
    out.data.clear();
    out.data.push(d);
}

// computes a = B**n mod b without division or multiplication useful for
// normalizing numbers in a Montgomery system.
pub fn montgomery_calc_normalization<D, M, O>(a: &mut Bignum<M>, b: &Bignum<M>, ops: O)
        where D: Digit, M: DigitVec<D>, O: Ops<D, M> {
    let digit_bits = <D as Digit>::bits();

    // how many bits of last digit does b use
    let mut bits = count_bits(b) % digit_bits;
    if bits == 0 {
        bits = digit_bits;
    }

    // compute A = B^(n-1) * 2^(bits-1)
    if b.data.len() > 1 {
        twoexpt(a, (b.data.len() - 1) * digit_bits + bits - 1);
    } else {
        set(a, Int::one());
        bits = 1;
    }

    // now compute C = A * B mod b
    for x in (bits - 1..digit_bits) {
        mul_2(a);
        if cmp_mag(a, b) >= 0 {
            let mut tmp: Bignum<M> = Bignum::new();
            copy(&mut tmp, a);
            ops.unsigned_sub(a, &tmp, b);
        }
    }
}

// computes x/R == x (mod N) via Montgomery Reduction
pub fn montgomery_reduce<D, M, O>(a: &mut Bignum<M>, m: &Bignum<M>, mp: D, ops: O)
        where D: Digit, M: DigitVec<D>, O: Ops<D, M> {
    // bail if too large
    if m.data.len() > m.data.capacity() / 2 {
        panic!("Too large");
    }

    let c: Bignum<M> = Bignum::new();

    let mut pa = m.data.len();

    // copy the input
    let oldused = a.data.len();
    unsafe {
        c.data.grow_uninit(a.data.len());
        for (c_x, &a_x) in c.data.iter_mut().zip(a.data.iter()) {
            *c_x = a_x;
        }
    }

    for x in (0..pa) {
        let mut cy: D = 0;
        // get Mu for this round
        let mut mu = c.data[x] * mp;
        //  _

    }
}

/*
#define INNERMUL                                      \
   do { fp_word t;                                    \
   _c[0] = t  = ((fp_word)_c[0] + (fp_word)cy) +      \
                (((fp_word)mu) * ((fp_word)*tmpm++)); \
   cy = (t >> DIGIT_BIT);                             \
   } while (0)

#define PROPCARRY \
   do { fp_digit t = _c[0] += cy; cy = (t < cy); } while (0)

#endif

/* computes x/R == x (mod N) via Montgomery Reduction */
void fp_montgomery_reduce(fp_int *a, fp_int *m, fp_digit mp)
{
   fp_digit c[FP_SIZE], *_c, *tmpm, mu;
   int      oldused, x, y, pa;

   /* bail if too large */
   if (m->used > (FP_SIZE/2)) {
      return;
   }

   /* now zero the buff */
   memset(c, 0, sizeof c);
   pa = m->used;

   /* copy the input */
   oldused = a->used;
   for (x = 0; x < oldused; x++) {
       c[x] = a->dp[x];
   }

   for (x = 0; x < pa; x++) {
       fp_digit cy = 0;
       /* get Mu for this round */
#define LOOP_START \
   mu = c[x] * mp

       LOOP_START;
       _c   = c + x;
       tmpm = m->dp;
       y = 0;

       for (; y < pa; y++) {
          INNERMUL;
          ++_c;
       }
       while (cy) {
           PROPCARRY;
           ++_c;
       }
  }

  /* now copy out */
  _c   = c + pa;
  tmpm = a->dp;
  for (x = 0; x < pa+1; x++) {
     *tmpm++ = *_c++;
  }

  for (; x < oldused; x++)   {
     *tmpm++ = 0;
  }

  a->used = pa+1;
  fp_clamp(a);

  /* if A >= m then A = A - m */
  if (fp_cmp_mag (a, m) != FP_LT) {
    s_fp_sub (a, m, a);
  }
}
*/


/*

/* ISO C code */
#define LOOP_START \
   mu = c[x] * mp

#define INNERMUL                                      \
   do { fp_word t;                                    \
   _c[0] = t  = ((fp_word)_c[0] + (fp_word)cy) +      \
                (((fp_word)mu) * ((fp_word)*tmpm++)); \
   cy = (t >> DIGIT_BIT);                             \
   } while (0)

#define PROPCARRY \
   do { fp_digit t = _c[0] += cy; cy = (t < cy); } while (0)

/* computes x/R == x (mod N) via Montgomery Reduction */
void fp_montgomery_reduce(fp_int *a, fp_int *m, fp_digit mp)
{
   fp_digit c[FP_SIZE], *_c, *tmpm, mu;
   int      oldused, x, y, pa;

    ...

   for (x = 0; x < pa; x++) {
       fp_digit cy = 0;
       /* get Mu for this round */
       LOOP_START;
       _c   = c + x;
       tmpm = m->dp;
       y = 0;

       for (; y < pa; y++) {
          INNERMUL;
          ++_c;
       }
       while (cy) {
           PROPCARRY;
           ++_c;
       }
  }

  /* now copy out */
  _c   = c + pa;
  tmpm = a->dp;
  for (x = 0; x < pa+1; x++) {
     *tmpm++ = *_c++;
  }

  for (; x < oldused; x++)   {
     *tmpm++ = 0;
  }

  a->used = pa+1;
  fp_clamp(a);

  /* if A >= m then A = A - m */
  if (fp_cmp_mag (a, m) != FP_LT) {
    s_fp_sub (a, m, a);
  }
}

*/





fn main() {
//    let a: Bignum<DataU16x100> = Bignum::new();
//    let b: Bignum<DataU16x100> = Bignum::new();
//    let mut x: Bignum<DataU16x100> = Bignum::new();
//
//    add(&mut x, &a, &b, GenericOps);

    type BN = Bignum<DataU16x100>;

    let mut a: BN = Bignum::new();
    let mut b: BN = Bignum::new();
    let mut r: BN = Bignum::new();

    read_radix(&mut a, "33000", 10, GenericOps);
    // read_radix(&mut b, "19", 10, GenericOps);

    // mul(&mut r, &a, &b, GenericOps);
    // sqr(&mut r, &a, GenericOps);
    mul_2(&mut a);

    let result = to_radix(&a, 10, GenericOps);
    println!("Result: {}", &result[..]);
}

#[cfg(test)]
mod test {
    use super::*;

    use std::str::FromStr;
    use std::rand::IsaacRng;
    use std::rand::Rng;

    use num::BigInt;

    fn mul_bignum(a_str: &str, b_str: &str) -> String {
        type BN = Bignum<DataU8x200>;

        let mut a: BN = Bignum::new();
        let mut b: BN = Bignum::new();
        let mut r: BN = Bignum::new();

        read_radix(&mut a, a_str, 10, GenericOps);
        read_radix(&mut b, b_str, 10, GenericOps);

        mul(&mut r, &a, &b, GenericOps);
        println!("r: {:?}", r);

        let result = to_radix(&r, 10, GenericOps);
        result
    }

    fn mul_bigint(a_str: &str, b_str: &str) -> String {
        let a: BigInt = FromStr::from_str(a_str).unwrap();
        let b: BigInt = FromStr::from_str(b_str).unwrap();
        let c = a * b;
        format!("{}", c)
    }

    #[test]
    fn test1() {
        let mut rng = IsaacRng::new_unseeded();
        let mut a = String::new();
        let mut b = String::new();
        for _ in (0..100) {
            a.clear();
            b.clear();
            for _ in (0..100) {
                a.push(('0' as u8 + rng.gen_range(0, 10)) as char);
                b.push(('0' as u8 + rng.gen_range(0, 10)) as char);
                println!("{} * {}", a, b);
                let bigint_result = mul_bigint(&a[..], &b[..]);
                let bignum_result = mul_bignum(&a[..], &b[..]);
                println!("bigint: {}", bigint_result);
                println!("bignum: {}", bignum_result);
                assert!(bigint_result == bignum_result);
            }
        }
    }
}
