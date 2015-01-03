// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::ops::{Index, IndexMut, Slice, SliceMut};
use std::mem;
use std::num::Int;
use std::cmp;

pub trait Digit<W>: Int {
    fn as_word(self) -> W;
}

pub trait Word<D>: Int {
    fn as_digit(self) -> D;
    fn shift_digit_right(self) -> Self;
}

/*
impl Digit<u64> for u32 {
    fn as_word(self) -> u64 { self as u64 }
    fn bits() -> uint { 32 }
}
*/

impl Digit<u32> for u16 {
    fn as_word(self) -> u32 { self as u32 }
}

/*
impl Word<u32> for u64 {
    fn as_digit(self) -> u32 { self as u32 }
}
*/

impl Word<u16> for u32 {
    fn as_digit(self) -> u16 { self as u16 }
    fn shift_digit_right(self) -> u32 { self >> 16 }
}

pub trait Data<T>: Index<uint, T> + IndexMut<uint, T> + Slice<uint, [T]> + SliceMut<uint, [T]> {
    fn new() -> Self;
    fn len(&self) -> uint;
    fn clear(&mut self);
    unsafe fn grow_uninit(&mut self, additional: uint);
    fn pop(&mut self);

    fn push(&mut self, val: T) {
        let old_len = self.len();
        unsafe {
            self.grow_uninit(1);
            self[old_len] = val;
        }
    }

    fn is_empty(&self) -> bool { self.len() == 0}

    fn as_ptr(&self) -> *const T;
    fn as_mut_ptr(&mut self) -> *mut T;
}

#[macro_export]
macro_rules! bignum_data(
    ($name:ident, $ty:ty, $size:expr) => {
        pub struct $name {
            len: uint,
            data: [$ty; $size]
        }

        impl Index<uint, $ty> for $name {
            fn index(&self, index: &uint) -> &$ty { &self.data[*index] }
        }

        impl IndexMut<uint, $ty> for $name {
            fn index_mut(&mut self, index: &uint) -> &mut $ty { &mut self.data[*index] }
        }

        impl Slice<uint, [$ty]> for $name {
            fn as_slice_(&self) -> &[$ty] { self.data[..self.len()] }
            fn slice_from_or_fail(&self, start: &uint) -> &[$ty] { self.data[*start..self.len()] }
            fn slice_to_or_fail(&self, end: &uint) -> &[$ty] {
                if *end > self.len() {
                    panic!("Out of bounds");
                }
                self.data[..*end]
            }
            fn slice_or_fail(&self, start: &uint, end: &uint) -> &[$ty] {
                if *end > self.len() {
                    panic!("Out of bounds");
                }
                self.data[*start..*end]
            }
        }

        impl SliceMut<uint, [$ty]> for $name {
            fn as_mut_slice_(&mut self) -> &mut [$ty] {
                let l = self.len();
                &mut *self.data[..l]
            }
            fn slice_from_or_fail_mut(&mut self, start: &uint) -> &mut [$ty] {
                let l = self.len();
                &mut *self.data[*start..l]
            }
            fn slice_to_or_fail_mut(&mut self, end: &uint) -> &mut [$ty] {
                if *end > self.len() {
                    panic!("Out of bounds");
                }
                &mut *self.data[..*end]
            }
            fn slice_or_fail_mut(&mut self, start: &uint, end: &uint) -> &mut [$ty] {
                if *end > self.len() {
                    panic!("Out of bounds");
                }
                &mut *self.data[*start..*end]
            }
        }

        impl Data<$ty> for $name {
            fn new() -> $name {
                $name {
                    len: 0,
                    data: unsafe { mem::uninitialized() }
                }
            }

            fn len(&self) -> uint { self.len }

            // fn capacity(&self) -> uint { $size }

            fn clear(&mut self) {
                self.len = 0;
            }

            fn pop(&mut self) {
                if self.len == 0 {
                    panic!("Can't pop empty data");
                }
                self.len -= 1;
            }

            unsafe fn grow_uninit(&mut self, additional: uint) {
                if self.len + additional > $size {
                    panic!("Size too big");
                }
                self.len += additional;
            }

            fn as_ptr(&self) -> *const $ty {
                self.data.as_ptr()
            }

            fn as_mut_ptr(&mut self) -> *mut $ty {
                self.data.as_mut_ptr()
            }
        }
    }
);

bignum_data!(DataU16x100, u16, 100);


pub struct Bignum<T> {
    pub pos: bool,
    pub data: T
}

impl <D, W, M> Bignum<M>
        where D: Digit<W>, W: Word<D>, M: Data<D> {

    pub fn new() -> Bignum<M> {
        Bignum {
            pos: true,
            data: Data::new()
        }
    }
}

pub fn clamp<D, W, M>(x: &mut Bignum<M>)
        where D: Digit<W>, W: Word<D>, M: Data<D> {
    while x.data[].last().map_or(false, |&tmp| tmp == Int::zero()) {
        x.data.pop();
    }
    if x.data.is_empty() {
        x.pos = true;
    }
}


pub trait Ops<D, W, M>: Copy {
    fn unsigned_add(&self, out: &mut Bignum<M>, a: &Bignum<M>, b: &Bignum<M>);
    fn unsigned_sub(&self, out: &mut Bignum<M>, a: &Bignum<M>, b: &Bignum<M>);
    fn muladd(&self, i: D, j: D, mut c0: D, mut c1: D, mut c2: D) -> (D, D, D);
}

#[derive(Copy)]
pub struct GenericOps;

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

impl <D, W, M> Ops<D, W, M> for GenericOps
        where D: Digit<W>, W: Word<D>, M: Data<D> {
    fn unsigned_add(&self, out: &mut Bignum<M>, a: &Bignum<M>, b: &Bignum<M>) {
        out.data.clear();
        let mut t: W = Int::zero();
        for (&tmpa, &tmpb) in zip_with_default(&Int::zero(), a.data[].iter(), b.data[].iter()) {
            t = t + tmpa.as_word() + tmpb.as_word();
            out.data.push(t.as_digit());
            t = t.shift_digit_right();
        }
        if t != Int::zero() {
            out.data.push(t.as_digit());
        }
        clamp(out);
    }

    /// out = a - b; abs(a) >= abs(b)
    fn unsigned_sub(&self, out: &mut Bignum<M>, a: &Bignum<M>, b: &Bignum<M>) {
        out.data.clear();
        let mut t: W = Int::zero();
        let mut a_iter = a.data[].iter();
        for (&tmpa, &tmpb) in a_iter.by_ref().zip(b.data[].iter()) {
            t = tmpa.as_word() - tmpb.as_word() + t;
            out.data.push(t.as_digit());
            t = t.shift_digit_right();
        }
        for &tmpa in a_iter {
            t = tmpa.as_word() - t;
            out.data.push(t.as_digit());
            t = t.shift_digit_right();
        }
        clamp(out);
    }

    fn muladd(&self, i: D, j: D, mut c0: D, mut c1: D, mut c2: D) -> (D, D, D) {
        let mut t: W;
        t = c0.as_word() + i.as_word() * j.as_word();
        c0 = t.as_digit();
        t = c1.as_word() + t.shift_digit_right();
        c1 = t.as_digit();
        c2 = c2 + t.shift_digit_right().as_digit();
        (c0, c1, c2)
    }
}

/// Unsigned comparison
pub fn cmp_mag<D, W, M>(a: &Bignum<M>, b: &Bignum<M>) -> int
        where D: Digit<W>, W: Word<D>, M: Data<D> {
    if a.data.len() > b.data.len() {
        return 1;
    } else if a.data.len() < b.data.len() {
        return -1;
    } else {
        for (&tmpa, &tmpb) in a.data[].iter().rev().zip(b.data[].iter().rev()) {
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
pub fn cmp<D, W, M>(a: &Bignum<M>, b: &Bignum<M>) -> int
        where D: Digit<W>, W: Word<D>, M: Data<D> {
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

pub fn add<D, W, M, O>(out: &mut Bignum<M>, a: &Bignum<M>, b: &Bignum<M>, ops: O)
        where D: Digit<W>, W: Word<D>, M: Data<D>, O: Ops<D, W, M> {
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

pub fn sub<D, W, M, O>(out: &mut Bignum<M>, a: &Bignum<M>, b: &Bignum<M>, ops: O)
        where D: Digit<W>, W: Word<D>, M: Data<D>, O: Ops<D, W, M> {
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

pub fn mul<D, W, M, O>(out: &mut Bignum<M>, a: &Bignum<M>, b: &Bignum<M>, ops: O)
        where D: Digit<W>, W: Word<D>, M: Data<D>, O: Ops<D, W, M> {
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

        let mut tmpx = unsafe { a.data.as_ptr().offset(tx as int) };
        let mut tmpy = unsafe { b.data.as_ptr().offset(ty as int) };
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

        unsafe { *out.data.as_mut_ptr().offset(ix as int) = c0; }
    }

    out.pos = a.pos == b.pos;

    clamp(out);
}

pub fn div<D, W, M, O>(out: &mut Bignum<M>, a: &Bignum<M>, b: &Bignum<M>, ops: O)
        where D: Digit<W>, W: Word<D>, M: Data<D>, O: Ops<D, W, M> {

}

fn test() {
    let a: Bignum<DataU16x100> = Bignum::new();
    let b: Bignum<DataU16x100> = Bignum::new();
    let mut x: Bignum<DataU16x100> = Bignum::new();

    add(&mut x, &a, &b, GenericOps);
}