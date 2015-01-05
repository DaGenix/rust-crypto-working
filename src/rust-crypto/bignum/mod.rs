// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::ops::{Index, IndexMut, Slice, SliceMut, Add, Sub, Mul, Shl, Shr};
use std::{cmp, mem, ptr};
use std::num::Int;

// Must by Copy so that we can do byte copies
pub trait Digit: Int + Copy {
    type Word: WordOps<Self>;

    fn as_word(self) -> Self::Word;
    fn bits(self) -> uint;
}

// Must by Copy so that we can do byte copies
pub trait WordOps<D>: Int + Copy {
    fn shift_digit_right(self) -> Self;
    fn as_digit(self) -> D;
}

// Helper functions to call WordOps methods since it looks
// like a Rust bug is preventing method syntax from working.
fn as_digit<D, W: WordOps<D>>(w: W) -> D { w.as_digit() }
fn shift_digit_right<D, W: WordOps<D>>(w: W) -> W { w.shift_digit_right() }

fn bits<T>() -> uint {
    mem::size_of::<T>() * 8
}

impl Digit for u16 {
    type Word = u32;

    fn as_word(self) -> u32 { self as u32 }
    fn bits(self) -> uint { 16 }
}

impl WordOps<u16> for u32 {
    fn shift_digit_right(self) -> u32 { self >> 16 }
    fn as_digit(self) -> u16 { self as u16 }
}

pub trait Data<T>: Index<uint, Output=T> + IndexMut<uint, Output=T> + Slice<uint, [T]> + SliceMut<uint, [T]> {
    fn new() -> Self;
    fn len(&self) -> uint;
    fn capacity(&self) -> uint;
    fn clear(&mut self);
    unsafe fn grow_uninit(&mut self, additional: uint);
    fn shrink(&mut self, ammount: uint);
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

        impl Index<uint> for $name {
            type Output = $ty;

            fn index(&self, index: &uint) -> &$ty { &self.data[*index] }
        }

        impl IndexMut<uint> for $name {
            type Output = $ty;

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

            fn capacity(&self) -> uint { $size }

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

            fn shrink(&mut self, ammount: uint) {
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
    }
);

bignum_data!(DataU16x100, u16, 100);

pub struct Bignum<T> {
    pub pos: bool,
    pub data: T
}

impl <D, M> Bignum<M>
        where D: Digit, M: Data<D> {
    pub fn new() -> Bignum<M> {
        Bignum {
            pos: true,
            data: Data::new()
        }
    }
}

pub fn clamp<D, M>(x: &mut Bignum<M>)
        where D: Digit, M: Data<D> {
    while x.data[].last().map_or(false, |&tmp| tmp == Int::zero()) {
        x.data.pop();
    }
    if x.data.is_empty() {
        x.pos = true;
    }
}


pub trait Ops<D, M>: Copy {
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

impl <D, M> Ops<D, M> for GenericOps
        where
            D: Digit,
            <D as Digit>::Word: Add<Output = <D as Digit>::Word>,
            <D as Digit>::Word: Sub<Output = <D as Digit>::Word>,
            <D as Digit>::Word: Mul<Output = <D as Digit>::Word>,
            M: Data<D> {
    fn unsigned_add(&self, out: &mut Bignum<M>, a: &Bignum<M>, b: &Bignum<M>) {
        out.data.clear();
        let mut t: <D as Digit>::Word = Int::zero();
        for (&tmpa, &tmpb) in zip_with_default(&Int::zero(), a.data[].iter(), b.data[].iter()) {
            t = t + tmpa.as_word() + tmpb.as_word();
            out.data.push(as_digit(t));
            t = shift_digit_right(t);
        }
        if t != Int::zero() {
            out.data.push(as_digit(t));
        }
        clamp(out);
    }

    /// out = a - b; abs(a) >= abs(b)
    fn unsigned_sub(&self, out: &mut Bignum<M>, a: &Bignum<M>, b: &Bignum<M>) {
        out.data.clear();
        let mut t: <D as Digit>::Word = Int::zero();
        let mut a_iter = a.data[].iter();
        for (&tmpa, &tmpb) in a_iter.by_ref().zip(b.data[].iter()) {
            t = tmpa.as_word() - tmpb.as_word() + t;
            out.data.push(as_digit(t));
            t = shift_digit_right(t);
        }
        for &tmpa in a_iter {
            t = tmpa.as_word() - t;
            out.data.push(as_digit(t));
            t = shift_digit_right(t);
        }
        clamp(out);
    }

    fn muladd(&self, i: D, j: D, mut c0: D, mut c1: D, mut c2: D) -> (D, D, D) {
        let mut t: <D as Digit>::Word;
        t = c0.as_word() + i.as_word() * j.as_word();
        c0 = as_digit(t);
        t = c1.as_word() + shift_digit_right(t);
        c1 = as_digit(t);
        c2 = c2 + as_digit(shift_digit_right(t));
        (c0, c1, c2)
    }
}

fn copy<D, M>(x: &mut Bignum<M>, a: &Bignum<M>) where D: Digit, M: Data<D> {
    x.data.clear();
    unsafe {
        x.data.grow_uninit(a.data.len());
        ptr::copy_nonoverlapping_memory(
            (&mut *x.data[]).as_mut_ptr(),
            a.data[].as_ptr(),
            a.data.len());
    }
    x.pos = a.pos;
}

fn is_zero<D, M>(a: &Bignum<M>) -> bool
        where D: Digit, M: Data<D> {
    a.data.is_empty()
}

fn zero<D, M>(a: &mut Bignum<M>) where D: Digit, M: Data<D> {
    a.data.clear();
    a.pos = true;
}

/// Unsigned comparison
pub fn cmp_mag<D, M>(a: &Bignum<M>, b: &Bignum<M>) -> int
        where D: Digit, M: Data<D> {
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
pub fn cmp<D, M>(a: &Bignum<M>, b: &Bignum<M>) -> int
        where D: Digit, M: Data<D> {
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
        where D: Digit, M: Data<D>, O: Ops<D, M> {
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

pub fn sub<D, M, O>(out: &mut Bignum<M>, a: &Bignum<M>, b: &Bignum<M>, ops: O)
        where D: Digit, M: Data<D>, O: Ops<D, M> {
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
        where D: Digit, M: Data<D>, O: Ops<D, M> {
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

// x = a * 2**b
fn mul_2d<D, M>(out: &mut Bignum<M>, a: &Bignum<M>, mut b: uint) where D: Digit, M: Data<D> {
    copy(out, a);

    let digit_bits = bits::<D>();

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
fn mul_d<D, M>(out: &mut Bignum<M>, a: &Bignum<M>, b: D)
        where
            D: Digit,
            <D as Digit>::Word: Mul<Output = <D as Digit>::Word>,
            <D as Digit>::Word: Add<Output = <D as Digit>::Word>,
            <D as Digit>::Word: Shr<uint, Output = <D as Digit>::Word>,
            M: Data<D> {
    let digit_bits = bits::<D>();

    let old_len = out.data.len();
    out.data.clear();
    unsafe {
        out.data.grow_uninit(a.data.len());
        out.pos = a.pos;
        let mut w: <D as Digit>::Word = Int::zero();
        let mut x: uint = 0;
        while x < a.data.len() {
            w = a.data[x].as_word() * b.as_word() + w;
            out.data[x] = as_digit(w);
            w = w >> digit_bits;
            x += 1;
        }
        if w != Int::zero() && a.data.len() < a.data.capacity() {
            let tmp = out.data.len();
            out.data.grow_uninit(1);
            out.data[tmp] = as_digit(w);
            x += 1;
        }
        while x < old_len {
            out.data[x] = Int::zero();
            x += 1;
        }
        clamp(out);
    }
}

fn lsh_digits<D, M>(a: &mut Bignum<M>, x: uint) where D: Digit, M: Data<D> {
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

fn rsh_digits<D, M>(a: &mut Bignum<M>, x: uint) where D: Digit, M: Data<D> {
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

fn count_bits<D, M>(a: &Bignum<M>) -> uint where D: Digit, M: Data<D> {
    if a.data.len() == 0 {
        return 0;
    }

    let digit_bits = bits::<D>();

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
fn mod_2d<D, M>(out: &mut Bignum<M>, a: &Bignum<M>, b: uint) where D: Digit, M: Data<D> {
    let digit_bits = bits::<D>();

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
pub fn div_2d<D, M, O>(
        quotient: &mut Bignum<M>,
        remainder: Option<&mut Bignum<M>>,
        a: &Bignum<M>,
        b: uint)
        where D: Digit, M: Data<D>, O: Ops<D, M> {
    let digit_bits = bits::<D>();

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
    let D: uint = b % digit_bits;
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

pub fn div_rem<D, M, O>(
        quotient: Option<&mut Bignum<M>>,
        remainder: Option<&mut Bignum<M>>,
        a: &Bignum<M>,
        b: &Bignum<M>,
        ops: O)
        where D: Digit, M: Data<D>, O: Ops<D, M> {
    if is_zero(b) {
        panic!("Divide by 0");
    }

    // if a < b, then q = 0, r = a
    if cmp_mag(a, b) < 0 {
        if let Some(r) = remainder {
            copy(r, a);
        }
        if let Some(q) = quotient {
            zero(q);
        }
        return;
    }

    let digit_bits = bits::<D>();

    let neg = a.pos == b.pos;

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
        let norm = count_bits(&y) % digit_bits;


    }
/*
  fp_int  q, x, y, t1, t2;
  int     n, t, i, norm, neg;

  fp_init(&q);
  q.used = a->used + 2;

  fp_init(&t1);
  fp_init(&t2);
  fp_init_copy(&x, a);
  fp_init_copy(&y, b);

  /* fix the sign */
  neg = (a->sign == b->sign) ? FP_ZPOS : FP_NEG;
  x.sign = y.sign = FP_ZPOS;

  /* normalize both x and y, ensure that y >= b/2, [b == 2**DIGIT_BIT] */
  norm = fp_count_bits(&y) % DIGIT_BIT;
  if (norm < (int)(DIGIT_BIT-1)) {
     norm = (DIGIT_BIT-1) - norm;
     fp_mul_2d (&x, norm, &x);
     fp_mul_2d (&y, norm, &y);
  } else {
     norm = 0;
  }

  /* note hac does 0 based, so if used==5 then its 0,1,2,3,4, e.g. use 4 */
  n = x.used - 1;
  t = y.used - 1;

  /* while (x >= y*b**n-t) do { q[n-t] += 1; x -= y*b**{n-t} } */
  fp_lshd (&y, n - t);                                             /* y = y*b**{n-t} */

  while (fp_cmp (&x, &y) != FP_LT) {
    ++(q.dp[n - t]);
    fp_sub (&x, &y, &x);
  }

  /* reset y by shifting it back down */
  fp_rshd (&y, n - t);

  /* step 3. for i from n down to (t + 1) */
  for (i = n; i >= (t + 1); i--) {
    if (i > x.used) {
      continue;
    }

    /* step 3.1 if xi == yt then set q{i-t-1} to b-1,
     * otherwise set q{i-t-1} to (xi*b + x{i-1})/yt */
    if (x.dp[i] == y.dp[t]) {
      q.dp[i - t - 1] = ((((fp_word)1) << DIGIT_BIT) - 1);
    } else {
      fp_word tmp;
      tmp = ((fp_word) x.dp[i]) << ((fp_word) DIGIT_BIT);
      tmp |= ((fp_word) x.dp[i - 1]);
      tmp /= ((fp_word) y.dp[t]);
      q.dp[i - t - 1] = (fp_digit) (tmp);
    }

    /* while (q{i-t-1} * (yt * b + y{t-1})) >
             xi * b**2 + xi-1 * b + xi-2

       do q{i-t-1} -= 1;
    */
    q.dp[i - t - 1] = (q.dp[i - t - 1] + 1);
    do {
      q.dp[i - t - 1] = (q.dp[i - t - 1] - 1);

      /* find left hand */
      fp_zero (&t1);
      t1.dp[0] = (t - 1 < 0) ? 0 : y.dp[t - 1];
      t1.dp[1] = y.dp[t];
      t1.used = 2;
      fp_mul_d (&t1, q.dp[i - t - 1], &t1);

      /* find right hand */
      t2.dp[0] = (i - 2 < 0) ? 0 : x.dp[i - 2];
      t2.dp[1] = (i - 1 < 0) ? 0 : x.dp[i - 1];
      t2.dp[2] = x.dp[i];
      t2.used = 3;
    } while (fp_cmp_mag(&t1, &t2) == FP_GT);

    /* step 3.3 x = x - q{i-t-1} * y * b**{i-t-1} */
    fp_mul_d (&y, q.dp[i - t - 1], &t1);
    fp_lshd  (&t1, i - t - 1);
    fp_sub   (&x, &t1, &x);

    /* if x < 0 then { x = x + y*b**{i-t-1}; q{i-t-1} -= 1; } */
    if (x.sign == FP_NEG) {
      fp_copy (&y, &t1);
      fp_lshd (&t1, i - t - 1);
      fp_add (&x, &t1, &x);
      q.dp[i - t - 1] = q.dp[i - t - 1] - 1;
    }
  }

  /* now q is the quotient and x is the remainder
   * [which we have to normalize]
   */

  /* get sign before writing to c */
  x.sign = x.used == 0 ? FP_ZPOS : a->sign;

  if (c != NULL) {
    fp_clamp (&q);
    fp_copy (&q, c);
    c->sign = neg;
  }

  if (d != NULL) {
    fp_div_2d (&x, norm, &x, NULL);

/* the following is a kludge, essentially we were seeing the right remainder but
   with excess digits that should have been zero
 */
    for (i = b->used; i < x.used; i++) {
        x.dp[i] = 0;
    }
    fp_clamp(&x);
    fp_copy (&x, d);
  }

  return FP_OKAY;
*/
}

fn test() {
    let a: Bignum<DataU16x100> = Bignum::new();
    let b: Bignum<DataU16x100> = Bignum::new();
    let mut x: Bignum<DataU16x100> = Bignum::new();

    add(&mut x, &a, &b, GenericOps);
}