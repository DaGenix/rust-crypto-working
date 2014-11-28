// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/*

use std::mem;
use std::u32;
use std::io;
use std::string;
use std::num;

use super::Bignum;
use super::Digit;
use super::Word;

// 10^0 ... 10^20
static base10powers: [u64, ..20] = [
    1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000, 10000000000,
    100000000000, 1000000000000, 10000000000000, 100000000000000, 1000000000000000,
    10000000000000000, 100000000000000000, 1000000000000000000, 10000000000000000000 ];

pub fn read_str(out: &mut Bignum, v: &str) -> bool {
    out.dp.clear();

    if v.len() == 0 {
        return false;
    }

    let positive: bool;
    let mut it = if v.chars().next() == Some('-') {
        positive = false;
        v.as_bytes().slice_from(1).chunks(9)
    } else {
        positive = true;
        v.as_bytes().chunks(9)
    };

    let mut tmp1 = Bignum::new();
    let mut tmp2 = Bignum::new();
    let mut base = Bignum::new();

    for c in it {
//        match u32::parse_bytes(c, 10) {
        match num::FromStrRadix::from_str_radix(c, 10) {
            Some(d) => {
                base.set_d(base10powers[c.len()] as Digit);
                tmp1.set_mul(out, &base);
                tmp2.set_d(d as Digit);
                out.set_add(&tmp1, &tmp2);
            }
            None => { return false; }
        }
    }

    if !out.is_zero() {
        out.positive = positive;
    }
    true
}

pub fn to_str(v: &Bignum) -> String {
//     let mut out = String::new();
    if v.is_zero() {
        return String::from_str("0");
//         out.push_char('0');
//         return out;
    }

    let positive = v.positive;

    let mut v = v.clone();
    let mut q = Bignum::new();
    let mut r = Bignum::new();
    let base10 = Bignum::new_d(100000000);

    let mut w = io::MemWriter::new();

    while !v.is_zero() {
        super::div_rem(Some(&mut q), Some(&mut r), &v, &base10);
        let d = if r.is_zero() { 0 } else { r.dp[0] };
        write!(&mut w as &mut io::Writer, "{}", d);

//         out.push_char((('0' as uint) + (d as uint)) as u8 as char);
        mem::swap(&mut v, &mut q);
    }

    if !positive {
        w.write(['-' as u8].as_slice());
    }

    let mut raw = w.unwrap();
    raw.reverse();
    for c in raw.as_mut_slice().mut_chunks(8) {
        c.reverse();
    }
    unsafe {
//         out.as_mut_bytes().reverse();
        string::raw::from_utf8(raw)
    }

//     out
}
*/

/*
int fp_toradix(fp_int *a, char *str, int radix)
{
  int     digs;
  fp_int  t;
  fp_digit d;
  char   *_s = str;

  // check range of the radix
  if (radix < 2 || radix > 64) {
    return FP_VAL;
  }

  // quick out if its zero
  if (fp_iszero(a) == 1) {
     *str++ = '0';
     *str = '\0';
     return FP_OKAY;
  }

  fp_init_copy(&t, a);

  // if it is negative output a -
  if (t.sign == FP_NEG) {
    ++_s;
    *str++ = '-';
    t.sign = FP_ZPOS;
  }

  digs = 0;
  while (fp_iszero (&t) == FP_NO) {
    fp_div_d (&t, (fp_digit) radix, &t, &d);
    *str++ = fp_s_rmap[d];
    ++digs;
  }

  // reverse the digits of the string.  In this case _s points
  // to the first digit [exluding the sign] of the number]
  fp_reverse ((unsigned char *)_s, digs);

  // append a NULL so the string is properly terminated
  *str = '\0';
  return FP_OKAY;
}
*/