// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::mem;

use super::Bignum;
use super::Digit;

pub fn read_str(out: &mut Bignum, v: &str) -> bool {
    out.dp.clear();

    let mut it = v.chars().peekable();

    let positive = if it.peek() == Some(&'-') {
        it.next();
        false
    } else {
        true
    };

    let mut tmp1 = Bignum::new();
    let mut tmp2 = Bignum::new();
    let base10 = Bignum::new_d(10);

    for c in it {
        if c < '0' || c > '9' {
            return false;
        }
        let d = ((c as Digit) - ('0' as Digit));

        tmp1.set_mul(out, &base10);
        tmp2.set_d(d);
        out.set_add(&tmp1, &tmp2);
    }

    if !out.is_zero() {
        out.positive = positive;
    }
    true
}

pub fn to_str(v: &Bignum) -> String {
    let mut out = String::new();
    if v.is_zero() {
        out.push_char('0');
        return out;
    }

    let positive = v.positive;

    let mut v = v.clone();
    let mut q = Bignum::new();
    let mut r = Bignum::new();
    let base10 = Bignum::new_d(10);

    while !v.is_zero() {
        super::div_rem(Some(&mut q), Some(&mut r), &v, &base10);
        let d = if r.is_zero() { 0 } else { r.dp[0] };
        out.push_char((('0' as uint) + (d as uint)) as u8 as char);
        mem::swap(&mut v, &mut q);
    }

    if !positive {
        out.push_char('-');
    }

    unsafe {
        out.as_mut_bytes().reverse();
    }

    out
}

/*
int fp_toradix(fp_int *a, char *str, int radix)
{
  int     digs;
  fp_int  t;
  fp_digit d;
  char   *_s = str;

  /* check range of the radix */
  if (radix < 2 || radix > 64) {
    return FP_VAL;
  }

  /* quick out if its zero */
  if (fp_iszero(a) == 1) {
     *str++ = '0';
     *str = '\0';
     return FP_OKAY;
  }

  fp_init_copy(&t, a);

  /* if it is negative output a - */
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

  /* reverse the digits of the string.  In this case _s points
   * to the first digit [exluding the sign] of the number]
   */
  fp_reverse ((unsigned char *)_s, digs);

  /* append a NULL so the string is properly terminated */
  *str = '\0';
  return FP_OKAY;
}
*/