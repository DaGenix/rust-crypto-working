// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![feature(asm)]
#![feature(macro_rules)]
#![feature(simd)]
#![feature(phase)]

#[phase(plugin, link)] extern crate log;

extern crate serialize;
extern crate test;

use digest::Digest;

pub mod aes;
pub mod aessafe;
pub mod bcrypt;
pub mod bcrypt_pbkdf;
pub mod blockmodes;
pub mod blowfish;
pub mod buffer;
pub mod chacha20;
mod cryptoutil;
pub mod digest;
pub mod hmac;
pub mod mac;
pub mod md5;
pub mod pbkdf2;
pub mod poly1305;
pub mod rc4;
pub mod salsa20;
pub mod scrypt;
pub mod sha1;
pub mod sha2;
pub mod symmetriccipher;
pub mod util;


    /// Feed 1,000,000 'a's into the digest with varying input sizes and check that the result is
    /// correct.
    fn test_digest_1million_random<D: Digest>(digest: &mut D, blocksize: uint, expected: &str) {
        use std::num::Bounded;

    use std::rand::IsaacRng;
    use std::rand::distributions::{IndependentSample, Range};

    use cryptoutil::{add_bytes_to_bits, add_bytes_to_bits_tuple, fixed_time_eq};

    
println!("0");
        let total_size = 1000000;
        let buffer = Vec::from_elem(blocksize * 2, 'a' as u8);
        let mut rng = IsaacRng::new_unseeded();
        let range = Range::new(0, 2 * blocksize + 1);
        let mut count = 0;

        digest.reset();
println!("a");
        while count < total_size {
            let next = range.ind_sample(&mut rng);
            let remaining = total_size - count;
            let size = if next > remaining { remaining } else { next };
println!("b");
            let v = buffer.slice_to(size);
println!("b.2");
            digest.input(v);
            count += size;
        }

println!("c");
        let result_str = digest.result_str();
println!("d");

        assert!(expected == result_str.as_slice());
    }


    fn main() {
        use sha2::Sha512;
    
    println!("-1");
        let mut sh = Sha512::new();
    println!("-2");
        test_digest_1million_random(
            &mut sh,
            128,
            "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");
        }
