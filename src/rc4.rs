// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/*!
 * An implementation of the RC4 (also sometimes called ARC4) stream cipher. THIS IMPLEMENTATION IS
 * NOT A FIXED TIME IMPLEMENTATION.
 */

use buffer::{BufferResult, RefReadBuffer, RefWriteBuffer};
use symmetriccipher::{Encryptor, Decryptor, SynchronousStreamCipher, SymmetricCipherError};
use cryptoutil::symm_enc_or_dec;

#[derive(Copy)]
pub struct Rc4 {
    i: u8,
    j: u8,
    state: [u8; 256]
}

impl Clone for Rc4 { fn clone(&self) -> Rc4 { *self } }

impl Rc4 {
    pub fn new(key: &[u8]) -> Rc4 {
        assert!(key.len() >= 1 && key.len() <= 256);
        let mut rc4 = Rc4 { i: 0, j: 0, state: [0; 256] };
        for (i, x) in rc4.state.iter_mut().enumerate() {
            *x = i as u8;
        }
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(rc4.state[i]).wrapping_add(key[i % key.len()]);
            rc4.state.swap(i, j as usize);
        }
        rc4
    }
    fn next(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.state[self.i as usize]);
        self.state.swap(self.i as usize, self.j as usize);
        let k = self.state[(self.state[self.i as usize].wrapping_add(self.state[self.j as usize])) as usize];
        k
    }
}

impl SynchronousStreamCipher for Rc4 {
    fn process(&mut self, input: &[u8], output: &mut [u8]) {
        assert!(input.len() == output.len());
        for (x, y) in input.iter().zip(output.iter_mut()) {
            *y = *x ^ self.next();
        }
    }
}

impl Encryptor for Rc4 {
    fn encrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

impl Decryptor for Rc4 {
    fn decrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

#[cfg(test)]
mod test {
    use std::cmp;
    use std::iter::repeat;

    use symmetriccipher::SynchronousStreamCipher;
    use rc4::Rc4;

    // use testutil::{read_data, parse_tests, test_in_parts};
    use testutil::test_synchronous_stream_cipher;

    #[test]
    fn test_rc4() {
        test_synchronous_stream_cipher("testdata/rc4.toml", 1024, |key, _| Rc4::new(key));
        // parse_tests("testdata/rc4.toml", "test-rc4", |tests| {
        //     for test_table in tests {
        //         let test = test_table.as_table().expect("Test data must be in Table format.");
        //         let key = read_data(test, "key");
        //         let input = read_data(test, "input");
        //         let expected_result = read_data(test, "result");
        //
        //         {
        //             let mut rc4 = Rc4::new(&key);
        //             let mut result: Vec<u8> = repeat(0).take(expected_result.len()).collect();
        //             rc4.process(&input, &mut result);
        //             assert_eq!(result, expected_result);
        //         }
        //
        //         for permutation in 0..3 {
        //             let mut rc4 = Rc4::new(&key);
        //             let mut result = Vec::with_capacity(expected_result.len());
        //             test_in_parts(
        //                 &input,
        //                 1,
        //                 cmp::min(input.len(), 2048),
        //                 permutation,
        //                 |chunk| {
        //                     let pos = result.len();
        //                     result.extend(repeat(0).take(chunk.len()));
        //                     rc4.process(chunk, &mut result[pos..]);
        //                 });
        //             assert_eq!(result, expected_result);
        //         }
        //     }
        // });
    }
}

#[cfg(all(test, feature = "with-bench"))]
mod bench {
    use test::Bencher;
    use symmetriccipher::SynchronousStreamCipher;
    use rc4::Rc4;

    #[bench]
    pub fn rc4_10(bh: & mut Bencher) {
        let mut rc4 = Rc4::new("key".as_bytes());
        let input = [1u8; 10];
        let mut output = [0u8; 10];
        bh.iter( || {
            rc4.process(&input, &mut output);
        });
        bh.bytes = input.len() as u64;
    }

    #[bench]
    pub fn rc4_1k(bh: & mut Bencher) {
        let mut rc4 = Rc4::new("key".as_bytes());
        let input = [1u8; 1024];
        let mut output = [0u8; 1024];
        bh.iter( || {
            rc4.process(&input, &mut output);
        });
        bh.bytes = input.len() as u64;
    }

    #[bench]
    pub fn rc4_64k(bh: & mut Bencher) {
        let mut rc4 = Rc4::new("key".as_bytes());
        let input = [1u8; 65536];
        let mut output = [0u8; 65536];
        bh.iter( || {
            rc4.process(&input, &mut output);
        });
        bh.bytes = input.len() as u64;
    }
}
