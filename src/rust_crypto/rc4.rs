// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use symmetriccipher::{StreamEncryptor, StreamDecryptor};

pub struct Rc4 {
    priv i: int,
    priv j: int,
    priv state: [u8, ..256]
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Rc4 {
        let mut rc4 = Rc4 { i: 0, j: 0, state: [0, ..256] };
        for i in range(0u8, 256) {
            rc4.state[i] = i;
        }
        let mut j: u8 = 0;
        for i in range(0u8, 256) {
            j = j + rc4.state[i] + key[i % key.len()];
            swap(&mut rc4.state[i], &mut rc4.state[j]);
        }
    }
}

impl StreamEncryptor for Rc4 {
    fn encrypt(&mut self, input: &[u8], out: &mut [u8]) { }
}

impl StreamDecryptor for Rc4 {
    fn encrypt(&mut self, input: &[u8], out: &mut [u8]) { }
}
