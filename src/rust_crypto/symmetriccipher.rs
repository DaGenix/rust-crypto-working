// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use buffer::{RefReadBuffer, RefWriteBuffer, BufferResult};

pub trait BlockEncryptor {
    fn encrypt_block(&self, input: &[u8], output: &mut [u8]);
}

pub trait BlockEncryptorX8 {
    fn encrypt_block_x8(&self, input: &[u8], output: &mut [u8]);
}

pub trait BlockDecryptor {
    fn decrypt_block(&self, input: &[u8], output: &mut [u8]);
}

pub trait BlockDecryptorX8 {
    fn decrypt_block_x8(&self, input: &[u8], output: &mut [u8]);
}

pub trait Encryptor {
    fn encrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer) -> BufferResult;
    fn encrypt_final(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer) -> BufferResult;
}

pub trait Decryptor {
    fn decrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer) -> BufferResult;
    fn decrypt_final(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer) -> BufferResult;
}

pub trait SynchronousStreamCipher {
    fn generate(&mut self, result: &mut [u8]);
    fn process(&mut self, input: &[u8], output: &mut [u8]);
}
