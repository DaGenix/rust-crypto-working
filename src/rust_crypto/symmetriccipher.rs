// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use buffer::{ReadBuffer, WriteBuffer, BufferResult};

pub trait BlockEncryptor {
    fn block_size(&self) -> uint;
    fn encrypt_block(&self, input: &[u8], output: &mut [u8]);
}

pub trait BlockEncryptorX8 {
    fn block_size(&self) -> uint;
    fn encrypt_block_x8(&self, input: &[u8], output: &mut [u8]);
}

pub trait BlockDecryptor {
    fn block_size(&self) -> uint;
    fn decrypt_block(&self, input: &[u8], output: &mut [u8]);
}

pub trait BlockDecryptorX8 {
    fn block_size(&self) -> uint;
    fn decrypt_block_x8(&self, input: &[u8], output: &mut [u8]);
}

pub trait Encryptor {
    // TODO - Better error handling
    fn encrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, eof: bool)
        -> Result<BufferResult, &'static str>;
}

pub trait Decryptor {
    // TODO - Better error handling
    fn decrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, eof: bool)
        -> Result<BufferResult, &'static str>;
}

pub trait SynchronousStreamCipher {
    fn generate(&mut self, result: &mut [u8]);
    fn process(&mut self, input: &[u8], output: &mut [u8]);
}
