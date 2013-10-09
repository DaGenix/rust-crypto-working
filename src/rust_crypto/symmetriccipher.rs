// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub use blockmodes::padded_16;

/// Trait for an algorithm that works on blocks of 8 bytes at a time
pub trait BlockSize8 { }

/// Trait for an algorithm that works on blocks of 16 bytes at a time
pub trait BlockSize16 { }

/// Trait for an algorithm that uses 8 byte keys
pub trait KeySize8 { }

/// Trait for an algorithm that uses 16 byte keys
pub trait KeySize16 { }

/// Trait for an algorithm that uses 24 byte keys
pub trait KeySize24 { }

/// Trait for an algorithm that uses 32 byte keys
pub trait KeySize32 { }

/// Trait for a Cipher that can encrypt a block of data
pub trait BlockEncryptor {
    fn encrypt_block(&self, input: &[u8], output: &mut [u8]);
}

/// Trait for a Cipher that can decrypt a block of data
pub trait BlockDecryptor {
    fn decrypt_block(&self, input: &[u8], output: &mut [u8]);
}

/// Trait for a block cipher mode of operation that requires padding the end of the stream
pub trait PaddedEncryptionMode {
    fn encrypt_block(&mut self, input: &[u8], handler: &fn(&[u8]));
    fn encrypt_final_block(&mut self, input: Option<&[u8]>, handler: &fn(&[u8]));
}

/// Trait for a block cipher mode of operation that requires padding the end of the stream
pub trait PaddedDecryptionMode {
    fn decrypt_block(&mut self, input: &[u8], handler: &fn(&[u8]));
    fn decrypt_final_block(&mut self, input: Option<&[u8]>, handler: &fn(&[u8]));
}

/// Trait for an object that buffers data to encrypt until there is a full block
pub trait EncryptionBuffer {
    fn encrypt(&mut self, input: &[u8], handler: &fn(&[u8]));
    fn final(&mut self, handler: &fn(&[u8]));
}

/// Trait for an object that buffers data to decrypt until there is a full block
pub trait DecryptionBuffer {
    fn decrypt(&mut self, input: &[u8], handler: &fn(&[u8]));
    fn final(&mut self, handler: &fn(&[u8]));
}

/// Trait for an encryptor that can operate on byte streams
pub trait StreamEncryptor {
    fn encrypt(&mut self, input: &[u8], out: &mut [u8]);
}

/// Trait for a decryptor that can operate on byte streams
pub trait StreamDecryptor {
    fn decrypt(&mut self, input: &[u8], out: &mut [u8]);
}
