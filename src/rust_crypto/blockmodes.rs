// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use buffer::{ReadBuffer, WriteBuffer, RefReadBuffer, OwnedWriteBuffer, RefWriteBuffer, BufferResult,
    BufferUnderflow, BufferOverflow};
use cryptoutil::FixedBufferHeap;
use symmetriccipher::{BlockEncryptor, Encryptor};

use std::num;
use std::vec;

/*
pub struct EcbBlockMode<T> {
    priv algo: T,
    priv in_buff: FixedBufferHeap,
    priv out_buff: FixedBufferHeap
}

impl <T: BlockEncryptor> EcbBlockMode<T> {
    pub fn new(algo: T) -> EcbBlockMode<T> {
        EcbBlockMode {
            algo: algo,
            in_buff: FixedBufferHeap::new(16),
            out_buff: FixedBufferHeap::new(16)
        }
    }
}

fn encrypt_loop(
        size: uint,
        input: &mut Buffer,
        in_buff: FixedBufferHeap,
        output: &mut MutBuffer,
        out_buff: FixedBufferHeap) -> BufferResult {
    BufferUnderflow
}
*/




fn next_slices<'a>(size: uint, input: &'a mut RefReadBuffer, output: &'a mut RefWriteBuffer) ->
        Option<(&'a [u8], &'a mut [u8])> {
    let has_input = input.remaining() >= size;
    let has_output = output.remaining() >= size;
    if has_input && has_output {
        Some((input.next(size), output.next(size)))
    } else {
        None
    }
}

struct UnpaddedBlockBuffer {
    block_size: uint,
    in_buff: OwnedWriteBuffer,
    out_buff: OwnedWriteBuffer
}

impl UnpaddedBlockBuffer {
    fn new(block_size: uint) -> UnpaddedBlockBuffer {
        UnpaddedBlockBuffer {
            block_size: block_size,
            in_buff: OwnedWriteBuffer::new(vec::from_elem(block_size, 0u8)),
            out_buff: OwnedWriteBuffer::new(vec::from_elem(block_size, 0u8))
        }
    }
    fn is_empty(&self) -> bool {
        self.in_buff.is_empty() && self.out_buff.is_empty()
    }
    fn flush_output(&mut self, output: &mut RefWriteBuffer) -> bool {
        if self.out_buff.is_empty() {
            true
        } else {
            if self.out_buff.remaining() <= output.remaining() {
                let len = self.out_buff.remaining();
                vec::bytes::copy_memory(output.next(len), self.out_buff.next(len), len);
                true
            } else {
                let len = output.remaining();
                vec::bytes::copy_memory(output.next(len), self.out_buff.next(len), len);
                false
            }
        }
    }
    fn fill_input(&mut self, input: &mut RefReadBuffer) {
        if !input.is_empty() && !self.in_buff.is_full() {
            let len = num::min(self.in_buff.remaining(), input.remaining());
            vec::bytes::copy_memory(self.in_buff.next(len), input.next(len), len);
        }
    }
    fn set_padding(&mut self, pad_func: |&mut OwnedWriteBuffer|) {
        pad_func(&mut self.in_buff);
    }
    fn process(
            &mut self,
            input: &mut RefReadBuffer,
            output: &mut RefWriteBuffer,
            func: |&[u8], &mut [u8]|) -> BufferResult {
        if !self.flush_output(output) {
            return BufferOverflow;
        }
        if !self.in_buff.is_empty() {
            self.fill_input(input);
            if self.in_buff.is_full() {
                if output.remaining() >= self.block_size {
                    let mut in_reader = self.in_buff.read_buffer();
                    func(in_reader.all(), output.next(self.block_size));
                } else {
                    {
                        let mut in_reader = self.in_buff.read_buffer();
                        func(in_reader.all(), self.out_buff.next(self.block_size));
                    }
                    self.flush_output(output);
                    return BufferOverflow;
                }
            } else {
                return BufferUnderflow;
            }
        }
        // if we get here, it means that both input_buff and output_buff are empty
        loop {
            match next_slices(self.block_size, input, output) {
                Some((slice_in, slice_out)) => {
                    func(slice_in, slice_out);
                }
                None => break
            }
        }
        if input.remaining() < self.block_size {
            self.fill_input(input);
            BufferUnderflow
        } else {
            func(input.next(self.block_size), self.out_buff.next(self.block_size));
            self.flush_output(output);
            BufferOverflow
        }
    }
}

pub struct EcbBlockMode<T> {
    priv algo: T,
    priv buff: UnpaddedBlockBuffer
}

impl <T: BlockEncryptor> EcbBlockMode<T> {
    pub fn new(algo: T) -> EcbBlockMode<T> {
        EcbBlockMode {
            algo: algo,
            buff: UnpaddedBlockBuffer::new(16),
        }
    }
}

impl <T: BlockEncryptor> Encryptor for EcbBlockMode<T> {
    fn encrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer) -> BufferResult {
        do self.buff.process(input, output) |slice_in, slice_out| {
            self.algo.encrypt_block(slice_in, slice_out);
        }
    }
    fn encrypt_final(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer)
            -> BufferResult {
        match self.encrypt(input, output) {
            BufferUnderflow => {
                assert!(self.buff.is_empty());
                BufferUnderflow
            }
            BufferOverflow => {
                BufferOverflow
            }
        }
    }
}

enum PkcsPaddingEncryptionState {
    Encrypting,
    AddingPadding,
    Done
}

pub struct EcbPkcs7PaddingBlockMode<T> {
    priv algo: T,
    priv buff: UnpaddedBlockBuffer,
}

impl <T: BlockEncryptor> EcbPkcs7PaddingBlockMode<T> {
    pub fn new(algo: T) -> EcbPkcs7PaddingBlockMode<T> {
        EcbPkcs7PaddingBlockMode {
            algo: algo,
            buff: UnpaddedBlockBuffer::new(16),
        }
    }
}

impl <T: BlockEncryptor> Encryptor for EcbPkcs7PaddingBlockMode<T> {
    fn encrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer) -> BufferResult {
        do self.buff.process(input, output) |slice_in, slice_out| {
            self.algo.encrypt_block(slice_in, slice_out);
        }
    }
    fn encrypt_final(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer)
            -> BufferResult {
        match self.encrypt(input, output) {
            BufferUnderflow => {
                do self.buff.set_padding() |owb| {
                    let remaining = owb.remaining();
                    for x in owb.next(remaining).mut_iter() {
                        *x = remaining as u8;
                    }
                }
                self.encrypt(input, output)
            }
            BufferOverflow => {
                BufferOverflow
            }
        }
    }
}

pub struct CbcBlockMode<T> {
    priv algo: T,
    priv buff: UnpaddedBlockBuffer,
    priv temp1: ~[u8],
    priv temp2: ~[u8]
}

impl <T: BlockEncryptor> CbcBlockMode<T> {
    pub fn new(algo: T, iv: &[u8]) -> CbcBlockMode<T> {
        let mut temp1 = vec::from_elem(16, 0u8);
        vec::bytes::copy_memory(temp1, iv, 16);
        CbcBlockMode {
            algo: algo,
            buff: UnpaddedBlockBuffer::new(16),
            temp1: temp1,
            temp2: vec::from_elem(16, 0u8)
        }
    }
}

impl <T: BlockEncryptor> Encryptor for CbcBlockMode<T> {
    fn encrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer) -> BufferResult {
        do self.buff.process(input, output) |slice_in, slice_out| {
            for ((x, y), o) in self.temp1.iter().zip(slice_in.iter()).zip(self.temp2.mut_iter()) {
                *o = *x ^ *y;
            }
            self.algo.encrypt_block(self.temp2, self.temp1);
            vec::bytes::copy_memory(slice_out, self.temp1, 16);
        }
     }
    fn encrypt_final(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer)
            -> BufferResult {
        match self.encrypt(input, output) {
            BufferUnderflow => {
                assert!(self.buff.is_empty());
                BufferUnderflow
            }
            BufferOverflow => {
                BufferOverflow
            }
        }
    }
}

pub struct CbcPkcs7PaddingBlockMode<T> {
    priv algo: T,
    priv buff: UnpaddedBlockBuffer,
    priv temp1: ~[u8],
    priv temp2: ~[u8]
}

impl <T: BlockEncryptor> CbcPkcs7PaddingBlockMode<T> {
    pub fn new(algo: T, iv: &[u8]) -> CbcPkcs7PaddingBlockMode<T> {
        let mut temp1 = vec::from_elem(16, 0u8);
        vec::bytes::copy_memory(temp1, iv, 16);
        CbcPkcs7PaddingBlockMode {
            algo: algo,
            buff: UnpaddedBlockBuffer::new(16),
            temp1: temp1,
            temp2: vec::from_elem(16, 0u8)
        }
    }
}

impl <T: BlockEncryptor> Encryptor for CbcPkcs7PaddingBlockMode<T> {
    fn encrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer) -> BufferResult {
        do self.buff.process(input, output) |slice_in, slice_out| {
            for ((x, y), o) in self.temp1.iter().zip(slice_in.iter()).zip(self.temp2.mut_iter()) {
                *o = *x ^ *y;
            }
            self.algo.encrypt_block(self.temp2, self.temp1);
            vec::bytes::copy_memory(slice_out, self.temp1, 16);
        }
     }
    fn encrypt_final(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer)
            -> BufferResult {
        match self.encrypt(input, output) {
            BufferUnderflow => {
                do self.buff.set_padding() |owb| {
                    let remaining = owb.remaining();
                    for x in owb.next(remaining).mut_iter() {
                        *x = remaining as u8;
                    }
                }
                self.encrypt(input, output)
            }
            BufferOverflow => {
                BufferOverflow
            }
        }
    }
}


#[cfg(test)]
fn print_hex(d: &[u8]) {
    for x in d.iter() {
        print!("0x{:x} ", *x);
    }
    println("");
}

#[test]
fn test_ecb() {
    use aessafe;
    let key = [0u8, ..16];
    let plaintext = [0u8, ..16];
    let mut ciphertext = [0u8, ..16];
    {
        let mut rrb = RefReadBuffer::new(plaintext);
        let mut rwb = RefWriteBuffer::new(ciphertext);
        let aes = aessafe::AesSafe128Encryptor::new(key);
        let mut ecb = EcbBlockMode::new(aes);
        match ecb.encrypt_final(&mut rrb, &mut rwb) {
            BufferUnderflow => {}
            BufferOverflow => fail!("Yikes")
        }
    }
//    print_hex(ciphertext);
}

#[test]
fn test_ecb_pkcs_padding() {
    use aessafe;
    let key = [0u8, ..16];
    let plaintext = [0u8, ..16];
    let mut ciphertext = [0u8, ..32];
    {
        let mut rrb = RefReadBuffer::new(plaintext);
        let mut rwb = RefWriteBuffer::new(ciphertext);
        let aes = aessafe::AesSafe128Encryptor::new(key);
        let mut ecb = EcbPkcs7PaddingBlockMode::new(aes);
        match ecb.encrypt_final(&mut rrb, &mut rwb) {
            BufferUnderflow => {}
            BufferOverflow => fail!("Yikes")
        }
    }
//     print_hex(ciphertext);
}

#[test]
fn test_cbc() {
    use aessafe;
    let key = [0u8, ..16];
    let iv = [0u8, ..16];
    let plaintext = [0u8, ..32];
    let mut ciphertext = [0u8, ..32];
    {
        let mut rrb = RefReadBuffer::new(plaintext);
        let mut rwb = RefWriteBuffer::new(ciphertext);
        let aes = aessafe::AesSafe128Encryptor::new(key);
        let mut ecb = CbcBlockMode::new(aes, iv);
        match ecb.encrypt_final(&mut rrb, &mut rwb) {
            BufferUnderflow => {}
            BufferOverflow => fail!("Yikes")
        }
    }
//    print_hex(ciphertext);
}

#[test]
fn test_cbc_padding() {
    use aessafe;
    let key = [0u8, ..16];
    let iv = [0u8, ..16];
    let plaintext = [0u8, ..17];
    let mut ciphertext = [0u8, ..32];
    {
        let mut rrb = RefReadBuffer::new(plaintext);
        let mut rwb = RefWriteBuffer::new(ciphertext);
        let aes = aessafe::AesSafe128Encryptor::new(key);
        let mut ecb = CbcPkcs7PaddingBlockMode::new(aes, iv);
        match ecb.encrypt_final(&mut rrb, &mut rwb) {
            BufferUnderflow => {}
            BufferOverflow => fail!("Yikes")
        }
    }
    print_hex(ciphertext);
}

/*
impl <T: BlockEncryptor> Encryptor for EcbBlockMode<T> {
    fn encrypt(&mut self, input: &mut Buffer, output: &mut MutBuffer) -> BufferResult {
        BufferUnderflow
    }
    fn encrypt_final(&mut self, input: &mut Buffer, output: &mut MutBuffer) -> BufferResult {
        BufferUnderflow
    }
}

*/


























/*
use buffer::{Buffer, MutBuffer, BufferResult, BufferUnderflow, BufferOverflow, next_slices};
use cryptoutil::FixedBufferHeap;
use symmetriccipher::{BlockEncryptor, Encryptor};

pub struct EcbBlockMode<T> {
    priv algo: T,
    priv in_buff: FixedBufferHeap,
    priv out_buff: FixedBufferHeap
}

impl <T: BlockEncryptor> EcbBlockMode<T> {
    pub fn new(algo: T) -> EcbBlockMode<T> {
        EcbBlockMode {
            algo: algo,
            in_buff: FixedBufferHeap::new(16),
            out_buff: FixedBufferHeap::new(16)
        }
    }
}

fn encrypt_loop(
        size: uint,
        input: &mut Buffer,
        in_buff: FixedBufferHeap,
        output: &mut MutBuffer,
        out_buff: FixedBufferHeap) -> BufferResult {
    BufferUnderflow
}



struct UnpaddedBlockBuffer {
    block_size: uint,
    input_buff: ~[u8],
    output_buff: ~[u8]
}

impl UnpaddedBlockBuffer {
    fn new(block_size: uint) -> UnpaddedBlockBuffer {
        UnpaddedBlockBuffer {
            block_size: block_size,
            input_buff: vec::with_capacity(block_size),
            output_buff: vec::with_capacity(block_size)
        }
    }
    fn next_slices<'a>(&self, input: &'a mut Buffer, output: &'a mut MutBuffer) ->
            Option<(&'a [u8], &'a mut [u8])> {
        let has_input = input.remaining() >= self.block_size;
        let has_output = output.remaining() >= self.block_size;
        if has_input && has_output {
            Some((input.next_slice(self.block_size), output.next_slice(self.block_size)))
        } else {
            None
        }
    }
    fn flush_output(&mut self, output: &mut MutBuffer) -> BufferResult {
        while self.output_buff.len() > 0 {
            if output.remaining() > 0 {
                let x = self.output_buff().shift();
                output.next_slice(1)[0] = x;
            } else {
                return BufferOverflow;
            }
        }
        return BufferUnderflow;
    }
    fn fill_input(&mut self, input: &mut Buffer) -> BufferResult {
        while self.input_buff.len() < self.input_buff.capacity() {
            if input.remaining() > 0 {
                self.input_buff.push(input.next_slice(1)[0]);
            } else {
                return BufferUnderflow;
            }
        }
        return BufferOverflow;
    }
    fn process(
            &mut self,
            input: &mut Buffer,
            output: &mut MutBuffer,
            func: |(&[u8], &mut [u8])|) -> BufferResult {
        if self.flush_output(output) == BufferOverflow {
            return BufferOverflow;
        }
        if self.input_buff.len() > 0 {
            if self.fill_input(input) == BufferUnderflow {
                return BufferUnderflow;
            } else {
                // process input_buff
                if output.remaining() >= self.block_size {
                    func(self.input_buff, output.next_slice(self.block_size));
                    self.input_buff.truncate(0);
                } else {
                    func(self.input_buff, self.output_buff);
                    self.input_buff.truncate(0);
                    self.flush_output(output);
                    return BufferOverflow;
                }
            }
        }
        // if we get here, it means that both input_buff and output_buff are empty
        loop {
            match next_slices(block_size, input, output) {
                Some((slice_in, slice_out)) => {
                    func(slice_in, slice_out);
                }
                None => break
            }
        }
        if input.remaining() < self.block_size {
            self.fill_input(input)
            BufferUnderflow
        } else {
            func(input.next_slice(self.block_size), self.output_buff);
            self.flush_output(output)
            BufferOverflow
        }
    }
}


impl <T: BlockEncryptor> Encryptor for EcbBlockMode<T> {
    fn encrypt(&mut self, input: &mut Buffer, output: &mut MutBuffer) -> BufferResult {
        BufferUnderflow
    }
    fn encrypt_final(&mut self, input: &mut Buffer, output: &mut MutBuffer) -> BufferResult {
        BufferUnderflow
    }
}
*/







#[cfg(test)]
mod tests {
/*
    use std::num::from_str_radix;
    use std::vec;
    use std::iter::range_step;

    use aes::*;
    use blockmodes::padded_16::*;
    use symmetriccipher::*;

    // Test vectors from: NIST SP 800-38A

    fn key128() -> ~[u8] {
        from_str("2b7e151628aed2a6abf7158809cf4f3c")
    }

    fn iv() -> ~[u8] {
        from_str("000102030405060708090a0b0c0d0e0f")
    }

    fn ctr_iv() -> ~[u8] {
        from_str("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    }

    fn plain() -> ~[u8] {
        from_str(
            "6bc1bee22e409f96e93d7e117393172a" + "ae2d8a571e03ac9c9eb76fac45af8e51" +
            "30c81c46a35ce411e5fbc1191a0a52ef" + "f69f2445df4f9b17ad2b417be66c3710")
    }

    fn from_str(input: &str) -> ~[u8] {
        let mut out: ~[u8] = ~[];
        for i in range_step(0u, input.len(), 2) {
            let tmp: Option<u8> = from_str_radix(input.slice(i, i+2), 16);
            out.push(tmp.unwrap());
        };
        return out;
    }

    #[test]
    fn test_ecb_no_padding_128() {
        let key = key128();
        let plain = plain();
        let cipher = from_str(
            "3ad77bb40d7a3660a89ecaf32466ef97" + "f5d3d58503b9699de785895a96fdbaaf" +
            "43b1cd7f598ece23881b00e3ed030688" + "7b0c785e27e8ad3f8223207104725dd4");

        let mut output = ~[];

        let mut m_enc = EncryptionBuffer16::new(EcbEncryptionWithNoPadding16::new(
            Aes128Encryptor::new(key)));
        m_enc.encrypt(plain, |d: &[u8]| { output.push_all(d); });
        m_enc.final(|d: &[u8]| { output.push_all(d); });
        assert!(output == cipher);

//         let mut m_dec = EcbDecryptionWithNoPadding16::new(Aes128Encryptor::new(key));
//         m_dec.decrypt(cipher, tmp);
//         assert!(tmp == plain);
    }

    #[test]
    fn test_cbc_no_padding_128() {
        let key = key128();
        let iv = iv();
        let plain = plain();
        let cipher = from_str(
            "7649abac8119b246cee98e9b12e9197d" + "5086cb9b507219ee95db113a917678b2" +
            "73bed6b8e3c1743b7116e69e22229516" + "3ff1caa1681fac09120eca307586e1a7");

        let mut output = ~[];

        let mut m_enc = EncryptionBuffer16::new(CbcEncryptionWithNoPadding16::new(
            Aes128Encryptor::new(key), iv));
        m_enc.encrypt(plain, |d: &[u8]| { output.push_all(d); });
        m_enc.final(|d: &[u8]| { output.push_all(d); });
        assert!(output == cipher);

//         let mut m_dec = EcbDecryptionWithNoPadding16::new(Aes128Encryptor::new(key));
//         m_dec.decrypt(cipher, tmp);
//         assert!(tmp == plain);
    }

    #[test]
    fn test_ctr_128() {
        let key = key128();
        let iv = ctr_iv();
        let plain = plain();
        let cipher = from_str(
            "874d6191b620e3261bef6864990db6ce" + "9806f66b7970fdff8617187bb9fffdff" +
            "5ae4df3edbd5d35e5b4f09020db03eab" + "1e031dda2fbe03d1792170a0f3009cee");

        let mut tmp = vec::from_elem(plain.len(), 0u8);

        let mut m_enc = CtrMode16::new(Aes128Encryptor::new(key), iv);
        m_enc.encrypt(plain, tmp);
        assert!(tmp == cipher);

        let mut m_dec = CtrMode16::new(Aes128Encryptor::new(key), iv);
        m_dec.decrypt(cipher, tmp);
        assert!(tmp == plain);
    }
*/
}
