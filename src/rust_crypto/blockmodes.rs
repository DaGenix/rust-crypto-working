// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use buffer::{ReadBuffer, WriteBuffer, RefReadBuffer, OwnedReadBuffer, RefWriteBuffer,
    OwnedWriteBuffer, BufferResult, BufferUnderflow, BufferOverflow};
use cryptoutil::FixedBufferHeap;
use symmetriccipher::{BlockEncryptor, Encryptor};

use std::num;
use std::vec;

fn push<R: ReadBuffer, W: WriteBuffer>(input: &mut R, output: &mut W) {
    let size = num::min(output.remaining(), input.remaining());
    vec::bytes::copy_memory(output.next(size), input.next(size), size);
}

fn next_slices<'a, R: ReadBuffer, W: WriteBuffer>(
        block_size: uint,
        input: &'a mut R,
        output: &'a mut W,
        eof: bool)
        -> Option<(&'a [u8], &'a mut [u8], bool)> {
    let input_ok = input.remaining() > block_size || (input.remaining() >= block_size && eof);
    let output_ok = output.remaining() >= block_size;
    if input_ok && output_ok {
        let no_more_input = input.remaining() == block_size;
        let slice_in = input.next(block_size);
        let slice_out = output.next(block_size);
        Some((slice_in, slice_out, no_more_input))
    } else {
        None
    }
}

enum BlockEngineState {
    NeedInput,
    FillingIn,
    NeedOutput,
    AwaitingPadding,
    Finishing
}

struct BlockEngine {
    block_size: uint,
    in_buff: OwnedWriteBuffer,
    out_write_buff: Option<OwnedWriteBuffer>,
    out_read_buff: Option<OwnedReadBuffer>,
    state: BlockEngineState
}

impl BlockEngine {
    fn new(block_size: uint) -> BlockEngine {
        BlockEngine {
            block_size: block_size,
            in_buff: OwnedWriteBuffer::new(vec::from_elem(block_size, 0u8)),
            out_write_buff: Some(OwnedWriteBuffer::new(vec::from_elem(block_size, 0u8))),
            out_read_buff: None,
            state: NeedInput
        }
    }
    fn is_empty(&self) -> bool {
        match self.state {
            NeedInput => true,
            _ => false
        }
    }
    fn add_padding<'a>(&'a mut self, padding_func: |&'a mut OwnedWriteBuffer|) {
        match self.state {
            AwaitingPadding => {
                padding_func(&mut self.in_buff);
                self.state = Finishing;
            }
            _ => {}
        }
    }
    fn process<R: ReadBuffer, W: WriteBuffer>(
            &mut self,
            input: &mut R,
            output: &mut W,
            eof: bool,
            func: |&[u8], &mut [u8], bool|) -> BufferResult {
        loop {
            match self.state {
                NeedInput => {
                    loop {
                        match next_slices(self.block_size, input, output, eof) {
                            Some((slice_in, slice_out, no_more_input)) => {
                                let last = eof && no_more_input;
                                func(slice_in, slice_out, last);
                            }
                            None => break
                        }
                    }
                    if input.is_empty() {
                        if eof {
                            self.state = AwaitingPadding;
                        }
                        return BufferUnderflow;
                    } else {
                        self.state = FillingIn;
                    }
                }
                FillingIn => {
                    let mut out_write_buff = match self.out_write_buff.take() {
                        Some(x) => x,
                        None => fail!("No out_write_buff.")
                    };
                    push(input, &mut self.in_buff);
                    let has_more_input = input.remaining() > 0;
                    if self.in_buff.is_full() && (eof || has_more_input) {
                        // TODO - common function for this and Finishing state
                        // TODO - write directly to output if possible
                        {
                            let mut in_reader = self.in_buff.read_buffer();
                            let slice_in = in_reader.next(self.block_size);
                            let slice_out = out_write_buff.next(self.block_size);
                            func(slice_in, slice_out, eof);
                        }
                        self.in_buff.reset();
                        self.out_read_buff = Some(out_write_buff.get_read_buffer());
                        self.state = NeedOutput;
                    } else {
                        self.out_write_buff = Some(out_write_buff);
                        if eof {
                            self.state = AwaitingPadding;
                            return BufferUnderflow;
                        } else {
                            return BufferUnderflow;
                        }
                    }
                }
                NeedOutput => {
                    let mut out_read_buff = self.out_read_buff.take_unwrap();
                    push(&mut out_read_buff, output);
                    if out_read_buff.is_empty() {
                        self.out_write_buff = Some(out_read_buff.get_write_buffer());
                        if eof {
                            self.state = AwaitingPadding;
                            return BufferUnderflow;
                        } else {
                            self.state = NeedInput;
                        }
                    } else {
                        self.out_read_buff = Some(out_read_buff);
                        self.state = NeedOutput;
                        return BufferOverflow;
                    }
                }
                AwaitingPadding => {
                    fail!("Waiting for padding or called incorrectly");
                }
                Finishing => {
                    assert!(input.is_empty());
                    if self.in_buff.is_full() {
                        let mut out_write_buff = self.out_write_buff.take_unwrap();
                        // TODO - common function for this and FillingIn state
                        // TODO - write directly to output if possible
                        {
                            let mut in_reader = self.in_buff.read_buffer();
                            let slice_in = in_reader.next(self.block_size);
                            let slice_out = out_write_buff.next(self.block_size);
                            func(slice_in, slice_out, eof);
                        }
                        self.in_buff.reset();
                        self.out_read_buff = Some(out_write_buff.get_read_buffer());
                    }
                    match self.out_read_buff {
                        Some(ref mut out_read_buff) => {
                            push(out_read_buff, output);
                            if out_read_buff.is_empty() {
                                return BufferUnderflow;
                            } else {
                                return BufferOverflow;
                            }
                        }
                        None => fail!("In Finishing state without out_read_buff.")
                    }
                }
            }
        }
    }
}

pub struct EcbNoPaddingEncryptor<T> {
    priv algo: T,
    priv block_engine: BlockEngine
}

impl <T: BlockEncryptor> EcbNoPaddingEncryptor<T> {
    pub fn new(algo: T) -> EcbNoPaddingEncryptor<T> {
        let block_size = algo.block_size();
        EcbNoPaddingEncryptor {
            algo: algo,
            block_engine: BlockEngine::new(block_size),
        }
    }
}

impl <T: BlockEncryptor> Encryptor for EcbNoPaddingEncryptor<T> {
    fn encrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, eof: bool)
            -> BufferResult {
        let enc_fun: |&[u8], &mut [u8], bool| = |slice_in, slice_out, _| {
            self.algo.encrypt_block(slice_in, slice_out);
        };
        let result = self.block_engine.process(input, output, eof, enc_fun);
        match (eof, result, self.block_engine.is_empty()) {
            (true, BufferUnderflow, false) => {
                fail!("NoPadding modes can only work on multiples of the block size.");
            }
            _ => {}
        }
        return result;
    }
}

pub struct EcbPkcs7PaddingEncryptor<T> {
    priv algo: T,
    priv block_engine: BlockEngine
}

impl <T: BlockEncryptor> EcbPkcs7PaddingEncryptor<T> {
    pub fn new(algo: T) -> EcbPkcs7PaddingEncryptor<T> {
        let block_size = algo.block_size();
        EcbPkcs7PaddingEncryptor {
            algo: algo,
            block_engine: BlockEngine::new(block_size),
        }
    }
}

impl <T: BlockEncryptor> Encryptor for EcbPkcs7PaddingEncryptor<T> {
    fn encrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, eof: bool)
            -> BufferResult {
        let enc_fun: |&[u8], &mut [u8], bool| = |slice_in, slice_out, _| {
            self.algo.encrypt_block(slice_in, slice_out);
        };
        let result = do self.block_engine.process(input, output, eof) |a, b, c| {
            enc_fun(a, b, c);
        };
        match (eof, result) {
            (true, BufferUnderflow) => {
                do self.block_engine.add_padding() |in_buff| {
                    let remaining = in_buff.remaining();
                    for x in in_buff.next(remaining).mut_iter() {
                        *x = remaining as u8;
                    }
                }
                return do self.block_engine.process(input, output, eof) |a, b, c| {
                    enc_fun(a, b, c);
                };
            }
            _ => return result
        }
    }
}

pub struct CbcNoPaddingEncryptor<T> {
    priv algo: T,
    priv block_engine: BlockEngine,
    priv temp1: ~[u8],
    priv temp2: ~[u8]
}

impl <T: BlockEncryptor> CbcNoPaddingEncryptor<T> {
    pub fn new(algo: T, iv: &[u8]) -> CbcNoPaddingEncryptor<T> {
        let block_size = algo.block_size();
        let mut temp1 = vec::from_elem(block_size, 0u8);
        vec::bytes::copy_memory(temp1, iv, block_size);
        CbcNoPaddingEncryptor {
            algo: algo,
            block_engine: BlockEngine::new(block_size),
            temp1: temp1,
            temp2: vec::from_elem(block_size, 0u8)
        }
    }
}

impl <T: BlockEncryptor> Encryptor for CbcNoPaddingEncryptor<T> {
    fn encrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, eof: bool)
            -> BufferResult {
        let enc_fun: |&[u8], &mut [u8], bool| = |slice_in, slice_out, _| {
            for ((x, y), o) in self.temp1.iter().zip(slice_in.iter()).zip(self.temp2.mut_iter()) {
                *o = *x ^ *y;
            }
            self.algo.encrypt_block(self.temp2, self.temp1);
            vec::bytes::copy_memory(slice_out, self.temp1, self.algo.block_size());
        };
        let result = self.block_engine.process(input, output, eof, enc_fun);
        match (eof, result, self.block_engine.is_empty()) {
            (true, BufferUnderflow, false) => {
                fail!("NoPadding modes can only work on multiples of the block size.");
            }
            _ => {}
        }
        return result;
    }
}

pub struct CbcPkcs7PaddingEncryptor<T> {
    priv algo: T,
    priv block_engine: BlockEngine,
    priv temp1: ~[u8],
    priv temp2: ~[u8]
}

impl <T: BlockEncryptor> CbcPkcs7PaddingEncryptor<T> {
    pub fn new(algo: T, iv: &[u8]) -> CbcPkcs7PaddingEncryptor<T> {
        let block_size = algo.block_size();
        let mut temp1 = vec::from_elem(block_size, 0u8);
        vec::bytes::copy_memory(temp1, iv, block_size);
        CbcPkcs7PaddingEncryptor {
            algo: algo,
            block_engine: BlockEngine::new(block_size),
            temp1: temp1,
            temp2: vec::from_elem(block_size, 0u8)
        }
    }
}

impl <T: BlockEncryptor> Encryptor for CbcPkcs7PaddingEncryptor<T> {
    fn encrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, eof: bool)
            -> BufferResult {
        let enc_fun: |&[u8], &mut [u8], bool| = |slice_in, slice_out, _| {
            for ((x, y), o) in self.temp1.iter().zip(slice_in.iter()).zip(self.temp2.mut_iter()) {
                *o = *x ^ *y;
            }
            self.algo.encrypt_block(self.temp2, self.temp1);
            vec::bytes::copy_memory(slice_out, self.temp1, self.algo.block_size());
        };
        let result = do self.block_engine.process(input, output, eof) |a, b, c| {
            enc_fun(a, b, c);
        };
        match (eof, result) {
            (true, BufferUnderflow) => {
                do self.block_engine.add_padding() |in_buff| {
                    let remaining = in_buff.remaining();
                    for x in in_buff.next(remaining).mut_iter() {
                        *x = remaining as u8;
                    }
                }
                return do self.block_engine.process(input, output, true) |a, b, c| {
                    enc_fun(a, b, c);
                };
            }
            _ => return result
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
fn test_ecb_no_padding() {
    use aessafe;
    let key = [0u8, ..16];
    let plaintext = [0u8, ..16];
    let mut ciphertext = [0u8, ..16];
    {
        let mut rrb = RefReadBuffer::new(plaintext);
        let mut rwb = RefWriteBuffer::new(ciphertext);
        let aes = aessafe::AesSafe128Encryptor::new(key);
        let mut ecb = EcbNoPaddingEncryptor::new(aes);
        match ecb.encrypt(&mut rrb, &mut rwb, true) {
            BufferUnderflow => {}
            BufferOverflow => fail!("Yikes")
        }
    }
    print_hex(ciphertext);
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
        let mut ecb = EcbPkcs7PaddingEncryptor::new(aes);
        match ecb.encrypt(&mut rrb, &mut rwb, true) {
            BufferUnderflow => {}
            BufferOverflow => fail!("Yikes")
        }
    }
    print_hex(ciphertext);
}

#[test]
fn test_cbc_no_padding() {
    use aessafe;
    let key = [0u8, ..16];
    let iv = [0u8, ..16];
    let plaintext = [0u8, ..32];
    let mut ciphertext = [0u8, ..32];
    {
        let mut rrb = RefReadBuffer::new(plaintext);
        let mut rwb = RefWriteBuffer::new(ciphertext);
        let aes = aessafe::AesSafe128Encryptor::new(key);
        let mut cbc = CbcNoPaddingEncryptor::new(aes, iv);
        match cbc.encrypt(&mut rrb, &mut rwb, true) {
            BufferUnderflow => {}
            BufferOverflow => fail!("Yikes")
        }
    }
    print_hex(ciphertext);
}

#[test]
fn test_cbc_pkcs_padding() {
    use aessafe;
    let key = [0u8, ..16];
    let iv = [0u8, ..16];
    let plaintext = [0u8, ..17];
    let mut ciphertext = [0u8, ..32];
    {
        let mut rrb = RefReadBuffer::new(plaintext);
        let mut rwb = RefWriteBuffer::new(ciphertext);
        let aes = aessafe::AesSafe128Encryptor::new(key);
        let mut cbc = CbcPkcs7PaddingEncryptor::new(aes, iv);
        match cbc.encrypt(&mut rrb, &mut rwb, true) {
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
