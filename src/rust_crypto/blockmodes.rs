// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use buffer::{ReadBuffer, WriteBuffer, RefReadBuffer, OwnedReadBuffer, RefWriteBuffer,
    OwnedWriteBuffer, BufferResult, BufferUnderflow, BufferOverflow};
use cryptoutil::FixedBufferHeap;
use symmetriccipher::{BlockEncryptor, Encryptor, BlockDecryptor, Decryptor};

use std::num;
use std::vec;

trait BlockProcessor {
    fn process_block(&mut self, history: &[u8], input: &[u8], output: &mut [u8]);
    fn last_input<W: WriteBuffer>(&mut self, input_buffer: &mut W) { }
    fn last_output<W: WriteBuffer>(&mut self, output_buffer: &mut W) { }
}

enum BlockEngineState {
    ScratchEmpty,
    NeedInput,
    NeedOutput
}

struct BlockEngine<P> {
    in_size: uint,
    out_size: uint,
    hist_size: uint,
    in_scratch: OwnedWriteBuffer,
    out_write_scratch: Option<OwnedWriteBuffer>,
    out_read_scratch: Option<OwnedReadBuffer>,
    hist_scratch: ~[u8],
    processor: P,
    state: BlockEngineState
}

impl <P: BlockProcessor> BlockEngine<P> {
    fn new(processor: P, in_size: uint, out_size: uint) -> BlockEngine<P> {
        BlockEngine {
            in_size: in_size,
            out_size: out_size,
            hist_size: 0,
            in_scratch: OwnedWriteBuffer::new(vec::from_elem(in_size, 0u8)),
            out_write_scratch: Some(OwnedWriteBuffer::new(vec::from_elem(out_size, 0u8))),
            out_read_scratch: None,
            hist_scratch: ~[],
            processor: processor,
            state: ScratchEmpty
        }
    }
    fn new_with_history(
            processor: P,
            in_size: uint,
            out_size: uint,
            initial_hist: ~[u8]) -> BlockEngine<P> {
        BlockEngine {
            hist_size: initial_hist.len(),
            hist_scratch: initial_hist,
            ..BlockEngine::new(processor, in_size, out_size)
        }
    }
    /*
    fn do_run_processor<R: ReadBuffer, W: WriteBuffer>(
            &mut self,
            input: &mut R,
            output: &mut W) {
        let next_in = input.next(self.in_size);
        let next_out = output.next(self.out_size);
        self.processor.process_block(next_in, next_out, self.hist_scratch.as_slice());
        vec::bytes::copy_memory(
            self.hist_scratch,
            next_in.slice_from(self.in_size - self.hist_size),
            self.hist_size);
    }
    fn run_processor<R: ReadBuffer, W: WriteBuffer>(
            &mut self,
            input: &mut R,
            output: &mut W,
            eof: bool) {
        loop {
            let enough_input = input.remaining() > self.in_size ||
                (eof && input.remaining() >= self.in_size);
            let enough_output = output.remaining() >= self.out_size;
            if enough_input && enough_output {
                self.do_run_processor(input, output);
            } else {
                break;
            }
        }
    }
    */
    fn fast_mode<R: ReadBuffer, W: WriteBuffer>(
            &mut self,
            input: &mut R,
            output: &mut W,
            eof: bool) {
        let has_next = || {
            let enough_input = input.remaining() > self.in_size ||
                (eof && input.remaining() >= self.in_size);
            let enough_output = output.remaining() >= self.out_size;
            (enough_input, enough_output)
        };

        /*
        {
            let enough_input = input.remaining() > self.in_size ||
                (eof && input.remaining() >= self.in_size);
            let enough_output = output.remaining() >= self.out_size;
            if enough_input && enough_output {
                let next_in = input.next(self.in_size);
                let next_out = output.next(self.out_size);
                self.processor.process_block(next_in, next_out, self.hist_scratch.as_slice());
            }
        }
        loop {
            let enough_input = input.remaining() > self.in_size ||
                (eof && input.remaining() >= self.in_size);
            let enough_output = output.remaining() >= self.out_size;
            if enough_input && enough_output {
                let next_in = input.next(self.in_size);
                let next_out = output.next(self.out_size);
                self.processor.process_block(next_in, next_out, self.hist_scratch.as_slice());
            } else {
                break;
            }
        }
        */
    }
    fn process<R: ReadBuffer, W: WriteBuffer>(
            &mut self,
            input: &mut R,
            output: &mut W,
            eof: bool) -> BufferResult {
        loop {
        /*
            match self.state {
                ScratchEmpty => {
                    self.run_processor(input, output, eof);

                    if input.remaining() <= self.in_size {
                        if eof {
                            self.state = LastInput;
                        } else {
                            if input.is_empty() {

                            } else {

                            }
                        }
                    } else {

                    }




                    if eof && input.remaining() < self.in_size {

                    }

                    if input.is_empty() {

                    } else {

                    }


                    if !input.is_empty() {
                        self.state = NeedInput;
                    } else {
                        if eof {
                            self.state = LastInput;
                        } else {
                            return BufferUnderflow;
                        }
                    }
                }
                NeedInput => {
                    input.push_to(&mut self.in_scratch);
                    if self.in_scratch.is_full() {
                        let mut rin = self.in_scratch.take_read_buffer();
                        if output.remaining() < self.out_size {
                            let mut wout = self.out_write_scratch.take_unwrap();
                            self.run_processor(&mut rin, &mut wout, eof && input.is_empty());
                            self.out_read_scratch = Some(wout.into_read_buffer());
                            self.state = NeedOutput;
                        } else {
                            self.run_processor(&mut rin, output, eof && input.is_empty());
                            self.state = ScratchEmpty;
                        }
                    } else {
                        if eof {
                            self.state = LastInput;
                        } else {
                            return BufferUnderflow;
                        }
                    }
                }
                NeedOutput => {
                    let mut rout = self.out_read_scratch.take_unwrap();
                    rout.push_to(output);
                    if rout.is_empty() {
                        self.out_write_scratch = Some(rout.into_write_buffer());
                        self.state = ScratchEmpty;
                    } else {
                        self.out_read_scratch = Some(rout);
                        return BufferOverflow;
                    }
                }
                LastInput => {
                    self.processor.last_input(self.in_scratch);
                    if self.in_scratch.is_full() {
                        self.run_processor(
                            self.in_scratch.take_read_buffer(),
                            wout,
                            true);
                    }
                    self.processor.last_output(wout);
                }
            }
        */
        }
    }
}





/*




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
            // TODO - this seems awkward
            AwaitingPadding | Finishing => true,
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
            func: |&[u8], &mut [u8], bool| -> uint) -> BufferResult {
        loop {
            match self.state {
                NeedInput => {
                    loop {
                        // TODO - convert to ChunkIter / zip?
                        let cnt: uint;
                        match next_slices(self.block_size, input, output, eof) {
                            Some((slice_in, slice_out, no_more_input)) => {
                                let last = eof && no_more_input;
                                cnt = func(slice_in, slice_out, last);
                            }
                            None => break
                        }
                        output.rewind(self.block_size - cnt);
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
                        let cnt: uint;
                        {
                            let mut in_reader = self.in_buff.read_buffer();
                            let slice_in = in_reader.next(self.block_size);
                            let slice_out = out_write_buff.next(self.block_size);
                            cnt = func(slice_in, slice_out, eof);
                        }
                        out_write_buff.rewind(self.block_size - cnt);
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
                        let cnt: uint;
                        {
                            let mut in_reader = self.in_buff.read_buffer();
                            let slice_in = in_reader.next(self.block_size);
                            let slice_out = out_write_buff.next(self.block_size);
                            cnt = func(slice_in, slice_out, eof);
                        }
                        out_write_buff.rewind(self.block_size - cnt);
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
        let enc_fun: |&[u8], &mut [u8], bool| -> uint = |slice_in, slice_out, _| {
            self.algo.encrypt_block(slice_in, slice_out);
            self.algo.block_size()
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

pub struct EcbNoPaddingDecryptor<T> {
    priv algo: T,
    priv block_engine: BlockEngine
}

impl <T: BlockDecryptor> EcbNoPaddingDecryptor<T> {
    pub fn new(algo: T) -> EcbNoPaddingDecryptor<T> {
        let block_size = algo.block_size();
        EcbNoPaddingDecryptor {
            algo: algo,
            block_engine: BlockEngine::new(block_size),
        }
    }
}

impl <T: BlockDecryptor> Decryptor for EcbNoPaddingDecryptor<T> {
    fn decrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, eof: bool)
            -> BufferResult {
        let dec_fun: |&[u8], &mut [u8], bool| -> uint = |slice_in, slice_out, _| {
            self.algo.decrypt_block(slice_in, slice_out);
            self.algo.block_size()
        };
        let result = self.block_engine.process(input, output, eof, dec_fun);
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
        let enc_fun: |&[u8], &mut [u8], bool| -> uint = |slice_in, slice_out, _| {
            self.algo.encrypt_block(slice_in, slice_out);
            self.algo.block_size()
        };
        let result = do self.block_engine.process(input, output, eof) |a, b, c| {
            enc_fun(a, b, c)
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
                    enc_fun(a, b, c)
                };
            }
            _ => return result
        }
    }
}

pub struct EcbPkcs7PaddingDecryptor<T> {
    priv algo: T,
    priv block_engine: BlockEngine
}

impl <T: BlockDecryptor> EcbPkcs7PaddingDecryptor<T> {
    pub fn new(algo: T) -> EcbPkcs7PaddingDecryptor<T> {
        let block_size = algo.block_size();
        EcbPkcs7PaddingDecryptor {
            algo: algo,
            block_engine: BlockEngine::new(block_size),
        }
    }
}

impl <T: BlockDecryptor> Decryptor for EcbPkcs7PaddingDecryptor<T> {
    fn decrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, eof: bool)
            -> BufferResult {
        let dec_fun: |&[u8], &mut [u8], bool| -> uint = |slice_in, slice_out, last_block| {
            self.algo.decrypt_block(slice_in, slice_out);
            if last_block {
                // TODO - verify all bytes!
                let bs = self.algo.block_size();
                bs - (slice_out[bs - 1] as uint)
            } else {
                self.algo.block_size()
            }
        };
        let result = do self.block_engine.process(input, output, eof) |a, b, c| {
            dec_fun(a, b, c)
        };
        return result
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
        let enc_fun: |&[u8], &mut [u8], bool| -> uint = |slice_in, slice_out, _| {
            for ((x, y), o) in self.temp1.iter().zip(slice_in.iter()).zip(self.temp2.mut_iter()) {
                *o = *x ^ *y;
            }
            self.algo.encrypt_block(self.temp2, self.temp1);
            vec::bytes::copy_memory(slice_out, self.temp1, self.algo.block_size());
            self.algo.block_size()
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
        let enc_fun: |&[u8], &mut [u8], bool| -> uint = |slice_in, slice_out, _| {
            for ((x, y), o) in self.temp1.iter().zip(slice_in.iter()).zip(self.temp2.mut_iter()) {
                *o = *x ^ *y;
            }
            self.algo.encrypt_block(self.temp2, self.temp1);
            vec::bytes::copy_memory(slice_out, self.temp1, self.algo.block_size());
            self.algo.block_size()
        };
        let result = do self.block_engine.process(input, output, eof) |a, b, c| {
            enc_fun(a, b, c)
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
                    enc_fun(a, b, c)
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
}








*/






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









#[cfg(test_OFF)]
mod test {
    use aessafe;
    use blockmodes::{EcbNoPaddingEncryptor, EcbNoPaddingDecryptor, EcbPkcs7PaddingEncryptor,
        EcbPkcs7PaddingDecryptor};
    use buffer::{RefReadBuffer, RefWriteBuffer};
    use symmetriccipher::{Encryptor, Decryptor};

    use std::vec;

    trait CipherTest {
        fn get_plain<'a>(&'a self) -> &'a [u8];
        fn get_cipher<'a>(&'a self) -> &'a [u8];
    }

    struct EcbTest {
        key: ~[u8],
        plain: ~[u8],
        cipher: ~[u8]
    }

    impl CipherTest for EcbTest {
        fn get_plain<'a>(&'a self) -> &'a [u8] {
            self.plain.slice(0, self.plain.len())
        }
        fn get_cipher<'a>(&'a self) -> &'a [u8] {
            self.cipher.slice(0, self.cipher.len())
        }
    }

    struct CbcTest {
        key: ~[u8],
        iv: ~[u8],
        plain: ~[u8],
        cipher: ~[u8]
    }

    impl CipherTest for CbcTest {
        fn get_plain<'a>(&'a self) -> &'a [u8] {
            self.plain.slice(0, self.plain.len())
        }
        fn get_cipher<'a>(&'a self) -> &'a [u8] {
            self.cipher.slice(0, self.cipher.len())
        }
    }

    fn aes_ecb_no_padding_tests() -> ~[EcbTest] {
        ~[
            EcbTest {
                key: ~[0, ..16],
                plain: ~[0, ..32],
                cipher: ~[
                    0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
                    0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e,
                    0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
                    0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e ]
            }
        ]
    }

    fn aes_ecb_pkcs_padding_tests() -> ~[EcbTest] {
        ~[
            EcbTest {
                key: ~[0, ..16],
                plain: ~[0, ..32],
                cipher: ~[
                    0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
                    0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e,
                    0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
                    0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e,
                    0x01, 0x43, 0xdb, 0x63, 0xee, 0x66, 0xb0, 0xcd,
                    0xff, 0x9f, 0x69, 0x91, 0x76, 0x80, 0x15, 0x1e ]
            },
            EcbTest {
                key: ~[0, ..16],
                plain: ~[0, ..33],
                cipher: ~[
                    0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
                    0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e,
                    0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
                    0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e,
                    0x7a, 0xdc, 0x99, 0xb2, 0x9e, 0x82, 0xb1, 0xb2,
                    0xb0, 0xa6, 0x5a, 0x38, 0xbc, 0x57, 0x8a, 0x01 ]
            }
        ]
    }

    fn aes_cbc_no_padding_tests() -> ~[CbcTest] {
        ~[
            CbcTest {
                key: ~[0, ..16],
                iv: ~[0, ..16],
                plain: ~[0, ..32],
                cipher: ~[
                    0x72, 0xe1, 0x63, 0xaf, 0x20, 0x38, 0x29, 0x1e,
                    0x91, 0x1f, 0x86, 0xbb, 0x48, 0xca, 0xa9, 0x68,
                    0x35, 0x01, 0xbc, 0x97, 0x4d, 0x74, 0xc5, 0x07,
                    0xb8, 0x19, 0x67, 0x5e, 0x0b, 0x2d, 0xb8, 0xe3 ]
            }
        ]
    }

    fn aes_cbc_pkcs_padding_tests() -> ~[CbcTest] {
        ~[
            CbcTest {
                key: ~[0, ..16],
                iv: ~[0, ..16],
                plain: ~[0, ..32],
                cipher: ~[
                    0x79, 0xf2, 0x17, 0x8e, 0x3a, 0xcc, 0x12, 0xa2,
                    0x37, 0x3e, 0x99, 0xbc, 0x32, 0xb6, 0x9e, 0xfe,
                    0xef, 0x09, 0x08, 0x02, 0xc1, 0xa9, 0x28, 0x72,
                    0xc5, 0x4d, 0x50, 0xd2, 0x63, 0x5b, 0x91, 0xf5,
                    0xa0, 0x69, 0x8f, 0x4c, 0x25, 0x48, 0xab, 0x09,
                    0xd6, 0x2d, 0xab, 0x35, 0xd2, 0x40, 0xa7, 0x89 ]
            },
            CbcTest {
                key: ~[0, ..16],
                iv: ~[0, ..16],
                plain: ~[0, ..33],
                cipher: ~[
                    0x84, 0xd9, 0x09, 0x97, 0x8e, 0xb4, 0x93, 0xa4,
                    0x9c, 0x74, 0xf1, 0xa9, 0xf1, 0x79, 0x20, 0xda,
                    0xd6, 0x05, 0x89, 0xf4, 0x43, 0x64, 0xfd, 0x3b,
                    0x49, 0x75, 0x7d, 0xc1, 0x63, 0x0a, 0xc3, 0x87,
                    0x5d, 0x46, 0x4a, 0xea, 0xaa, 0x9a, 0x0d, 0x17,
                    0x8a, 0xc1, 0x25, 0x59, 0x4c, 0x1e, 0xf6, 0x99 ]
            }
        ]
    }

    fn get_aes_ecb_no_padding(test: &EcbTest)
            -> (EcbNoPaddingEncryptor<aessafe::AesSafe128Encryptor>,
                EcbNoPaddingDecryptor<aessafe::AesSafe128Decryptor>) {
        let aes_enc = aessafe::AesSafe128Encryptor::new(test.key);
        let aes_dec = aessafe::AesSafe128Decryptor::new(test.key);
        (EcbNoPaddingEncryptor::new(aes_enc), EcbNoPaddingDecryptor::new(aes_dec))
    }

    fn get_aes_ecb_pkcs_padding(test: &EcbTest)
            -> (EcbPkcs7PaddingEncryptor<aessafe::AesSafe128Encryptor>,
                EcbPkcs7PaddingDecryptor<aessafe::AesSafe128Decryptor>) {
        let aes_enc = aessafe::AesSafe128Encryptor::new(test.key);
        let aes_dec = aessafe::AesSafe128Decryptor::new(test.key);
        (EcbPkcs7PaddingEncryptor::new(aes_enc), EcbPkcs7PaddingDecryptor::new(aes_dec))
    }

    fn run_test<T: CipherTest, E: Encryptor, D: Decryptor>(
            test: &T,
            enc: &mut E,
            dec: &mut D) {
        let mut cipher_out = vec::from_elem(test.get_cipher().len(), 0u8);
        {
            let mut buff_in = RefReadBuffer::new(test.get_plain());
            let mut buff_out = RefWriteBuffer::new(cipher_out);
            match enc.encrypt(&mut buff_in, &mut buff_out, true) {
                BufferOverflow => fail!("Encryption not completed"),
                _ => {}
            }
        }
        assert!(test.get_cipher() == cipher_out);

        let mut plain_out = vec::from_elem(test.get_plain().len(), 0u8);
        {
            let mut buff_in = RefReadBuffer::new(test.get_cipher());
            let mut buff_out = RefWriteBuffer::new(plain_out);
            match dec.decrypt(&mut buff_in, &mut buff_out, true) {
                BufferOverflow => fail!("Decryption not completed"),
                _ => {}
            }
        }
        assert!(test.get_plain() == plain_out);
    }

    #[test]
    fn aes_ecb_no_padding() {
        let tests = aes_ecb_no_padding_tests();
        for test in tests.iter() {
            let (mut enc, mut dec) = get_aes_ecb_no_padding(test);
            run_test(test, &mut enc, &mut dec);
        }
    }

    #[test]
    fn aes_ecb_pkcs_padding() {
        let tests = aes_ecb_pkcs_padding_tests();
        for test in tests.iter() {
            let (mut enc, mut dec) = get_aes_ecb_pkcs_padding(test);
            run_test(test, &mut enc, &mut dec);
        }
    }
}
















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
