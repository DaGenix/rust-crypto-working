// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// TODO - Optimize the XORs
// TODO - Try to speed up CBC modes by reducing buffer copies (history for output?)

use buffer::{ReadBuffer, WriteBuffer, OwnedReadBuffer, OwnedWriteBuffer, BufferResult,
    BufferUnderflow, BufferOverflow};
use symmetriccipher::{BlockEncryptor, BlockEncryptorX8, Encryptor, BlockDecryptor, Decryptor};

use std::vec;

trait BlockProcessor {
    fn process_block(&mut self, history: &[u8], input: &[u8], output: &mut [u8]);
    #[allow(unused_variable)]
    fn last_input<W: WriteBuffer>(&mut self, input_buffer: &mut W) -> bool { true }
    #[allow(unused_variable)]
    fn last_output<W: WriteBuffer>(&mut self, output_buffer: &mut W) -> bool { true }
}

enum BlockEngineState {
    ScratchEmpty,
    NeedInput,
    NeedOutput,
    LastInput,
    Finished,
    Error
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
    fn fast_mode<R: ReadBuffer, W: WriteBuffer>(
            &mut self,
            input: &mut R,
            output: &mut W,
            eof: bool) -> BlockEngineState {
        let has_next = || {
            let enough_input = input.remaining() > self.in_size ||
                (eof && input.remaining() >= self.in_size);
            let enough_output = output.remaining() >= self.out_size;
            (enough_input, enough_output)
        };
        let update_history = |last_in: &[u8]| {
            vec::bytes::copy_memory(
                self.hist_scratch,
                last_in.slice_from(last_in.len() - self.hist_size),
                self.hist_size);
        };
        let try_complete = |next_input_ok: bool, next_iter_ok: bool| {
            if next_iter_ok {
                input.rewind(self.hist_size);
                None
            } else {
                let last_input_block = eof && !next_input_ok;
                if  last_input_block {
                    if self.processor.last_output(output) {
                        // TODO - process the padding directly here so that we can avoid copying
                        // into the history_buffer.
                        Some(NeedInput)
                    } else {
                        Some(Error)
                    }
                } else {
                    if input.is_empty() {
                        Some(ScratchEmpty)
                    } else {
                        Some(NeedInput)
                    }
                }
            }
        };

        match has_next() {
            (true, true) => {
                let next_input_ok: bool;
                let next_iter_ok: bool;

                {
                    let next_in = input.take_next(self.in_size);
                    let next_out = output.take_next(self.out_size);
                    self.processor.process_block(self.hist_scratch.as_slice(), next_in, next_out);
                    match has_next() {
                        (a, b) => { next_input_ok = a; next_iter_ok = a && b; }
                    }
                    if !next_iter_ok {
                        update_history(next_in);
                    }
                }

                match try_complete(next_input_ok, next_iter_ok) {
                    Some(r) => return r,
                    None => { }
                }
            }
            _ => {
                if input.is_empty() {
                    return ScratchEmpty;
                } else {
                    return NeedInput;
                }
            }
        }

        loop {
            let next_input_ok: bool;
            let next_iter_ok: bool;

            {
                let next_in = input.take_next(self.hist_size + self.in_size);
                let next_out = output.take_next(self.out_size);
                self.processor.process_block(
                    next_in.slice_to(self.hist_size),
                    next_in.slice_from(self.hist_size),
                    next_out);
                match has_next() {
                    (a, b) => { next_input_ok = a; next_iter_ok = a && b; }
                }
                if !next_iter_ok {
                    update_history(next_in);
                }
            }

            match try_complete(next_input_ok, next_iter_ok) {
                Some(r) => return r,
                None => { }
            }
        }
    }
    fn process<R: ReadBuffer, W: WriteBuffer>(
            &mut self,
            input: &mut R,
            output: &mut W,
            eof: bool) -> Result<BufferResult, &'static str> {
        loop {
            match self.state {
                ScratchEmpty => {
                    self.state = self.fast_mode(input, output, eof);
                    match self.state {
                        ScratchEmpty => {
                            if input.is_empty() {
                                return Ok(BufferUnderflow);
                            }
                        }
                        _ => {}
                    }
                }
                NeedInput => {
                    input.push_to(&mut self.in_scratch);
                    if self.in_scratch.is_full() && (eof || !input.is_empty()) {
                        let mut rin = self.in_scratch.take_read_buffer();
                        let mut wout = self.out_write_scratch.take_unwrap();

                        {
                            let next_in = rin.take_remaining();
                            let next_out = wout.take_remaining();
                            self.processor.process_block(
                                self.hist_scratch.as_slice(),
                                next_in,
                                next_out);
                            vec::bytes::copy_memory(
                                self.hist_scratch,
                                next_in.slice_from(self.in_size - self.hist_size),
                                self.hist_size);
                        }

                        if eof && input.remaining() < self.in_size {
                            if self.processor.last_output(&mut wout) {
                                self.state = NeedOutput;
                            } else {
                                self.state = Error;
                            }
                        } else {
                            self.state = NeedOutput;
                        }

                        self.out_read_scratch = Some(wout.into_read_buffer());
                    } else {
                        if eof {
                            self.state = LastInput;
                        } else {
                            return Ok(BufferUnderflow);
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
                        return Ok(BufferOverflow);
                    }
                }
                LastInput => {
                    if self.processor.last_input(&mut self.in_scratch) {
                        if self.in_scratch.is_full() {
                            let mut rin = self.in_scratch.take_read_buffer();
                            let mut wout = self.out_write_scratch.take_unwrap();
                            {
                                let next_in = rin.take_remaining();
                                let next_out = wout.take_remaining();
                                self.processor.process_block(
                                    self.hist_scratch.as_slice(),
                                    next_in,
                                    next_out);
                            }
                            self.out_read_scratch = Some(wout.into_read_buffer());
                        }
                        self.state = Finished;
                    } else {
                        self.state = Error;
                    }
                }
                Finished => {
                    match self.out_read_scratch {
                        Some(ref mut rout) => {
                            rout.push_to(output);
                            if rout.is_empty() {
                                return Ok(BufferUnderflow);
                            } else {
                                return Ok(BufferOverflow);
                            }
                        }
                        None => { return Ok(BufferUnderflow); }
                    }
                }
                Error => {
                    // TODO - Better error messages / codes
                    return Err("Failed somewhere.");
                }
            }
        }
    }
    fn reset(&mut self) {
        self.state = ScratchEmpty;
        self.in_scratch.reset();
        if self.out_read_scratch.is_some() {
            let ors = self.out_read_scratch.take_unwrap();
            let ows = ors.into_write_buffer();
            self.out_write_scratch = Some(ows);
        } else {
            self.out_write_scratch.as_mut().mutate( |ows| { ows.reset(); ows } );
        }
    }
    fn reset_with_history(&mut self, history: &[u8]) {
        self.reset();
        vec::bytes::copy_memory(self.hist_scratch, history, self.hist_size);
    }
    fn get_mut_processor<'a>(&'a mut self) -> &'a mut P { &mut self.processor }
}

fn add_pkcs_padding<W: WriteBuffer>(input_buffer: &mut W) -> bool {
    let rem = input_buffer.remaining();
    assert!(rem != 0 && rem <= 255);
    for v in input_buffer.take_remaining().mut_iter() {
        *v = rem as u8;
    }
    true
}

fn strip_pkcs_padding<W: WriteBuffer>(output_buffer: &mut W) -> bool {
    let last_byte: u8;
    {
        let mut rb = output_buffer.peek_read_buffer();
        let data = rb.take_remaining();
        last_byte = *data.last();
        for x in data.iter().invert().take(last_byte as uint) {
            if *x != last_byte {
                return false;
            }
        }
    }
    output_buffer.rewind(last_byte as uint);
    true
}

struct EcbNoPaddingEncryptorProcessor<T> {
    algo: T
}

impl <T: BlockEncryptor> BlockProcessor for EcbNoPaddingEncryptorProcessor<T> {
    fn process_block(&mut self, _: &[u8], input: &[u8], output: &mut [u8]) {
        self.algo.encrypt_block(input, output);
    }
    fn last_input<W: WriteBuffer>(&mut self, input_buffer: &mut W) -> bool {
        input_buffer.is_empty()
    }
}

pub struct EcbNoPaddingEncryptor<T> {
    priv block_engine: BlockEngine<EcbNoPaddingEncryptorProcessor<T>>
}

impl <T: BlockEncryptor> EcbNoPaddingEncryptor<T> {
    pub fn new(algo: T) -> EcbNoPaddingEncryptor<T> {
        let block_size = algo.block_size();
        let processor = EcbNoPaddingEncryptorProcessor {
            algo: algo
        };
        EcbNoPaddingEncryptor {
            block_engine: BlockEngine::new(processor, block_size, block_size)
        }
    }
    pub fn reset(&mut self) {
        self.block_engine.reset();
    }
}

impl <T: BlockEncryptor> Encryptor for EcbNoPaddingEncryptor<T> {
    fn encrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, eof: bool)
            -> Result<BufferResult, &'static str> {
        self.block_engine.process(input, output, eof)
    }
}

struct EcbNoPaddingDecryptorProcessor<T> {
    algo: T
}

impl <T: BlockDecryptor> BlockProcessor for EcbNoPaddingDecryptorProcessor<T> {
    fn process_block(&mut self, _: &[u8], input: &[u8], output: &mut [u8]) {
        self.algo.decrypt_block(input, output);
    }
    fn last_input<W: WriteBuffer>(&mut self, input_buffer: &mut W) -> bool {
        input_buffer.is_empty()
    }
}

pub struct EcbNoPaddingDecryptor<T> {
    priv block_engine: BlockEngine<EcbNoPaddingDecryptorProcessor<T>>
}

impl <T: BlockDecryptor> EcbNoPaddingDecryptor<T> {
    pub fn new(algo: T) -> EcbNoPaddingDecryptor<T> {
        let block_size = algo.block_size();
        let processor = EcbNoPaddingDecryptorProcessor {
            algo: algo
        };
        EcbNoPaddingDecryptor {
            block_engine: BlockEngine::new(processor, block_size, block_size)
        }
    }
    pub fn reset(&mut self) {
        self.block_engine.reset();
    }
}

impl <T: BlockDecryptor> Decryptor for EcbNoPaddingDecryptor<T> {
    fn decrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, eof: bool)
            -> Result<BufferResult, &'static str> {
        self.block_engine.process(input, output, eof)
    }
}

struct EcbPkcsPaddingEncryptorProcessor<T> {
    algo: T
}

impl <T: BlockEncryptor> BlockProcessor for EcbPkcsPaddingEncryptorProcessor<T> {
    fn process_block(&mut self, _: &[u8], input: &[u8], output: &mut [u8]) {
        self.algo.encrypt_block(input, output);
    }
    fn last_input<W: WriteBuffer>(&mut self, input_buffer: &mut W) -> bool {
        add_pkcs_padding(input_buffer)
    }
}

pub struct EcbPkcsPaddingEncryptor<T> {
    priv block_engine: BlockEngine<EcbPkcsPaddingEncryptorProcessor<T>>
}

impl <T: BlockEncryptor> EcbPkcsPaddingEncryptor<T> {
    pub fn new(algo: T) -> EcbPkcsPaddingEncryptor<T> {
        let block_size = algo.block_size();
        let processor = EcbPkcsPaddingEncryptorProcessor {
            algo: algo
        };
        EcbPkcsPaddingEncryptor {
            block_engine: BlockEngine::new(processor, block_size, block_size)
        }
    }
    pub fn reset(&mut self) {
        self.block_engine.reset();
    }
}

impl <T: BlockEncryptor> Encryptor for EcbPkcsPaddingEncryptor<T> {
    fn encrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, eof: bool)
            -> Result<BufferResult, &'static str> {
        self.block_engine.process(input, output, eof)
    }
}

struct EcbPkcsPaddingDecryptorProcessor<T> {
    algo: T
}

impl <T: BlockDecryptor> BlockProcessor for EcbPkcsPaddingDecryptorProcessor<T> {
    fn process_block(&mut self, _: &[u8], input: &[u8], output: &mut [u8]) {
        self.algo.decrypt_block(input, output);
    }
    fn last_output<W: WriteBuffer>(&mut self, output_buffer: &mut W) -> bool {
        strip_pkcs_padding(output_buffer)
    }
}

pub struct EcbPkcsPaddingDecryptor<T> {
    priv block_engine: BlockEngine<EcbPkcsPaddingDecryptorProcessor<T>>
}

impl <T: BlockDecryptor> EcbPkcsPaddingDecryptor<T> {
    pub fn new(algo: T) -> EcbPkcsPaddingDecryptor<T> {
        let block_size = algo.block_size();
        let processor = EcbPkcsPaddingDecryptorProcessor {
            algo: algo
        };
        EcbPkcsPaddingDecryptor {
            block_engine: BlockEngine::new(processor, block_size, block_size)
        }
    }
    pub fn reset(&mut self) {
        self.block_engine.reset();
    }
}

impl <T: BlockDecryptor> Decryptor for EcbPkcsPaddingDecryptor<T> {
    fn decrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, eof: bool)
            -> Result<BufferResult, &'static str> {
        self.block_engine.process(input, output, eof)
    }
}

struct CbcNoPaddingEncryptorProcessor<T> {
    algo: T,
    temp1: ~[u8],
    temp2: ~[u8]
}

impl <T> CbcNoPaddingEncryptorProcessor<T> {
    fn reset(&mut self, iv: &[u8]) {
        vec::bytes::copy_memory(self.temp1, iv, iv.len());
    }
}

impl <T: BlockEncryptor> BlockProcessor for CbcNoPaddingEncryptorProcessor<T> {
    fn process_block(&mut self, _: &[u8], input: &[u8], output: &mut [u8]) {
        for ((x, y), o) in self.temp1.iter().zip(input.iter()).zip(self.temp2.mut_iter()) {
            *o = *x ^ *y;
        }
        self.algo.encrypt_block(self.temp2, self.temp1);
        vec::bytes::copy_memory(output, self.temp1, self.algo.block_size());
    }
    fn last_input<W: WriteBuffer>(&mut self, input_buffer: &mut W) -> bool {
        input_buffer.is_empty()
    }
}

pub struct CbcNoPaddingEncryptor<T> {
    priv block_engine: BlockEngine<CbcNoPaddingEncryptorProcessor<T>>
}

impl <T: BlockEncryptor> CbcNoPaddingEncryptor<T> {
    pub fn new(algo: T, iv: ~[u8]) -> CbcNoPaddingEncryptor<T> {
        let block_size = algo.block_size();
        let processor = CbcNoPaddingEncryptorProcessor {
            algo: algo,
            temp1: iv,
            temp2: vec::from_elem(block_size, 0u8)
        };
        CbcNoPaddingEncryptor {
            block_engine: BlockEngine::new(processor, block_size, block_size)
        }
    }
    pub fn reset(&mut self, iv: &[u8]) {
        self.block_engine.reset();
        self.block_engine.get_mut_processor().reset(iv);
    }
}

impl <T: BlockEncryptor> Encryptor for CbcNoPaddingEncryptor<T> {
    fn encrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, eof: bool)
            -> Result<BufferResult, &'static str> {
        self.block_engine.process(input, output, eof)
    }
}

struct CbcNoPaddingDecryptorProcessor<T> {
    algo: T,
    temp: ~[u8]
}

impl <T: BlockDecryptor> BlockProcessor for CbcNoPaddingDecryptorProcessor<T> {
    fn process_block(&mut self, history: &[u8], input: &[u8], output: &mut [u8]) {
        self.algo.decrypt_block(input, self.temp);
        for ((x, y), o) in self.temp.iter().zip(history.iter()).zip(output.mut_iter()) {
            *o = *x ^ *y;
        }
    }
    fn last_input<W: WriteBuffer>(&mut self, input_buffer: &mut W) -> bool {
        input_buffer.is_empty()
    }
}

pub struct CbcNoPaddingDecryptor<T> {
    priv block_engine: BlockEngine<CbcNoPaddingDecryptorProcessor<T>>
}

impl <T: BlockDecryptor> CbcNoPaddingDecryptor<T> {
    pub fn new(algo: T, iv: ~[u8]) -> CbcNoPaddingDecryptor<T> {
        let block_size = algo.block_size();
        let processor = CbcNoPaddingDecryptorProcessor {
            algo: algo,
            temp: vec::from_elem(block_size, 0u8)
        };
        CbcNoPaddingDecryptor {
            block_engine: BlockEngine::new_with_history(processor, block_size, block_size, iv)
        }
    }
    pub fn reset(&mut self, iv: &[u8]) {
        self.block_engine.reset_with_history(iv);
    }
}

impl <T: BlockDecryptor> Decryptor for CbcNoPaddingDecryptor<T> {
    fn decrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, eof: bool)
            -> Result<BufferResult, &'static str> {
        self.block_engine.process(input, output, eof)
    }
}

struct CbcPkcsPaddingEncryptorProcessor<T> {
    algo: T,
    temp1: ~[u8],
    temp2: ~[u8]
}

impl <T> CbcPkcsPaddingEncryptorProcessor<T> {
    fn reset(&mut self, iv: &[u8]) {
        vec::bytes::copy_memory(self.temp1, iv, iv.len());
    }
}

impl <T: BlockEncryptor> BlockProcessor for CbcPkcsPaddingEncryptorProcessor<T> {
    fn process_block(&mut self, _: &[u8], input: &[u8], output: &mut [u8]) {
        for ((x, y), o) in self.temp1.iter().zip(input.iter()).zip(self.temp2.mut_iter()) {
            *o = *x ^ *y;
        }
        self.algo.encrypt_block(self.temp2, self.temp1);
        vec::bytes::copy_memory(output, self.temp1, self.algo.block_size());
    }
    fn last_input<W: WriteBuffer>(&mut self, input_buffer: &mut W) -> bool {
        add_pkcs_padding(input_buffer)
    }
}

pub struct CbcPkcsPaddingEncryptor<T> {
    priv block_engine: BlockEngine<CbcPkcsPaddingEncryptorProcessor<T>>
}

impl <T: BlockEncryptor> CbcPkcsPaddingEncryptor<T> {
    pub fn new(algo: T, iv: ~[u8]) -> CbcPkcsPaddingEncryptor<T> {
        let block_size = algo.block_size();
        let processor = CbcPkcsPaddingEncryptorProcessor {
            algo: algo,
            temp1: iv,
            temp2: vec::from_elem(block_size, 0u8)
        };
        CbcPkcsPaddingEncryptor {
            block_engine: BlockEngine::new(processor, block_size, block_size)
        }
    }
    pub fn reset(&mut self, iv: &[u8]) {
        self.block_engine.reset();
        self.block_engine.get_mut_processor().reset(iv);
    }
}

impl <T: BlockEncryptor> Encryptor for CbcPkcsPaddingEncryptor<T> {
    fn encrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, eof: bool)
            -> Result<BufferResult, &'static str> {
        self.block_engine.process(input, output, eof)
    }
}

struct CbcPkcsPaddingDecryptorProcessor<T> {
    algo: T,
    temp: ~[u8]
}

impl <T: BlockDecryptor> BlockProcessor for CbcPkcsPaddingDecryptorProcessor<T> {
    fn process_block(&mut self, history: &[u8], input: &[u8], output: &mut [u8]) {
        self.algo.decrypt_block(input, self.temp);
        for ((x, y), o) in self.temp.iter().zip(history.iter()).zip(output.mut_iter()) {
            *o = *x ^ *y;
        }
    }
    fn last_output<W: WriteBuffer>(&mut self, output_buffer: &mut W) -> bool {
        strip_pkcs_padding(output_buffer)
    }
}

pub struct CbcPkcsPaddingDecryptor<T> {
    priv block_engine: BlockEngine<CbcPkcsPaddingDecryptorProcessor<T>>
}

impl <T: BlockDecryptor> CbcPkcsPaddingDecryptor<T> {
    pub fn new(algo: T, iv: ~[u8]) -> CbcPkcsPaddingDecryptor<T> {
        let block_size = algo.block_size();
        let processor = CbcPkcsPaddingDecryptorProcessor {
            algo: algo,
            temp: vec::from_elem(block_size, 0u8)
        };
        CbcPkcsPaddingDecryptor {
            block_engine: BlockEngine::new_with_history(processor, block_size, block_size, iv)
        }
    }
    pub fn reset(&mut self, iv: &[u8]) {
        self.block_engine.reset_with_history(iv);
    }
}

impl <T: BlockDecryptor> Decryptor for CbcPkcsPaddingDecryptor<T> {
    fn decrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, eof: bool)
            -> Result<BufferResult, &'static str> {
        self.block_engine.process(input, output, eof)
    }
}

fn min3(a: uint, b: uint, c: uint) -> uint {
    if a < b {
        if a < c {
            a
        } else {
            c
        }
    } else {
        if b < c {
            b
        } else {
            c
        }
    }
}

fn add_ctr(ctr: &mut [u8], mut ammount: u8) {
    for i in ctr.mut_iter().invert() {
        let prev = *i;
        *i += ammount;
        if *i >= prev {
            break;
        }
        ammount = 1;
    }
}

pub struct CtrMode<A> {
    priv algo: A,
    priv ctr: ~[u8],
    priv bytes: OwnedReadBuffer
}

impl <A: BlockEncryptor> CtrMode<A> {
    fn new(algo: A, ctr: ~[u8]) -> CtrMode<A> {
        let block_size = algo.block_size();
        CtrMode {
            algo: algo,
            ctr: ctr,
            bytes: OwnedReadBuffer::new_with_len(vec::from_elem(block_size, 0u8), 0)
        }
    }
    fn reset(&mut self, ctr: &[u8]) {
        vec::bytes::copy_memory(self.ctr, ctr, self.algo.block_size());
        self.bytes.reset();
    }
}

impl <A: BlockEncryptor> Encryptor for CtrMode<A> {
    fn encrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, _: bool)
            -> Result<BufferResult, &'static str> {
        loop {
            if input.is_empty() {
                return Ok(BufferUnderflow);
            }
            if output.is_full() {
                return Ok(BufferOverflow)
            }
            if self.bytes.is_empty() {
                let mut wb = self.bytes.borrow_write_buffer();
                self.algo.encrypt_block(self.ctr, wb.take_remaining());
                add_ctr(self.ctr, 1);
            }
            let count = min3(self.bytes.remaining(), input.remaining(), output.remaining());
            let bytes_it = self.bytes.take_next(count).iter();
            let in_it = input.take_next(count).iter();
            let out_it = output.take_next(count).mut_iter();
            for ((x, y), o) in bytes_it.zip(in_it).zip(out_it) {
                *o = *x ^ *y;
            }
        }
    }
}

impl <A: BlockEncryptor> Decryptor for CtrMode<A> {
    fn decrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, eof: bool)
            -> Result<BufferResult, &'static str> {
        self.encrypt(input, output, eof)
    }
}

pub struct CtrModeX8<A> {
    priv algo: A,
    priv ctr_x8: ~[u8],
    priv bytes: OwnedReadBuffer
}

fn construct_ctr_x8(in_ctr: &[u8], out_ctr_x8: &mut [u8]) {
    for (i, ctr_i) in out_ctr_x8.mut_chunks(in_ctr.len()).enumerate() {
        vec::bytes::copy_memory(ctr_i, in_ctr, in_ctr.len());
        add_ctr(ctr_i, i as u8);
    }
}

impl <A: BlockEncryptorX8> CtrModeX8<A> {
    fn new(algo: A, ctr: &[u8]) -> CtrModeX8<A> {
        let block_size = algo.block_size();
        let mut ctr_x8 = vec::from_elem(block_size * 8, 0u8);
        construct_ctr_x8(ctr, ctr_x8);
        CtrModeX8 {
            algo: algo,
            ctr_x8: ctr_x8,
            bytes: OwnedReadBuffer::new_with_len(vec::from_elem(block_size * 8, 0u8), 0)
        }
    }
    fn reset(&mut self, ctr: &[u8]) {
        construct_ctr_x8(ctr, self.ctr_x8);
        self.bytes.reset();
    }
}

impl <A: BlockEncryptorX8> Encryptor for CtrModeX8<A> {
    fn encrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, _: bool)
            -> Result<BufferResult, &'static str> {
        loop {
            if input.is_empty() {
                return Ok(BufferUnderflow);
            }
            if output.is_full() {
                return Ok(BufferOverflow)
            }
            // TODO - Can some of this be combined with regular CtrMode?
            if self.bytes.is_empty() {
                let mut wb = self.bytes.borrow_write_buffer();
                self.algo.encrypt_block_x8(self.ctr_x8, wb.take_remaining());
                for ctr_i in self.ctr_x8.mut_chunks(self.algo.block_size()) {
                    add_ctr(ctr_i, 8);
                }
            }
            let count = min3(self.bytes.remaining(), input.remaining(), output.remaining());
            let bytes_it = self.bytes.take_next(count).iter();
            let in_it = input.take_next(count).iter();
            let out_it = output.take_next(count).mut_iter();
            for ((x, y), o) in bytes_it.zip(in_it).zip(out_it) {
                *o = *x ^ *y;
            }
        }
    }
}

impl <A: BlockEncryptorX8> Decryptor for CtrModeX8<A> {
    fn decrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, eof: bool)
            -> Result<BufferResult, &'static str> {
        self.encrypt(input, output, eof)
    }
}

#[cfg(test)]
mod test {
    use aessafe;
    use aesni;
    use blockmodes::{EcbNoPaddingEncryptor, EcbNoPaddingDecryptor, EcbPkcsPaddingEncryptor,
        EcbPkcsPaddingDecryptor, CbcNoPaddingEncryptor, CbcNoPaddingDecryptor,
        CbcPkcsPaddingEncryptor, CbcPkcsPaddingDecryptor, CtrMode, CtrModeX8};
    use buffer::{RefReadBuffer, RefWriteBuffer};
    use symmetriccipher::{Encryptor, Decryptor};

    use std::vec;
    use extra::test::BenchHarness;

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

    struct CtrTest {
        key: ~[u8],
        ctr: ~[u8],
        plain: ~[u8],
        cipher: ~[u8]
    }

    impl CipherTest for CtrTest {
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
                key: ~[1, ..16],
                iv: ~[3, ..16],
                plain: ~[2, ..32],
                cipher: ~[
                    0x5e, 0x77, 0xe5, 0x9f, 0x8f, 0x85, 0x94, 0x34,
                    0x89, 0xa2, 0x41, 0x49, 0xc7, 0x5f, 0x4e, 0xc9,
                    0xe0, 0x9a, 0x77, 0x36, 0xfb, 0xc8, 0xb2, 0xdc,
                    0xb3, 0xfb, 0x9f, 0xc0, 0x31, 0x4c, 0xb0, 0xb1 ]
            }
        ]
    }

    fn aes_cbc_pkcs_padding_tests() -> ~[CbcTest] {
        ~[
            CbcTest {
                key: ~[1, ..16],
                iv: ~[3, ..16],
                plain: ~[2, ..32],
                cipher: ~[
                    0x5e, 0x77, 0xe5, 0x9f, 0x8f, 0x85, 0x94, 0x34,
                    0x89, 0xa2, 0x41, 0x49, 0xc7, 0x5f, 0x4e, 0xc9,
                    0xe0, 0x9a, 0x77, 0x36, 0xfb, 0xc8, 0xb2, 0xdc,
                    0xb3, 0xfb, 0x9f, 0xc0, 0x31, 0x4c, 0xb0, 0xb1,
                    0xa4, 0xc2, 0xe4, 0x62, 0xef, 0x7a, 0xe3, 0x7e,
                    0xef, 0x88, 0xf3, 0x27, 0xbd, 0x9c, 0xc8, 0x4d ]
            },
            CbcTest {
                key: ~[1, ..16],
                iv: ~[3, ..16],
                plain: ~[2, ..33],
                cipher: ~[
                    0x5e, 0x77, 0xe5, 0x9f, 0x8f, 0x85, 0x94, 0x34,
                    0x89, 0xa2, 0x41, 0x49, 0xc7, 0x5f, 0x4e, 0xc9,
                    0xe0, 0x9a, 0x77, 0x36, 0xfb, 0xc8, 0xb2, 0xdc,
                    0xb3, 0xfb, 0x9f, 0xc0, 0x31, 0x4c, 0xb0, 0xb1,
                    0x6c, 0x47, 0xcd, 0xec, 0xae, 0xbb, 0x1a, 0x65,
                    0x04, 0xd2, 0x32, 0x23, 0xa6, 0x8d, 0x4a, 0x65 ]
            }
        ]
    }

    fn aes_ctr_tests() -> ~[CtrTest] {
        ~[
            CtrTest {
                key: ~[1, ..16],
                ctr: ~[3, ..16],
                plain: ~[2, ..33],
                cipher: ~[
                    0x64, 0x3e, 0x05, 0x19, 0x79, 0x78, 0xd7, 0x45,
                    0xa9, 0x10, 0x5f, 0xd8, 0x4c, 0xd7, 0xe6, 0xb1,
                    0x5f, 0x66, 0xc6, 0x17, 0x4b, 0x25, 0xea, 0x24,
                    0xe6, 0xf9, 0x19, 0x09, 0xb7, 0xdd, 0x84, 0xfb,
                    0x86 ]
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
            -> (EcbPkcsPaddingEncryptor<aessafe::AesSafe128Encryptor>,
                EcbPkcsPaddingDecryptor<aessafe::AesSafe128Decryptor>) {
        let aes_enc = aessafe::AesSafe128Encryptor::new(test.key);
        let aes_dec = aessafe::AesSafe128Decryptor::new(test.key);
        (EcbPkcsPaddingEncryptor::new(aes_enc), EcbPkcsPaddingDecryptor::new(aes_dec))
    }

    fn get_aes_cbc_no_padding(test: &CbcTest)
            -> (CbcNoPaddingEncryptor<aessafe::AesSafe128Encryptor>,
                CbcNoPaddingDecryptor<aessafe::AesSafe128Decryptor>) {
        let aes_enc = aessafe::AesSafe128Encryptor::new(test.key);
        let aes_dec = aessafe::AesSafe128Decryptor::new(test.key);
        (CbcNoPaddingEncryptor::new(aes_enc, test.iv.clone()),
         CbcNoPaddingDecryptor::new(aes_dec, test.iv.clone()))
    }

    fn get_aes_cbc_pkcs_padding(test: &CbcTest)
            -> (CbcPkcsPaddingEncryptor<aessafe::AesSafe128Encryptor>,
                CbcPkcsPaddingDecryptor<aessafe::AesSafe128Decryptor>) {
        let aes_enc = aessafe::AesSafe128Encryptor::new(test.key);
        let aes_dec = aessafe::AesSafe128Decryptor::new(test.key);
        (CbcPkcsPaddingEncryptor::new(aes_enc, test.iv.clone()),
         CbcPkcsPaddingDecryptor::new(aes_dec, test.iv.clone()))
    }

    fn get_aes_ctr(test: &CtrTest)
            -> (CtrMode<aessafe::AesSafe128Encryptor>,
                CtrMode<aessafe::AesSafe128Encryptor>) {
        let aes_enc_1 = aessafe::AesSafe128Encryptor::new(test.key);
        let aes_enc_2 = aessafe::AesSafe128Encryptor::new(test.key);
        (CtrMode::new(aes_enc_1, test.ctr.clone()),
         CtrMode::new(aes_enc_2, test.ctr.clone()))
    }

    fn get_aes_ctr_x8(test: &CtrTest)
            -> (CtrModeX8<aessafe::AesSafe128EncryptorX8>,
                CtrModeX8<aessafe::AesSafe128EncryptorX8>) {
        let aes_enc_1 = aessafe::AesSafe128EncryptorX8::new(test.key);
        let aes_enc_2 = aessafe::AesSafe128EncryptorX8::new(test.key);
        (CtrModeX8::new(aes_enc_1, test.ctr),
         CtrModeX8::new(aes_enc_2, test.ctr))
    }

    fn run_test_full<T: CipherTest, E: Encryptor, D: Decryptor>(
            test: &T,
            enc: &mut E,
            dec: &mut D) {
        let mut cipher_out = vec::from_elem(test.get_cipher().len(), 0u8);
        {
            let mut buff_in = RefReadBuffer::new(test.get_plain());
            let mut buff_out = RefWriteBuffer::new(cipher_out);
            match enc.encrypt(&mut buff_in, &mut buff_out, true) {
                Ok(BufferOverflow) => fail!("Encryption not completed"),
                Err(_) => fail!("Error"),
                _ => {}
            }
        }
        assert!(test.get_cipher() == cipher_out);

        let mut plain_out = vec::from_elem(test.get_plain().len(), 0u8);
        {
            let mut buff_in = RefReadBuffer::new(test.get_cipher());
            let mut buff_out = RefWriteBuffer::new(plain_out);
            match dec.decrypt(&mut buff_in, &mut buff_out, true) {
                Ok(BufferOverflow) => fail!("Decryption not completed"),
                Err(_) => fail!("Error"),
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
            run_test_full(test, &mut enc, &mut dec);
        }
    }

    #[test]
    fn aes_ecb_pkcs_padding() {
        let tests = aes_ecb_pkcs_padding_tests();
        for test in tests.iter() {
            let (mut enc, mut dec) = get_aes_ecb_pkcs_padding(test);
            run_test_full(test, &mut enc, &mut dec);
        }
    }

    #[test]
    fn aes_cbc_no_padding() {
        let tests = aes_cbc_no_padding_tests();
        for test in tests.iter() {
            let (mut enc, mut dec) = get_aes_cbc_no_padding(test);
            run_test_full(test, &mut enc, &mut dec);
        }
    }

    #[test]
    fn aes_cbc_pkcs_padding() {
        let tests = aes_cbc_pkcs_padding_tests();
        for test in tests.iter() {
            let (mut enc, mut dec) = get_aes_cbc_pkcs_padding(test);
            run_test_full(test, &mut enc, &mut dec);
        }
    }

    #[test]
    fn aes_ctr() {
        let tests = aes_ctr_tests();
        for test in tests.iter() {
            let (mut enc, mut dec) = get_aes_ctr(test);
            run_test_full(test, &mut enc, &mut dec);
        }
    }

    #[test]
    fn aes_ctr_x8() {
        let tests = aes_ctr_tests();
        for test in tests.iter() {
            let (mut enc, mut dec) = get_aes_ctr_x8(test);
            run_test_full(test, &mut enc, &mut dec);
        }
    }

    #[bench]
    pub fn aes_ecb_no_padding_bench(bh: &mut BenchHarness) {
        let key = [1u8, ..16];
        let plain = [3u8, ..512];
        let mut cipher = [3u8, ..528];

        let aes_enc = aesni::AesNi128Encryptor::new(key);
        let mut enc = EcbNoPaddingEncryptor::new(aes_enc);

        bh.iter( || {
            enc.reset();

            let mut buff_in = RefReadBuffer::new(plain);
            let mut buff_out = RefWriteBuffer::new(cipher);

            match enc.encrypt(&mut buff_in, &mut buff_out, true) {
                Ok(BufferOverflow) => fail!("Encryption not completed"),
                Err(_) => fail!("Error"),
                _ => {}
            }
        });

        bh.bytes = (plain.len()) as u64;
    }

    #[bench]
    pub fn aes_cbc_pkcs_padding_bench(bh: &mut BenchHarness) {
        let key = [1u8, ..16];
        let iv = [2u8, ..16];
        let plain = [3u8, ..512];
        let mut cipher = [3u8, ..528];

        let aes_enc = aesni::AesNi128Encryptor::new(key);
        let mut enc = CbcPkcsPaddingEncryptor::new(aes_enc, iv.to_owned());

        bh.iter( || {
            enc.reset(iv);

            let mut buff_in = RefReadBuffer::new(plain);
            let mut buff_out = RefWriteBuffer::new(cipher);

            match enc.encrypt(&mut buff_in, &mut buff_out, true) {
                Ok(BufferOverflow) => fail!("Encryption not completed"),
                Err(_) => fail!("Error"),
                _ => {}
            }
        });

        bh.bytes = (plain.len()) as u64;
    }

    #[bench]
    pub fn aes_ctr_bench(bh: &mut BenchHarness) {
        let key = [1u8, ..16];
        let ctr = [2u8, ..16];
        let plain = [3u8, ..512];
        let mut cipher = [3u8, ..528];

        let aes_enc = aesni::AesNi128Encryptor::new(key);
        let mut enc = CtrMode::new(aes_enc, ctr.to_owned());

        bh.iter( || {
            enc.reset(ctr);

            let mut buff_in = RefReadBuffer::new(plain);
            let mut buff_out = RefWriteBuffer::new(cipher);

            match enc.encrypt(&mut buff_in, &mut buff_out, true) {
                Ok(BufferOverflow) => fail!("Encryption not completed"),
                Err(_) => fail!("Error"),
                _ => {}
            }
        });

        bh.bytes = (plain.len()) as u64;
    }

    #[bench]
    pub fn aes_ctr_x8_bench(bh: &mut BenchHarness) {
        let key = [1u8, ..16];
        let ctr = [2u8, ..16];
        let plain = [3u8, ..512];
        let mut cipher = [3u8, ..528];

        let aes_enc = aessafe::AesSafe128EncryptorX8::new(key);
        let mut enc = CtrModeX8::new(aes_enc, ctr.to_owned());

        bh.iter( || {
            enc.reset(ctr);

            let mut buff_in = RefReadBuffer::new(plain);
            let mut buff_out = RefWriteBuffer::new(cipher);

            match enc.encrypt(&mut buff_in, &mut buff_out, true) {
                Ok(BufferOverflow) => fail!("Encryption not completed"),
                Err(_) => fail!("Error"),
                _ => {}
            }
        });

        bh.bytes = (plain.len()) as u64;
    }
}
