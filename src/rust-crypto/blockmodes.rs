// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// TODO - Optimize the XORs

use std::vec;

use buffer::{ReadBuffer, WriteBuffer, OwnedReadBuffer, OwnedWriteBuffer, BufferResult,
    BufferUnderflow, BufferOverflow};
use cryptoutil::symm_enc_or_dec;
use symmetriccipher::{BlockEncryptor, BlockEncryptorX8, Encryptor, BlockDecryptor, Decryptor,
    SynchronousStreamCipher, SymmetricCipherError, InvalidPadding, InvalidLength};

/// The BlockProcessor trait is used to implement modes that require processing complete blocks of
/// data. The methods of this trait are called by the BlockEngine which is in charge of properly
/// buffering input data.
trait BlockProcessor {
    /// Process a block of data. The in_hist and out_hist parameters represent the input and output
    /// when the last block was processed. These values are necessary for certain modes.
    fn process_block(&mut self, in_hist: &[u8], out_hist: &[u8], input: &[u8], output: &mut [u8]);

    /// Add padding to the last block of input data
    /// If the mode can't handle a non-full block, it signals that error by simply leaving the block
    /// as it is which will be detected as an InvalidLength error.
    #[allow(unused_variable)]
    fn pad_input<W: WriteBuffer>(&mut self, input_buffer: &mut W) { }

    /// Remove padding from the last block of output data
    /// If false is returned, the processing fails
    #[allow(unused_variable)]
    fn strip_output<R: ReadBuffer>(&mut self, output_buffer: &mut R) -> bool { true }
}

/// The BlockEngine is implemented as a state machine with the following states. See comments in the
/// BlockEngine code for more information on the states.
enum BlockEngineState {
    FastMode,
    NeedInput,
    NeedOutput,
    LastInput,
    LastInput2,
    Finished,
    Error(SymmetricCipherError)
}

/// BlockEngine buffers input and output data and handles sending complete block of data to the
/// Processor object. Additionally, BlockEngine handles logic necessary to add or remove padding by
/// calling the appropriate methods on the Processor object.
struct BlockEngine<P> {
    /// The block sized expected by the Processor
    block_size: uint,

    /// in_hist and out_hist keep track of data that was input to and output from the last
    /// invocation of the process_block() method of the Processor. Depending on the mode, these may
    /// be empty vectors if history is not needed.
    in_hist: ~[u8],
    out_hist: ~[u8],

    /// If some input data is supplied, but not a complete blocks worth, it is stored in this buffer
    /// until enough arrives that it can be passed to the process_block() method of the Processor.
    in_scratch: OwnedWriteBuffer,

    /// If input data is processed but there isn't enough space in the output buffer to store it,
    /// it is written into out_write_scratch. OwnedWriteBuffer's may be converted into
    /// OwnedReaderBuffers without re-allocating, so, after being written, out_write_scratch is
    /// turned into out_read_scratch. After that, if is written to the output as more output becomes
    /// available. The main point is - only out_write_scratch or out_read_scratch contains a value
    /// at any given time; never both.
    out_write_scratch: Option<OwnedWriteBuffer>,
    out_read_scratch: Option<OwnedReadBuffer>,

    /// The processor that implements the particular block mode.
    processor: P,

    /// The current state of the operation.
    state: BlockEngineState
}

fn update_history(in_hist: &mut [u8], out_hist: &mut [u8], last_in: &[u8], last_out: &[u8]) {
    let in_hist_len = in_hist.len();
    if in_hist_len > 0 {
        vec::bytes::copy_memory(
            in_hist,
            last_in.slice_from(last_in.len() - in_hist_len));
    }
    let out_hist_len = out_hist.len();
    if out_hist_len > 0 {
        vec::bytes::copy_memory(
            out_hist,
            last_out.slice_from(last_out.len() - out_hist_len));
    }
}

impl <P: BlockProcessor> BlockEngine<P> {
    /// Create a new BlockProcessor instance with the given processor and block_size. No history
    /// will be saved.
    fn new(processor: P, block_size: uint) -> BlockEngine<P> {
        BlockEngine {
            block_size: block_size,
            in_hist: ~[],
            out_hist: ~[],
            in_scratch: OwnedWriteBuffer::new(vec::from_elem(block_size, 0u8)),
            out_write_scratch: Some(OwnedWriteBuffer::new(vec::from_elem(block_size, 0u8))),
            out_read_scratch: None,
            processor: processor,
            state: FastMode
        }
    }

    /// Create a new BlockProcessor instance with the given processor, block_size, and initial input
    /// and output history.
    fn new_with_history(
            processor: P,
            block_size: uint,
            in_hist: ~[u8],
            out_hist: ~[u8]) -> BlockEngine<P> {
        BlockEngine {
            in_hist: in_hist,
            out_hist: out_hist,
            ..BlockEngine::new(processor, block_size)
        }
    }

    /// This implements the FastMode state. Ideally, the encryption or decryption operation should
    /// do the bulk of its work in FastMode. Significantly, FastMode avoids doing copies as much as
    /// possible. The FastMode state does not handle the final block of data.
    fn fast_mode<R: ReadBuffer, W: WriteBuffer>(
            &mut self,
            input: &mut R,
            output: &mut W) -> BlockEngineState {
        let has_next = || {
            // Not the greater than - very important since this method must never process the last
            // block.
            let enough_input = input.remaining() > self.block_size;
            let enough_output = output.remaining() >= self.block_size;
            enough_input && enough_output
        };
        fn split_at<'a>(vec: &'a [u8], at: uint) -> (&'a [u8], &'a [u8]) {
            (vec.slice_to(at), vec.slice_from(at))
        }

        // First block processing. We have to retrieve the history information from self.in_hist and
        // self.out_hist.
        if !has_next() {
            if input.is_empty() {
                return FastMode;
            } else {
                return NeedInput;
            }
        } else {
            let next_in = input.take_next(self.block_size);
            let next_out = output.take_next(self.block_size);
            self.processor.process_block(
                self.in_hist.as_slice(),
                self.out_hist.as_slice(),
                next_in,
                next_out);
        }

        // Process all remaing blocks. We can pull the history out of the buffers without having to
        // do any copies
        let next_in_size = self.in_hist.len() + self.block_size;
        let next_out_size = self.out_hist.len() + self.block_size;
        while has_next() {
            input.rewind(self.in_hist.len());
            let (in_hist, next_in) = split_at(input.take_next(next_in_size), self.in_hist.len());
            output.rewind(self.out_hist.len());
            let (out_hist, next_out) = output.take_next(next_out_size).mut_split_at(
                self.out_hist.len());
            self.processor.process_block(
                in_hist,
                out_hist,
                next_in,
                next_out);
        }

        // Save the history and then transition to the next state
        {
            input.rewind(self.in_hist.len());
            let last_in = input.take_next(self.in_hist.len());
            output.rewind(self.out_hist.len());
            let last_out = output.take_next(self.out_hist.len());
            update_history(self.in_hist, self.out_hist, last_in, last_out);
        }
        if input.is_empty() {
            return FastMode;
        } else {
            return NeedInput;
        }
    }

    /// This method implements the BlockEngine state machine.
    fn process<R: ReadBuffer, W: WriteBuffer>(
            &mut self,
            input: &mut R,
            output: &mut W,
            eof: bool) -> Result<BufferResult, SymmetricCipherError> {
        // Process a block of data from in_scratch and write the result to out_write_scratch.
        // Finally, convert out_write_scratch into out_read_scratch.
        let process_scratch = || {
            let mut rin = self.in_scratch.take_read_buffer();
            let mut wout = self.out_write_scratch.take_unwrap();

            {
                let next_in = rin.take_remaining();
                let next_out = wout.take_remaining();
                self.processor.process_block(
                    self.in_hist.as_slice(),
                    self.out_hist.as_slice(),
                    next_in,
                    next_out);
                update_history(self.in_hist, self.out_hist, next_in, next_out);
            }

            let rb = wout.into_read_buffer();
            self.out_read_scratch = Some(rb);
        };

        loop {
            match self.state {
                // FastMode tries to process as much data as possible while minimizing copies.
                // FastMode doesn't make use of the scratch buffers and only updates the history
                // just before exiting.
                FastMode => {
                    self.state = self.fast_mode(input, output);
                    match self.state {
                        FastMode => {
                            // If FastMode completes but stays in the FastMode state, it means that
                            // we've run out of input data.
                            return Ok(BufferUnderflow);
                        }
                        _ => {}
                    }
                }

                // The NeedInput mode is entered when there isn't enough data to run in FastMode
                // anymore. Input data is buffered in in_scratch until there is a full block or eof
                // occurs. IF eof doesn't occur, the data is processed and then we go to the
                // NeedOutput state. Otherwise, we go to the LastInput state. This state always
                // writes all available data into in_scratch before transitioning to the next state.
                NeedInput => {
                    input.push_to(&mut self.in_scratch);
                    if !input.is_empty() {
                        // !is_empty() guarantees two things - in_scratch is full and its not the
                        // last block. This state must never process the last block.
                        process_scratch();
                        self.state = NeedOutput;
                    } else {
                        if eof {
                            self.state = LastInput;
                        } else {
                            return Ok(BufferUnderflow);
                        }
                    }
                }

                // The NeedOutput state just writes buffered processed data to the output stream
                // until all of it has been written.
                NeedOutput => {
                    let mut rout = self.out_read_scratch.take_unwrap();
                    rout.push_to(output);
                    if rout.is_empty() {
                        self.out_write_scratch = Some(rout.into_write_buffer());
                        self.state = FastMode;
                    } else {
                        self.out_read_scratch = Some(rout);
                        return Ok(BufferOverflow);
                    }
                }

                // None of the other states are allowed to process the last block of data since
                // last block handling is a little tricky due to modes have special needs regarding
                // padding. When the last block of data is detected, this state is transitioned to
                // for handling.
                LastInput => {
                    // We we arrive in this state, we know that all input data that is going to be
                    // supplied has been suplied and that that data has been written to in_scratch
                    // by the NeedInput state. Furthermore, we know that one of three things must be
                    // true about in_scratch:
                    // 1) It is empty. This only occurs if the input is zero length. We can do last
                    //    block processing by executing the pad_input() method of the processor
                    //    which may either pad out to a full block or leave it empty, process the
                    //    data if it was padded out to a full block, and then pass it to
                    //    strip_output().
                    // 2) It is partially filled. This will occur if the input data was not a
                    //    multiple of the block size. Processing proceeds identically to case #1.
                    // 3) It is full. This case occurs when the input data was a multiple of the
                    //    block size. This case is a little trickier, since, depending on the mode,
                    //    we might actually have 2 blocks worth of data to process - the last user
                    //    supplied block (currently in in_scratch) and then another block that could
                    //    be added as padding. Processing proceeds by first processing the data in
                    //    in_scratch and writing it to out_scratch. Then, the now-empty in_scratch
                    //    buffer is passed to pad_input() which may leave it empty or write a block
                    //    of padding to it. If no padding is added, processing proceeds as in cases
                    //    #1 and #2. However, if padding is added, now have data in in_scratch and
                    //    also in out_scratch meaning that we can't immediately process the padding
                    //    data since we have nowhere to put it. So, we transition to the LastInput2
                    //    state which will first write out the last non-padding block, then process
                    //    the padding block (in in_scratch) and write it to the now-empty
                    //    out_scratch.
                    if !self.in_scratch.is_full() {
                        self.processor.pad_input(&mut self.in_scratch);
                        if self.in_scratch.is_full() {
                            process_scratch();
                            if self.processor.strip_output(self.out_read_scratch.get_mut_ref()) {
                                self.state = Finished;
                            } else {
                                self.state = Error(InvalidPadding);
                            }
                        } else if self.in_scratch.is_empty() {
                            self.state = Finished;
                        } else {
                            self.state = Error(InvalidLength);
                        }
                    } else {
                        process_scratch();
                        self.processor.pad_input(&mut self.in_scratch);
                        if self.in_scratch.is_full() {
                            self.state = LastInput2;
                        } else if self.in_scratch.is_empty() {
                            if self.processor.strip_output(self.out_read_scratch.get_mut_ref()) {
                                self.state = Finished;
                            } else {
                                self.state = Error(InvalidPadding);
                            }
                        } else {
                            self.state = Error(InvalidLength);
                        }
                    }
                }

                // See the comments on LastInput for more details. This state handles final blocks
                // of data in the case that the input was a multiple of the block size and the mode
                // decided to add a full extra block of padding.
                LastInput2 => {
                    let mut rout = self.out_read_scratch.take_unwrap();
                    rout.push_to(output);
                    if rout.is_empty() {
                        self.out_write_scratch = Some(rout.into_write_buffer());
                        process_scratch();
                        if self.processor.strip_output(self.out_read_scratch.get_mut_ref()) {
                            self.state = Finished;
                        } else {
                            self.state = Error(InvalidPadding);
                        }
                    } else {
                        self.out_read_scratch = Some(rout);
                        return Ok(BufferOverflow);
                    }
                }

                // The Finished mode just writes the data in out_scratch to the output until there
                // is no more data left.
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

                // The Error state is used to store error information.
                Error(err) => {
                    return Err(err);
                }
            }
        }
    }
    fn reset(&mut self) {
        self.state = FastMode;
        self.in_scratch.reset();
        if self.out_read_scratch.is_some() {
            let ors = self.out_read_scratch.take_unwrap();
            let ows = ors.into_write_buffer();
            self.out_write_scratch = Some(ows);
        } else {
            self.out_write_scratch.get_mut_ref().reset();
        }
    }
    fn reset_with_history(&mut self, in_hist: &[u8], out_hist: &[u8]) {
        self.reset();
        vec::bytes::copy_memory(self.in_hist, in_hist);
        vec::bytes::copy_memory(self.out_hist, out_hist);
    }
}

fn add_pkcs_padding<W: WriteBuffer>(input_buffer: &mut W) {
    let rem = input_buffer.remaining();
    assert!(rem != 0 && rem <= 255);
    for v in input_buffer.take_remaining().mut_iter() {
        *v = rem as u8;
    }
}

fn strip_pkcs_padding<R: ReadBuffer>(output_buffer: &mut R) -> bool {
    let last_byte: u8;
    {
        let data = output_buffer.peek_remaining();
        last_byte = *data.last();
        for &x in data.iter().invert().take(last_byte as uint) {
            if x != last_byte {
                return false;
            }
        }
    }
    output_buffer.truncate(last_byte as uint);
    true
}

struct EcbNoPaddingEncryptorProcessor<T> {
    algo: T
}

impl <T: BlockEncryptor> BlockProcessor for EcbNoPaddingEncryptorProcessor<T> {
    fn process_block(&mut self, _: &[u8], _: &[u8], input: &[u8], output: &mut [u8]) {
        self.algo.encrypt_block(input, output);
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
            block_engine: BlockEngine::new(processor, block_size)
        }
    }
    pub fn reset(&mut self) {
        self.block_engine.reset();
    }
}

impl <T: BlockEncryptor> Encryptor for EcbNoPaddingEncryptor<T> {
    fn encrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, eof: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        self.block_engine.process(input, output, eof)
    }
}

struct EcbNoPaddingDecryptorProcessor<T> {
    algo: T
}

impl <T: BlockDecryptor> BlockProcessor for EcbNoPaddingDecryptorProcessor<T> {
    fn process_block(&mut self, _: &[u8], _: &[u8], input: &[u8], output: &mut [u8]) {
        self.algo.decrypt_block(input, output);
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
            block_engine: BlockEngine::new(processor, block_size)
        }
    }
    pub fn reset(&mut self) {
        self.block_engine.reset();
    }
}

impl <T: BlockDecryptor> Decryptor for EcbNoPaddingDecryptor<T> {
    fn decrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, eof: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        self.block_engine.process(input, output, eof)
    }
}

struct EcbPkcsPaddingEncryptorProcessor<T> {
    algo: T
}

impl <T: BlockEncryptor> BlockProcessor for EcbPkcsPaddingEncryptorProcessor<T> {
    fn process_block(&mut self, _: &[u8], _: &[u8], input: &[u8], output: &mut [u8]) {
        self.algo.encrypt_block(input, output);
    }
    fn pad_input<W: WriteBuffer>(&mut self, input_buffer: &mut W) {
        add_pkcs_padding(input_buffer);
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
            block_engine: BlockEngine::new(processor, block_size)
        }
    }
    pub fn reset(&mut self) {
        self.block_engine.reset();
    }
}

impl <T: BlockEncryptor> Encryptor for EcbPkcsPaddingEncryptor<T> {
    fn encrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, eof: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        self.block_engine.process(input, output, eof)
    }
}

struct EcbPkcsPaddingDecryptorProcessor<T> {
    algo: T
}

impl <T: BlockDecryptor> BlockProcessor for EcbPkcsPaddingDecryptorProcessor<T> {
    fn process_block(&mut self, _: &[u8], _: &[u8], input: &[u8], output: &mut [u8]) {
        self.algo.decrypt_block(input, output);
    }
    fn strip_output<R: ReadBuffer>(&mut self, output_buffer: &mut R) -> bool {
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
            block_engine: BlockEngine::new(processor, block_size)
        }
    }
    pub fn reset(&mut self) {
        self.block_engine.reset();
    }
}

impl <T: BlockDecryptor> Decryptor for EcbPkcsPaddingDecryptor<T> {
    fn decrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, eof: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        self.block_engine.process(input, output, eof)
    }
}

struct CbcNoPaddingEncryptorProcessor<T> {
    algo: T,
    temp: ~[u8]
}

impl <T: BlockEncryptor> BlockProcessor for CbcNoPaddingEncryptorProcessor<T> {
    fn process_block(&mut self, _: &[u8], out_hist: &[u8], input: &[u8], output: &mut [u8]) {
        for ((&x, &y), o) in input.iter().zip(out_hist.iter()).zip(self.temp.mut_iter()) {
            *o = x ^ y;
        }
        self.algo.encrypt_block(self.temp, output);
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
            temp: vec::from_elem(block_size, 0u8)
        };
        CbcNoPaddingEncryptor {
            block_engine: BlockEngine::new_with_history(processor, block_size, ~[], iv)
        }
    }
    pub fn reset(&mut self, iv: &[u8]) {
        self.block_engine.reset_with_history(&[], iv);
    }
}

impl <T: BlockEncryptor> Encryptor for CbcNoPaddingEncryptor<T> {
    fn encrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, eof: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        self.block_engine.process(input, output, eof)
    }
}

struct CbcNoPaddingDecryptorProcessor<T> {
    algo: T,
    temp: ~[u8]
}

impl <T: BlockDecryptor> BlockProcessor for CbcNoPaddingDecryptorProcessor<T> {
    fn process_block(&mut self, in_hist: &[u8], _: &[u8], input: &[u8], output: &mut [u8]) {
        self.algo.decrypt_block(input, self.temp);
        for ((&x, &y), o) in self.temp.iter().zip(in_hist.iter()).zip(output.mut_iter()) {
            *o = x ^ y;
        }
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
            block_engine: BlockEngine::new_with_history(processor, block_size, iv, ~[])
        }
    }
    pub fn reset(&mut self, iv: &[u8]) {
        self.block_engine.reset_with_history(iv, &[]);
    }
}

impl <T: BlockDecryptor> Decryptor for CbcNoPaddingDecryptor<T> {
    fn decrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, eof: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        self.block_engine.process(input, output, eof)
    }
}

struct CbcPkcsPaddingEncryptorProcessor<T> {
    algo: T,
    temp: ~[u8]
}

impl <T: BlockEncryptor> BlockProcessor for CbcPkcsPaddingEncryptorProcessor<T> {
    fn process_block(&mut self, _: &[u8], out_hist: &[u8], input: &[u8], output: &mut [u8]) {
        for ((&x, &y), o) in input.iter().zip(out_hist.iter()).zip(self.temp.mut_iter()) {
            *o = x ^ y;
        }
        self.algo.encrypt_block(self.temp, output);
    }
    fn pad_input<W: WriteBuffer>(&mut self, input_buffer: &mut W) {
        add_pkcs_padding(input_buffer);
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
            temp: vec::from_elem(block_size, 0u8)
        };
        CbcPkcsPaddingEncryptor {
            block_engine: BlockEngine::new_with_history(processor, block_size, ~[], iv)
        }
    }
    pub fn reset(&mut self, iv: &[u8]) {
        self.block_engine.reset_with_history(&[], iv);
    }
}

impl <T: BlockEncryptor> Encryptor for CbcPkcsPaddingEncryptor<T> {
    fn encrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, eof: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        self.block_engine.process(input, output, eof)
    }
}

struct CbcPkcsPaddingDecryptorProcessor<T> {
    algo: T,
    temp: ~[u8]
}

impl <T: BlockDecryptor> BlockProcessor for CbcPkcsPaddingDecryptorProcessor<T> {
    fn process_block(&mut self, in_hist: &[u8], _: &[u8], input: &[u8], output: &mut [u8]) {
        self.algo.decrypt_block(input, self.temp);
        for ((&x, &y), o) in self.temp.iter().zip(in_hist.iter()).zip(output.mut_iter()) {
            *o = x ^ y;
        }
    }
    fn strip_output<R: ReadBuffer>(&mut self, output_buffer: &mut R) -> bool {
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
            block_engine: BlockEngine::new_with_history(processor, block_size, iv, ~[])
        }
    }
    pub fn reset(&mut self, iv: &[u8]) {
        self.block_engine.reset_with_history(iv, &[]);
    }
}

impl <T: BlockDecryptor> Decryptor for CbcPkcsPaddingDecryptor<T> {
    fn decrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, eof: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        self.block_engine.process(input, output, eof)
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
    pub fn new(algo: A, ctr: ~[u8]) -> CtrMode<A> {
        let block_size = algo.block_size();
        CtrMode {
            algo: algo,
            ctr: ctr,
            bytes: OwnedReadBuffer::new_with_len(vec::from_elem(block_size, 0u8), 0)
        }
    }
    pub fn reset(&mut self, ctr: &[u8]) {
        vec::bytes::copy_memory(self.ctr, ctr);
        self.bytes.reset();
    }
    fn process(&mut self, input: &[u8], output: &mut [u8]) {
        assert!(input.len() == output.len());
        let len = input.len();
        let mut i = 0u;
        while i < len {
            if self.bytes.is_empty() {
                let mut wb = self.bytes.borrow_write_buffer();
                self.algo.encrypt_block(self.ctr, wb.take_remaining());
                add_ctr(self.ctr, 1);
            }
            let count = std::cmp::min(self.bytes.remaining(), len - i);
            let bytes_it = self.bytes.take_next(count).iter();
            let in_it = input.slice_from(i).iter();
            let out_it = output.mut_slice_from(i).mut_iter();
            for ((&x, &y), o) in bytes_it.zip(in_it).zip(out_it) {
                *o = x ^ y;
            }
            i += count;
        }
    }
}

impl <A: BlockEncryptor> SynchronousStreamCipher for CtrMode<A> {
    fn process(&mut self, input: &[u8], output: &mut [u8]) {
        self.process(input, output);
    }
}

impl <A: BlockEncryptor> Encryptor for CtrMode<A> {
    fn encrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

impl <A: BlockEncryptor> Decryptor for CtrMode<A> {
    fn decrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

pub struct CtrModeX8<A> {
    priv algo: A,
    priv ctr_x8: ~[u8],
    priv bytes: OwnedReadBuffer
}

fn construct_ctr_x8(in_ctr: &[u8], out_ctr_x8: &mut [u8]) {
    for (i, ctr_i) in out_ctr_x8.mut_chunks(in_ctr.len()).enumerate() {
        vec::bytes::copy_memory(ctr_i, in_ctr);
        add_ctr(ctr_i, i as u8);
    }
}

impl <A: BlockEncryptorX8> CtrModeX8<A> {
    pub fn new(algo: A, ctr: &[u8]) -> CtrModeX8<A> {
        let block_size = algo.block_size();
        let mut ctr_x8 = vec::from_elem(block_size * 8, 0u8);
        construct_ctr_x8(ctr, ctr_x8);
        CtrModeX8 {
            algo: algo,
            ctr_x8: ctr_x8,
            bytes: OwnedReadBuffer::new_with_len(vec::from_elem(block_size * 8, 0u8), 0)
        }
    }
    pub fn reset(&mut self, ctr: &[u8]) {
        construct_ctr_x8(ctr, self.ctr_x8);
        self.bytes.reset();
    }
    fn process(&mut self, input: &[u8], output: &mut [u8]) {
        // TODO - Can some of this be combined with regular CtrMode?
        assert!(input.len() == output.len());
        let len = input.len();
        let mut i = 0u;
        while i < len {
            if self.bytes.is_empty() {
                let mut wb = self.bytes.borrow_write_buffer();
                self.algo.encrypt_block_x8(self.ctr_x8, wb.take_remaining());
                for ctr_i in self.ctr_x8.mut_chunks(self.algo.block_size()) {
                    add_ctr(ctr_i, 8);
                }
            }
            let count = std::cmp::min(self.bytes.remaining(), len - i);
            let bytes_it = self.bytes.take_next(count).iter();
            let in_it = input.slice_from(i).iter();
            let out_it = output.mut_slice_from(i).mut_iter();
            for ((&x, &y), o) in bytes_it.zip(in_it).zip(out_it) {
                *o = x ^ y;
            }
            i += count;
        }
    }
}

impl <A: BlockEncryptorX8> SynchronousStreamCipher for CtrModeX8<A> {
    fn process(&mut self, input: &[u8], output: &mut [u8]) {
        self.process(input, output);
    }
}

impl <A: BlockEncryptorX8> Encryptor for CtrModeX8<A> {
    fn encrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

impl <A: BlockEncryptorX8> Decryptor for CtrModeX8<A> {
    fn decrypt<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R, output: &mut W, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

#[cfg(test)]
mod test {
    use aessafe;
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
                Ok(BufferUnderflow) => {}
                Ok(BufferOverflow) => fail!("Encryption not completed"),
                Err(_) => fail!("Error"),
            }
        }
        assert!(test.get_cipher() == cipher_out);

        let mut plain_out = vec::from_elem(test.get_plain().len(), 0u8);
        {
            let mut buff_in = RefReadBuffer::new(test.get_cipher());
            let mut buff_out = RefWriteBuffer::new(plain_out);
            match dec.decrypt(&mut buff_in, &mut buff_out, true) {
                Ok(BufferUnderflow) => {}
                Ok(BufferOverflow) => fail!("Decryption not completed"),
                Err(_) => fail!("Error"),
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

        let aes_enc = aessafe::AesSafe128Encryptor::new(key);
        let mut enc = EcbNoPaddingEncryptor::new(aes_enc);

        bh.iter( || {
            enc.reset();

            let mut buff_in = RefReadBuffer::new(plain);
            let mut buff_out = RefWriteBuffer::new(cipher);

            match enc.encrypt(&mut buff_in, &mut buff_out, true) {
                Ok(BufferUnderflow) => {}
                Ok(BufferOverflow) => fail!("Encryption not completed"),
                Err(_) => fail!("Error"),
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

        let aes_enc = aessafe::AesSafe128Encryptor::new(key);
        let mut enc = CbcPkcsPaddingEncryptor::new(aes_enc, iv.to_owned());

        bh.iter( || {
            enc.reset(iv);

            let mut buff_in = RefReadBuffer::new(plain);
            let mut buff_out = RefWriteBuffer::new(cipher);

            match enc.encrypt(&mut buff_in, &mut buff_out, true) {
                Ok(BufferUnderflow) => {}
                Ok(BufferOverflow) => fail!("Encryption not completed"),
                Err(_) => fail!("Error"),
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

        let aes_enc = aessafe::AesSafe128Encryptor::new(key);
        let mut enc = CtrMode::new(aes_enc, ctr.to_owned());

        bh.iter( || {
            enc.reset(ctr);

            let mut buff_in = RefReadBuffer::new(plain);
            let mut buff_out = RefWriteBuffer::new(cipher);

            match enc.encrypt(&mut buff_in, &mut buff_out, true) {
                Ok(BufferUnderflow) => {}
                Ok(BufferOverflow) => fail!("Encryption not completed"),
                Err(_) => fail!("Error"),
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
                Ok(BufferUnderflow) => {}
                Ok(BufferOverflow) => fail!("Encryption not completed"),
                Err(_) => fail!("Error"),
            }
        });

        bh.bytes = (plain.len()) as u64;
    }
}
