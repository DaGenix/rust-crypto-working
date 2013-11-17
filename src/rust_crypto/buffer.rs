// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/*
pub enum BufferResult {
    BufferUnderflow,
    BufferOverflow
}

pub struct Buffer<'self> {
    buff: &'self [u8]
}

impl <'self> Buffer<'self> {
    pub fn new<'a>(buff: &'a [u8]) -> Buffer<'a> {
        Buffer {
            buff: buff
        }
    }
    pub fn remaining(&self) -> uint {
        self.buff.len()
    }
    pub fn next_slice(&mut self, size: uint) -> &'self [u8] {
        let s = self.buff.slice_to(size);
        let r = self.buff.slice_from(size);
        self.buff = r;
        s
    }
}

pub struct MutBuffer<'self> {
    buff: &'self mut [u8],
    len: uint,
    pos: uint
}

impl <'self> MutBuffer<'self> {
    pub fn new<'a>(buff: &'a mut [u8]) -> MutBuffer<'a> {
        let len = buff.len();
        MutBuffer {
            buff: buff,
            len: len,
            pos: 0
        }
    }
    pub fn remaining(&self) -> uint {
        self.len - self.pos
    }
    pub fn next_slice(&mut self, size: uint) -> &'self mut [u8] {
        let s = self.buff.mut_slice(self.pos, self.pos + size);
        self.pos += size;
        s
    }
}
*/


pub enum BufferResult {
    BufferUnderflow,
    BufferOverflow
}

pub trait ReadBuffer {
    fn remaining(&self) -> uint;
    fn is_empty(&self) -> bool;
    fn next<'a>(&'a mut self, size: uint) -> &'a [u8];
    fn all<'a>(&'a mut self) -> &'a [u8];
}

pub trait WriteBuffer {
    fn remaining(&self) -> uint;
    fn is_empty(&self) -> bool;
    fn is_full(&self) -> bool;
    fn next<'a>(&'a mut self, size: uint) -> &'a mut [u8];
    fn read_buffer<'a>(&'a mut self) -> RefReadBuffer<'a>;
}

pub struct RefReadBuffer<'self> {
    buff: &'self [u8]
}

impl <'self> RefReadBuffer<'self> {
    pub fn new<'a>(buff: &'a [u8]) -> RefReadBuffer<'a> {
        RefReadBuffer {
            buff: buff
        }
    }
}

impl <'self> ReadBuffer for RefReadBuffer<'self> {
    fn remaining(&self) -> uint {
        self.buff.len()
    }
    fn is_empty(&self) -> bool {
        self.buff.len() == 0
    }
    fn next<'a>(&'a mut self, size: uint) -> &'a [u8] {
        let s = self.buff.slice_to(size);
        let r = self.buff.slice_from(size);
        self.buff = r;
        s
    }
    fn all<'a>(&'a mut self) -> &'a [u8] {
        self.buff
    }
}

pub struct RefWriteBuffer<'self> {
    buff: &'self mut [u8],
    len: uint,
    pos: uint
}

impl <'self> RefWriteBuffer<'self> {
    pub fn new<'a>(buff: &'a mut [u8]) -> RefWriteBuffer<'a> {
        let len = buff.len();
        RefWriteBuffer {
            buff: buff,
            len: len,
            pos: 0
        }
    }
}

impl <'self> WriteBuffer for RefWriteBuffer<'self> {
    fn remaining(&self) -> uint {
        self.len - self.pos
    }
    fn is_empty(&self) -> bool {
        self.pos == 0
    }
    fn is_full(&self) -> bool {
        self.pos == self.len
    }
    fn next<'a>(&'a mut self, size: uint) -> &'a mut [u8] {
        let s = self.buff.mut_slice(self.pos, self.pos + size);
        self.pos += size;
        s
    }
    fn read_buffer<'a>(&'a mut self) -> RefReadBuffer<'a> {
        let r = RefReadBuffer::new(self.buff.slice_to(self.pos));
        self.pos = 0;
        r
    }
}

pub struct OwnedWriteBuffer {
    buff: ~[u8],
    len: uint,
    pos: uint
}

impl OwnedWriteBuffer {
    pub fn new(buff: ~[u8]) -> OwnedWriteBuffer {
        let len = buff.len();
        OwnedWriteBuffer {
            buff: buff,
            len: len,
            pos: 0
        }
    }
    pub fn reset(&mut self) {
        self.pos = 0;
    }
}

impl WriteBuffer for OwnedWriteBuffer {
    fn remaining(&self) -> uint {
        self.len - self.pos
    }
    fn is_empty(&self) -> bool {
        self.pos == 0
    }
    fn is_full(&self) -> bool {
        self.pos == self.len
    }
    fn next<'a>(&'a mut self, size: uint) -> &'a mut [u8] {
        println!("pos: {}, size: {}, remaining: {}", self.pos, size, self.remaining());
        let s = self.buff.mut_slice(self.pos, self.pos + size);
        self.pos += size;
        s
    }
    fn read_buffer<'a>(&'a mut self) -> RefReadBuffer<'a> {
        let r = RefReadBuffer::new(self.buff.slice_to(self.pos));
        self.pos = 0;
        r
    }
}
