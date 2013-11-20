// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::vec;

pub enum BufferResult {
    BufferUnderflow,
    BufferOverflow
}

pub trait ReadBuffer {
    fn remaining(&self) -> uint;
    fn is_empty(&self) -> bool;
    fn next<'a>(&'a mut self, size: uint) -> &'a [u8];
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
}

pub struct OwnedReadBuffer {
    buff: ~[u8],
    len: uint,
    pos: uint
}

impl OwnedReadBuffer {
    pub fn new(buff: ~[u8]) -> OwnedReadBuffer {
        let len = buff.len();
        OwnedReadBuffer {
            buff: buff,
            len: len,
            pos: 0
        }
    }
    pub fn new_with_len<'a>(buff: ~[u8], len: uint) -> OwnedReadBuffer {
        OwnedReadBuffer {
            buff: buff,
            len: len,
            pos: 0
        }
    }
    pub fn get_write_buffer(self) -> OwnedWriteBuffer {
        OwnedWriteBuffer::new(self.buff)
    }
}

impl ReadBuffer for OwnedReadBuffer {
    fn remaining(&self) -> uint {
        self.len - self.pos
    }
    fn is_empty(&self) -> bool {
        self.pos == self.len
    }
    fn next<'a>(&'a mut self, size: uint) -> &'a [u8] {
        let s = self.buff.slice(self.pos, self.pos + size);
        self.pos += size;
        s
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
//     pub fn clone_as_read_buffer(&self) -> OwnedReadBuffer {
//         let mut nb = vec::from_elem(self.pos, 0u8);
//         vec::bytes::copy_memory(nb, self.buff, self.pos);
//         OwnedReadBuffer::new(nb)
//     }
    pub fn get_read_buffer(self) -> OwnedReadBuffer {
        let pos = self.pos;
        OwnedReadBuffer::new_with_len(self.buff, pos)
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
