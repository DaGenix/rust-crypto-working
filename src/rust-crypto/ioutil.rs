// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use mac::Mac;

use std::io::IoResult;

pub struct MacWriter<'a, W, M> {
    priv writer: W,
    priv mac: M
}

impl <'a, W: Writer, M: Mac> MacWriter<'a, W, M> {
    pub fn new(writer: W, mac: M) -> MacWriter<'a, W, M> {
        MacWriter {
            writer: writer,
            mac: mac
        }
    }
    pub fn unwrap(self) -> (W, M) {
        let MacWriter {writer, mac} = self;
        (writer, mac)
    }
}

impl <'a, W: Writer, M: Mac> Writer for MacWriter<'a, W, M> {
    fn write(&mut self, buff: &[u8]) -> IoResult<()> {
        self.mac.input(buff);
        self.writer.write(buff)
    }
}

pub struct MacReader<'a, R, M> {
    priv reader: R,
    priv mac: M
}

impl <'a, R: Reader, M: Mac> MacReader<'a, R, M> {
    pub fn new(reader: R, mac: M) -> MacReader<'a, R, M> {
        MacReader {
            reader: reader,
            mac: mac
        }
    }
    pub fn unwrap(self) -> (R, M) {
        let MacReader {reader, mac} = self;
        (reader, mac)
    }
}

impl <'a, R: Reader, M: Mac> Reader for MacReader<'a, R, M> {
    fn read(&mut self, buff: &mut [u8]) -> IoResult<uint> {
        let cnt = if_ok!(self.reader.read(buff));
        self.mac.input(buff.slice_to(cnt));
        Ok(cnt)
    }
}
