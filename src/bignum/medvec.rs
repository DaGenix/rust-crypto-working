// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![macro_escape]

use std::mem;

pub trait BignumData<T>: Index<uint, T> + IndexMut<uint, T> + Slice<uint, [T]> + SliceMut<uint, [T]> {
    fn len(&self) -> uint;
    fn capacity(&self) -> uint;
    unsafe fn grow(&mut self, additional: uint);
}

macro_rules! bignum_data(
    ($name:ident, $ty:ty, $size:expr) => {
        pub struct $name {
            len: uint,
            data: [$ty, ..$size]
        }

        impl $name {
            fn new() -> $name {
                $name {
                    len: 0,
                    data: unsafe { mem::uninitialized() }
                }
            }
        }

        impl Index<uint, $ty> for $name {
            fn index(&self, index: &uint) -> &$ty { &self.data[*index] }
        }

        impl IndexMut<uint, $ty> for $name {
            fn index_mut(&mut self, index: &uint) -> &mut $ty { &mut self.data[*index] }
        }

        impl Slice<uint, [$ty]> for $name {
            fn as_slice_(&self) -> &[$ty] { self.data[] }
            fn slice_from_or_fail(&self, start: &uint) -> &[$ty] { self.data[*start..] }
            fn slice_to_or_fail(&self, end: &uint) -> &[$ty] { self.data[..*end] }
            fn slice_or_fail(&self, start: &uint, end: &uint) -> &[$ty] { self.data[*start..*end] }
        }

        impl SliceMut<uint, [$ty]> for $name {
            fn as_mut_slice_(&mut self) -> &mut [$ty] { self.data[mut] }
            fn slice_from_or_fail_mut(&mut self, start: &uint) -> &mut [$ty] { self.data[mut *start..] }
            fn slice_to_or_fail_mut(&mut self, end: &uint) -> &mut [$ty] { self.data[mut ..*end] }
            fn slice_or_fail_mut(&mut self, start: &uint, end: &uint) -> &mut [$ty] { self.data[mut *start..*end] }
        }

        impl BignumData<$ty> for $name {
            fn len(&self) -> uint { self.len }

            fn capacity(&self) -> uint { $size }

            unsafe fn grow(&mut self, additional: uint) {
                if self.len + additional > $size {
                    panic!("Size too big");
                }
                self.len += additional;
            }
        }
    }
)

bignum_data!(Vec12, u32, 100)
