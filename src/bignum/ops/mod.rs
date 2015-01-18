// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub use self::op_addsub::{op_unsigned_add, op_unsigned_sub};
pub use self::op_muladd::op_muladd;

#[path = "generic/op_addsub.rs"]
mod op_addsub;

#[path = "generic/op_muladd.rs"]
mod op_muladd;