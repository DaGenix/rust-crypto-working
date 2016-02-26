// Copyright 2012-2013 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::fs::File;
use std::io::prelude::*;
use std::iter::repeat;

use toml;
use toml::Value;

use serialize::hex::FromHex;

use digest::Digest;

/// Read a value that may be specified either as a string of in hex.
fn read_val(table: &toml::Table, key: &str) -> Vec<u8> {
    let hex_val = table.get(&(key.to_string() + "-hex"));
    let str_val = table.get(&(key.to_string() + "-str"));

    match (hex_val, str_val) {
        (Some(&Value::String(ref h)), None) => {
            match h.from_hex() {
                Ok(res) => res,
                Err(err) => panic!("Couldn't parse hex value: {}", err)
            }
        },
        (None, Some(&Value::String(ref s))) => s.as_bytes().to_vec(),
        (Some(_), Some(_)) => panic!(format!("Value {} specified as both -hex and -str.", key)),
        (None, None) => panic!(format!("Could not find value {}.", key)),
        _ => panic!(format!("Value {} is not a String.", key))
    }
}

/// Parse the tests file, passing tests with the specified name
/// to the given function to run them.
fn parse_tests<F>(test_file: &str, test_name: &str, run_tests: F) where F: FnOnce(&toml::Array) {
    let mut input = String::new();
    if let Err(err) = File::open(test_file).and_then(|mut f| f.read_to_string(&mut input)) {
        panic!(format!("Failed to read file {}: {}", test_file, err));
    }

    let mut parser = toml::Parser::new(&input);
    let toml = parser.parse().expect(&format!("Test file {} file is invalid.", test_file));

    match toml.get(test_name) {
        Some(&Value::Array(ref tests)) => run_tests(tests),
        _ => panic!(format!("Couldn't find any tests to run for name {}.", test_name))
    };
}

/// Test the given Digest using tests data from the specified file.
pub fn test_digest<D>(test_file: &str, digest: &mut D) where D: Digest {
    parse_tests(test_file, "test-digest", |tests| {
        let mut actual_result: Vec<u8> = repeat(0).take(digest.output_bytes()).collect();
        for test_table in tests {
            if let &Value::Table(ref test) = test_table {
                let input = read_val(test, "input");
                let expected_result = read_val(test, "result");

                // Test that it works when accepting the message all at once
                digest.input(&input[..]);
                digest.result(&mut actual_result[..]);
                assert_eq!(expected_result, actual_result);
                digest.reset();

                // Test that it works when accepting the message in pieces
                let len = input.len();
                let mut left = len;
                while left > 0 {
                    let take = (left + 1) / 2;
                    digest.input(&input[len - left..take + len - left]);
                    left -= take;
                }

                digest.result(&mut actual_result[..]);
                assert_eq!(expected_result, actual_result);
                digest.reset();
            }
        }
    });
}
