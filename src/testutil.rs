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
use mac::{Mac, MacResult};

/// Read a value that may be specified either as a string of in hex.
fn read_val(table: &toml::Table, key: &str) -> Vec<u8> {
    let hex_val = table.get(&(key.to_string() + "-hex"));
    let str_val = table.get(&(key.to_string() + "-str"));

    match (hex_val, str_val) {
        (Some(&Value::String(ref h)), None) => {
            match h.from_hex() {
                Ok(res) => res,
                Err(err) => panic!("Couldn't parse hex value for {}-hex: {}", key, err)
            }
        },
        (None, Some(&Value::String(ref s))) => s.as_bytes().to_vec(),
        (Some(_), Some(_)) => panic!(format!("Value {} specified as both -hex and -str.", key)),
        (None, None) => panic!(format!("Could not find value {0}-hex or {0}-str.", key)),
        _ => panic!(format!("Value for {0}-hex or {0}-str is not a String.", key))
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

/// Test the given Digest using test data from the specified file.
pub fn test_digest<D>(test_file: &str, digest: &mut D) where D: Digest {
    parse_tests(test_file, "test-digest", |tests| {
        for test_table in tests {
            let test = test_table.as_table().expect("Test data must be in Table format.");
            let input = read_val(test, "input");
            let expected_result = read_val(test, "result");

            assert!(digest.output_bytes() == 0 || digest.output_bytes() == expected_result.len());

            let mut actual_result = vec![0u8; expected_result.len()];

            // Test that it works when accepting the message all at once
            digest.input(&input[..]);
            digest.result(&mut actual_result[..]);
            assert_eq!(actual_result, expected_result);
            digest.reset();

            // Test that it works when accepting the message in pieces
            let mut i = 0;
            while i < input.len() {
                let input_len = (input.len() - i + 1)/2;
                digest.input(&input[i..i + input_len]);
                i += input_len;
            }
            digest.result(&mut actual_result[..]);
            assert_eq!(actual_result, expected_result);
            digest.reset();
        }
    });
}

/// Test the given Mac using test data from the specified file.
pub fn test_mac<F, M>(test_file: &str, create_mac: F) where M: Mac, F: Fn(&[u8]) -> M {
    parse_tests(test_file, "test-mac", |tests| {
        for test_table in tests {
            let test = test_table.as_table().expect("Test data must be in Table format.");
            let key = read_val(test, "key");
            let input = read_val(test, "input");
            let expected_result = MacResult::new(&read_val(test, "result"));

            let mut mac = create_mac(&key);

            // Test that it works when accepting the message all at once
            mac.input(&input[..]);
            let actual_result = mac.result();
            assert!(actual_result == expected_result);
            mac.reset();

            // Test that it works when accepting the message in pieces
            let mut i = 0;
            while i < input.len() {
                let input_len = (input.len() - i + 1)/2;
                mac.input(&input[i..i + input_len]);
                println!("{} - {}", i, i + input_len);
                i += input_len;
            }
            let actual_result = mac.result();
            assert!(actual_result == expected_result);
            mac.reset();
        }
    });
}
