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

fn read_val(table: &toml::Table, key: &str) -> Vec<u8> {
    let hex_val = table.get(&(key.to_string() + "-hex"));
    let str_val = table.get(&(key.to_string() + "-str"));

    match (hex_val, str_val) {
        (Some(&Value::String(ref h)), None) => {
            h.from_hex().ok().expect("Invalid hex value.")
        },
        (None, Some(&Value::String(ref s))) => {
            s.as_bytes().to_vec()
        },
        _ => {
            panic!("Invalid value.")
        }
    }
}

fn parse_tests<F>(test_file: &str, test_name: &str, run_tests: F) where F: FnOnce(&toml::Array) {
    let mut input = String::new();
    File::open(test_file).and_then(|mut f| {
        f.read_to_string(&mut input)
    }).unwrap();

    let mut parser = toml::Parser::new(&input);
    let toml = parser.parse().expect("toml file is invalid");

    let data = Value::Table(toml);
    if let Value::Table(root) = data {
        if let &Value::Array(ref tests) = root.get(test_name).expect("no tests found") {
            run_tests(tests);
        }
    }
}

pub fn test_digest<D>(digest: &mut D, test_file: &str) where D: Digest {
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
