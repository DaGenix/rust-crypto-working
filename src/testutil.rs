// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use digest::Digest;
use mac::{Mac, MacResult};
use symmetriccipher::SynchronousStreamCipher;

use std;
use std::fs::File;
use std::hash::{SipHasher, Hasher, Hash};
use std::io::prelude::*;
use std::iter::repeat;

use num::traits::ToPrimitive;

use rand::{Isaac64Rng, SeedableRng};
use rand::distributions::{IndependentSample, Range};

use toml;
use toml::Value;

use serialize::hex::FromHex;


/// Read a value that may be specified either as a string of in hex.
pub fn read_data(table: &toml::Table, key: &str) -> Vec<u8> {
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

/// Read a u32 value.
pub fn read_opt_u32(table: &toml::Table, key: &str) -> Option<u32> {
    table.get(key).map(|x| {
        let val = x.as_integer().expect(&format!("Value for {} is not an int.", key));
        val.to_u32().expect(&format!("Value for {} is not a valid u32: {}", key, val))
    })
}

/// Parse the tests file, passing tests with the specified name
/// to the given function to run them.
pub fn parse_tests<F>(
        test_file: &str,
        test_name: &str,
        run_tests: F) where F: FnOnce(&toml::Array) {
    let mut input = String::new();
    if let Err(err) = File::open(test_file).and_then(|mut f| f.read_to_string(&mut input)) {
        panic!(format!("Failed to read file {}: {}", test_file, err));
    }

    let mut parser = toml::Parser::new(&input);
    let toml = parser.parse().expect(&format!("Test file {} file is invalid.", test_file));

    // Try to catch any typos.
    for key in toml.keys() {
        if key != "test-digest" &&
                key != "test-mac" &&
                key != "test-synchronous-stream-cipher" {
            panic!(format!("Invalid test entry found: {}", key))
        }
    }

    for (key, val) in toml {
        match val {
            Value::Array(tests) => {
                if key == test_name {
                    run_tests(&tests);
                    return;
                }
            }
            _ => panic!(format!("Found non array value for key {}", key))
        }
    }
    panic!(format!("No tests found to run for test name: {}", test_name));
}

/// Process test data in (generally) one big part.
///
/// Provide the test data as slices to the callback, `next`, where the
/// each provided slice is equal to the entire `input`. This process
/// will be repeated `input_repeat` time. After all input is provided,
/// `check` is called to validate the result. `check` should `panic!()`
/// if the test failed.
pub fn test_all_at_once<F>(
        input: &Vec<u8>,
        input_repeat: u32,
        mut next: F) where F: FnMut(&[u8]) {
    for _ in 0..input_repeat {
        next(&input);
    }
}

/// Process test data in random, small parts.
///
/// Test data is read from `input` and passsed to the callback `next`.
/// No slice will ever be larger than `max_input_size`. The actual sizes
/// of the slices are random and depend on the contents of `input` - however,
/// they will remain the same between different test runs. After all input is provided,
/// `check` is called to validate the result. `check` should `panic!()`
/// if the test failed.
pub fn test_in_parts<F>(
        input: &Vec<u8>,
        input_repeat: u32,
        max_input_size: usize,
        permutation: u64,
        mut next: F) where F: FnMut(&[u8]) {
    assert!(max_input_size <= std::usize::MAX / 2 && max_input_size > 0);

    // We use the hash of the input to see the RNG to generate different,
    // but consistent, series of inputs for each test data.
    let input_hash = {
        let mut hasher = SipHasher::new();
        for _ in 0..input_repeat {
            input.hash(&mut hasher);
        }
        hasher.finish()
    };

    // The length is a u64 since the lentgh of hashed data can be
    // longer than fits in a usize.
    let input_len = input.len()
        .to_u64()
        .and_then(|x| x.checked_mul(input_repeat as u64))
        .expect("input length times input repeat won't fit in a u64.");

    // We need a buffer that so that we can get a single slice that contains
    // max_input_size bytes - it turns out that buffer must contain 2 * max_input_size - 1
    // bytes to allow that.
    let sized_input = {
        let mut v: Vec<u8> = Vec::new();
        if input.len() > 0 {
            while v.len() < 2 * max_input_size - 1 {
                v.extend_from_slice(input);
            }
        }
        v
    };

    let size_range = Range::new(0, max_input_size + 1);

    let mut rng: Isaac64Rng = SeedableRng::from_seed(&[permutation, input_len, input_hash][..]);

    let mut in_pos = 0;
    let mut count = 0;

    while count < input_len {
        let remaining = input_len - count;
        // size can't be bigger than a usize due to how the range is defined.
        let size = std::cmp::min(
            remaining,
            size_range.ind_sample(&mut rng).to_u64().unwrap()) as usize;

        if in_pos >= max_input_size {
            in_pos -= max_input_size;
        }

        next(&sized_input[in_pos..in_pos + size]);

        in_pos += size;

        // size can't be bigger than max_input_size which is a u32, so
        // this cast is safe.
        count += size as u64;
    }
}

/// Test the given Digest using test data from the specified file.
pub fn test_digest<D, F>(
        test_file: &str,
        block_size: usize,
        create_digest: F) where D: Digest, F: Fn() -> D {
    assert!(block_size < std::usize::MAX / 2);

    parse_tests(test_file, "test-digest", |tests| {
        for test_table in tests {
            let test = test_table.as_table().expect("Test data must be in Table format.");
            let input = read_data(test, "input");
            let input_repeat = read_opt_u32(test, "input-repeat").unwrap_or(1);
            let expected_result = read_data(test, "result");

            let mut digest = create_digest();

            assert!(
                digest.output_bytes() == 0 ||
                digest.output_bytes() == expected_result.len());

            fn check<D: Digest>(digest: &mut D, expected_result: &Vec<u8>) {
                let mut actual_result = vec![0u8; expected_result.len()];
                digest.result(&mut actual_result[..]);
                assert_eq!(&actual_result, expected_result);
                digest.reset();
            }

            test_all_at_once(
                &input,
                input_repeat,
                |chunk| digest.input(chunk));
            check(&mut digest, &expected_result);

            for permutation in 0..3 {
                test_in_parts(
                    &input,
                    input_repeat,
                    block_size * 2,
                    permutation,
                    |chunk| digest.input(chunk));
                check(&mut digest, &expected_result);
            }
        }
    });
}

/// Test the given Mac using test data from the specified file.
pub fn test_mac<F, M>(
        test_file: &str,
        block_size: usize,
        create_mac: F) where M: Mac, F: Fn(&[u8]) -> M {
    assert!(block_size < std::usize::MAX / 2);

    parse_tests(test_file, "test-mac", |tests| {
        for test_table in tests {
            let test = test_table.as_table().expect("Test data must be in Table format.");
            let key = read_data(test, "key");
            let input = read_data(test, "input");
            let input_repeat = read_opt_u32(test, "input-repeat").unwrap_or(1);
            let expected_result = MacResult::new(&read_data(test, "result"));

            let mut mac = create_mac(&key);

            fn check<M: Mac>(mac: &mut M, expected_result: &MacResult) {
                let actual_result = mac.result();
                assert!(actual_result == *expected_result);
                mac.reset();
            };

            test_all_at_once(
                &input,
                input_repeat,
                |chunk| mac.input(chunk));
            check(&mut mac, &expected_result);

            for permutation in 0..3 {
                test_in_parts(
                    &input,
                    input_repeat,
                    block_size * 2,
                    permutation,
                    |chunk| mac.input(chunk));
                check(&mut mac, &expected_result);
            }
        }
    });
}

pub fn test_synchronous_stream_cipher<F, C>(
        test_file: &str,
        block_size: usize,
        create_cipher: F) where C: SynchronousStreamCipher, F: Fn(&[u8], &[u8]) -> C {
    assert!(block_size < std::usize::MAX / 2);

    parse_tests(test_file, "test-synchronous-stream-cipher", |tests| {
        for test_table in tests {
            let test = test_table.as_table().expect("Test data must be in Table format.");
            let key = read_data(test, "key");
            let iv = read_data(test, "iv");
            let input = read_data(test, "input");
            let expected_result = read_data(test, "result");

            {
                let mut cipher = create_cipher(&key, &iv);
                let mut result: Vec<u8> = repeat(0).take(expected_result.len()).collect();
                cipher.process(&input, &mut result);
                assert_eq!(result, expected_result);
            }

            for permutation in 0..3 {
                let mut cipher = create_cipher(&key, &iv);
                let mut result = Vec::with_capacity(expected_result.len());
                test_in_parts(
                    &input,
                    1,
                    block_size,
                    permutation,
                    |chunk| {
                        let pos = result.len();
                        result.extend(repeat(0).take(chunk.len()));
                        cipher.process(&input, &mut result[pos..]);
                    });
                assert_eq!(result, expected_result);
            }
        }
    });
}
