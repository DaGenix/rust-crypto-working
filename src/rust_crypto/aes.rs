// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/*

#[cfg(target_arch = "x86")]
#[cfg(target_arch = "x86_64")]
use aesni::*;

use aessafe::*;
use symmetriccipher::*;
use util::*;


macro_rules! define_struct(
    (
        $Aes:ident,
        $AesEngine:ident
    ) => (
        struct $Aes {
            engine: $AesEngine
        }
    )
)

macro_rules! define_impl(
    (
        $Aes:ident,
        $AesNiEngine:ident => $AesNi: ident,
        $AesSafeEngine:ident => $AesSafe:ident
    ) => (
        impl $Aes {
            #[cfg(target_arch = "x86")]
            #[cfg(target_arch = "x86_64")]
            pub fn new(key: &[u8]) -> $Aes {
                if supports_aesni() {
                    $Aes {
                        engine: $AesNiEngine($AesNi::new(key))
                    }
                } else {
                    $Aes {
                        engine: $AesSafeEngine($AesSafe::new(key))
                    }
                }
            }

            #[cfg(not(target_arch = "x86"), not(target_arch = "x86_64"))]
            pub fn new(key: &[u8]) -> $Aes {
                $Aes {
                    engine: $AesSafeEngine($AesSafe::new(key))
                }
            }
        }
    )
)

macro_rules! define_block(
    (
        $name:ident
    ) => (
        impl BlockSize16 for $name { }
    )
)

macro_rules! define_enc(
    (
        $AesEncryptor:ident,
        $AesNiEncryptionEngine:ident,
        $AesSafeEncryptionEngine:ident
    ) => (
        impl BlockEncryptor for $AesEncryptor {
            #[cfg(target_arch = "x86")]
            #[cfg(target_arch = "x86_64")]
            fn encrypt_block(&self, input: &[u8], output: &mut [u8]) {
                match self.engine {
                    $AesNiEncryptionEngine(ref engine) => {
                        engine.encrypt_block(input, output);
                    },
                    $AesSafeEncryptionEngine(ref engine) => {
                        engine.encrypt_block(input, output);
                    }
                }
            }

            #[cfg(not(target_arch = "x86"), not(target_arch = "x86_64"))]
            fn encrypt_block(&self, input: &[u8], output: &mut [u8]) {
                match self.engine {
                    $AesSafeEncryptionEngine(ref engine) => {
                        engine.encrypt_block(input, output);
                    }
                }
            }
        }
    )
)

macro_rules! define_dec(
    (
        $AesDecryptor:ident,
        $AesNiDecryptionEngine:ident,
        $AesSafeDecryptionEngine:ident
    ) => (
        impl BlockDecryptor for $AesDecryptor {
            #[cfg(target_arch = "x86")]
            #[cfg(target_arch = "x86_64")]
            fn decrypt_block(&self, input: &[u8], output: &mut [u8]) {
                match self.engine {
                    $AesNiDecryptionEngine(ref engine) => {
                        engine.decrypt_block(input, output);
                    },
                    $AesSafeDecryptionEngine(ref engine) => {
                        engine.decrypt_block(input, output);
                    }
                }
            }

            #[cfg(not(target_arch = "x86"), not(target_arch = "x86_64"))]
            fn decrypt_block(&self, input: &[u8], output: &mut [u8]) {
                match self.engine {
                    $AesSafeDecryptionEngine(ref engine) => {
                        engine.decrypt_block(input, output);
                    }
                }
            }
        }
    )
)

#[cfg(target_arch = "x86")]
#[cfg(target_arch = "x86_64")]
enum AesEncryptionEngine128 {
    AesNiEncryptionEngine128(AesNi128Encryptor),
    AesSafeEncryptionEngine128(AesSafe128Encryptor)
}

#[cfg(not(target_arch = "x86", target_arch = "x86_64"))]
enum AesEncryptionEngine128 {
    AesSafeEncryptionEngine128(AesSafe128Encryptor)
}


#[cfg(target_arch = "x86")]
#[cfg(target_arch = "x86_64")]
enum AesDecryptionEngine128 {
    AesNiDecryptionEngine128(AesNi128Decryptor),
    AesSafeDecryptionEngine128(AesSafe128Decryptor)
}

#[cfg(not(target_arch = "x86", target_arch = "x86_64"))]
enum AesDecryptionEngine128 {
    AesSafeDecryptionEngine128(AesSafe128Decryptor)
}

define_struct!(Aes128Encryptor, AesEncryptionEngine128)
define_struct!(Aes128Decryptor, AesDecryptionEngine128)
define_impl!(
    Aes128Encryptor,
    AesNiEncryptionEngine128 => AesNi128Encryptor,
    AesSafeEncryptionEngine128 => AesSafe128Encryptor)
define_impl!(
    Aes128Decryptor,
    AesNiDecryptionEngine128 => AesNi128Decryptor,
    AesSafeDecryptionEngine128 => AesSafe128Decryptor)
define_block!(Aes128Encryptor)
define_block!(Aes128Decryptor)
define_enc!(
    Aes128Encryptor,
    AesNiEncryptionEngine128,
    AesSafeEncryptionEngine128)
define_dec!(
    Aes128Decryptor,
    AesNiDecryptionEngine128,
    AesSafeDecryptionEngine128)


#[cfg(not(target_arch = "x86", target_arch = "x86_64"))]
enum AesEncryptionEngine192 {
    AesSafeEncryptionEngine192(AesSafe192Encryptor)
}

#[cfg(target_arch = "x86")]
#[cfg(target_arch = "x86_64")]
enum AesEncryptionEngine192 {
    AesNiEncryptionEngine192(AesNi192Encryptor),
    AesSafeEncryptionEngine192(AesSafe192Encryptor)
}

#[cfg(not(target_arch = "x86", target_arch = "x86_64"))]
enum AesDecryptionEngine192 {
    AesSafeDecryptionEngine192(AesSafe192Decryptor)
}

#[cfg(target_arch = "x86")]
#[cfg(target_arch = "x86_64")]
enum AesDecryptionEngine192 {
    AesNiDecryptionEngine192(AesNi192Decryptor),
    AesSafeDecryptionEngine192(AesSafe192Decryptor)
}

define_struct!(Aes192Encryptor, AesEncryptionEngine192)
define_struct!(Aes192Decryptor, AesDecryptionEngine192)
define_impl!(
    Aes192Encryptor,
    AesNiEncryptionEngine192 => AesNi192Encryptor,
    AesSafeEncryptionEngine192 => AesSafe192Encryptor)
define_impl!(
    Aes192Decryptor,
    AesNiDecryptionEngine192 => AesNi192Decryptor,
    AesSafeDecryptionEngine192 => AesSafe192Decryptor)
define_block!(Aes192Encryptor)
define_block!(Aes192Decryptor)
define_enc!(
    Aes192Encryptor,
    AesNiEncryptionEngine192,
    AesSafeEncryptionEngine192)
define_dec!(
    Aes192Decryptor,
    AesNiDecryptionEngine192,
    AesSafeDecryptionEngine192)


#[cfg(not(target_arch = "x86", target_arch = "x86_64"))]
enum AesEncryptionEngine256 {
    AesSafeEncryptionEngine256(AesSafe256Encryptor)
}

#[cfg(target_arch = "x86")]
#[cfg(target_arch = "x86_64")]
enum AesEncryptionEngine256 {
    AesNiEncryptionEngine256(AesNi256Encryptor),
    AesSafeEncryptionEngine256(AesSafe256Encryptor)
}

#[cfg(not(target_arch = "x86", target_arch = "x86_64"))]
enum AesDecryptionEngine256 {
    AesSafeDecryptionEngine256(AesSafe256Decryptor)
}

#[cfg(target_arch = "x86")]
#[cfg(target_arch = "x86_64")]
enum AesDecryptionEngine256 {
    AesNiDecryptionEngine256(AesNi256Decryptor),
    AesSafeDecryptionEngine256(AesSafe256Decryptor)
}

define_struct!(Aes256Encryptor, AesEncryptionEngine256)
define_struct!(Aes256Decryptor, AesDecryptionEngine256)
define_impl!(
    Aes256Encryptor,
    AesNiEncryptionEngine256 => AesNi256Encryptor,
    AesSafeEncryptionEngine256 => AesSafe256Encryptor)
define_impl!(
    Aes256Decryptor,
    AesNiDecryptionEngine256 => AesNi256Decryptor,
    AesSafeDecryptionEngine256 => AesSafe256Decryptor)
define_block!(Aes256Encryptor)
define_block!(Aes256Decryptor)
define_enc!(
    Aes256Encryptor,
    AesNiEncryptionEngine256,
    AesSafeEncryptionEngine256)
define_dec!(
    Aes256Decryptor,
    AesNiDecryptionEngine256,
    AesSafeDecryptionEngine256)

*/

#[cfg(test)]
mod test {
//    use aes::*;

    #[cfg(target_arch = "x86")]
    #[cfg(target_arch = "x86_64")]
    use aesni::*;

    use aessafe::*;
    use symmetriccipher::*;
    use util::*;

    // Test vectors from:
    // http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors

    struct Test {
        key: ~[u8],
        data: ~[TestData]
    }

    struct TestData {
        plain: ~[u8],
        cipher: ~[u8]
    }

    fn tests128() -> ~[Test] {
        return ~[
            Test {
                key: ~[0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                       0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c],
                data: ~[
                    TestData {
                        plain:  ~[0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                                 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a],
                        cipher: ~[0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
                                 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97]
                    },
                    TestData {
                        plain:  ~[0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                                 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51],
                        cipher: ~[0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d,
                                 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf]
                    },
                    TestData {
                        plain:  ~[0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
                                 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef],
                        cipher: ~[0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23,
                                 0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88]
                    },
                    TestData {
                        plain:  ~[0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
                                 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10],
                        cipher: ~[0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f,
                                 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4]
                    }
                ]
            }
        ];
    }

    fn tests192() -> ~[Test] {
        return ~[
            Test {
                key: ~[0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b,
                       0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b],
                data: ~[
                    TestData {
                        plain:  ~[0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                                  0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a],
                        cipher: ~[0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f,
                                  0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc]
                    },
                    TestData {
                        plain:  ~[0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                                  0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51],
                        cipher: ~[0x97, 0x41, 0x04, 0x84, 0x6d, 0x0a, 0xd3, 0xad,
                                  0x77, 0x34, 0xec, 0xb3, 0xec, 0xee, 0x4e, 0xef]
                    },
                    TestData {
                        plain:  ~[0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
                                  0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef],
                        cipher: ~[0xef, 0x7a, 0xfd, 0x22, 0x70, 0xe2, 0xe6, 0x0a,
                                  0xdc, 0xe0, 0xba, 0x2f, 0xac, 0xe6, 0x44, 0x4e]
                    },
                    TestData {
                        plain:  ~[0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
                                  0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10],
                        cipher: ~[0x9a, 0x4b, 0x41, 0xba, 0x73, 0x8d, 0x6c, 0x72,
                                  0xfb, 0x16, 0x69, 0x16, 0x03, 0xc1, 0x8e, 0x0e]
                    }
                ]
            }
        ];
    }

    fn tests256() -> ~[Test] {
        return ~[
            Test {
                key: ~[0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                       0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                       0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                       0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4],
                data: ~[
                    TestData {
                        plain:  ~[0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                                  0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a],
                        cipher: ~[0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
                                  0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8]
                    },
                    TestData {
                        plain:  ~[0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                                  0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51],
                        cipher: ~[0x59, 0x1c, 0xcb, 0x10, 0xd4, 0x10, 0xed, 0x26,
                                  0xdc, 0x5b, 0xa7, 0x4a, 0x31, 0x36, 0x28, 0x70]
                    },
                    TestData {
                        plain:  ~[0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
                                  0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef],
                        cipher: ~[0xb6, 0xed, 0x21, 0xb9, 0x9c, 0xa6, 0xf4, 0xf9,
                                  0xf1, 0x53, 0xe7, 0xb1, 0xbe, 0xaf, 0xed, 0x1d]
                    },
                    TestData {
                        plain:  ~[0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
                                  0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10],
                        cipher: ~[0x23, 0x30, 0x4b, 0x7a, 0x39, 0xf9, 0xf3, 0xff,
                                  0x06, 0x7d, 0x8d, 0x8f, 0x9e, 0x24, 0xec, 0xc7]
                    }
                ]
            }
        ];
    }

    fn run_test<E: BlockEncryptor, D: BlockDecryptor>(enc: &mut E, dec: &mut D, test: &Test) {
        let mut tmp = [0u8, ..16];
        for data in test.data.iter() {
            enc.encrypt_block(data.plain, tmp);
            assert!(tmp == data.cipher);
            dec.decrypt_block(data.cipher, tmp);
            assert!(tmp == data.plain);
        }
    }

/*
    #[test]
    fn testAesDefault128() {
        let tests = tests128();
        for t in tests.iter() {
            let mut enc = Aes128Encryptor::new(t.key);
            let mut dec = Aes128Decryptor::new(t.key);
            run_test(&mut enc, &mut dec, t);
        }
    }

    #[test]
    fn testAesDefault192() {
        let tests = tests192();
        for t in tests.iter() {
            let mut enc = Aes192Encryptor::new(t.key);
            let mut dec = Aes192Decryptor::new(t.key);
            run_test(&mut enc, &mut dec, t);
        }
    }

    #[test]
    fn testAesDefault256() {
        let tests = tests256();
        for t in tests.iter() {
            let mut enc = Aes256Encryptor::new(t.key);
            let mut dec = Aes256Decryptor::new(t.key);
            run_test(&mut enc, &mut dec, t);
        }
    }
*/

    #[cfg(target_arch = "x86")]
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn testAesNi128() {
        if supports_aesni() {
            let tests = tests128();
            for t in tests.iter() {
                let mut enc = AesNi128Encryptor::new(t.key);
                let mut dec = AesNi128Decryptor::new(t.key);
                run_test(&mut enc, &mut dec, t);
            }
        }
    }

    #[cfg(target_arch = "x86")]
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn testAesNi192() {
        if supports_aesni() {
            let tests = tests192();
            for t in tests.iter() {
                let mut enc = AesNi192Encryptor::new(t.key);
                let mut dec = AesNi192Decryptor::new(t.key);
                run_test(&mut enc, &mut dec, t);
            }
        }
    }

    #[cfg(target_arch = "x86")]
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn testAesNi256() {
        if supports_aesni() {
            let tests = tests256();
            for t in tests.iter() {
                let mut enc = AesNi256Encryptor::new(t.key);
                let mut dec = AesNi256Decryptor::new(t.key);
                run_test(&mut enc, &mut dec, t);
            }
        }
    }

    #[test]
    fn testAesSafe128() {
        let tests = tests128();
        for t in tests.iter() {
            let mut enc = AesSafe128Encryptor::new(t.key);
            let mut dec = AesSafe128Decryptor::new(t.key);
            run_test(&mut enc, &mut dec, t);
        }
    }

    #[test]
    fn testAesSafe192() {
        let tests = tests192();
        for t in tests.iter() {
            let mut enc = AesSafe192Encryptor::new(t.key);
            let mut dec = AesSafe192Decryptor::new(t.key);
            run_test(&mut enc, &mut dec, t);
        }
    }

    #[test]
    fn testAesSafe256() {
        let tests = tests256();
        for t in tests.iter() {
            let mut enc = AesSafe256Encryptor::new(t.key);
            let mut dec = AesSafe256Decryptor::new(t.key);
            run_test(&mut enc, &mut dec, t);
        }
    }

    #[test]
    fn testAesSafe128_x8() {
        let key: [u8, ..16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c ];
        let plain: [u8, ..128] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a ];
        let cipher: [u8, ..128] = [
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
            0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
            0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
            0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
            0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
            0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
            0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
            0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
            0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97 ];

        let enc = AesSafe128EncryptorX8::new(key);
        let dec = AesSafe128DecryptorX8::new(key);
        let mut tmp = [0u8, ..128];
        enc.encrypt_block_x8(plain, tmp);
        assert!(tmp == cipher);
        dec.decrypt_block_x8(cipher, tmp);
        assert!(tmp == plain);
    }
}

#[cfg(test)]
mod bench {
    use extra::test::BenchHarness;

    use aessafe::*;
    use symmetriccipher::*;

    #[bench]
    pub fn aes_bench(bh: &mut BenchHarness) {
        let key: [u8, ..16] = [1u8, ..16];
        let plain: [u8, ..16] = [2u8, ..16];

        // Dangerous - 158 MB/s
        // Safe (orig) - 5 MB/s
        // Safe (S-boxes bitspliced only; not working): 6 MB/s
        // Safe (bs) - 10 MB/s!

        let a = AesSafe128Encryptor::new(key);

        let mut tmp = [0u8, ..16];

        do bh.iter {
            a.encrypt_block(plain, tmp);
        }

        bh.bytes = (plain.len()) as u64;
    }

    #[bench]
    pub fn aes_bench_x8(bh: &mut BenchHarness) {
        let key: [u8, ..16] = [1u8, ..16];
        let plain: [u8, ..128] = [2u8, ..128];

        let a = AesSafe128EncryptorX8::new(key);

        let mut tmp = [0u8, ..128];

        do bh.iter {
            a.encrypt_block_x8(plain, tmp);
        }

        // HACK: Multiply by 100 to get fractional MB/s reported
        bh.bytes = (plain.len() * 100) as u64;
    }
}
