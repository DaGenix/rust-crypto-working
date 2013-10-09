// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.


macro_rules! impl_padded_modes(
    (
        $modname:ident,
        $block_size:expr,
        $FixedBuffer:ident,
        $BlockSize:ident,
        $EcbEncryptionWithNoPadding:ident,
        $EcbEncryptionWithPkcs7Padding:ident,
        $CbcEncryptionWithNoPadding:ident,
        $CbcEncryptionWithPkcs7Padding:ident,
        $CtrMode:ident,

        $EncryptionBuffer:ident,
        $DecryptionBuffer:ident
    ) =>
    (
        pub mod $modname {
            use std::vec::bytes;

            use cryptoutil::*;
            use symmetriccipher::*;


            pub struct $EcbEncryptionWithNoPadding<A> {
                priv algo: A
            }

            impl <A: BlockEncryptor + $BlockSize> $EcbEncryptionWithNoPadding<A> {
                pub fn new(algo: A) -> $EcbEncryptionWithNoPadding<A> {
                    $EcbEncryptionWithNoPadding {
                        algo: algo
                    }
                }
            }

            impl <A> $BlockSize for $EcbEncryptionWithNoPadding<A> { }

            impl <A: BlockEncryptor + $BlockSize> PaddedEncryptionMode
                    for $EcbEncryptionWithNoPadding<A> {
                fn encrypt_block(&mut self, input: &[u8], handler: &fn(&[u8])) {
                    let mut tmp = [0u8, ..$block_size];
                    self.algo.encrypt_block(input, tmp);
                    handler(tmp);
                }
                fn encrypt_final_block(&mut self, input: Option<&[u8]>, handler: &fn(&[u8])) {
                    match input {
                        Some(input) => { self.encrypt_block(input, handler) }
                        None => { }
                    }
                }
            }


            pub struct $EcbEncryptionWithPkcs7Padding<A> {
                priv algo: A
            }

            impl <A: BlockEncryptor + $BlockSize> $EcbEncryptionWithPkcs7Padding<A> {
                pub fn new(algo: A) -> $EcbEncryptionWithPkcs7Padding<A> {
                    $EcbEncryptionWithPkcs7Padding {
                        algo: algo
                    }
                }
            }

            impl <A> $BlockSize for $EcbEncryptionWithPkcs7Padding<A> { }

            impl <A: BlockEncryptor + $BlockSize> PaddedEncryptionMode for
                    $EcbEncryptionWithPkcs7Padding<A> {
                fn encrypt_block(&mut self, input: &[u8], handler: &fn(&[u8])) {
                    let mut tmp = [0u8, ..$block_size];
                    self.algo.encrypt_block(input, tmp);
                    handler(tmp);
                }
                fn encrypt_final_block(&mut self, input: Option<&[u8]>, handler: &fn(&[u8])) {
                    match input {
                        Some(input) => {
                            match input.len() % $block_size {
                                0 => {
                                    self.encrypt_block(input, |d: &[u8]| { handler(d); });
                                    let buff = [$block_size as u8, ..$block_size];
                                    self.encrypt_block(buff, |d: &[u8]| { handler(d); });
                                },
                                _ => {
                                    if (input.len() > $block_size) {
                                        fail!();
                                    }
                                    let val = ($block_size - input.len()) as u8;
                                    let mut buff = [0u8, ..$block_size];
                                    for i in range(0, input.len()) {
                                        buff[i] = input[i];
                                    }
                                    for i in range(input.len(), $block_size) {
                                        buff[i] = val;
                                    }
                                    self.encrypt_block(buff, |d: &[u8]| { handler(d); });
                                }
                            }
                        }
                        None => { }
                    }
                }
            }


            pub struct $CbcEncryptionWithNoPadding<A> {
                priv algo: A,
                priv last_block: [u8, ..$block_size]
            }

            impl <A: BlockEncryptor + $BlockSize> $CbcEncryptionWithNoPadding<A> {
                pub fn new(algo: A, iv: &[u8]) -> $CbcEncryptionWithNoPadding<A> {
                    let mut m = $CbcEncryptionWithNoPadding {
                        algo: algo,
                        last_block: [0u8, ..$block_size]
                    };
                    if (iv.len() != $block_size) {
                        fail!();
                    }
                    // TODO - this would be more efficient, but seems to crash:
                    // bytes::copy_memory(m.last_block, iv, $block_size);
                    for i in range(0, $block_size) {
                        m.last_block[i] = iv[i];
                    }
                    return m;
                }
            }

            impl <A> $BlockSize for $CbcEncryptionWithNoPadding<A> { }

            impl <A: BlockEncryptor + $BlockSize> PaddedEncryptionMode for
                    $CbcEncryptionWithNoPadding<A> {
                fn encrypt_block(&mut self, input: &[u8], handler: &fn(&[u8])) {
                    let mut tmp = [0u8, ..$block_size];
                    for i in range(0, $block_size) {
                        tmp[i] = self.last_block[i] ^ input[i];
                    }
                    self.algo.encrypt_block(tmp, self.last_block);
                    handler(self.last_block);
                }
                fn encrypt_final_block(&mut self, input: Option<&[u8]>, handler: &fn(&[u8])) {
                    match input {
                        Some(input) => { self.encrypt_block(input, handler) }
                        None => { }
                    }
                }
            }


            pub struct $CbcEncryptionWithPkcs7Padding<A> {
                priv algo: A,
                priv last_block: [u8, ..$block_size]
            }

            impl <A: BlockEncryptor + $BlockSize> $CbcEncryptionWithPkcs7Padding<A> {
                pub fn new(algo: A, iv: &[u8]) -> $CbcEncryptionWithPkcs7Padding<A> {
                    let mut m = $CbcEncryptionWithPkcs7Padding {
                        algo: algo,
                        last_block: [0u8, ..$block_size]
                    };
                    if (iv.len() != $block_size) {
                        fail!();
                    }
                    // TODO - this would be more efficient, but seems to crash:
                    // bytes::copy_memory(m.last_block, iv, $block_size);
                    for i in range(0, $block_size) {
                        m.last_block[i] = iv[i];
                    }
                    return m;
                }
            }

            impl <A> $BlockSize for $CbcEncryptionWithPkcs7Padding<A> { }

            impl <A: BlockEncryptor + $BlockSize> PaddedEncryptionMode for
                    $CbcEncryptionWithPkcs7Padding<A> {
                fn encrypt_block(&mut self, input: &[u8], handler: &fn(&[u8])) {
                    let mut tmp = [0u8, ..$block_size];
                    for i in range(0, $block_size) {
                        tmp[i] = self.last_block[i] ^ input[i];
                    }
                    self.algo.encrypt_block(tmp, self.last_block);
                    handler(self.last_block);
                }

                fn encrypt_final_block(&mut self, input: Option<&[u8]>, handler: &fn(&[u8])) {
                    match input {
                        Some(input) => {
                            match input.len() % $block_size {
                                0 => {
                                    self.encrypt_block(input, |d: &[u8]| { handler(d); });
                                    let buff = [$block_size as u8, ..$block_size];
                                    self.encrypt_block(buff, |d: &[u8]| { handler(d); });
                                },
                                _ => {
                                    if (input.len() > $block_size) {
                                        fail!();
                                    }
                                    let val = ($block_size - input.len()) as u8;
                                    let mut buff = [0u8, ..$block_size];
                                    for i in range(0, input.len()) {
                                        buff[i] = input[i];
                                    }
                                    for i in range(input.len(), $block_size) {
                                        buff[i] = val;
                                    }
                                    self.encrypt_block(buff, handler);
                                }
                            }
                        }
                        None => { }
                    }
                }
            }


            struct $EncryptionBuffer <M> {
                mode: M,
                buffer: $FixedBuffer
            }

            impl <M: PaddedEncryptionMode + $BlockSize> $EncryptionBuffer<M> {
                pub fn new(mode: M) -> $EncryptionBuffer<M> {
                    $EncryptionBuffer {
                        mode: mode,
                        buffer: $FixedBuffer::new()
                    }
                }
            }

            impl <M: PaddedEncryptionMode + $BlockSize> EncryptionBuffer for $EncryptionBuffer<M> {
                fn encrypt(&mut self, input: &[u8], handler: &fn(&[u8])) {
                    let func = |data: &[u8]| {
                        self.mode.encrypt_block(
                            data,
                            |x: &[u8]| { handler(x); })
                    };
                    self.buffer.input(input, func);
                }

                fn final(&mut self, handler: &fn(&[u8])) {
                    match self.buffer.position() {
                        0 => { self.mode.encrypt_final_block(None, handler); }
                        _ => {
                            self.mode.encrypt_final_block(
                                Some(self.buffer.current_buffer()),
                                handler);
                        }
                    }
                }
            }


            struct $CtrMode <A> {
                priv algo: A,
                priv last_block: [u8, ..$block_size],
                priv last_block_idx: uint,
                priv ctr: [u8, ..$block_size]
            }

            impl <A: BlockEncryptor + $BlockSize> $CtrMode<A> {
                pub fn new(algo: A, iv: &[u8]) -> $CtrMode<A> {
                    let mut m = $CtrMode {
                        algo: algo,
                        last_block: [0u8, ..$block_size],
                        last_block_idx: 0,
                        ctr: [0u8, ..$block_size]
                    };

                    let bs = $block_size;

                    bytes::copy_memory(m.ctr, iv, bs);
                    m.algo.encrypt_block(m.ctr, m.last_block);

                    return m;
                }
            }

            fn process_ctr<A: BlockEncryptor + $BlockSize>(
                    ctr: &mut $CtrMode<A>,
                    input: &[u8],
                    out: &mut [u8]) {
                let mut i = 0;
                while i < input.len() {
                    if ctr.last_block_idx == $block_size {
                        // increment the counter
                        for i in range(0, $block_size) {
                            ctr.ctr[$block_size - i - 1] += 1;
                            if ctr.ctr[$block_size - i - 1] != 0 {
                                break;
                            }
                        }

                        ctr.algo.encrypt_block(ctr.ctr, ctr.last_block);
                        ctr.last_block_idx = 0;
                    }
                    out[i] = ctr.last_block[ctr.last_block_idx] ^ input[i];
                    ctr.last_block_idx += 1;
                    i += 1;
                }
            }

            impl <A: BlockEncryptor + $BlockSize> StreamEncryptor for $CtrMode<A> {
                fn encrypt(&mut self, input: &[u8], out: &mut [u8]) {
                    process_ctr(self, input, out);
                }
            }

            impl <A: BlockEncryptor + $BlockSize> StreamDecryptor for $CtrMode<A> {
                fn decrypt(&mut self, input: &[u8], out: &mut [u8]) {
                    process_ctr(self, input, out);
                }
            }
        }
    )
)

impl_padded_modes!(
    padded_16, // mod name
    16, // block size
    FixedBuffer16, // FixedBuffer implementation to use
    BlockSize16, // Block size
    EcbEncryptionWithNoPadding16, // ecb w/ no padding mode name
    EcbEncryptionWithPkcs7Padding16, // ecb w/ pkcs#7 padding mode name
    CbcEncryptionWithNoPadding16, // cbc w/ no padding mode name
    CbcEncryptionWithPkcsPadding16, // cbc w/ no padding mode name
    CtrMode16, // ctr mode

    EncryptionBuffer16, // EncryptionBuffer for 128 bit block size
    DecryptionBuffer16 // EncryptionBuffer for 128 bit block size
)

#[cfg(test)]
mod tests {
    use std::num::from_str_radix;
    use std::vec;
    use std::iter::range_step;

    use aes::*;
    use blockmodes::padded_16::*;
    use symmetriccipher::*;

    // Test vectors from: NIST SP 800-38A

    fn key128() -> ~[u8] {
        from_str("2b7e151628aed2a6abf7158809cf4f3c")
    }

    fn iv() -> ~[u8] {
        from_str("000102030405060708090a0b0c0d0e0f")
    }

    fn ctr_iv() -> ~[u8] {
        from_str("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    }

    fn plain() -> ~[u8] {
        from_str(
            "6bc1bee22e409f96e93d7e117393172a" + "ae2d8a571e03ac9c9eb76fac45af8e51" +
            "30c81c46a35ce411e5fbc1191a0a52ef" + "f69f2445df4f9b17ad2b417be66c3710")
    }

    fn from_str(input: &str) -> ~[u8] {
        let mut out: ~[u8] = ~[];
        for i in range_step(0u, input.len(), 2) {
            let tmp: Option<u8> = from_str_radix(input.slice(i, i+2), 16);
            out.push(tmp.unwrap());
        };
        return out;
    }

    #[test]
    fn test_ecb_no_padding_128() {
        let key = key128();
        let plain = plain();
        let cipher = from_str(
            "3ad77bb40d7a3660a89ecaf32466ef97" + "f5d3d58503b9699de785895a96fdbaaf" +
            "43b1cd7f598ece23881b00e3ed030688" + "7b0c785e27e8ad3f8223207104725dd4");

        let mut output = ~[];

        let mut m_enc = EncryptionBuffer16::new(EcbEncryptionWithNoPadding16::new(
            Aes128Encryptor::new(key)));
        m_enc.encrypt(plain, |d: &[u8]| { output.push_all(d); });
        m_enc.final(|d: &[u8]| { output.push_all(d); });
        assert!(output == cipher);

//         let mut m_dec = EcbDecryptionWithNoPadding16::new(Aes128Encryptor::new(key));
//         m_dec.decrypt(cipher, tmp);
//         assert!(tmp == plain);
    }

    #[test]
    fn test_cbc_no_padding_128() {
        let key = key128();
        let iv = iv();
        let plain = plain();
        let cipher = from_str(
            "7649abac8119b246cee98e9b12e9197d" + "5086cb9b507219ee95db113a917678b2" +
            "73bed6b8e3c1743b7116e69e22229516" + "3ff1caa1681fac09120eca307586e1a7");

        let mut output = ~[];

        let mut m_enc = EncryptionBuffer16::new(CbcEncryptionWithNoPadding16::new(
            Aes128Encryptor::new(key), iv));
        m_enc.encrypt(plain, |d: &[u8]| { output.push_all(d); });
        m_enc.final(|d: &[u8]| { output.push_all(d); });
        assert!(output == cipher);

//         let mut m_dec = EcbDecryptionWithNoPadding16::new(Aes128Encryptor::new(key));
//         m_dec.decrypt(cipher, tmp);
//         assert!(tmp == plain);
    }

    #[test]
    fn test_ctr_128() {
        let key = key128();
        let iv = ctr_iv();
        let plain = plain();
        let cipher = from_str(
            "874d6191b620e3261bef6864990db6ce" + "9806f66b7970fdff8617187bb9fffdff" +
            "5ae4df3edbd5d35e5b4f09020db03eab" + "1e031dda2fbe03d1792170a0f3009cee");

        let mut tmp = vec::from_elem(plain.len(), 0u8);

        let mut m_enc = CtrMode16::new(Aes128Encryptor::new(key), iv);
        m_enc.encrypt(plain, tmp);
        assert!(tmp == cipher);

        let mut m_dec = CtrMode16::new(Aes128Encryptor::new(key), iv);
        m_dec.decrypt(cipher, tmp);
        assert!(tmp == plain);
    }
}
