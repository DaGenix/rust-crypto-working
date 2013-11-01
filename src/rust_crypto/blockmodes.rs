// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use symmetriccipher::{BlockEncryptor, BlockEncryptorX8, BlockDecryptor, BlockDecryptorX8,
    Encryptor, Decryptor, SynchronousStreamCipher};

struct EcbMode<A> {
    algo: A,
    buffer: FixedBuffer
}

impl Encryptor {
    fn encrypt(&mut self, input: &[u8], handler: |&[u8]|) {

    }
    fn encrypt_final(&mut self, input: &[u8], handler: |&[u8]|) {

    }
}








trait BlockEncryptionModes {
    fn encrypt_ecb(&self, input: &[u8], output: &mut [u8]);
    fn encrypt_cbc_no_padding(&self, iv: &[u8], input: &[u8], output: &mut [u8]);
    fn encrypt_cbc_pkcs7(&self, iv: &[u8], input: &[u8], output: &mut [u8]);
    fn encrypt_ctr(&self, ctr: &[u8], input: &[u8], output: &mut [u8]);
}

impl <T: BlockEncryptor> BlockEncryptionModes for T {
    fn encrypt_ecb(&self, input: &[u8], output: &mut [u8]) {

    }
    fn encrypt_cbc_no_padding(&self, iv: &[u8], input: &[u8], output: &mut [u8]) {

    }
    fn encrypt_cbc_pkcs7(&self, iv: &[u8], input: &[u8], output: &mut [u8]) {

    }
    fn encrypt_ctr(&self, ctr: &[u8], input: &[u8], output: &mut [u8]) {

    }
}

trait BlockDecryptionModes {
    fn decrypt_ecb(&self, input: &[u8], output: &mut [u8]);
    fn decrypt_cbc_no_padding(&self, iv: &[u8], input: &[u8], output: &mut [u8]);
    fn decrypt_cbc_pkcs7(&self, iv: &[u8], input: &[u8], output: &mut [u8]);
    fn decrypt_ctr(&self, ctr: &[u8], input: &[u8], output: &mut [u8]);
}

impl <T: BlockEncryptor> BlockDecryptionModes for T {
    fn decrypt_ecb(&self, input: &[u8], output: &mut [u8]) {

    }
    fn decrypt_cbc_no_padding(&self, iv: &[u8], input: &[u8], output: &mut [u8]) {

    }
    fn decrypt_cbc_pkcs7(&self, iv: &[u8], input: &[u8], output: &mut [u8]) {

    }
    fn decrypt_ctr(&self, ctr: &[u8], input: &[u8], output: &mut [u8]) {

    }
}

#[cfg(test)]
mod tests {
/*
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
*/
}
