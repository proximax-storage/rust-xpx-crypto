use rand::rngs::OsRng;
use rand::RngCore;

use crate::{ExpandedSecretKey, PublicKey, SecretKey, IV_SIZE, KEY_SIZE};
use curve25519_dalek::edwards::EdwardsPoint;
use hex::{decode, encode};

use crate::aes::Aes256;
use ::std::{
    string::{String, ToString},
    vec::Vec,
};
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use curve25519_dalek::digest::Digest;
use sha3::Sha3_256;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

/**
 * Implementation of the block cipher for Ed25519.
 */
struct Ed25519BlockCipher {
    secret_key: SecretKey,
    random: OsRng,
}

impl Ed25519BlockCipher {
    pub fn new(secret_key: SecretKey) -> Self {
        Ed25519BlockCipher {
            secret_key,
            random: OsRng::default(),
        }
    }

    fn xor_with_g(&self, other: &[u8], key: &[u8]) -> [u8; KEY_SIZE] {
        assert_eq!(other.len(), KEY_SIZE);
        let mut r = [0u8; KEY_SIZE];
        for (i, (a, b)) in key.iter().zip(other.iter()).enumerate() {
            r[i] = a ^ b;
        }
        r
    }

    pub fn encrypt(&mut self, msg: &[u8], public: PublicKey) -> Vec<u8> {
        let mut salt = [0u8; KEY_SIZE];
        self.random.fill_bytes(&mut salt);
        let key = self.derive_shared_key(&salt, public);

        let mut iv = [0u8; IV_SIZE];
        self.random.fill_bytes(&mut iv);

        let cipher = Aes256Cbc::new_var(&key, &iv).unwrap();
        let body = cipher.encrypt_vec(msg);
        let mut output = vec![];
        output.extend_from_slice(&salt);
        output.extend_from_slice(&iv);
        output.extend_from_slice(&body);
        output
    }

    pub fn decrypt(&mut self, enc_msg: &[u8], public: PublicKey) -> Result<Vec<u8>, String> {
        if enc_msg.len() < 48 {
            return Err(String::from("Too short encrypt message"));
        }
        let salt = &enc_msg[..KEY_SIZE];
        let iv = &enc_msg[KEY_SIZE..KEY_SIZE + IV_SIZE];
        let body = &enc_msg[KEY_SIZE + IV_SIZE..];

        let key = self.derive_shared_key(&salt, public);

        let cipher = Aes256Cbc::new_var(&key, &iv).unwrap();
        match cipher.decrypt_vec(body) {
            Ok(msg) => Ok(msg),
            Err(err) => Err(err.to_string()),
        }
    }

    fn derive_shared_key(&mut self, salt: &[u8], public: PublicKey) -> Vec<u8> {
        let shared_secret = self.derive_shared_secret(public);
        let sb = self.xor_with_g(salt, &shared_secret);
        let shared_secret = Sha3_256::digest(&sb);

        shared_secret.to_vec()
    }

    fn derive_shared_secret(&mut self, public: PublicKey) -> [u8; KEY_SIZE] {
        let d: ExpandedSecretKey = ExpandedSecretKey::from(&self.secret_key);

        let minus_a = public.1;

        let a: EdwardsPoint = d.key * &(minus_a);
        let shared_secret = a.compress().to_bytes();

        shared_secret
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use failure::_core::str::from_utf8;

    #[test]
    fn keypair_clear_on_drop() {
        let sender_secret_key = SecretKey::from_bytes(
            &decode("B38A1490B33A4BD718ABB0A1BEF389CAE07A435F3DEC39BC518D84B1ABF8531B").unwrap(),
        )
        .unwrap();

        let recipient_secret_key = SecretKey::from_bytes(
            &decode("69441d693502557fa37b3d030bf997425d8bd60e3d42f8a404aa14798ae97bea").unwrap(),
        )
        .unwrap();

        let sender_public_key: PublicKey = (&sender_secret_key).into();

        let mut block = Ed25519BlockCipher::new(sender_secret_key);

        let msg = "eleazar.garrido@proximax.io".as_bytes();

        let public_key: PublicKey = (&recipient_secret_key).into();
        let block_msg = block.encrypt(msg, public_key);
        println!("two: {:?}", encode(&block_msg));

        let mut block = Ed25519BlockCipher::new(recipient_secret_key);

        let block_msg = block.decrypt(&block_msg, sender_public_key);

        println!("two: {:?}", from_utf8(&block_msg.unwrap()));
    }
}
