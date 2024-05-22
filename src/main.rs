//! In Module 1, we discussed Block ciphers like AES. Block ciphers have a fixed length input.
//! Real wold data that we wish to encrypt _may_ be exactly the right length, but is probably not.
//! When your data is too short, you can simply pad it up to the correct length.
//! When your data is too long, you have some options.
//!
//! In this exercise, we will explore a few of the common ways that large pieces of data can be
//! broken up and combined in order to encrypt it with a fixed-length block cipher.
//!
//! WARNING: ECB MODE IS NOT SECURE.
//! Seriously, ECB is NOT secure. Don't use it irl. We are implementing it here to understand _why_
//! it is not secure and make the point that the most straight-forward approach isn't always the
//! best, and can sometimes be trivially broken.

use aes::{
    cipher::{generic_array::GenericArray, BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};
use rand::{Rng};

///We're using AES 128 which has 16-byte (128 bit) blocks.
const BLOCK_SIZE: usize = 16;

fn main() {
    todo!("Maybe this should be a library crate. TBD");
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_encrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    // Convert the inputs to the necessary data type
    let mut block = GenericArray::from(data);
    let key = GenericArray::from(*key);

    let cipher = Aes128::new(&key);

    cipher.encrypt_block(&mut block);

    block.into()
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_decrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    // Convert the inputs to the necessary data type
    let mut block = GenericArray::from(data);
    let key = GenericArray::from(*key);

    let cipher = Aes128::new(&key);

    cipher.decrypt_block(&mut block);

    block.into()
}

/// Before we can begin encrypting our raw data, we need it to be a multiple of the
/// block length which is 16 bytes (128 bits) in AES128.
///
/// The padding algorithm here is actually not trivial. The trouble is that if we just
/// naively throw a bunch of zeros on the end, there is no way to know, later, whether
/// those zeros are padding, or part of the message, or some of each.
///
/// The scheme works like this. If the data is not a multiple of the block length,  we
/// compute how many pad bytes we need, and then write that number into the last several bytes.
/// Later we look at the last byte, and remove that number of bytes.
///
/// But if the data _is_ a multiple of the block length, then we have a problem. We don't want
/// to later look at the last byte and remove part of the data. Instead, in this case, we add
/// another entire block containing the block length in each byte. In our case,
/// [16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]
fn pad(mut data: Vec<u8>) -> Vec<u8> {
    // When twe have a multiple the second term is 0
    let number_pad_bytes = BLOCK_SIZE - data.len() % BLOCK_SIZE;

    for _ in 0..number_pad_bytes {
        data.push(number_pad_bytes as u8);
    }

    data
}

/// Groups the data into BLOCK_SIZE blocks. Assumes the data is already
/// a multiple of the block size. If this is not the case, call `pad` first.
fn group(data: Vec<u8>) -> Vec<[u8; BLOCK_SIZE]> {
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let mut block: [u8; BLOCK_SIZE] = Default::default();
        block.copy_from_slice(&data[i..i + BLOCK_SIZE]);
        blocks.push(block);

        i += BLOCK_SIZE;
    }

    blocks
}

/// Does the opposite of the group function
fn un_group(blocks: Vec<[u8; BLOCK_SIZE]>) -> Vec<u8> {
    blocks.into_iter().flatten().collect()
}

/// Does the opposite of the pad function.
fn un_pad(data: Vec<u8>) -> Vec<u8> {
    let mut result = data.clone();
    let n_bytes = data.last().unwrap().clone() as usize;
    result.truncate(result.len() - n_bytes);
    result
}

/// The first mode we will implement is the Electronic Code Book, or ECB mode.
/// Warning: THIS MODE IS NOT SECURE!!!!
///
/// This is probably the first thing you think of when considering how to encrypt
/// large data. In this mode we simply encrypt each block of data under the same key.
/// One good thing about this mode is that it is parallelizable. But to see why it is
/// insecure look at: https://www.ubiqsecurity.com/wp-content/uploads/2022/02/ECB2.png
fn ecb_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    un_group(
        group(pad(plain_text))
            .into_iter()
            .map(|x| aes_encrypt(x, &key))
            .collect(),
    )
}

/// Opposite of ecb_encrypt.
fn ecb_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    un_pad(un_group(
        group(cipher_text)
            .into_iter()
            .map(|x| aes_decrypt(x, &key))
            .collect(),
    ))
}

/// The next mode, which you can implement on your own is cipherblock chaining.
/// This mode actually is secure, and it often used in real world applications.
///
/// In this mode, the ciphertext from the first block is XORed with the
/// plaintext of the next block before it is encrypted.
///
/// For more information, and a very clear diagram,
/// see https://de.wikipedia.org/wiki/Cipher_Block_Chaining_Mode
///
/// You will need to generate a random initialization vector (IV) to encrypt the
/// very first block because it doesn't have a previous block. Typically this IV
/// is inserted as the first block of ciphertext.
fn cbc_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // Remember to generate a random initialization vector for the first block.
    let mut iv = [0u8; 16].map(|_| rand::thread_rng().gen_range(0..=255u8));

    let padded_group = group(pad(plain_text));
    let mut encrypted_group = vec![];
    encrypted_group.push(iv);

    for i in 0..padded_group.len() {
        let chunk = padded_group[i];
        let mut idx = 0;
        let xor_chunk = chunk.map(|v| {
            idx += 1;
            v ^ iv[idx - 1]
        });
        encrypted_group.push(aes_encrypt(xor_chunk, &key));
        iv = encrypted_group[i + 1].clone();
    }

    un_group(encrypted_group)
}

fn cbc_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let grouped = group(cipher_text);
    let mut iv = grouped[0];
    let mut decrypted_group = vec![];

    for i in 1..grouped.len() {
        let chunk = grouped[i];
        let mut idx = 0;
        let decrypted_chunk = aes_decrypt(chunk, &key);
        let xor_chunk = decrypted_chunk.map(|v| {
            idx += 1;
            v ^ iv[idx - 1]
        });
        decrypted_group.push(xor_chunk);
        iv = grouped[i].clone();
    }

    un_pad(un_group(decrypted_group))
}

/// Another mode which you can implement on your own is counter mode.
/// This mode is secure as well, and is used in real world applications.
/// It allows parallelized encryption and decryption, as well as random read access when decrypting.
///
/// In this mode, there is an index for each block being encrypted (the "counter"), as well as a random nonce.
/// For a 128-bit cipher, the nonce is 64 bits long.
///
/// For the ith block, the 128-bit value V of `nonce | counter` is constructed, where | denotes
/// concatenation. Then, V is encrypted with the key using ECB mode. Finally, the encrypted V is
/// XOR'd with the plaintext to produce the ciphertext.
///
/// A very clear diagram is present here:
/// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
///
/// Once again, you will need to generate a random nonce which is 64 bits long. This should be
/// inserted as the first block of the ciphertext.
fn ctr_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let plain_text = pad(plain_text);
    let mut cipher_text = Vec::with_capacity(plain_text.len() + BLOCK_SIZE);
    let nonce = rand::thread_rng().gen::<u64>();
    cipher_text.extend(nonce.to_le_bytes());
    (0..BLOCK_SIZE - 8).for_each(|_| cipher_text.push(0));
    cipher_text.extend(ctr_transform(plain_text, key, nonce));
    cipher_text
}

fn ctr_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let nonce = u64::from_le_bytes(cipher_text[..8].try_into().unwrap());
    let cipher_text = cipher_text[BLOCK_SIZE..].to_owned();
    un_pad(ctr_transform(cipher_text, key, nonce))
}

fn ctr_transform(data: Vec<u8>, key: [u8; BLOCK_SIZE], nonce: u64) -> Vec<u8> {
    let mut cipher_text = Vec::with_capacity(data.len());

    for (counter, block) in group(data).into_iter().enumerate() {
        let v = nonce
            .to_le_bytes()
            .into_iter()
            .chain((counter as u64).to_le_bytes().into_iter())
            .collect::<Vec<_>>();
        cipher_text.extend(
            ecb_encrypt(v, key.clone())
                .iter()
                .zip(block.iter())
                .map(|(a, b)| a ^ b)
                .collect::<Vec<_>>(),
        );
    }

    cipher_text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unpadding() {
        let data = vec![1, 2, 3];
        let padded = pad(data.clone());
        assert_eq!(padded.len() % BLOCK_SIZE, 0);
        assert_eq!(un_pad(padded), data);
    }

    #[test]
    fn test_ungrouping() {
        let data = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
        ];
        let padded = pad(data.clone());
        let grouped = group(padded.clone());
        let ungrouped = un_group(grouped);
        assert_eq!(ungrouped, padded);
        assert_eq!(un_pad(ungrouped), data);
    }

    #[test]
    fn test_ecb_encrypt_decrypt() {
        let data = b"Hello, world! ECB!";
        let key = [1u8; BLOCK_SIZE];
        let encrypted = ecb_encrypt(data.to_vec(), key);
        let decrypted = ecb_decrypt(encrypted, key);
        assert_eq!(decrypted, data.to_vec());
    }

    #[test]
    fn test_cbc_encrypt_decrypt() {
        let data = b"Hello, world! CBC!";
        let key = [1u8; BLOCK_SIZE];
        let encrypted = cbc_encrypt(data.to_vec(), key);
        let decrypted = cbc_decrypt(encrypted, key);
        assert_eq!(decrypted, data.to_vec());
    }

    #[test]
    fn test_ctr_encrypt_decrypt() {
        let data = b"Hello, world! CTR!";
        let key = [1u8; BLOCK_SIZE];
        let encrypted = ctr_encrypt(data.to_vec(), key);
        let decrypted = ctr_decrypt(encrypted, key);
        assert_eq!(decrypted, data.to_vec());
    }
}
