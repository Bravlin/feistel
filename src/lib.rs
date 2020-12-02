//! Provides functions to start applying specialized Feistel ciphers right away.

pub mod padding;

use padding::PaddingError;

fn execute_rounds<K, F>(
    result: &mut [u8],
    block_size: usize,
    mut key_generator: K,
    round_function: F,
    rounds: usize,
)
where
    K: FnMut() -> Vec<u8>,
    F: Fn(&[u8], &[u8]) -> Vec<u8>,
{
    let (mut start, mut middle, mut end): (usize, usize, usize);
    let (mut left, mut right);
    let mut key;
    let half_block_size = block_size/2;

    start = 0;
    while start < result.len() {
        middle = start + half_block_size;
        end = middle + half_block_size;

        for _ in 1..=rounds {
            left = result[start..middle].to_owned();
            right = result[middle..end].to_owned();

            result[start..middle].copy_from_slice(&right[..]);
            
            // Produces the next right side
            key = key_generator();
            right = round_function(&right[..], &key[..]);
            for i in 0..half_block_size {
                left[i] ^= right[i];
            }
            result[middle..end].copy_from_slice(&left[..]);
        }

        left = result[start..middle].to_owned();
        right = result[middle..end].to_owned();
        result[start..middle].copy_from_slice(&right[..]);
        result[middle..end].copy_from_slice(&left[..]);
        
        start = end;
    }
}

/// Returns an encrypted message.
///
/// # Arguments
///
/// * `message` - A byte string slice to the original message.
///
/// * `block_size` - The data block size in bytes. It must be a multiple of 2.
///
/// * `padder` - A closure that adds the necessary padding to the original message.
///
/// * `key_generator` - A FnMut closure that provides the key for each round.
///
/// * `round_function` - A closure that receives a slice of a data block and a slice of a key to
/// produce an owned output of the same size as the data block.
/// 
/// * `rounds` - The number of times that the Fiestel cipher should be applied.
///
/// # Panics
///
/// The specified block size was 0 or it was not a multiple of 2.
pub fn cipher<P, K, F>(
    message: &[u8],
    block_size: usize,
    padder: P,
    key_generator: K,
    round_function: F,
    rounds: usize,
) -> Vec<u8>
where
    P: Fn(&[u8], usize) -> Vec<u8>,
    K: FnMut() -> Vec<u8>,
    F: Fn(&[u8], &[u8]) -> Vec<u8>,
{
    assert!(block_size > 0, "Block size was 0!");
    assert!(block_size%2 == 0, "Block size was not a multiple of 2!");


    let mut result = padder(message, block_size);
    execute_rounds(&mut result[..], block_size, key_generator, round_function, rounds);

    result
}

/// Returns a desencrypted message.
///
/// # Arguments
///
/// * `message` - A byte string slice to the encrypted message.
///
/// * `block_size` - The data block size in bytes. It must be a multiple of 2.
///
/// * `key_generator` - A FnMut closure that provides the key for each round.
///
/// * `round_function` - A closure that receives a slice of a data block and a slice of a key to
/// produce an owned output of the same size as the data block.
/// 
/// * `rounds` - The number of times that the Fiestel cipher should be applied.
///
/// * `padding_remover` - A closure thar receives a desencrypted message stored in a Vec and
/// removes its padding (which was neccesary during the encryption of the message). It produces a
/// PaddingError in case that the message is malformed for the particular padding strategy.
///
/// # Panics
///
/// The specified block size was 0 or it was not a multiple of 2.
///
/// # Failures
///
/// If the desencrypted messsage was not correctly padded according to the closure
/// `padding_remover`, a `PaddingError` is produced.
pub fn decipher<K, F, R>(
    message: &[u8],
    block_size: usize,
    key_generator: K,
    round_function: F,
    rounds: usize,
    padding_remover: R,
) -> Result<Vec<u8>, PaddingError>
where
    K: FnMut() -> Vec<u8>,
    F: Fn(&[u8], &[u8]) -> Vec<u8>,
    R: Fn(&mut Vec<u8>) -> Result<(), PaddingError>,
{
    assert!(block_size > 0, "Block size was 0!");
    assert!(block_size%2 == 0, "Block size was not a multiple of 2!");

    let mut result = Vec::with_capacity(message.len());
    result.extend_from_slice(message);
    execute_rounds(&mut result[..], block_size, key_generator, round_function, rounds);
    padding_remover(&mut result)?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        padding::pkcs7,
    };

    fn slices_or(s1: &[u8], s2: &[u8]) -> Vec<u8> {
        let (shortest, longest) = if s1.len() < s2.len() { (s1, s2) } else { (s2, s1) };
        let mut result = Vec::with_capacity(longest.len());
        let mut i: usize = 0;
    
        while i < shortest.len() {
            result.push(shortest[i] | longest[i]);
            i += 1;
        }
        while i < longest.len() {
            result.push(longest[i]);
            i += 1;
        }
    
        result
    }

    #[test]
    fn test() {
        let message = b"Hello, World!";
        let key = b"Password";
        let mut key_count: u8 = 0;

        let ciphered = {
            let keys_to_cipher = || {
                let mut result = Vec::with_capacity(key.len());
                for i in 0..key.len() {
                    result.push(key[i] ^ key_count);
                }
                key_count += 1;
                
                result
            };
            cipher(
                &message[..],
                16,
                pkcs7::add_padding,
                keys_to_cipher,
                slices_or,
                50,
            )
        };

        let deciphered = {
            let keys_to_decipher = || {
                let mut result = Vec::with_capacity(key.len());
                key_count -= 1;
                for i in 0..key.len() {
                    result.push(key[i] ^ key_count);
                }

                result
            };
            decipher(
                &ciphered[..],
                16,
                keys_to_decipher,
                slices_or,
                50,
                pkcs7::remove_padding
            ).unwrap()
        };

        assert_eq!(&message[..], &deciphered[..]);
    }
}
