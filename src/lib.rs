use std::iter;

fn slices_xor(s1: &[u8], s2: &[u8]) -> Vec<u8> {
    assert_eq!(s1.len(), s2.len());

    let mut result = Vec::with_capacity(s1.len());
    for i in 0..s1.len() {
        result.push(s1[i] ^ s2[i]);
    }

    result
}

fn execute_rounds<F: Fn(&[u8], &[u8]) -> Vec<u8>>(
    result: &mut [u8],
    block_size: usize,
    key: &[u8],
    function: F,
    rounds: u32,
) {
    let (mut start, mut middle, mut end): (usize, usize, usize);
    let (mut left, mut right);
    let half_block_size = block_size/2;

    start = 0;
    while start < result.len() {
        middle = start + half_block_size;
        end = middle + half_block_size;

        for _ in 1..=rounds {
            left = result[start..middle].to_owned();
            right = result[middle..end].to_owned();

            result[start..middle].copy_from_slice(&right[..]);
            
            right = function(&right[..], key);
            left = slices_xor(&left[..], &right[..]);
            result[middle..end].copy_from_slice(&left[..]);
        }

        left = result[start..middle].to_owned();
        right = result[middle..end].to_owned();
        result[start..middle].copy_from_slice(&right[..]);
        result[middle..end].copy_from_slice(&left[..]);
        
        start = end;
    }
}

pub fn cipher<F: Fn(&[u8], &[u8]) -> Vec<u8>>(
    message: &[u8],
    block_size: usize,
    key: &[u8],
    function: F,
    rounds: u32,
) -> Vec<u8>
{
    assert!(block_size > 0 && block_size%2 == 0);

    let needed_padding = block_size - message.len() % block_size;
    let mut result = Vec::with_capacity(message.len() + needed_padding);
    result.extend_from_slice(message);
    result.extend(iter::repeat(needed_padding as u8).take(needed_padding));

    execute_rounds(&mut result[..], block_size, key, function, rounds);

    result
}

pub fn decipher<F: Fn(&[u8], &[u8]) -> Vec<u8>>(
    message: &[u8],
    block_size: usize,
    key: &[u8],
    function: F,
    rounds: u32,
) -> Vec<u8> {
    assert!(block_size > 0 && block_size%2 == 0);

    let mut result = Vec::with_capacity(message.len());
    result.extend_from_slice(message);

    execute_rounds(&mut result[..], block_size, key, function, rounds);

    let padding = match result.last() {
        None => panic!("No padding found."),
        Some(padding) => *padding,
    };

    for _ in 1..=padding {
        match result.pop() {
            Some(value) if value == padding => continue,
            _ => panic!("Malformed padding."),
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let ciphered = cipher(&message[..], 16, &key[..], slices_or, 50);
        let deciphered = decipher(&ciphered[..], 16, &key[..], slices_or, 50);
        assert_eq!(&message[..], &deciphered[..]);
    }
}
