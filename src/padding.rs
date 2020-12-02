//! Provides some common padding functions.

use std::fmt::{Display, Formatter, Result as FmtResult};

/// Represents an anomaly found when removing padding from a message.
#[derive(Debug)]
pub struct PaddingError(String);

impl Display for PaddingError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.0)
    }
}

pub mod pkcs7 {
    use {
        std::iter,
        super::PaddingError,
    };

    /// Produces a padded message to fit the given block size following PKCS#7.
    ///
    /// # Panics
    ///
    /// Only block sizes up to 256 are allowed. In any other case the function will panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use feistel::padding::pkcs7::add_padding;
    ///
    /// let msg = b"Hello, World!";
    /// let mut expected_result = Vec::with_capacity(msg.len() + 2);
    /// expected_result.extend_from_slice(&msg[..]);
    /// expected_result.push(2);
    /// expected_result.push(2);
    ///
    /// let padded_msg = add_padding(&msg[..], 15);
    /// 
    /// assert_eq!(&expected_result[..], &padded_msg[..]);
    /// ```
    pub fn add_padding(message: &[u8], block_size: usize) -> Vec<u8> {
        assert!(block_size <= 256, "Only block sizes up to 256 are allowed!");

        let needed_padding = block_size - message.len() % block_size;
        let mut result = Vec::with_capacity(message.len() + needed_padding);
        result.extend_from_slice(message);
        result.extend(iter::repeat(needed_padding as u8).take(needed_padding));

        result
    }

    /// Deletes padding from a message following PKCS#7.
    ///
    /// # Failures
    /// If a valid padding is not found, a `PaddingError` is produced.
    ///
    /// # Examples
    ///
    /// ```
    /// use feistel::padding::pkcs7::remove_padding;
    ///
    /// let msg = b"Hello, World!";
    /// let mut msg_to_clean = Vec::with_capacity(msg.len() + 2);
    /// msg_to_clean.extend_from_slice(&msg[..]);
    /// msg_to_clean.push(2);
    /// msg_to_clean.push(2);
    ///
    /// remove_padding(&mut msg_to_clean).unwrap();
    /// 
    /// assert_eq!(&msg[..], &msg_to_clean[..]);
    /// ```
    pub fn remove_padding(message: &mut Vec<u8>) -> Result<(), PaddingError>{
        let padding = match message.last() {
            None => return Err(PaddingError(String::from("Empty message."))),
            Some(padding) if *padding > 0 => *padding,
            _ => return Err(PaddingError(String::from("Padding number cannot be 0."))),
        };
        for _ in 1..=padding {
            match message.pop() {
                Some(value) if value == padding => continue,
                _ => return Err(PaddingError(String::from("Malformed padding."))),
            }
        }

        Ok(())
    }
}