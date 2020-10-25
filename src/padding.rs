use std::fmt::{Display, Formatter, Result as FmtResult};

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

    pub fn add_padding(message: &[u8], block_size: usize) -> Vec<u8> {
        let needed_padding = block_size - message.len() % block_size;
        let mut result = Vec::with_capacity(message.len() + needed_padding);
        result.extend_from_slice(message);
        result.extend(iter::repeat(needed_padding as u8).take(needed_padding));

        result
    }

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