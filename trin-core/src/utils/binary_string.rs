use rand::Rng;
use std::num::ParseIntError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Clone)]
pub enum BinaryStringError {
    #[error("Unable to parse binary string!")]
    ParseError(#[from] ParseIntError),
}

/// Generate random 256-bit binary string with leading zeroes
pub fn generate_random(leading_zeroes: u8) -> String {
    let charset: &[u8] = b"01";
    let rhs_len = 255 - leading_zeroes;
    let mut rng = rand::thread_rng();

    let rhs: String = (0..rhs_len)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx] as char
        })
        .collect();

    let mut result = "0".repeat(leading_zeroes as usize);
    // We want the bit after leading zeroes to always be 1
    result.push('1');

    result.push_str(&*rhs);

    result
}

/// Convert binary string to byte array
pub fn to_byte_array(input: &str) -> Result<Vec<u8>, BinaryStringError> {
    let mut z = input.chars().peekable();

    let mut result: Vec<u8> = Vec::new();

    while z.peek().is_some() {
        let chunk: String = z.by_ref().take(8).collect();
        let byte = u8::from_str_radix(&chunk, 2)?;
        result.push(byte);
    }
    Ok(result)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn generate_binary_string() {
        let result = generate_random(5);

        assert_eq!(result.len(), 256);
        assert_eq!(&result[0..5], "00000");
        assert_eq!(&result[5..6], "1");
    }

    #[test]
    fn string_to_byte_array() {
        let string = "000000111111111110101010";
        let byte_array = to_byte_array(string).unwrap();
        assert_eq!(vec![3, 255, 170], byte_array)
    }
}
