use thiserror::Error;

#[derive(Error, Debug, PartialEq, Clone)]
pub enum DistanceError {
    #[error("Vectors are different lengths, can only xor vectors of equal length.")]
    InvalidLengths,
}

pub fn xor_two_values(first: &[u8], second: &[u8]) -> Result<Vec<u8>, DistanceError> {
    if first.len() != second.len() {
        return Err(DistanceError::InvalidLengths);
    };

    Ok(first
        .iter()
        .zip(&mut second.iter())
        .map(|(&first, &second)| first ^ second)
        .collect())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_xor_two_zeros() {
        let one = vec![0];
        let two = vec![0];
        assert_eq!(xor_two_values(&one, &two).unwrap(), [0]);
    }

    #[test]
    fn test_xor_two_values() {
        let one = vec![1, 0, 0];
        let two = vec![0, 0, 1];
        assert_eq!(xor_two_values(&one, &two).unwrap(), [1, 0, 1]);
    }

    #[test]
    #[should_panic(expected = "InvalidLengths")]
    fn test_xor_panics_with_different_lengths() {
        let one = vec![1, 0];
        let two = vec![0, 0, 1];
        xor_two_values(&one, &two).unwrap();
    }
}
