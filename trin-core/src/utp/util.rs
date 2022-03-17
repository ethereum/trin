use num::ToPrimitive;
use rand::Rng;
use std::ops::Sub;

/// Calculate the exponential weighted moving average for a vector of numbers, with a smoothing
/// factor `alpha` between 0 and 1. A higher `alpha` discounts older observations faster.
pub fn ewma<'a, T, I>(mut samples: I, alpha: f64) -> f64
where
    T: ToPrimitive + 'a,
    I: Iterator<Item = &'a T>,
{
    let first = samples.next().map_or(0.0, |v| v.to_f64().unwrap());
    samples
        .map(|v| v.to_f64().unwrap())
        .fold(first, |avg, sample| alpha * sample + (1.0 - alpha) * avg)
}

/// Returns the absolute difference between two values.
pub fn abs_diff<T: PartialOrd + Sub<Output = U>, U>(a: T, b: T) -> U {
    if a > b {
        a - b
    } else {
        b - a
    }
}

/// Safely generates two sequential connection identifiers.
///
/// This avoids an overflow when the generated receiver identifier is the largest
/// representable value in u16 and it is incremented to yield the corresponding sender
/// identifier.
pub fn generate_sequential_identifiers() -> (u16, u16) {
    let mut rng = rand::thread_rng();
    let id = rng.gen::<u16>();
    if id.checked_add(1).is_some() {
        (id, id + 1)
    } else {
        (id - 1, id)
    }
}

#[cfg(test)]
mod test {
    use crate::utp::util::*;

    #[test]
    fn test_ewma_empty_vector() {
        let empty: Vec<u32> = vec![];
        let alpha = 1.0 / 3.0;
        assert_eq!(ewma(empty.iter(), alpha), 0.0);
    }

    #[test]
    fn test_ewma_one_element() {
        let input = vec![1u32];
        let alpha = 1.0 / 3.0;
        assert_eq!(ewma(input.iter(), alpha), 1.0);
    }

    #[test]
    fn test_exponential_smoothed_moving_average() {
        let input = (1u32..11).collect::<Vec<u32>>();
        let alpha = 1.0 / 3.0;
        let expected = [
            1.0,
            4.0 / 3.0,
            17.0 / 9.0,
            70.0 / 27.0,
            275.0 / 81.0,
            1036.0 / 243.0,
            3773.0 / 729.0,
            13378.0 / 2187.0,
            46439.0 / 6561.0,
            158488.0 / 19683.0,
        ];
        assert_eq!(ewma(input.iter(), alpha), expected[expected.len() - 1]);
    }

    #[test]
    fn test_abs_diff() {
        let a = 10;
        let b = 5;
        assert_eq!(abs_diff(a, b), 5);
        assert_eq!(abs_diff(b, a), 5);
    }

    #[test]
    fn test_generate_sequential_identifiers() {
        let (id_1, id_2) = generate_sequential_identifiers();
        assert!(id_2 == id_1 + 1 || id_2 == id_1 - 1);
    }
}
