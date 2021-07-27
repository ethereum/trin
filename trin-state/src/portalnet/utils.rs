use super::protocol::TRIN_DATA_ENV_VAR;
use std::env;

pub fn xor_two_values(first: &Vec<u8>, second: &Vec<u8>) -> Vec<u8> {
    if &first.len() != &second.len() {
        panic!("Can only xor vectors of equal length.")
    };

    first
        .iter()
        .zip(&mut second.iter())
        .map(|(&first, &second)| first ^ second)
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_xor_two_zeros() {
        let one = vec![0];
        let two = vec![0];
        assert_eq!(xor_two_values(&one, &two), [0]);
    }

    #[test]
    fn test_xor_two_values() {
        let one = vec![1, 0, 0];
        let two = vec![0, 0, 1];
        assert_eq!(xor_two_values(&one, &two), [1, 0, 1]);
    }

    #[test]
    #[should_panic(expected = "Can only xor vectors of equal length.")]
    fn test_xor_panics_with_different_lengths() {
        let one = vec![1, 0];
        let two = vec![0, 0, 1];
        xor_two_values(&one, &two);
    }
}

pub fn get_data_dir() -> String {
    match env::var(TRIN_DATA_ENV_VAR) {
        Ok(data_path) => data_path,
        Err(_) => get_default_data_dir(),
    }
}

pub fn get_default_data_dir() -> String {
    // Windows: C:\Users\Username\AppData\Roaming\Trin
    // macOS: ~/Library/Application Support/Trin
    // Unix-like: ~/.trin

    if cfg!(windows) {
        let path_ret = env::var("APPDATA").unwrap();
        format!("{}{}", path_ret, "\\Trin")
    } else {
        let path_ret = env::var("Home").unwrap_or(String::from("/"));
        if cfg!(macos) {
            format!("{}{}", path_ret, "/Library/Application Support/Trin")
        } else {
            format!("{}{}", path_ret, "/.trin")
        }
    }
}
