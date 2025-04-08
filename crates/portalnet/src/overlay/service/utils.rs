use ssz::Encode;

/// Limits the elements count to a maximum packet size, including the discv5 header overhead.
pub fn pop_while_ssz_bytes_len_gt<SSZObject: Encode>(
    elements: &mut Vec<SSZObject>,
    max_size: usize,
) {
    while elements.ssz_bytes_len() > max_size {
        elements.pop();
    }
}
