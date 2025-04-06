use ethportal_api::SszEnr;
use ssz::Encode;

/// Limits a to a maximum packet size, including the discv5 header overhead.
pub fn pop_while_ssz_bytes_len_gt(enrs: &mut Vec<SszEnr>, max_size: usize) {
    while enrs.ssz_bytes_len() > max_size {
        enrs.pop();
    }
}
