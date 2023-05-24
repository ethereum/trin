use ethereum_types::U256;

// distance function as defined at...
// https://github.com/ethereum/portal-network-specs/blob/master/state-network.md
pub fn distance(node_id: U256, content_id: U256) -> U256 {
    let diff: U256 = if node_id > content_id {
        node_id.saturating_sub(content_id)
    } else {
        content_id.saturating_sub(node_id)
    };

    let mid = U256::from(2).pow(U256::from(255));
    if diff > mid {
        return U256::max_value()
            .saturating_sub(diff)
            .saturating_add(U256::from(1));
    }

    diff
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use test_log::test;

    // all 7 of these test cases are from
    // https://github.com/ethereum/portal-network-specs/blob/master/state-network.md
    // assert distance(10, 10) == 0
    #[test]
    fn test_distance_one() {
        let calculated_distance = distance(U256::from(10), U256::from(10));
        assert_eq!(calculated_distance, U256::from(0))
    }

    // assert distance(5, 2**256 - 1) == 6
    #[test]
    fn test_distance_two() {
        let calculated_distance = distance(U256::from(5), U256::max_value());
        assert_eq!(calculated_distance, U256::from(6))
    }

    // assert distance(2**256 - 1, 6) == 7
    #[test]
    fn test_distance_three() {
        let calculated_distance = distance(U256::max_value(), U256::from(6));
        assert_eq!(calculated_distance, U256::from(7))
    }

    // assert distance(5, 1) == 4
    #[test]
    fn test_distance_four() {
        let calculated_distance = distance(U256::from(5), U256::from(1));
        assert_eq!(calculated_distance, U256::from(4))
    }

    // assert distance(1, 5) == 4
    #[test]
    fn test_distance_five() {
        let calculated_distance = distance(U256::from(1), U256::from(5));
        assert_eq!(calculated_distance, U256::from(4))
    }

    // assert distance(0, 2**255) == 2**255
    #[test]
    fn test_distance_six() {
        let calculated_2_power_255 = U256::from(2).pow(U256::from(255));
        let calculated_distance = distance(U256::from(0), calculated_2_power_255);
        assert_eq!(calculated_distance, calculated_2_power_255)
    }

    // assert distance(0, 2**255 + 1) == 2**255 - 1
    #[test]
    fn test_distance_seven() {
        let calculated_2_power_255 = U256::from(2).pow(U256::from(255));
        let calculated_distance = distance(
            U256::from(0),
            calculated_2_power_255.saturating_add(U256::from(1)),
        );
        assert_eq!(
            calculated_distance,
            calculated_2_power_255.saturating_sub(U256::from(1))
        )
    }
}
