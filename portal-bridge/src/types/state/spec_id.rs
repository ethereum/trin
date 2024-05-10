use revm_primitives::SpecId;

// Execution Layer hard forks https://github.com/ethereum/execution-specs/tree/master/network-upgrades/mainnet-upgrades
pub const SPEC_FORK_BLOCK_NUMBER: [(SpecId, u64); 18] = [
    (SpecId::FRONTIER, 0),
    (SpecId::FRONTIER_THAWING, 200000),
    (SpecId::HOMESTEAD, 1150000),
    (SpecId::DAO_FORK, 1920000),
    (SpecId::TANGERINE, 2463000),
    (SpecId::SPURIOUS_DRAGON, 2675000),
    (SpecId::BYZANTIUM, 4370000),
    (SpecId::CONSTANTINOPLE, 7280000),
    (SpecId::PETERSBURG, 7280000), // Petersburg is a network upgrade that replaced Constantinople
    (SpecId::ISTANBUL, 9069000),
    (SpecId::MUIR_GLACIER, 9200000),
    (SpecId::BERLIN, 12244000),
    (SpecId::LONDON, 12965000),
    (SpecId::ARROW_GLACIER, 13773000),
    (SpecId::GRAY_GLACIER, 15050000),
    (SpecId::MERGE, 15537394),
    (SpecId::SHANGHAI, 17034870),
    (SpecId::CANCUN, 19426587),
];

pub fn get_spec_id(block_number: u64) -> SpecId {
    for (spec_id, fork_block_number) in SPEC_FORK_BLOCK_NUMBER.iter().rev() {
        if block_number >= *fork_block_number {
            return *spec_id;
        }
    }
    SpecId::LATEST
}

pub fn get_spec_block_number(spec_id: SpecId) -> u64 {
    match SPEC_FORK_BLOCK_NUMBER
        .iter()
        .find(|(id, _)| *id == spec_id)
        .map(|(_, block_number)| *block_number)
    {
        Some(block_number) => block_number,
        None => unimplemented!("SpecId {:?} is not supported", spec_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_spec_id() {
        assert_eq!(get_spec_id(0), SpecId::FRONTIER);
        assert_eq!(get_spec_id(200000), SpecId::FRONTIER_THAWING);
        assert_eq!(get_spec_id(1150000), SpecId::HOMESTEAD);
        assert_eq!(get_spec_id(1920000), SpecId::DAO_FORK);
        assert_eq!(get_spec_id(2463000), SpecId::TANGERINE);
        assert_eq!(get_spec_id(2675000), SpecId::SPURIOUS_DRAGON);
        assert_eq!(get_spec_id(4370000), SpecId::BYZANTIUM);
        assert_eq!(get_spec_id(7280000), SpecId::PETERSBURG);
        assert_eq!(get_spec_id(9069000), SpecId::ISTANBUL);
        assert_eq!(get_spec_id(9200000), SpecId::MUIR_GLACIER);
        assert_eq!(get_spec_id(12244000), SpecId::BERLIN);
        assert_eq!(get_spec_id(12965000), SpecId::LONDON);
        assert_eq!(get_spec_id(13773000), SpecId::ARROW_GLACIER);
        assert_eq!(get_spec_id(15050000), SpecId::GRAY_GLACIER);
        assert_eq!(get_spec_id(15537394), SpecId::MERGE);
        assert_eq!(get_spec_id(17034870), SpecId::SHANGHAI);
        assert_eq!(get_spec_id(19426587), SpecId::CANCUN);
    }

    #[test]
    fn test_get_spec_id_block_1() {
        assert_eq!(get_spec_id(1), SpecId::FRONTIER);
    }

    #[test]
    fn test_get_spec_id_between_forks() {
        assert_eq!(get_spec_id(2563000), SpecId::TANGERINE);
        assert_eq!(get_spec_id(12644000), SpecId::BERLIN);
    }

    #[test]
    fn test_get_spec_id_after_cancun() {
        assert_eq!(get_spec_id(20000000), SpecId::CANCUN);
    }

    #[test]
    fn test_get_spec_block_number() {
        assert_eq!(get_spec_block_number(SpecId::FRONTIER), 0);
        assert_eq!(get_spec_block_number(SpecId::FRONTIER_THAWING), 200000);
        assert_eq!(get_spec_block_number(SpecId::HOMESTEAD), 1150000);
        assert_eq!(get_spec_block_number(SpecId::DAO_FORK), 1920000);
        assert_eq!(get_spec_block_number(SpecId::TANGERINE), 2463000);
        assert_eq!(get_spec_block_number(SpecId::SPURIOUS_DRAGON), 2675000);
        assert_eq!(get_spec_block_number(SpecId::BYZANTIUM), 4370000);
        assert_eq!(get_spec_block_number(SpecId::CONSTANTINOPLE), 7280000);
        assert_eq!(get_spec_block_number(SpecId::PETERSBURG), 7280000);
        assert_eq!(get_spec_block_number(SpecId::ISTANBUL), 9069000);
        assert_eq!(get_spec_block_number(SpecId::MUIR_GLACIER), 9200000);
        assert_eq!(get_spec_block_number(SpecId::BERLIN), 12244000);
        assert_eq!(get_spec_block_number(SpecId::LONDON), 12965000);
        assert_eq!(get_spec_block_number(SpecId::ARROW_GLACIER), 13773000);
        assert_eq!(get_spec_block_number(SpecId::GRAY_GLACIER), 15050000);
        assert_eq!(get_spec_block_number(SpecId::MERGE), 15537394);
        assert_eq!(get_spec_block_number(SpecId::SHANGHAI), 17034870);
        assert_eq!(get_spec_block_number(SpecId::CANCUN), 19426587);
    }

    #[test]
    #[should_panic]
    fn test_get_spec_block_number_unsupported() {
        get_spec_block_number(SpecId::LATEST);
    }

    #[test]
    fn test_spec_fork_block_number_id_ordered() {
        let mut prev_block_number = 0;
        for (_, block_number) in SPEC_FORK_BLOCK_NUMBER.iter() {
            assert!(prev_block_number <= *block_number);
            prev_block_number = *block_number;
        }
    }
}
