use revm_primitives::SpecId;

// Execution Layer hard forks https://github.com/ethereum/execution-specs/tree/master/network-upgrades/mainnet-upgrades
pub const FRONTIER_BLOCK_NUMBER: u64 = 0;
pub const FRONTIER_THAWING_BLOCK_NUMBER: u64 = 200000;
pub const HOMESTEAD_BLOCK_NUMBER: u64 = 1150000;
pub const DAO_FORK_BLOCK_NUMBER: u64 = 1920000;
pub const TANGERINE_BLOCK_NUMBER: u64 = 2463000;
pub const SPURIOUS_DRAGON_BLOCK_NUMBER: u64 = 2675000;
pub const BYZANTIUM_BLOCK_NUMBER: u64 = 4370000;
pub const CONSTANTINOPLE_BLOCK_NUMBER: u64 = 7280000;
pub const PETERSBURG_BLOCK_NUMBER: u64 = 7280000; // Petersburg is a network upgrade that replaced Constantinople
pub const ISTANBUL_BLOCK_NUMBER: u64 = 9069000;
pub const MUIR_GLACIER_BLOCK_NUMBER: u64 = 9200000;
pub const BERLIN_BLOCK_NUMBER: u64 = 12244000;
pub const LONDON_BLOCK_NUMBER: u64 = 12965000;
pub const ARROW_GLACIER_BLOCK_NUMBER: u64 = 13773000;
pub const GRAY_GLACIER_BLOCK_NUMBER: u64 = 15050000;
pub const MERGE_BLOCK_NUMBER: u64 = 15537394;
pub const SHANGHAI_BLOCK_NUMBER: u64 = 17034870;
pub const CANCUN_BLOCK_NUMBER: u64 = 19426587;

pub fn get_spec_id(block_number: u64) -> SpecId {
    if block_number >= CANCUN_BLOCK_NUMBER {
        SpecId::CANCUN
    } else if block_number >= SHANGHAI_BLOCK_NUMBER {
        SpecId::SHANGHAI
    } else if block_number >= MERGE_BLOCK_NUMBER {
        SpecId::MERGE
    } else if block_number >= GRAY_GLACIER_BLOCK_NUMBER {
        SpecId::GRAY_GLACIER
    } else if block_number >= ARROW_GLACIER_BLOCK_NUMBER {
        SpecId::ARROW_GLACIER
    } else if block_number >= LONDON_BLOCK_NUMBER {
        SpecId::LONDON
    } else if block_number >= BERLIN_BLOCK_NUMBER {
        SpecId::BERLIN
    } else if block_number >= MUIR_GLACIER_BLOCK_NUMBER {
        SpecId::MUIR_GLACIER
    } else if block_number >= ISTANBUL_BLOCK_NUMBER {
        SpecId::ISTANBUL
    } else if block_number >= PETERSBURG_BLOCK_NUMBER {
        SpecId::PETERSBURG
    } else if block_number >= CONSTANTINOPLE_BLOCK_NUMBER {
        SpecId::CONSTANTINOPLE
    } else if block_number >= BYZANTIUM_BLOCK_NUMBER {
        SpecId::BYZANTIUM
    } else if block_number >= SPURIOUS_DRAGON_BLOCK_NUMBER {
        SpecId::SPURIOUS_DRAGON
    } else if block_number >= TANGERINE_BLOCK_NUMBER {
        SpecId::TANGERINE
    } else if block_number >= DAO_FORK_BLOCK_NUMBER {
        SpecId::DAO_FORK
    } else if block_number >= HOMESTEAD_BLOCK_NUMBER {
        SpecId::HOMESTEAD
    } else if block_number >= FRONTIER_THAWING_BLOCK_NUMBER {
        SpecId::FRONTIER_THAWING
    } else {
        SpecId::FRONTIER
    }
}
