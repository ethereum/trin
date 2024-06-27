use std::str::FromStr;

#[derive(Clone, Debug, PartialEq, Default, Eq)]
pub enum BlockToTrace {
    #[default]
    None,
    All,
    Block(u64),
}

impl BlockToTrace {
    pub fn should_trace(&self, block_number: u64) -> bool {
        match self {
            BlockToTrace::None => false,
            BlockToTrace::All => true,
            BlockToTrace::Block(b) => *b == block_number,
        }
    }
}

impl FromStr for BlockToTrace {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(BlockToTrace::None),
            "all" => Ok(BlockToTrace::All),
            val => match val.split_once(':') {
                Some(("block", block_number)) => {
                    let block_number = block_number
                        .parse()
                        .map_err(|err| format!("Invalid block number: {err}"))?;
                    Ok(BlockToTrace::Block(block_number))
                }
                _ => Err(format!("Invalid block trace argument: {val}")),
            },
        }
    }
}
