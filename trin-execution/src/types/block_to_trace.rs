use std::{
    fs::{self, File},
    io::{BufWriter, Write},
    path::PathBuf,
    str::FromStr,
};

use ethportal_api::{types::execution::transaction::Transaction, Header};

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

    /// Creates file writer for tracing given transaction.
    ///
    /// Returns None if transaction shouldn't be traced.
    pub fn create_trace_writer(
        &self,
        root_dir: PathBuf,
        header: &Header,
        tx: &Transaction,
    ) -> std::io::Result<Option<Box<dyn Write>>> {
        let block_number = header.number;
        if self.should_trace(block_number) {
            let output_dir = root_dir
                .join("evm_traces")
                .join(format!("block_{block_number}"));
            fs::create_dir_all(&output_dir)?;
            let output_file = File::create(output_dir.join(format!("tx_{}.json", tx.hash())))?;
            Ok(Some(Box::new(BufWriter::new(output_file))))
        } else {
            Ok(None)
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
