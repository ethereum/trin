use alloy::consensus::Header;
use revm::{inspector_handle_register, inspectors::TracerEip3155, Evm};
use revm_primitives::{db::Database, BlobExcessGasAndPrice, BlockEnv, SpecId, U256};
use spec_id::get_spec_id;
use tx_env_modifier::TxEnvModifier;

pub mod async_db;
pub mod spec_id;
pub mod tx_env_modifier;

/// Creates [BlockEnv] based on data in the [Header].
pub fn create_block_env(header: &Header) -> BlockEnv {
    // EIP-4844: Excess blob gas and blob gasprice, introduced in Cancun
    let blob_excess_gas_and_price = header.excess_blob_gas.map(BlobExcessGasAndPrice::new);

    // EIP-4399: Expose beacon chain randomness in eth EVM, introduced in Paris (aka the Merge)
    let prevrandao = if get_spec_id(header.number).is_enabled_in(SpecId::MERGE) {
        Some(header.mix_hash)
    } else {
        None
    };

    BlockEnv {
        number: U256::from(header.number),
        coinbase: header.beneficiary,
        timestamp: U256::from(header.timestamp),
        gas_limit: U256::from(header.gas_limit),
        basefee: U256::from(header.base_fee_per_gas.unwrap_or_default()),
        difficulty: header.difficulty,
        prevrandao,
        blob_excess_gas_and_price,
    }
}

/// Creates [Evm] that is ready to execute provided transaction.
pub fn create_evm<'evm, 'db, DB: Database, Tx: TxEnvModifier>(
    block_env: BlockEnv,
    tx: &Tx,
    db: &'db mut DB,
) -> Evm<'evm, (), &'db mut DB> {
    let block_number = block_env.number.to();
    let spec_id = get_spec_id(block_number);
    Evm::builder()
        .with_block_env(block_env)
        .modify_tx_env(|tx_env| tx.modify(block_number, tx_env))
        .with_spec_id(spec_id)
        .with_db(db)
        .build()
}

/// Creates [Evm] that is ready to execute provided transaction, with attached tracer.
pub fn create_evm_with_tracer<'evm, 'db, DB: Database, Tx: TxEnvModifier>(
    block_env: BlockEnv,
    tx: &Tx,
    db: &'db mut DB,
    tracer: TracerEip3155,
) -> Evm<'evm, TracerEip3155, &'db mut DB> {
    create_evm(block_env, tx, db)
        .modify()
        .reset_handler_with_external_context(tracer)
        .append_handler_register(inspector_handle_register)
        .build()
}
