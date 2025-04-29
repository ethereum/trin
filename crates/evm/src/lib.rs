use alloy::consensus::Header;
use revm::{
    context::{BlockEnv, TxEnv},
    context_interface::block::BlobExcessGasAndPrice,
    handler::MainnetContext,
    inspector::inspectors::TracerEip3155,
    Database, MainBuilder, MainnetEvm,
};
use revm_primitives::hardfork::SpecId;
use spec_id::get_spec_id;
use tx_env_modifier::TxEnvModifier;

pub mod async_db;
pub mod spec_id;
pub mod tx_env_modifier;

/// Creates [BlockEnv] based on data in the [Header].
pub fn create_block_env(header: &Header) -> BlockEnv {
    // EIP-4844: Excess blob gas and blob gasprice, introduced in Cancun
    let blob_excess_gas_and_price = header.excess_blob_gas.map(|excess_blob_gas| {
        BlobExcessGasAndPrice::new(
            excess_blob_gas,
            get_spec_id(header.number).is_enabled_in(SpecId::PRAGUE),
        )
    });

    // EIP-4399: Expose beacon chain randomness in eth EVM, introduced in Paris (aka the Merge)
    let prevrandao = if get_spec_id(header.number).is_enabled_in(SpecId::MERGE) {
        Some(header.mix_hash)
    } else {
        None
    };

    BlockEnv {
        number: header.number,
        timestamp: header.timestamp,
        gas_limit: header.gas_limit,
        basefee: header.base_fee_per_gas.unwrap_or_default(),
        difficulty: header.difficulty,
        prevrandao,
        blob_excess_gas_and_price,
        beneficiary: header.beneficiary,
    }
}

/// Creates [Evm] that is ready to execute provided transaction.
pub fn create_evm<'db, DB: Database, Tx: TxEnvModifier>(
    block_env: BlockEnv,
    tx: &Tx,
    db: &'db mut DB,
) -> MainnetEvm<MainnetContext<&'db mut DB>, ()> {
    let block_number = block_env.number;
    let spec_id = get_spec_id(block_number);
    let mut tx_env = TxEnv::default();
    tx.modify(block_number, &mut tx_env);
    MainnetContext::new(db, spec_id)
        .with_block(block_env)
        .with_tx(tx_env)
        .build_mainnet()
}

/// Creates [Evm] that is ready to execute provided transaction, with attached tracer.
pub fn create_evm_with_tracer<'db, DB: Database, Tx: TxEnvModifier>(
    block_env: BlockEnv,
    tx: &Tx,
    db: &'db mut DB,
    tracer: TracerEip3155,
) -> MainnetEvm<MainnetContext<&'db mut DB>, TracerEip3155> {
    create_evm(block_env, tx, db).with_inspector(tracer)
}
