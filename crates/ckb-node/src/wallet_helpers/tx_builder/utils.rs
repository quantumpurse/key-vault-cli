//! Utilities for transaction building.

use crate::client::QpClient;
use crate::error::NodeManagerError;
use ckb_sdk::traits::{DefaultCellDepResolver, HeaderDepResolver, TransactionDependencyProvider};
use ckb_sdk::types::ScriptId;
use ckb_types::core::{BlockView, Capacity, DepType, ScriptHashType, TransactionView};
use ckb_types::packed::{CellDep, CellOutput, OutPoint, Script};
use ckb_types::prelude::*;
use ckb_types::H256;
use qpv2_core::constants;

/// Fetches the genesis block via the active backend's RPC and creates a
/// cell dep resolver with the quantum-resistant lock script registered.
///
/// Routes through `QpClient::get_genesis_block` so it works on both the
/// full node (`get_block_by_number(0)`) and the light client
/// (`get_genesis_block`). The genesis block contains the system script
/// cell deps (sighash, multisig, DAO). The quantum-resistant lock
/// script is a custom deployment and must be registered explicitly
/// using the known deployment OutPoint.
pub fn cell_dep_resolver_from_rpc(
    qp_client: &QpClient,
    is_mainnet: bool,
) -> Result<DefaultCellDepResolver, NodeManagerError> {
    let genesis_block = qp_client.get_genesis_block()?;
    let block_view: BlockView = genesis_block.into();
    let mut resolver = DefaultCellDepResolver::from_genesis(&block_view).map_err(|e| {
        NodeManagerError::RpcError(format!("Failed to parse genesis info: {:?}", e))
    })?;

    // Register the quantum-resistant lock script cell dep.
    let (code_hash_hex, hash_type, dep_tx_hash_hex, dep_index) = if is_mainnet {
        (
            constants::CKB_MAINNET_CODE_HASH,
            ScriptHashType::Type,
            constants::CKB_MAINNET_CELL_DEP_TX_HASH,
            constants::CKB_MAINNET_CELL_DEP_INDEX,
        )
    } else {
        (
            constants::CKB_TESTNET_CODE_HASH,
            ScriptHashType::Data1,
            constants::CKB_TESTNET_CELL_DEP_TX_HASH,
            constants::CKB_TESTNET_CELL_DEP_INDEX,
        )
    };

    let code_hash: H256 = code_hash_hex
        .trim_start_matches("0x")
        .parse()
        .map_err(|e| NodeManagerError::RpcError(format!("Invalid QR lock code_hash: {}", e)))?;
    let dep_tx_hash: H256 = dep_tx_hash_hex
        .trim_start_matches("0x")
        .parse()
        .map_err(|e| NodeManagerError::RpcError(format!("Invalid QR lock dep tx_hash: {}", e)))?;

    let script_id = ScriptId::new(code_hash.clone(), hash_type);
    let cell_dep = CellDep::new_builder()
        .out_point(
            OutPoint::new_builder()
                .tx_hash(dep_tx_hash.pack())
                .index(dep_index)
                .build(),
        )
        .dep_type(DepType::Code)
        .build();

    resolver.insert(script_id, cell_dep, "Quantum resistant lock".to_string());

    Ok(resolver)
}

/// Converts a fee rate into an absolute fee in shannons, rounding up.
///
/// This function does one job: rounding up to the next shannon. Applying the
/// result to a transaction the SDK has already balanced is
/// [`enforce_ceiling_fee`]'s job, and the reasoning behind rounding up at all
/// is documented there.
pub(crate) fn ceiling_fee(fee_rate: u64, tx_size: u64) -> u64 {
    fee_rate.saturating_mul(tx_size).div_ceil(1000)
}

/// Makes sure the fee on a balanced transaction is at least the ceiling of the
/// requested fee rate.
///
/// Why:
///
/// Fee calculation can result in a fractional shannon, which is impossible to
/// represent on the CKB chain, so every layer has settled to the following convention:
///
/// ```text
///   [typed]        [SDK builds]           [explorer displays]
///   rate  ────────►   fee  ────────────────►  rate
///         floor(R×size/1000)      floor(fee×1000/size)
/// ```
///
/// Example:
///
/// ```text
/// 1  exact fee needed   1234 × 8316 / 1000   =  10,261.944 shannons
/// 2  SDK floors it                           →  10,261      ← 0.944 lost here
/// 3  effective rate now 10,261 × 1000 / 8316 =  1233.886    ← ALREADY below 1234
/// 4  explorer floors it                      →  1233
/// ```
///
/// In order to avoid the explorer displaying a rate lower than the user
/// requested, we predict the explorer's behaviour and round up to the next
/// shannon, so that the explorer's own floor lands back on the number the user typed.
pub(crate) fn enforce_ceiling_fee(
    tx: TransactionView,
    fee_rate: u64,
    owner_lock_script: &Script,
    change_cell_index: usize,
    tx_dep_provider: &dyn TransactionDependencyProvider,
    header_dep_resolver: &dyn HeaderDepResolver,
) -> Result<TransactionView, NodeManagerError> {
    let tx_size = tx.data().as_reader().serialized_size_in_block() as u64;

    // we target the ceiling because the SDK's fee calculation floors,
    // and the explorer's display of the fee rate also floors.
    let target_fee = ceiling_fee(fee_rate, tx_size);

    // Read the fee the balancer actually settled on the transaction.
    let actual_fee = ckb_sdk::tx_builder::tx_fee(tx.clone(), tx_dep_provider, header_dep_resolver)
        .map_err(|e| {
            NodeManagerError::RpcError(format!("Failed to read the transaction fee: {:?}", e))
        })?;

    let shortfall = target_fee.saturating_sub(actual_fee);

    // when the actual fee meets the target, the transaction is already good to go
    // and the explorer won't report a lower fee rate than the user requested.
    if shortfall == 0 {
        return Ok(tx);
    }

    // The ceiling and the floor of the same quotient differ by at most 1 shannon.
    if shortfall > 1 {
        return Err(NodeManagerError::RpcError(format!(
            "Refusing to raise the fee to {} shannons/1000 bytes: the transaction is short by \
             {} shannons, but rounding up can only ever be short by 1. The fee was not \
             calculated against this transaction.",
            fee_rate, shortfall
        )));
    }

    // We reduce one output's capacity by the shortfall - effectively making the
    // fee higher by the shortfall.
    let outputs: Vec<CellOutput> = tx.outputs().into_iter().collect();
    let change_cell = outputs.get(change_cell_index).cloned().ok_or_else(|| {
        NodeManagerError::RpcError(format!(
            "Cannot raise the fee to {} shannons/1000 bytes: output {} does not exist; the \
             transaction has {} outputs.",
            fee_rate,
            change_cell_index,
            outputs.len()
        ))
    })?;

    // Defense in depth in case the SDK has a bug and put the recepient lock to the change cell
    if change_cell.lock().as_slice() != owner_lock_script.as_slice() {
        return Err(NodeManagerError::RpcError(format!(
            "Cannot raise the fee to {} shannons/1000 bytes: output {} is not locked to the \
             sender, so taking {} shannon from it would spend capacity that is not theirs.",
            fee_rate, change_cell_index, shortfall
        )));
    }

    let change_cell_capacity: u64 = change_cell.capacity().unpack();
    let fee_output_data_len = tx
        .outputs_data()
        .get(change_cell_index)
        .map(|data| data.raw_data().len())
        .unwrap_or(0);
    let occupied_capacity = change_cell
        .occupied_capacity(Capacity::bytes(fee_output_data_len).map_err(|e| {
            NodeManagerError::RpcError(format!("Failed to size the output data: {}", e))
        })?)
        .map_err(|e| {
            NodeManagerError::RpcError(format!(
                "Failed to calculate the output's occupied capacity: {}",
                e
            ))
        })?
        .as_u64();

    // Substract the shortfall from the change cell's capacity, and make sure it is still above the occupied capacity.
    // We shoot error here instead of collecting more input cells to cover the shortfall because
    // 1 shannon is a very small amount and the case where the cell can not absorb the fee is rare.
    let new_capacity = change_cell_capacity
        .checked_sub(shortfall)
        .filter(|capacity| *capacity >= occupied_capacity)
        .ok_or_else(|| {
            NodeManagerError::RpcError(format!(
                "Cannot raise the fee to {} shannons/1000 bytes: taking {} shannon from output \
                 {} would drop it below its {} shannon minimum capacity.",
                fee_rate, shortfall, change_cell_index, occupied_capacity
            ))
        })?;

    // Overwriteing the change cell with a new capacity that's minus the shortfall.
    let mut new_outputs = outputs;
    new_outputs[change_cell_index] = change_cell
        .as_builder()
        .capacity(Capacity::shannons(new_capacity).pack())
        .build();

    Ok(tx.as_advanced_builder().set_outputs(new_outputs).build())
}

/// Computes the minimum capacity (in shannons) for a cell with only a lock
/// script and the 8-byte capacity field — no type script, no output data.
pub(crate) fn minimal_cell_capacity(
    lock_script: &ckb_types::packed::Script,
) -> Result<u64, NodeManagerError> {
    use ckb_types::core::Capacity;
    use ckb_types::packed::CellOutput;

    let output = CellOutput::new_builder().lock(lock_script.clone()).build();
    output
        .occupied_capacity(Capacity::zero())
        .map(|capacity| capacity.as_u64())
        .map_err(|e| {
            NodeManagerError::RpcError(format!("Failed to calculate minimal cell capacity: {}", e))
        })
}

#[cfg(test)]
mod tests {
    use super::ceiling_fee;

    /// The rate the explorer displays, derived the way explorers derive it.
    fn explorer_displayed_rate(fee: u64, tx_size: u64) -> u64 {
        fee * 1000 / tx_size
    }

    #[test]
    fn rounds_up_when_the_product_does_not_divide_evenly() {
        // The reported case: 1234 shannons/1000 bytes over 8316 bytes is
        // 10261.944 shannons, which the SDK floored to 10261.
        assert_eq!(ceiling_fee(1234, 8316), 10262);
    }

    #[test]
    fn is_exact_when_the_product_divides_evenly() {
        // 1000 * 1500 / 1000 = 1500 with no remainder, so rounding up must
        // not add a shannon the user did not ask for.
        assert_eq!(ceiling_fee(1000, 1500), 1500);
    }

    #[test]
    fn undivisible_rate_round_trips_through_the_explorer() {
        let (rate, size) = (1234, 8316);
        assert_eq!(explorer_displayed_rate(ceiling_fee(rate, size), size), rate);
        // Flooring is what produces the explorer display bug.
        assert_eq!(explorer_displayed_rate(rate * size / 1000, size), rate - 1);
    }

    #[test]
    fn divisible_rate_round_trips_through_the_explorer() {
        let (rate, size) = (1000, 1500);
        assert_eq!(explorer_displayed_rate(ceiling_fee(rate, size), size), rate);
    }

    #[test]
    fn never_undershoots_the_entered_rate() {
        // Rounding up must land on the entered rate exactly for any
        // transaction of at least 1000 bytes, never above and never below.
        for size in [1000u64, 1001, 4096, 8316, 17_000, 65_536] {
            for rate in [1000u64, 1001, 1234, 1999, 3000] {
                assert_eq!(
                    explorer_displayed_rate(ceiling_fee(rate, size), size),
                    rate,
                    "rate {} over {} bytes",
                    rate,
                    size
                );
            }
        }
    }

    #[test]
    fn saturates_instead_of_overflowing() {
        assert_eq!(ceiling_fee(u64::MAX, u64::MAX), u64::MAX / 1000 + 1);
    }
}
