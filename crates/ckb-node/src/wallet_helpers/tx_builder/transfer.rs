//! Transfer transaction builder.

use crate::client::QpClient;
use crate::error::NodeManagerError;
use ckb_sdk::{
    traits::CellDepResolver,
    tx_builder::{
        fill_placeholder_witnesses, transfer::CapacityTransferBuilder, CapacityBalancer,
        CapacityProvider, TxBuilder,
    },
    Address,
};
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, FeeRate, TransactionBuilder, TransactionView},
    packed::{CellInput, CellOutput, Script, WitnessArgs},
    prelude::*,
};

/// Default placeholder lock size for secp256k1 witnesses.
const DEFAULT_PLACEHOLDER_LOCK_SIZE: usize = 65;

/// Builder for transfer transactions.
pub struct QpTransferBuilder<'a> {
    qp_client: &'a QpClient,
    /// Whether the target network is mainnet (affects cell dep resolution).
    is_mainnet: bool,
    /// Size of the placeholder lock field in the witness.
    /// Must match the final signed witness lock length for correct fee estimation.
    placeholder_lock_size: usize,
}

impl<'a> QpTransferBuilder<'a> {
    /// Creates a new transfer builder with default secp256k1 placeholder size.
    pub fn new(qp_client: &'a QpClient, is_mainnet: bool) -> Self {
        QpTransferBuilder {
            qp_client,
            is_mainnet,
            placeholder_lock_size: DEFAULT_PLACEHOLDER_LOCK_SIZE,
        }
    }

    /// Sets the placeholder lock size for the witness.
    ///
    /// For SPHINCS+ transactions, this should be set to
    /// `5 + public_key_length + signature_length` to match the final
    /// signed witness format.
    pub fn with_placeholder_lock_size(mut self, size: usize) -> Self {
        self.placeholder_lock_size = size;
        self
    }

    /// Builds an unsigned transfer transaction.
    ///
    /// # Parameters
    /// - `from_address`: The sender's address
    /// - `to_address`: The recipient's address
    /// - `capacity_sh`: Amount to transfer in shannons (1 CKB = 10^8 shannons)
    /// - `fee_rate`: Fee rate in shannons per 1000 bytes
    /// - `data`: Optional data to include in the output cell
    ///
    /// # Returns
    /// An unsigned transaction ready for signing
    pub fn build_unsigned_transfer(
        &self,
        from_address: &Address,
        to_address: &Address,
        capacity_sh: u64,
        fee_rate: u64,
        data: Option<Vec<u8>>,
    ) -> Result<TransactionView, NodeManagerError> {
        if from_address.network() != to_address.network() {
            return Err(NodeManagerError::RpcError(
                "Sender and recipient are on different networks.".to_string(),
            ));
        }
        let from_lock_script = Script::from(from_address.payload());
        let to_lock_script = Script::from(to_address.payload());

        // Create output cell
        let to_output = CellOutput::new_builder()
            .capacity(Capacity::shannons(capacity_sh).pack())
            .lock(to_lock_script)
            .build();

        let output_data = data.unwrap_or_default();

        // Create transfer builder with output
        let transfer_builder =
            CapacityTransferBuilder::new(vec![(to_output, Bytes::from(output_data))]);

        // Setup balance parameters.
        // The placeholder lock size must match the final signed witness lock
        // field length so the fee estimator reserves enough capacity.
        // Default 65 bytes is for secp256k1; SPHINCS+ signatures are much larger.
        let placeholder_witness = WitnessArgs::new_builder()
            .lock(Some(Bytes::from(vec![0u8; self.placeholder_lock_size])).pack())
            .build();

        let balancer = CapacityBalancer {
            fee_rate: FeeRate::from_u64(fee_rate),
            change_lock_script: Some(from_lock_script.clone()),
            capacity_provider: CapacityProvider::new_simple(vec![(
                from_lock_script.clone(),
                placeholder_witness,
            )]),
            force_small_change_as_fee: None,
        };

        // Create collectors and resolvers via the trait so the right
        // backend impl (full node vs light client) is used.
        let mut cell_collector = self.qp_client.cell_collector();
        let cell_dep_resolver =
            super::utils::cell_dep_resolver_from_rpc(self.qp_client, self.is_mainnet)?;
        let header_dep_resolver = self.qp_client.header_dep_resolver();
        let tx_dep_provider = self.qp_client.tx_dep_provider();

        // Build the transaction
        let base_tx = transfer_builder
            .build_base(
                &mut *cell_collector,
                &cell_dep_resolver,
                &*header_dep_resolver,
                &*tx_dep_provider,
            )
            .map_err(|e| {
                NodeManagerError::RpcError(format!("Failed to build transfer: {:?}", e))
            })?;

        let (tx_filled_witnesses, _) = fill_placeholder_witnesses(
            base_tx,
            &*tx_dep_provider,
            &Default::default(),
        )
        .map_err(|e| {
            NodeManagerError::RpcError(format!("Failed to fill placeholder witnesses: {:?}", e))
        })?;

        let (tx, change_index) = balancer
            .rebalance_tx_capacity(
                &tx_filled_witnesses,
                &mut *cell_collector,
                &*tx_dep_provider,
                &cell_dep_resolver,
                &*header_dep_resolver,
                0,
                None,
            )
            .map_err(|e| {
                NodeManagerError::RpcError(format!("Failed to balance transfer: {:?}", e))
            })?;

        // TODO very rare: only when the difference between the input and output capacities equals exactly
        // floor(fee_rate * tx_size / 1000), leaving nothing for a change cell. One shannon either way and
        // the balancer creates one. Revisit and ship at the floor fee instead of failing.
        let change_index = change_index.ok_or_else(|| {
            NodeManagerError::RpcError(
                "Cannot meet the requested fee rate: the balanced transfer has no change cell."
                    .to_string(),
            )
        })?;

        // The balancer rounds the fee down; raise it so the transaction render (the explorer)
        // meets the rate the user intended to set.
        super::utils::enforce_ceiling_fee(
            tx,
            fee_rate,
            &from_lock_script,
            change_index,
            &*tx_dep_provider,
            &*header_dep_resolver,
        )
    }

    /// Builds an unsigned transfer transaction that sends all spendable balance
    /// from `from_address` to `to_address`, leaving no change cell.
    ///
    /// Returns the built transaction together with the final transfer amount in shannons.
    pub fn build_unsigned_transfer_all(
        &self,
        from_address: &Address,
        to_address: &Address,
        fee_rate: u64,
        data: Option<Vec<u8>>,
    ) -> Result<(TransactionView, u64), NodeManagerError> {
        if from_address.network() != to_address.network() {
            return Err(NodeManagerError::RpcError(
                "Sender and recipient are on different networks.".to_string(),
            ));
        }
        let from_lock_script = Script::from(from_address.payload());
        let to_lock_script = Script::from(to_address.payload());
        let output_data = Bytes::from(data.unwrap_or_default());

        let spendable_cells = crate::wallet_helpers::queries::spendable::collect_spendable_cells(
            self.qp_client,
            &from_lock_script,
        )?;

        let total_input_capacity: u64 = spendable_cells
            .iter()
            .map(|cell| {
                let capacity: u64 = cell.output.capacity().unpack();
                capacity
            })
            .sum();

        let cell_dep_resolver =
            super::utils::cell_dep_resolver_from_rpc(self.qp_client, self.is_mainnet)?;
        let sender_lock_dep = cell_dep_resolver
            .resolve(&from_lock_script)
            .ok_or_else(|| {
                NodeManagerError::RpcError("Failed to resolve sender lock cell dep.".to_string())
            })?;

        let min_cell_capacity = super::utils::minimal_cell_capacity(&to_lock_script)?;
        if total_input_capacity <= min_cell_capacity {
            return Err(NodeManagerError::RpcError(
                "Insufficient balance to send all after accounting for transaction fee."
                    .to_string(),
            ));
        }

        let placeholder_witness = WitnessArgs::new_builder()
            .lock(Some(Bytes::from(vec![0u8; self.placeholder_lock_size])).pack())
            .build();

        let inputs: Vec<CellInput> = spendable_cells
            .iter()
            .map(|cell| CellInput::new(cell.out_point.clone(), 0))
            .collect();

        let witnesses: Vec<_> = std::iter::once(placeholder_witness.as_bytes().pack())
            .chain(
                std::iter::repeat_with(|| Bytes::new().pack()).take(inputs.len().saturating_sub(1)),
            )
            .collect();

        // we know the new cell only has a lock script and the 8-byte capacity field.
        let placeholder_output = CellOutput::new_builder()
            .capacity(Capacity::shannons(total_input_capacity).pack())
            .lock(to_lock_script.clone())
            .build();

        // by building a provisional transaction, we know the exact tx size so we can calculate the required fee based on fee rate.
        let provisional_tx = TransactionBuilder::default()
            .set_cell_deps(vec![sender_lock_dep.clone()])
            .set_inputs(inputs.clone())
            .set_outputs(vec![placeholder_output])
            .set_outputs_data(vec![output_data.clone().pack()])
            .set_witnesses(witnesses)
            .build();

        let tx_size = provisional_tx.data().as_reader().serialized_size_in_block() as u64;
        let required_fee = super::utils::ceiling_fee(fee_rate, tx_size);
        let final_output_capacity =
            total_input_capacity
                .checked_sub(required_fee)
                .ok_or_else(|| {
                    NodeManagerError::RpcError(
                        "Insufficient balance to pay transaction fee.".to_string(),
                    )
                })?;

        let final_output = CellOutput::new_builder()
            .capacity(Capacity::shannons(final_output_capacity).pack())
            .lock(to_lock_script)
            .build();

        // Final check to ensure the output cell has enough capcity. With out this check, CKB node will reject any way.
        let data_capacity = Capacity::bytes(output_data.len()).map_err(|e| {
            NodeManagerError::RpcError(format!("Failed to calculate output data capacity: {}", e))
        })?;
        if final_output
            .is_lack_of_capacity(data_capacity)
            .map_err(|e| {
                NodeManagerError::RpcError(format!(
                    "Failed to validate final output capacity: {}",
                    e
                ))
            })?
        {
            return Err(NodeManagerError::RpcError(
                "Insufficient balance to create a valid output after fee deduction.".to_string(),
            ));
        }

        let tx = TransactionBuilder::default()
            .set_cell_deps(vec![sender_lock_dep])
            .set_inputs(inputs)
            .set_outputs(vec![final_output])
            .set_outputs_data(vec![output_data.pack()])
            .set_witnesses(
                std::iter::once(placeholder_witness.as_bytes().pack())
                    .chain(
                        std::iter::repeat_with(|| Bytes::new().pack())
                            .take(spendable_cells.len().saturating_sub(1)),
                    )
                    .collect(),
            )
            .build();

        Ok((tx, final_output_capacity))
    }
}
