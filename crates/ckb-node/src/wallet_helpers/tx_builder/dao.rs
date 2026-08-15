//! DAO transaction builders.

use crate::client::QpClient;
use crate::error::NodeManagerError;
use ckb_sdk::{
    constants::DAO_TYPE_HASH,
    traits::CellDepResolver,
    tx_builder::{
        dao::{
            DaoDepositBuilder, DaoDepositReceiver, DaoPrepareBuilder, DaoPrepareItem,
            DaoWithdrawBuilder, DaoWithdrawItem, DaoWithdrawReceiver,
        },
        fill_placeholder_witnesses, CapacityBalancer, CapacityProvider, TxBuilder,
    },
    Address,
};
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, FeeRate, ScriptHashType, TransactionBuilder, TransactionView},
    packed::{CellInput, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::*,
};

/// Default placeholder lock size for secp256k1 witnesses.
const DEFAULT_PLACEHOLDER_LOCK_SIZE: usize = 65;

/// Builds a balanced DAO transaction from an SDK builder.
///
/// Shared by the deposit and withdraw (phase 2) builders: the balancer setup,
/// the dependency resolvers and the build-then-balance sequence are the same
/// for both. What differs is which output pays the fee, which is why
/// `fee_output_without_change` is a parameter - a deposit always leaves change
/// and must use it, while a phase 2 withdraw never leaves change and pays from
/// its receiver cell instead.
fn build_balanced_dao_tx(
    builder: &dyn TxBuilder,
    lock_script: &Script,
    fee_rate: u64,
    qp_client: &QpClient,
    is_mainnet: bool,
    placeholder_lock_size: usize,
    fee_output_without_change: Option<usize>,
) -> Result<TransactionView, NodeManagerError> {
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; placeholder_lock_size])).pack())
        .build();

    let balancer = CapacityBalancer {
        fee_rate: FeeRate::from_u64(fee_rate),
        change_lock_script: Some(lock_script.clone()),
        capacity_provider: CapacityProvider::new_simple(vec![(
            lock_script.clone(),
            placeholder_witness,
        )]),
        force_small_change_as_fee: None,
    };

    let mut cell_collector = qp_client.cell_collector();
    let cell_dep_resolver = super::utils::cell_dep_resolver_from_rpc(qp_client, is_mainnet)?;
    let header_dep_resolver = qp_client.header_dep_resolver();
    let tx_dep_provider = qp_client.tx_dep_provider();

    let base_tx = builder
        .build_base(
            &mut *cell_collector,
            &cell_dep_resolver,
            &*header_dep_resolver,
            &*tx_dep_provider,
        )
        .map_err(|e| NodeManagerError::RpcError(format!("Failed to build DAO tx: {:?}", e)))?;

    let (tx_filled_witnesses, _) =
        fill_placeholder_witnesses(base_tx, &*tx_dep_provider, &Default::default()).map_err(
            |e| {
                NodeManagerError::RpcError(format!("Failed to fill placeholder witnesses: {:?}", e))
            },
        )?;

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
        .map_err(|e| NodeManagerError::RpcError(format!("Failed to balance DAO tx: {:?}", e)))?;

    // TODO still ad-hoc, improve.
    let change_cell_index = change_index.or(fee_output_without_change).ok_or_else(|| {
        NodeManagerError::RpcError(
            "Cannot meet the requested fee rate: the balanced DAO transaction has no change \
                 cell, and this path does not nominate another output to pay from."
                .to_string(),
        )
    })?;

    // The balancer rounds the fee down; raise it so the transaction meets
    // the rate the user entered.
    super::utils::enforce_ceiling_fee(
        tx,
        fee_rate,
        lock_script,
        change_cell_index,
        &*tx_dep_provider,
        &*header_dep_resolver,
    )
}

/// Builder for DAO deposit transactions.
pub struct QpDaoDepositBuilder<'a> {
    qp_client: &'a QpClient,
    is_mainnet: bool,
    placeholder_lock_size: usize,
}

impl<'a> QpDaoDepositBuilder<'a> {
    /// Creates a new DAO deposit builder with default secp256k1 placeholder size.
    pub fn new(qp_client: &'a QpClient, is_mainnet: bool) -> Self {
        QpDaoDepositBuilder {
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

    /// Builds an unsigned DAO deposit transaction.
    ///
    /// # Parameters
    /// - `from_address`: The address providing the capacity
    /// - `capacity_sh`: Amount to deposit in shannons
    /// - `fee_rate`: Fee rate in shannons per 1000 bytes
    ///
    /// # Returns
    /// An unsigned transaction ready for signing
    pub fn build_unsigned_deposit(
        &self,
        from_address: &Address,
        capacity_sh: u64,
        fee_rate: u64,
    ) -> Result<TransactionView, NodeManagerError> {
        let lock_script = Script::from(from_address.payload());

        // Create DAO deposit receiver
        let deposit_receiver = DaoDepositReceiver::new(lock_script.clone(), capacity_sh);
        let deposit_builder = DaoDepositBuilder::new(vec![deposit_receiver]);

        build_balanced_dao_tx(
            &deposit_builder,
            &lock_script,
            fee_rate,
            self.qp_client,
            self.is_mainnet,
            self.placeholder_lock_size,
            None,
        )
    }

    /// Builds an unsigned DAO deposit transaction that deposits all spendable
    /// capacity, leaving no change cell. Fee is deducted from the deposit amount.
    ///
    /// Returns the built transaction together with the final deposit amount in shannons.
    pub fn build_unsigned_deposit_all(
        &self,
        from_address: &Address,
        fee_rate: u64,
    ) -> Result<(TransactionView, u64), NodeManagerError> {
        let lock_script = Script::from(from_address.payload());

        let spendable_cells = crate::wallet_helpers::queries::spendable::collect_spendable_cells(
            self.qp_client,
            &lock_script,
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
        let sender_lock_dep = cell_dep_resolver.resolve(&lock_script).ok_or_else(|| {
            NodeManagerError::RpcError("Failed to resolve sender lock cell dep.".to_string())
        })?;

        // Resolve the DAO type script cell dep.
        let dao_type_script = Script::new_builder()
            .code_hash(DAO_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type)
            .build();
        let dao_cell_dep = cell_dep_resolver.resolve(&dao_type_script).ok_or_else(|| {
            NodeManagerError::RpcError("Failed to resolve DAO type script cell dep.".to_string())
        })?;

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

        // DAO deposit output: lock script + DAO type script + 8 bytes of zero data.
        let dao_output = CellOutput::new_builder()
            .capacity(Capacity::shannons(total_input_capacity).pack())
            .lock(lock_script.clone())
            .type_(Some(dao_type_script.clone()).pack())
            .build();
        let dao_data = Bytes::from(vec![0u8; 8]);

        // Build provisional transaction to calculate exact fee.
        let provisional_tx = TransactionBuilder::default()
            .set_cell_deps(vec![sender_lock_dep.clone(), dao_cell_dep.clone()])
            .set_inputs(inputs.clone())
            .set_outputs(vec![dao_output])
            .set_outputs_data(vec![dao_data.clone().pack()])
            .set_witnesses(witnesses)
            .build();

        let tx_size = provisional_tx.data().as_reader().serialized_size_in_block() as u64;
        let required_fee = super::utils::ceiling_fee(fee_rate, tx_size);
        let deposit_capacity = total_input_capacity
            .checked_sub(required_fee)
            .ok_or_else(|| {
                NodeManagerError::RpcError(
                    "Insufficient balance to pay transaction fee.".to_string(),
                )
            })?;

        let final_output = CellOutput::new_builder()
            .capacity(Capacity::shannons(deposit_capacity).pack())
            .lock(lock_script)
            .type_(Some(dao_type_script).pack())
            .build();

        // Validate the output cell has enough capacity (lock + type + 8 bytes data).
        let data_capacity = Capacity::bytes(dao_data.len()).map_err(|e| {
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
                "Insufficient balance to create a valid DAO deposit after fee deduction."
                    .to_string(),
            ));
        }

        let tx = TransactionBuilder::default()
            .set_cell_deps(vec![sender_lock_dep, dao_cell_dep])
            .set_inputs(inputs)
            .set_outputs(vec![final_output])
            .set_outputs_data(vec![dao_data.pack()])
            .set_witnesses(
                std::iter::once(placeholder_witness.as_bytes().pack())
                    .chain(
                        std::iter::repeat_with(|| Bytes::new().pack())
                            .take(spendable_cells.len().saturating_sub(1)),
                    )
                    .collect(),
            )
            .build();

        Ok((tx, deposit_capacity))
    }
}

/// Builder for DAO prepare (withdraw phase 1) transactions.
pub struct QpDaoPrepareBuilder<'a> {
    qp_client: &'a QpClient,
    is_mainnet: bool,
    placeholder_lock_size: usize,
}

impl<'a> QpDaoPrepareBuilder<'a> {
    /// Creates a new DAO prepare builder with default secp256k1 placeholder size.
    pub fn new(qp_client: &'a QpClient, is_mainnet: bool) -> Self {
        QpDaoPrepareBuilder {
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

    /// Builds an unsigned DAO prepare transaction.
    ///
    /// # Parameters
    /// - `from_address`: The address that owns the deposited cells
    /// - `deposit_out_points`: OutPoints of the deposited cells to prepare for withdrawal
    /// - `fee_rate`: Fee rate in shannons per 1000 bytes
    ///
    /// # Returns
    /// An unsigned transaction ready for signing
    pub fn build_unsigned_dao_request_withdraw(
        &self,
        from_address: &Address,
        deposit_out_points: Vec<OutPoint>,
        fee_rate: u64,
    ) -> Result<TransactionView, NodeManagerError> {
        let lock_script = Script::from(from_address.payload());

        // Create prepare items from deposit outpoints.
        let items = deposit_out_points
            .into_iter()
            .map(|out_point| DaoPrepareItem::from(CellInput::new(out_point, 0)))
            .collect::<Vec<_>>();

        let prepare_builder = DaoPrepareBuilder::new(items);

        // The SDK's DaoPrepareBuilder.build_base produces a transaction with
        // the deposited DAO cell as input 0 (using the user's lock script) but
        // sets no witnesses. The CapacityBalancer then detects the lock script
        // is already present in the inputs and skips placing a WitnessArgs
        // placeholder, leaving witness 0 empty. This causes two problems:
        //   1. generate_ckb_tx_message_all fails to parse witness 0 as WitnessArgs.
        //   2. Fee calculation doesn't account for the large SPHINCS+ lock field.
        //
        // Fix: build the base transaction, inject a WitnessArgs placeholder at
        // witness 0, then run the balancer on the patched transaction so fee
        // calculation includes the full witness size.
        let mut cell_collector = self.qp_client.cell_collector();
        let cell_dep_resolver =
            super::utils::cell_dep_resolver_from_rpc(self.qp_client, self.is_mainnet)?;
        let header_dep_resolver = self.qp_client.header_dep_resolver();
        let tx_dep_provider = self.qp_client.tx_dep_provider();

        let base_tx = prepare_builder
            .build_base(
                &mut *cell_collector,
                &cell_dep_resolver,
                &*header_dep_resolver,
                &*tx_dep_provider,
            )
            .map_err(|e| {
                NodeManagerError::RpcError(format!("Failed to build DAO prepare base: {:?}", e))
            })?;

        // Inject WitnessArgs with lock placeholder at witness 0.
        let placeholder_witness = WitnessArgs::new_builder()
            .lock(Some(Bytes::from(vec![0u8; self.placeholder_lock_size])).pack())
            .build();
        let mut witnesses: Vec<_> = base_tx.witnesses().into_iter().collect();
        // Pad witnesses to match input count (build_base sets none).
        while witnesses.len() < base_tx.inputs().len() {
            witnesses.push(Default::default());
        }
        witnesses[0] = placeholder_witness.as_bytes().pack();
        let patched_tx = base_tx
            .as_advanced_builder()
            .set_witnesses(witnesses)
            .build();

        // Balance the patched transaction (fee now accounts for full witness).
        let capacity_placeholder = WitnessArgs::new_builder()
            .lock(Some(Bytes::from(vec![0u8; self.placeholder_lock_size])).pack())
            .build();
        let balancer = CapacityBalancer {
            fee_rate: FeeRate::from_u64(fee_rate),
            change_lock_script: Some(lock_script.clone()),
            capacity_provider: CapacityProvider::new_simple(vec![(
                lock_script.clone(),
                capacity_placeholder,
            )]),
            force_small_change_as_fee: None,
        };

        let (tx, change_index) = balancer
            .rebalance_tx_capacity(
                &patched_tx,
                &mut *cell_collector,
                &*tx_dep_provider,
                &cell_dep_resolver,
                &*header_dep_resolver,
                0,
                None,
            )
            .map_err(|e| {
                NodeManagerError::RpcError(format!("Failed to balance DAO prepare: {:?}", e))
            })?;

        // TODO very rare: only when the difference between the input and output capacities equals exactly
        // floor(fee_rate * tx_size / 1000), leaving nothing for a change cell. One shannon either way and
        // the balancer creates one. Revisit and ship at the floor fee instead of failing.
        let change_index = change_index.ok_or_else(|| {
            NodeManagerError::RpcError(
                "Cannot meet the requested fee rate: the balanced DAO prepare has no change cell."
                    .to_string(),
            )
        })?;

        // The balancer rounds the fee down; raise it so the transaction meets
        // the rate the user entered.
        super::utils::enforce_ceiling_fee(
            tx,
            fee_rate,
            &lock_script,
            change_index,
            &*tx_dep_provider,
            &*header_dep_resolver,
        )
    }
}

/// Builder for DAO withdraw (phase 2) transactions.
pub struct QpDaoWithdrawBuilder<'a> {
    qp_client: &'a QpClient,
    is_mainnet: bool,
    placeholder_lock_size: usize,
}

impl<'a> QpDaoWithdrawBuilder<'a> {
    /// Creates a new DAO withdraw builder with default secp256k1 placeholder size.
    pub fn new(qp_client: &'a QpClient, is_mainnet: bool) -> Self {
        QpDaoWithdrawBuilder {
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

    /// Builds an unsigned DAO withdraw transaction.
    ///
    /// # Parameters
    /// - `from_address`: The address that owns the prepared cells
    /// - `prepared_out_points`: OutPoints of the prepared cells to withdraw
    /// - `fee_rate`: Fee rate in shannons per 1000 bytes
    ///
    /// # Returns
    /// An unsigned transaction ready for signing
    pub fn build_unsigned_dao_withdraw(
        &self,
        from_address: &Address,
        prepared_out_points: Vec<OutPoint>,
        fee_rate: u64,
    ) -> Result<TransactionView, NodeManagerError> {
        if prepared_out_points.is_empty() {
            return Err(NodeManagerError::RpcError(
                "No cells to withdraw.".to_string(),
            ));
        }

        let lock_script = Script::from(from_address.payload());

        // Create withdraw items from prepared outpoints
        let mut items = prepared_out_points
            .into_iter()
            .map(|out_point| DaoWithdrawItem::new(out_point, None))
            .collect::<Vec<_>>();

        // Set witness for first input
        items[0].init_witness = Some(
            WitnessArgs::new_builder()
                .lock(Some(Bytes::from(vec![0u8; self.placeholder_lock_size])).pack())
                .build(),
        );

        // Create withdraw receiver (where the funds go)
        let receiver = DaoWithdrawReceiver::LockScript {
            script: lock_script.clone(),
            fee_rate: Some(FeeRate::from_u64(fee_rate)),
        };

        let withdraw_builder = DaoWithdrawBuilder::new(items, receiver);

        // The receiver above carries a fee rate, so the SDK pays the fee out of
        // the withdrawn capacity and the balancer adds no change cell. Output 0
        // is that receiver cell - the sender's own - so it absorbs the
        // shortfall.
        build_balanced_dao_tx(
            &withdraw_builder,
            &lock_script,
            fee_rate,
            self.qp_client,
            self.is_mainnet,
            self.placeholder_lock_size,
            Some(0),
        )
    }
}
