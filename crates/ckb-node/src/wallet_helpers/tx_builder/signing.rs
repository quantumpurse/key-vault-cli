//! Transaction signing utilities for quantum-resistant (SPHINCS+) locks.
//!
//! Provides helpers to:
//! 1. Fetch input cell data needed for CKB_TX_MESSAGE_ALL.
//! 2. Fill a signed witness into a transaction.
//! 3. Send a signed transaction via RPC.

use crate::client::QpClient;
use crate::error::NodeManagerError;
use ckb_types::{
    bytes::Bytes,
    core::TransactionView,
    packed::{CellOutput, WitnessArgs},
    prelude::*,
    H256,
};

/// Computes the 32-byte CKB_TX_MESSAGE_ALL hash for a given unsigned transaction.
///
/// This is the message that each signer signs with their SPHINCS+ key.
/// Handles the `ckb_types` → `ckb_gen_types` conversion internally.
pub fn compute_signing_message(
    tx: &TransactionView,
    input_cells: &[(CellOutput, Bytes)],
    script_group_index: usize,
) -> Result<[u8; 32], NodeManagerError> {
    let packed_tx = tx.data();
    let gen_tx = ckb_gen_types::packed::Transaction::from_slice(packed_tx.as_slice())
        .map_err(|e| NodeManagerError::RpcError(format!("Invalid Transaction: {}", e)))?;

    let gen_inputs: Vec<(
        ckb_gen_types::packed::CellOutput,
        ckb_gen_types::bytes::Bytes,
    )> = input_cells
        .iter()
        .map(|(output, data)| {
            let gen_output = ckb_gen_types::packed::CellOutput::from_slice(output.as_slice())
                .expect("valid CellOutput");
            (
                gen_output,
                ckb_gen_types::bytes::Bytes::copy_from_slice(data),
            )
        })
        .collect();

    let mut hasher = ckb_fips205_utils::Hasher::message_hasher();
    ckb_fips205_utils::ckb_tx_message_all_from_mock_tx::generate_ckb_tx_message_all(
        &gen_tx,
        &gen_inputs,
        ckb_fips205_utils::ckb_tx_message_all_from_mock_tx::ScriptOrIndex::Index(
            script_group_index,
        ),
        &mut hasher,
    )
    .map_err(|e| NodeManagerError::RpcError(format!("Failed to compute tx message: {:?}", e)))?;

    Ok(hasher.hash())
}

/// Builds a `SigningRequest` from an unsigned transaction and its context.
///
/// Computes the CKB_TX_MESSAGE_ALL signing message and packages everything
/// a co-signer needs to verify and sign the transaction.
pub fn build_signing_request(
    tx: &TransactionView,
    input_cells: &[(CellOutput, Bytes)],
    config: &qpv2_core::types::MultisigConfig,
    script_group_index: usize,
    is_mainnet: bool,
    metadata: qpv2_core::types::SigningMetadata,
) -> Result<qpv2_core::types::SigningRequest, NodeManagerError> {
    let signing_message = compute_signing_message(tx, input_cells, script_group_index)?;

    let json_tx: ckb_jsonrpc_types::Transaction = tx.data().into();
    let unsigned_tx = serde_json::to_value(json_tx)
        .map_err(|e| NodeManagerError::RpcError(format!("TX serialization failed: {}", e)))?;

    let input_cells_hex: Vec<(String, String)> = input_cells
        .iter()
        .map(|(output, data)| (hex::encode(output.as_slice()), hex::encode(data.as_ref())))
        .collect();

    Ok(qpv2_core::types::SigningRequest {
        version: 1,
        unsigned_tx,
        input_cells: input_cells_hex,
        signing_message: hex::encode(signing_message),
        multisig_config: config.clone(),
        script_group_index,
        is_mainnet,
        metadata,
    })
}

/// Assembles the complete witness lock field for a multisig transaction.
///
/// Takes the multisig configuration and a set of `(signer_index, raw_signature)`
/// pairs. Validates that exactly M signatures are present, the first R signers
/// have signatures, and there are no duplicates.
///
/// Returns the byte vector to be placed in `WitnessArgs.lock`.
pub fn assemble_multisig_witness(
    config: &qpv2_core::types::MultisigConfig,
    signatures: &[(usize, Vec<u8>)],
) -> Result<Vec<u8>, NodeManagerError> {
    let n = config.signers.len();
    let m = config.threshold as usize;
    let r = config.required_first_n as usize;

    if signatures.len() != m {
        return Err(NodeManagerError::RpcError(format!(
            "Expected {} signatures (threshold), got {}.",
            m,
            signatures.len()
        )));
    }

    let sig_indices: std::collections::HashSet<usize> =
        signatures.iter().map(|(i, _)| *i).collect();
    if sig_indices.len() != signatures.len() {
        return Err(NodeManagerError::RpcError(
            "Duplicate signer indices in signatures.".to_string(),
        ));
    }

    for i in 0..r {
        if !sig_indices.contains(&i) {
            return Err(NodeManagerError::RpcError(format!(
                "Signer {} is required (required_first_n={}) but has no signature.",
                i, r
            )));
        }
    }

    for &(idx, _) in signatures {
        if idx >= n {
            return Err(NodeManagerError::RpcError(format!(
                "Signer index {} out of range (N={}).",
                idx, n
            )));
        }
    }

    let mut lock = Vec::new();
    lock.extend_from_slice(&config.header_bytes());

    for (i, signer) in config.signers.iter().enumerate() {
        let param_id: ckb_fips205_utils::ParamId = (signer.variant as u8)
            .try_into()
            .expect("SpxVariant and ParamId share discriminants");

        if let Some((_, sig)) = signatures.iter().find(|(idx, _)| *idx == i) {
            let (_, expected_sig_len) = ckb_fips205_utils::verifying::lengths(param_id);
            if sig.len() != expected_sig_len {
                return Err(NodeManagerError::RpcError(format!(
                    "Signer {} signature length mismatch: expected {}, got {}.",
                    i,
                    expected_sig_len,
                    sig.len()
                )));
            }
            lock.push(ckb_fips205_utils::construct_flag(param_id, true));
            lock.extend_from_slice(&signer.pubkey);
            lock.extend_from_slice(sig);
        } else {
            lock.push(ckb_fips205_utils::construct_flag(param_id, false));
            lock.extend_from_slice(&signer.pubkey);
        }
    }

    Ok(lock)
}

/// Fetches the input cells (CellOutput + data) for every input in a transaction.
///
/// This data is required by `generate_ckb_tx_message_all` to compute the
/// transaction message hash for quantum-resistant signing.
pub fn fetch_input_cells(
    qp_client: &QpClient,
    tx: &TransactionView,
) -> Result<Vec<(CellOutput, Bytes)>, NodeManagerError> {
    let mut inputs = Vec::new();

    for input in tx.inputs().into_iter() {
        let out_point = input.previous_output();
        let tx_hash: H256 = out_point.tx_hash().unpack();
        let index: u32 = out_point.index().unpack();

        let tx_status = qp_client.get_transaction(tx_hash.clone())?.ok_or_else(|| {
            NodeManagerError::RpcError(format!("Input transaction {} not found.", tx_hash))
        })?;

        let prev_tx_view = tx_status.transaction.ok_or_else(|| {
            NodeManagerError::RpcError(format!("Input transaction {} has no data.", tx_hash))
        })?;

        let output = prev_tx_view
            .inner
            .outputs
            .get(index as usize)
            .ok_or_else(|| {
                NodeManagerError::RpcError(format!(
                    "Output index {} not found in transaction {}.",
                    index, tx_hash
                ))
            })?;

        let data = prev_tx_view
            .inner
            .outputs_data
            .get(index as usize)
            .ok_or_else(|| {
                NodeManagerError::RpcError(format!(
                    "Output data index {} not found in transaction {}.",
                    index, tx_hash
                ))
            })?;

        // Convert from jsonrpc types to packed types
        let cell_output: CellOutput = output.clone().into();
        let cell_data: Bytes = data.clone().into_bytes();

        inputs.push((cell_output, cell_data));
    }

    Ok(inputs)
}

/// Fetches the full previous transaction for every input, keyed by tx hash.
///
/// A hardware signer (Trezor) verifies input capacities trustlessly by
/// re-serializing each referenced previous transaction and matching its
/// recomputed hash against the spending input's `OutPoint`. Unlike
/// [`fetch_input_cells`], which keeps only the single spent `CellOutput`, this
/// returns the entire previous transaction (version, inputs, outputs, data,
/// cell deps, header deps) that the device streams and re-hashes. Each distinct
/// referenced tx hash is fetched once.
pub fn fetch_prev_txs(
    qp_client: &QpClient,
    tx: &TransactionView,
) -> Result<std::collections::HashMap<H256, TransactionView>, NodeManagerError> {
    let mut prev_txs: std::collections::HashMap<H256, TransactionView> =
        std::collections::HashMap::new();

    for input in tx.inputs().into_iter() {
        let tx_hash: H256 = input.previous_output().tx_hash().unpack();
        if prev_txs.contains_key(&tx_hash) {
            continue;
        }

        let tx_status = qp_client.get_transaction(tx_hash.clone())?.ok_or_else(|| {
            NodeManagerError::RpcError(format!("Input transaction {} not found.", tx_hash))
        })?;
        let prev_tx_view = tx_status.transaction.ok_or_else(|| {
            NodeManagerError::RpcError(format!("Input transaction {} has no data.", tx_hash))
        })?;

        // jsonrpc Transaction -> packed -> core view, so the device can read
        // every RawTransaction field and recompute the hash.
        let packed: ckb_types::packed::Transaction = prev_tx_view.inner.into();
        prev_txs.insert(tx_hash, packed.into_view());
    }

    Ok(prev_txs)
}

/// Replaces the placeholder witness at the given index with the signed witness data.
///
/// The `signature_bytes` should be the complete lock field content as returned
/// by `KeyVault::ckb_sign()`, which includes the prefix, public key, and signature.
pub fn fill_witness(
    tx: TransactionView,
    script_group_index: usize,
    signature_bytes: Vec<u8>,
) -> Result<TransactionView, NodeManagerError> {
    let mut witnesses: Vec<_> = tx.witnesses().into_iter().collect();

    let original_witness = witnesses.get(script_group_index).ok_or_else(|| {
        NodeManagerError::RpcError(format!(
            "Witness index {} out of range.",
            script_group_index
        ))
    })?;

    // Parse the existing WitnessArgs (which has a placeholder lock)
    let witness_args = if original_witness.raw_data().is_empty() {
        WitnessArgs::default()
    } else {
        WitnessArgs::from_slice(original_witness.raw_data().as_ref())
            .map_err(|e| NodeManagerError::RpcError(format!("Invalid witness: {}", e)))?
    };

    // Replace the lock field with the actual signature
    let updated_witness = witness_args
        .as_builder()
        .lock(Some(Bytes::from(signature_bytes)).pack())
        .build();

    witnesses[script_group_index] = updated_witness.as_bytes().pack();

    Ok(tx.as_advanced_builder().set_witnesses(witnesses).build())
}

/// Sends a signed transaction via RPC.
///
/// Returns the transaction hash on success.
pub fn send_transaction(
    qp_client: &QpClient,
    tx: &TransactionView,
) -> Result<H256, NodeManagerError> {
    let json_tx: ckb_jsonrpc_types::Transaction = tx.data().into();
    qp_client.send_transaction(json_tx)
}
