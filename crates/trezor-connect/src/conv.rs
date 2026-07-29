//! Conversions from `ckb_types` transaction data into the device's protobuf shapes.

use std::collections::HashMap;

use ckb_types::{
    core::{HeaderView, TransactionView},
    packed,
    prelude::*,
    H256,
};
use trezor_client::protos;

use crate::TrezorSignerError;

const DAO_TYPE_CODE_HASH: [u8; 32] = [
    0x82, 0xd7, 0x6d, 0x1b, 0x75, 0xfe, 0x2f, 0xd9, 0xa2, 0x7d, 0xfb, 0xaa, 0x65, 0xa0, 0x39, 0x22,
    0x1a, 0x38, 0x0d, 0x76, 0xc9, 0x26, 0xf3, 0x78, 0xd3, 0xf8, 0x1c, 0xf3, 0xe7, 0xe1, 0x3f, 0x2e,
];

/// Read a molecule `Byte` (hash type / dep type) as a plain `u8`.
fn byte(b: packed::Byte) -> u8 {
    b.into()
}

/// Convert a packed `CellInput` into its protobuf form.
pub fn cell_input(input: &packed::CellInput) -> protos::CKBCellInput {
    let out_point = input.previous_output();
    let mut m = protos::CKBCellInput::new();
    m.set_previous_output_tx_hash(out_point.tx_hash().raw_data().to_vec());
    let index: u32 = out_point.index().unpack();
    m.set_previous_output_index(index);
    let since: u64 = input.since().unpack();
    m.set_since(since);
    m
}

/// Convert a packed `CellOutput` (+ its data) into its protobuf form.
pub fn cell_output(output: &packed::CellOutput, data: &[u8]) -> protos::CKBCellOutput {
    let mut m = protos::CKBCellOutput::new();
    let capacity: u64 = output.capacity().unpack();
    m.set_capacity(capacity);

    let lock = output.lock();
    m.set_lock_code_hash(lock.code_hash().raw_data().to_vec());
    m.set_lock_hash_type(byte(lock.hash_type()) as u32);
    m.set_lock_args(lock.args().raw_data().to_vec());

    if let Some(type_script) = output.type_().to_opt() {
        m.set_type_code_hash(type_script.code_hash().raw_data().to_vec());
        m.set_type_hash_type(byte(type_script.hash_type()) as u32);
        m.set_type_args(type_script.args().raw_data().to_vec());
    }

    if !data.is_empty() {
        m.set_data(data.to_vec());
    }
    m
}

/// Convert a packed `CellDep` into its protobuf form.
pub fn cell_dep(dep: &packed::CellDep) -> protos::CKBCellDep {
    let out_point = dep.out_point();
    let mut m = protos::CKBCellDep::new();
    m.set_tx_hash(out_point.tx_hash().raw_data().to_vec());
    let index: u32 = out_point.index().unpack();
    m.set_index(index);
    m.set_dep_type(byte(dep.dep_type()) as u32);
    m
}

/// All inputs of a transaction as protobuf messages.
pub fn inputs_of(tx: &TransactionView) -> Vec<protos::CKBCellInput> {
    tx.inputs().into_iter().map(|i| cell_input(&i)).collect()
}

/// Every top-level input converted for the device, with DAO phase-2
/// withdrawals resolved against `prev_txs` and `prev_tx_block_hashes` to carry
/// the `header_deps` indices of their deposit and withdraw blocks.
pub fn resolved_inputs_of(
    tx: &TransactionView,
    prev_txs: &HashMap<H256, TransactionView>,
    prev_tx_block_hashes: &HashMap<H256, H256>,
) -> Result<Vec<protos::CKBCellInput>, TrezorSignerError> {
    let header_deps: Vec<packed::Byte32> = tx.header_deps().into_iter().collect();
    let witnesses = tx.witnesses();
    let mut result = Vec::with_capacity(tx.inputs().len());

    for (input_index, input) in tx.inputs().into_iter().enumerate() {
        let mut converted = cell_input(&input);
        let out_point = input.previous_output();
        let prev_hash: H256 = out_point.tx_hash().unpack();
        let output_index: u32 = out_point.index().unpack();

        let is_dao_withdrawal = prev_txs
            .get(&prev_hash)
            .and_then(|prev| prev.output_with_data(output_index as usize))
            .is_some_and(|(output, data)| {
                let Some(type_script) = output.type_().to_opt() else {
                    return false;
                };
                let hash_type: u8 = type_script.hash_type().into();
                type_script.code_hash().raw_data().as_ref() == DAO_TYPE_CODE_HASH
                    && hash_type == 1
                    && data.len() == 8
                    && data.as_ref() != [0u8; 8]
            });

        if is_dao_withdrawal {
            let witness = witnesses.get(input_index).ok_or_else(|| {
                TrezorSignerError::Protocol(format!(
                    "DAO withdrawal input {input_index} has no witness"
                ))
            })?;
            let witness_args = packed::WitnessArgs::from_slice(witness.raw_data().as_ref())
                .map_err(|e| {
                    TrezorSignerError::Protocol(format!(
                        "DAO withdrawal input {input_index} has invalid WitnessArgs: {e}"
                    ))
                })?;
            let input_type_args = witness_args.input_type().to_opt().ok_or_else(|| {
                TrezorSignerError::Protocol(format!(
                    "DAO withdrawal input {input_index} witness has no deposit header index"
                ))
            })?;
            let deposit_header_index: [u8; 8] = input_type_args
                .raw_data()
                .as_ref()
                .try_into()
                .map_err(|_| {
                    TrezorSignerError::Protocol(format!(
                        "DAO withdrawal input {input_index} deposit header index is not 8 bytes"
                    ))
                })?;
            let deposit_header_index = u64::from_le_bytes(deposit_header_index);
            if deposit_header_index >= header_deps.len() as u64 {
                return Err(TrezorSignerError::Protocol(format!(
                    "DAO withdrawal input {input_index} deposit header index {deposit_header_index} is out of range"
                )));
            }
            // Bounded by `header_deps.len()` above, so narrowing to the
            // protobuf field's `u32` cannot lose information.
            let deposit_header_index = deposit_header_index as u32;

            let withdraw_block_hash = prev_tx_block_hashes.get(&prev_hash).ok_or_else(|| {
                TrezorSignerError::Protocol(format!(
                    "DAO withdrawal input {input_index} previous transaction has no committed block hash"
                ))
            })?;
            let packed_withdraw_hash: packed::Byte32 = withdraw_block_hash.pack();
            let withdraw_header_index = header_deps
                .iter()
                .position(|hash| hash == &packed_withdraw_hash)
                .ok_or_else(|| {
                    TrezorSignerError::Protocol(format!(
                        "DAO withdrawal input {input_index} phase-1 block is missing from header_deps"
                    ))
                })?;

            converted.set_dao_deposit_header_index(deposit_header_index);
            converted.set_dao_withdraw_header_index(withdraw_header_index as u32);
        }

        result.push(converted);
    }

    Ok(result)
}

/// All outputs of a transaction (with their data) as protobuf messages.
pub fn outputs_of(tx: &TransactionView) -> Vec<protos::CKBCellOutput> {
    let data = tx.outputs_data();
    tx.outputs()
        .into_iter()
        .enumerate()
        .map(|(i, out)| {
            let d = data.get(i).map(|b| b.raw_data()).unwrap_or_default();
            cell_output(&out, &d)
        })
        .collect()
}

/// All cell deps of a transaction as protobuf messages.
pub fn cell_deps_of(tx: &TransactionView) -> Vec<protos::CKBCellDep> {
    tx.cell_deps().into_iter().map(|d| cell_dep(&d)).collect()
}

/// RawTransaction version.
pub fn version_of(tx: &TransactionView) -> u32 {
    tx.data().raw().version().unpack()
}

/// Header deps as raw 32-byte hashes.
pub fn header_deps_of(tx: &TransactionView) -> Vec<Vec<u8>> {
    tx.data()
        .raw()
        .header_deps()
        .into_iter()
        .map(|h| h.raw_data().to_vec())
        .collect()
}

/// Convert a full CKB header into the shape streamed to the device.
pub fn block_header(header: &HeaderView) -> protos::CKBBlockHeader {
    let mut result = protos::CKBBlockHeader::new();
    result.set_version(header.version());
    result.set_compact_target(header.compact_target());
    result.set_timestamp(header.timestamp());
    result.set_number(header.number());
    result.set_epoch(header.epoch().full_value());
    result.set_parent_hash(header.parent_hash().raw_data().to_vec());
    result.set_transactions_root(header.transactions_root().raw_data().to_vec());
    result.set_proposals_hash(header.proposals_hash().raw_data().to_vec());
    result.set_extra_hash(header.extra_hash().raw_data().to_vec());
    result.set_dao(header.dao().raw_data().to_vec());
    result.set_nonce(header.nonce().to_le_bytes().to_vec());
    result
}

/// Build the `CKBWitnessArgs` for the signing witness: the device blanks the
/// lock to `lock_size` bytes, so only `input_type`/`output_type` (parsed from
/// the placeholder witness) enter the signing message.
pub fn signing_witness_args(placeholder: &[u8], lock_size: usize) -> protos::CKBWitnessArgs {
    let mut m = protos::CKBWitnessArgs::new();
    m.set_lock_size(lock_size as u32);
    if let Ok(wa) = packed::WitnessArgs::from_slice(placeholder) {
        if let Some(input_type) = wa.input_type().to_opt() {
            m.set_input_type(input_type.raw_data().to_vec());
        }
        if let Some(output_type) = wa.output_type().to_opt() {
            m.set_output_type(output_type.raw_data().to_vec());
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use ckb_types::{
        bytes::Bytes,
        core::{
            Capacity, EpochNumberWithFraction, HeaderBuilder, ScriptHashType, TransactionBuilder,
        },
        packed::{CellInput, CellOutput, OutPoint, Script, WitnessArgs},
    };

    #[test]
    fn dao_withdrawal_inputs_include_both_header_indices() {
        let dao_type = Script::new_builder()
            .code_hash(packed::Byte32::from_slice(&DAO_TYPE_CODE_HASH).unwrap())
            .hash_type(ScriptHashType::Type)
            .build();
        let prev_output = CellOutput::new_builder()
            .capacity(Capacity::shannons(10_000_000_000).pack())
            .lock(Script::default())
            .type_(Some(dao_type).pack())
            .build();
        let prev_tx = TransactionBuilder::default()
            .output(prev_output)
            .output_data(Bytes::from(1234u64.to_le_bytes().to_vec()).pack())
            .build();
        let prev_hash: H256 = prev_tx.hash().unpack();

        let deposit_header = H256::from([0x11; 32]);
        let withdraw_header = H256::from([0x22; 32]);
        let witness = WitnessArgs::new_builder()
            .input_type(Some(Bytes::from(0u64.to_le_bytes().to_vec())).pack())
            .build();
        let tx = TransactionBuilder::default()
            .input(CellInput::new(OutPoint::new(prev_tx.hash(), 0), 0))
            .header_dep(deposit_header.pack())
            .header_dep(withdraw_header.pack())
            .witness(witness.as_bytes().pack())
            .build();

        let prev_txs = HashMap::from([(prev_hash.clone(), prev_tx)]);
        let block_hashes = HashMap::from([(prev_hash, withdraw_header)]);
        let inputs = resolved_inputs_of(&tx, &prev_txs, &block_hashes).unwrap();

        assert_eq!(inputs.len(), 1);
        assert!(inputs[0].has_dao_deposit_header_index());
        assert!(inputs[0].has_dao_withdraw_header_index());
        assert_eq!(inputs[0].dao_deposit_header_index(), 0);
        assert_eq!(inputs[0].dao_withdraw_header_index(), 1);
    }

    #[test]
    fn block_header_fields_reproduce_canonical_header_bytes() {
        let header = HeaderBuilder::default()
            .version(7u32)
            .compact_target(0x1a2b3c4du32)
            .timestamp(1_725_000_000_123u64)
            .number(42u64)
            .epoch(EpochNumberWithFraction::new(3, 1, 10).full_value())
            .parent_hash(packed::Byte32::from_slice(&[0x11; 32]).unwrap())
            .transactions_root(packed::Byte32::from_slice(&[0x22; 32]).unwrap())
            .proposals_hash(packed::Byte32::from_slice(&[0x33; 32]).unwrap())
            .extra_hash(packed::Byte32::from_slice(&[0x44; 32]).unwrap())
            .dao(packed::Byte32::from_slice(&[0x55; 32]).unwrap())
            .nonce(0x0102_0304_0506_0708_1112_1314_1516_1718u128)
            .build();
        let converted = block_header(&header);

        let mut serialized = Vec::with_capacity(208);
        serialized.extend_from_slice(&converted.version().to_le_bytes());
        serialized.extend_from_slice(&converted.compact_target().to_le_bytes());
        serialized.extend_from_slice(&converted.timestamp().to_le_bytes());
        serialized.extend_from_slice(&converted.number().to_le_bytes());
        serialized.extend_from_slice(&converted.epoch().to_le_bytes());
        serialized.extend_from_slice(converted.parent_hash());
        serialized.extend_from_slice(converted.transactions_root());
        serialized.extend_from_slice(converted.proposals_hash());
        serialized.extend_from_slice(converted.extra_hash());
        serialized.extend_from_slice(converted.dao());
        serialized.extend_from_slice(converted.nonce());

        assert_eq!(serialized, header.data().as_slice());
    }
}
