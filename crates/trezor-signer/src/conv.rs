//! Conversions from `ckb_types` transaction data into the device's protobuf shapes.

use ckb_types::{core::TransactionView, packed, prelude::*};
use trezor_client::protos;

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
