//! This file contains the host-side implementation to allow
//! data streaming between quantumpurse(host) and Trezor device.
//!
//! Ported from the firmware's reference host loop
//! (`python/src/trezorlib/ckb.py::sign_tx`). The host sends the transaction
//! shape, then answers each `CKBTxRequest` the device issues — streaming the
//! transaction's inputs/outputs/cell-deps/witnesses and every referenced
//! previous transaction — and finally reassembles the signature the device
//! streams back as `TXSIGCHUNK`s. The reassembled blob is the complete witness
//! lock (`[header || pubkey || signature]`), ready for `fill_witness`.

use std::collections::HashMap;

use ckb_types::{
    core::{HeaderView, TransactionView},
    H256,
};
use protobuf::{Enum, Message, MessageField};
use trezor_client::protos::{self, CKBTxRequestType};
use trezor_client::TrezorMessage;

use crate::device::{network_name, TrezorDevice};
use crate::thp::ThpSession;
use crate::TrezorSignerError;

use qpv2_core::types::SpxVariant;

/// Wire message-type id of the device's `CKBTxRequest` reply, derived from
/// the generated protobuf enum so it cannot drift from the firmware proto.
const MSG_CKB_TX_REQUEST: u16 = protos::MessageType::MessageType_CKBTxRequest as u16;

/// The result of a device signing round-trip.
#[derive(Debug, Clone)]
pub struct SignedWitness {
    /// The complete witness lock (`[0x80,0x00,0x01,0x01,flag] || pubkey || signature`),
    /// ready to place into the signing witness via `ckb_node::fill_witness`.
    pub witness_lock: Vec<u8>,
    /// The transaction hash the device computed.
    pub tx_hash: [u8; 32],
}

impl TrezorDevice {
    /// Sign a CKB transaction on the device.
    ///
    /// `unsigned_tx` is the built transaction (with a placeholder witness);
    /// `signing_lock_size` is the final witness-lock length for the account's
    /// variant (`MultisigConfig::max_witness_lock_size()`); `prev_txs` maps each
    /// input's previous-output tx hash to its full transaction (see
    /// `ckb_node::fetch_prev_txs`); `sign_group_input_indices` lists the inputs
    /// of the lock-script group being signed (all inputs, for a single-sig
    /// account). Returns the assembled witness lock.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_tx(
        &mut self,
        account_index: u32,
        variant: SpxVariant,
        is_mainnet: bool,
        unsigned_tx: &TransactionView,
        signing_lock_size: usize,
        prev_txs: &HashMap<H256, TransactionView>,
        sign_group_input_indices: &[u32],
    ) -> Result<SignedWitness, TrezorSignerError> {
        self.sign_tx_with_context(
            account_index,
            variant,
            is_mainnet,
            unsigned_tx,
            signing_lock_size,
            prev_txs,
            &HashMap::new(),
            &[],
            sign_group_input_indices,
        )
    }

    /// Sign with the additional committed-block and header context required by
    /// Nervos DAO phase-2 inputs.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_tx_with_context(
        &mut self,
        account_index: u32,
        variant: SpxVariant,
        is_mainnet: bool,
        unsigned_tx: &TransactionView,
        signing_lock_size: usize,
        prev_txs: &HashMap<H256, TransactionView>,
        prev_tx_block_hashes: &HashMap<H256, H256>,
        headers: &[HeaderView],
        sign_group_input_indices: &[u32],
    ) -> Result<SignedWitness, TrezorSignerError> {
        let inputs = crate::conv::resolved_inputs_of(unsigned_tx, prev_txs, prev_tx_block_hashes)?;
        let outputs = crate::conv::outputs_of(unsigned_tx);
        let cell_deps = crate::conv::cell_deps_of(unsigned_tx);
        let witnesses = unsigned_tx.witnesses();
        let witnesses_count = witnesses.len();
        let signing_index = sign_group_input_indices.first().copied().unwrap_or(0) as usize;

        let mut kickoff = protos::CKBSphincsPlusSignTx::new();
        kickoff.set_account_index(account_index);
        kickoff.set_variant(variant as u32);
        kickoff.set_network(network_name(is_mainnet).to_owned());
        kickoff.set_inputs_count(inputs.len() as u32);
        kickoff.set_outputs_count(outputs.len() as u32);
        kickoff.set_cell_deps_count(cell_deps.len() as u32);
        kickoff.set_witnesses_count(witnesses_count as u32);
        kickoff.sign_group_input_indices = sign_group_input_indices.to_vec();
        // header_deps are committed in the tx hash, so the device must know
        // them to recompute it (empty for plain transfers).
        kickoff.header_deps = crate::conv::header_deps_of(unsigned_tx);

        let mut request = call(&mut self.session, kickoff)?;
        let mut sig_buf: Vec<u8> = Vec::new();
        let mut tx_hash = [0u8; 32];

        loop {
            match request.request_type() {
                CKBTxRequestType::TXFINISHED => {
                    if let Some(serialized) = request.serialized.as_ref() {
                        let h = serialized.tx_hash();
                        if h.len() == 32 {
                            tx_hash.copy_from_slice(h);
                        }
                    }
                    break;
                }
                CKBTxRequestType::TXINPUT => {
                    let idx = request_index(&request)?;
                    let mut ack = protos::CKBTxAckInput::new();
                    ack.input = MessageField::some(nth(&inputs, idx, "input")?);
                    request = call(&mut self.session, ack)?;
                }
                CKBTxRequestType::TXOUTPUT => {
                    let idx = request_index(&request)?;
                    let mut ack = protos::CKBTxAckOutput::new();
                    ack.output = MessageField::some(nth(&outputs, idx, "output")?);
                    request = call(&mut self.session, ack)?;
                }
                CKBTxRequestType::TXCELLDEP => {
                    let idx = request_index(&request)?;
                    let mut ack = protos::CKBTxAckCellDep::new();
                    ack.cell_dep = MessageField::some(nth(&cell_deps, idx, "cell_dep")?);
                    request = call(&mut self.session, ack)?;
                }
                CKBTxRequestType::TXWITNESS => {
                    let idx = request_index(&request)?;
                    let raw = witnesses
                        .get(idx)
                        .map(|b| b.raw_data())
                        .ok_or_else(|| protocol(format!("witness index {idx} out of range")))?;
                    let mut ack = protos::CKBTxAckWitness::new();
                    if idx == signing_index {
                        ack.witness_args = MessageField::some(crate::conv::signing_witness_args(
                            &raw,
                            signing_lock_size,
                        ));
                    } else {
                        ack.set_raw(raw.to_vec());
                    }
                    request = call(&mut self.session, ack)?;
                }
                CKBTxRequestType::TXPREVMETA => {
                    let prev = prev_lookup(prev_txs, &request_tx_hash(&request)?)?;
                    let mut ack = protos::CKBTxAckPrevMeta::new();
                    ack.set_version(crate::conv::version_of(prev));
                    ack.set_inputs_count(prev.inputs().len() as u32);
                    ack.set_outputs_count(prev.outputs().len() as u32);
                    ack.set_cell_deps_count(prev.cell_deps().len() as u32);
                    ack.header_deps = crate::conv::header_deps_of(prev);
                    request = call(&mut self.session, ack)?;
                }
                CKBTxRequestType::TXPREVINPUT => {
                    let prev = prev_lookup(prev_txs, &request_tx_hash(&request)?)?;
                    let idx = request_index(&request)?;
                    let inputs = crate::conv::inputs_of(prev);
                    let mut ack = protos::CKBTxAckInput::new();
                    ack.input = MessageField::some(nth(&inputs, idx, "prev input")?);
                    request = call(&mut self.session, ack)?;
                }
                CKBTxRequestType::TXPREVOUTPUT => {
                    let prev = prev_lookup(prev_txs, &request_tx_hash(&request)?)?;
                    let idx = request_index(&request)?;
                    let outputs = crate::conv::outputs_of(prev);
                    let mut ack = protos::CKBTxAckOutput::new();
                    ack.output = MessageField::some(nth(&outputs, idx, "prev output")?);
                    request = call(&mut self.session, ack)?;
                }
                CKBTxRequestType::TXPREVCELLDEP => {
                    let prev = prev_lookup(prev_txs, &request_tx_hash(&request)?)?;
                    let idx = request_index(&request)?;
                    let cell_deps = crate::conv::cell_deps_of(prev);
                    let mut ack = protos::CKBTxAckCellDep::new();
                    ack.cell_dep = MessageField::some(nth(&cell_deps, idx, "prev cell_dep")?);
                    request = call(&mut self.session, ack)?;
                }
                CKBTxRequestType::TXHEADER => {
                    let idx = request_index(&request)?;
                    let header = headers.get(idx).ok_or_else(|| {
                        protocol(format!("header dependency index {idx} out of range"))
                    })?;
                    let mut ack = protos::CKBTxAckHeader::new();
                    ack.header = MessageField::some(crate::conv::block_header(header));
                    request = call(&mut self.session, ack)?;
                }
                CKBTxRequestType::TXSIGCHUNK => {
                    let details = request
                        .details
                        .as_ref()
                        .ok_or_else(|| protocol("sig chunk missing details".to_string()))?;
                    let offset = details.signature_offset() as usize;
                    let chunk = request
                        .serialized
                        .as_ref()
                        .map(|s| s.signature().to_vec())
                        .unwrap_or_default();
                    if offset != sig_buf.len() {
                        return Err(protocol(format!(
                            "signature chunk gap: got offset {offset}, have {}",
                            sig_buf.len()
                        )));
                    }
                    sig_buf.extend_from_slice(&chunk);
                    request = call(&mut self.session, protos::CKBTxAckSigChunk::new())?;
                }
            }
        }

        if sig_buf.is_empty() {
            return Err(protocol("device returned an empty signature".to_string()));
        }

        Ok(SignedWitness {
            witness_lock: sig_buf,
            tx_hash,
        })
    }
}

/// Send a CKB message over the THP session (its wire type comes from the
/// message itself) and decode the device's next `CKBTxRequest`. `ButtonRequest`s
/// are auto-acknowledged inside the session.
fn call<S: TrezorMessage + Message>(
    session: &mut ThpSession,
    msg: S,
) -> Result<protos::CKBTxRequest, TrezorSignerError> {
    let message_type = u16::try_from(S::MESSAGE_TYPE.value())
        .map_err(|_| protocol("message type out of range".to_string()))?;
    let bytes = msg
        .write_to_bytes()
        .map_err(|e| protocol(format!("encode message: {e}")))?;
    let (reply_type, reply) = session.call_ckb(message_type, &bytes)?;
    if reply_type != MSG_CKB_TX_REQUEST {
        return Err(protocol(format!(
            "expected CKBTxRequest reply, got type {reply_type}"
        )));
    }
    protos::CKBTxRequest::parse_from_bytes(&reply)
        .map_err(|e| protocol(format!("decode CKBTxRequest: {e}")))
}

fn protocol(msg: String) -> TrezorSignerError {
    TrezorSignerError::Protocol(msg)
}

fn request_index(req: &protos::CKBTxRequest) -> Result<usize, TrezorSignerError> {
    let details = req
        .details
        .as_ref()
        .ok_or_else(|| protocol("request missing details".to_string()))?;
    Ok(details.request_index() as usize)
}

fn request_tx_hash(req: &protos::CKBTxRequest) -> Result<H256, TrezorSignerError> {
    let details = req
        .details
        .as_ref()
        .ok_or_else(|| protocol("previous-tx request missing details".to_string()))?;
    let raw = details.tx_hash();
    H256::from_slice(raw).map_err(|_| protocol(format!("bad tx_hash length {}", raw.len())))
}

fn prev_lookup<'a>(
    prev_txs: &'a HashMap<H256, TransactionView>,
    tx_hash: &H256,
) -> Result<&'a TransactionView, TrezorSignerError> {
    prev_txs
        .get(tx_hash)
        .ok_or_else(|| TrezorSignerError::MissingPrevTx(format!("{tx_hash:#x}")))
}

fn nth<T: Clone>(items: &[T], idx: usize, what: &str) -> Result<T, TrezorSignerError> {
    items
        .get(idx)
        .cloned()
        .ok_or_else(|| protocol(format!("{what} index {idx} out of range ({})", items.len())))
}
