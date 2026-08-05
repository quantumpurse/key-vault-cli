use ckb_node::{
    assemble_multisig_witness, build_signing_request, compute_signing_message, fill_witness,
};
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, ScriptHashType, TransactionBuilder, TransactionView},
    packed::{Byte32, CellInput, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::*,
};
use qpv2_core::types::{MultisigConfig, Signer, SigningMetadata, SingleSigConvention, SpxVariant};

fn byte32(seed: u8) -> Byte32 {
    Byte32::from_slice(&[seed; 32]).expect("32-byte hash")
}

fn out_point(seed: u8, index: u32) -> OutPoint {
    OutPoint::new(byte32(seed), index)
}

fn lock_script(seed: u8) -> Script {
    Script::new_builder()
        .code_hash(byte32(seed))
        .hash_type(ScriptHashType::Data1)
        .args(Bytes::from(vec![seed; 20]).pack())
        .build()
}

fn dao_type_script() -> Script {
    Script::new_builder()
        .code_hash(byte32(0xda))
        .hash_type(ScriptHashType::Type)
        .args(Bytes::new().pack())
        .build()
}

fn cell_output(lock_seed: u8, capacity_shannons: u64) -> CellOutput {
    CellOutput::new_builder()
        .capacity(Capacity::shannons(capacity_shannons).pack())
        .lock(lock_script(lock_seed))
        .build()
}

fn dao_cell_output(lock_seed: u8, capacity_shannons: u64) -> CellOutput {
    cell_output(lock_seed, capacity_shannons)
        .as_builder()
        .type_(Some(dao_type_script()).pack())
        .build()
}

fn placeholder_witness() -> ckb_types::packed::Bytes {
    WitnessArgs::default().as_bytes().pack()
}

fn transfer_tx(output_capacity: u64) -> TransactionView {
    TransactionBuilder::default()
        .input(CellInput::new(out_point(1, 0), 0))
        .output(cell_output(2, output_capacity))
        .output_data(Bytes::new().pack())
        .witness(placeholder_witness())
        .build()
}

fn dao_like_tx(output_data: Bytes, header_seed: u8) -> TransactionView {
    TransactionBuilder::default()
        .input(CellInput::new(out_point(3, 0), 0))
        .output(dao_cell_output(4, 102_00000000))
        .output_data(output_data.pack())
        .header_dep(byte32(header_seed))
        .witness(placeholder_witness())
        .build()
}

fn input_cells() -> Vec<(CellOutput, Bytes)> {
    vec![(cell_output(9, 120_00000000), Bytes::from(vec![0xaa, 0xbb]))]
}

fn param_id(variant: SpxVariant) -> ckb_fips205_utils::ParamId {
    (variant as u8)
        .try_into()
        .expect("SpxVariant and ParamId share discriminants")
}

fn signer(variant: SpxVariant, seed: u8) -> Signer {
    let (pubkey_len, _) = ckb_fips205_utils::verifying::lengths(param_id(variant));
    Signer {
        variant,
        pubkey: vec![seed; pubkey_len],
    }
}

fn signature(variant: SpxVariant, seed: u8) -> Vec<u8> {
    let (_, signature_len) = ckb_fips205_utils::verifying::lengths(param_id(variant));
    vec![seed; signature_len]
}

fn multisig_config() -> MultisigConfig {
    MultisigConfig::new(
        1,
        2,
        vec![
            signer(SpxVariant::Sha2128F, 0x11),
            signer(SpxVariant::Shake128S, 0x22),
            signer(SpxVariant::Sha2192S, 0x33),
        ],
    )
    .expect("valid 2-of-3 multisig config")
}

fn metadata() -> SigningMetadata {
    SigningMetadata {
        from_address: "ckt1from".to_string(),
        to_address: Some("ckt1to".to_string()),
        amount_ckb: Some("42.0".to_string()),
        tx_type: "Transfer".to_string(),
    }
}

fn assert_error_contains<T: std::fmt::Debug, E: std::fmt::Display>(
    result: Result<T, E>,
    needle: &str,
) {
    let message = result.expect_err("expected error").to_string();
    assert!(
        message.contains(needle),
        "expected error to contain `{needle}`, got `{message}`"
    );
}

#[test]
fn build_signing_request_preserves_unsigned_tx_inputs_and_metadata() {
    let tx = transfer_tx(100_00000000);
    let input_cells = input_cells();
    let config = MultisigConfig::single_sig(
        SpxVariant::Sha2128F,
        signer(SpxVariant::Sha2128F, 0x44).pubkey,
        SingleSigConvention::Standard,
    );

    let request = build_signing_request(&tx, &input_cells, &config, 0, false, metadata()).unwrap();
    let expected_message = compute_signing_message(&tx, &input_cells, 0).unwrap();

    assert_eq!(request.version, 1);
    assert_eq!(request.signing_message, hex::encode(expected_message));
    assert_eq!(
        request.multisig_config.header_bytes(),
        config.header_bytes()
    );
    assert_eq!(request.script_group_index, 0);
    assert!(!request.is_mainnet);
    assert_eq!(request.metadata.tx_type, "Transfer");
    assert_eq!(request.metadata.amount_ckb.as_deref(), Some("42.0"));
    assert_eq!(request.input_cells.len(), 1);

    let (output_hex, data_hex) = &request.input_cells[0];
    let decoded_output =
        CellOutput::from_slice(&hex::decode(output_hex).expect("valid output hex")).unwrap();
    assert_eq!(decoded_output, input_cells[0].0);
    assert_eq!(hex::decode(data_hex).unwrap(), input_cells[0].1.as_ref());

    let json_tx: ckb_jsonrpc_types::Transaction =
        serde_json::from_value(request.unsigned_tx).expect("valid transaction JSON");
    let packed_tx: ckb_types::packed::Transaction = json_tx.into();
    assert_eq!(packed_tx.calc_tx_hash(), tx.hash());
}

#[test]
fn dao_like_signing_message_commits_to_output_data_type_and_header_dep() {
    let input_cells = vec![(dao_cell_output(7, 104_00000000), Bytes::from(vec![1; 8]))];
    let dao_data = Bytes::from(0u64.to_le_bytes().to_vec());
    let base_message =
        compute_signing_message(&dao_like_tx(dao_data.clone(), 0x40), &input_cells, 0)
            .expect("base DAO signing message");

    let changed_dao_data = compute_signing_message(
        &dao_like_tx(Bytes::from(1u64.to_le_bytes().to_vec()), 0x40),
        &input_cells,
        0,
    )
    .expect("changed DAO data signing message");
    assert_ne!(base_message, changed_dao_data);

    let changed_header =
        compute_signing_message(&dao_like_tx(dao_data.clone(), 0x41), &input_cells, 0)
            .expect("changed header signing message");
    assert_ne!(base_message, changed_header);

    let changed_output = TransactionBuilder::default()
        .input(CellInput::new(out_point(3, 0), 0))
        .output(cell_output(4, 102_00000000))
        .output_data(dao_data.pack())
        .header_dep(byte32(0x40))
        .witness(placeholder_witness())
        .build();
    let changed_output_message =
        compute_signing_message(&changed_output, &input_cells, 0).expect("changed output");
    assert_ne!(base_message, changed_output_message);
}

#[test]
fn fill_witness_replaces_target_lock_and_rejects_bad_index() {
    let tx = TransactionBuilder::default()
        .input(CellInput::new(out_point(8, 0), 0))
        .input(CellInput::new(out_point(8, 1), 0))
        .output(cell_output(1, 90_00000000))
        .output_data(Bytes::new().pack())
        .witness(placeholder_witness())
        .witness(placeholder_witness())
        .build();

    let original_first_witness = tx.witnesses().get(0).unwrap();
    let lock = vec![0xab; 128];
    let signed = fill_witness(tx.clone(), 1, lock.clone()).unwrap();

    assert_eq!(signed.witnesses().get(0).unwrap(), original_first_witness);
    let updated_second_witness = signed.witnesses().get(1).unwrap();
    let witness_args = WitnessArgs::from_slice(updated_second_witness.raw_data().as_ref()).unwrap();
    assert_eq!(witness_args.lock().to_opt().unwrap().raw_data(), lock);

    assert_error_contains(
        fill_witness(tx, 2, vec![0xcd; 32]),
        "Witness index 2 out of range",
    );
}

#[test]
fn assemble_multisig_witness_builds_expected_layout() {
    let config = multisig_config();
    let first_signature = signature(SpxVariant::Sha2128F, 0xa1);
    let third_signature = signature(SpxVariant::Sha2192S, 0xc3);

    let lock = assemble_multisig_witness(
        &config,
        &[(0, first_signature.clone()), (2, third_signature.clone())],
    )
    .unwrap();

    assert_eq!(&lock[..4], &config.header_bytes());

    let mut offset = 4;
    for (index, signer) in config.signers.iter().enumerate() {
        let param_id = param_id(signer.variant);
        let signed = index == 0 || index == 2;
        assert_eq!(
            lock[offset],
            ckb_fips205_utils::construct_flag(param_id, signed)
        );
        offset += 1;
        assert_eq!(&lock[offset..offset + signer.pubkey.len()], signer.pubkey);
        offset += signer.pubkey.len();

        match index {
            0 => {
                assert_eq!(
                    &lock[offset..offset + first_signature.len()],
                    first_signature
                );
                offset += first_signature.len();
            }
            2 => {
                assert_eq!(
                    &lock[offset..offset + third_signature.len()],
                    third_signature
                );
                offset += third_signature.len();
            }
            _ => {}
        }
    }

    assert_eq!(offset, lock.len());
}

#[test]
fn assemble_multisig_witness_rejects_invalid_inputs() {
    let config = multisig_config();

    assert_error_contains(
        assemble_multisig_witness(&config, &[(0, signature(SpxVariant::Sha2128F, 0xa1))]),
        "Expected 2 signatures",
    );
    assert_error_contains(
        assemble_multisig_witness(
            &config,
            &[
                (0, signature(SpxVariant::Sha2128F, 0xa1)),
                (0, signature(SpxVariant::Sha2128F, 0xa2)),
            ],
        ),
        "Duplicate signer indices",
    );
    assert_error_contains(
        assemble_multisig_witness(
            &config,
            &[
                (1, signature(SpxVariant::Shake128S, 0xb2)),
                (2, signature(SpxVariant::Sha2192S, 0xc3)),
            ],
        ),
        "Signer 0 is required",
    );
    assert_error_contains(
        assemble_multisig_witness(
            &config,
            &[
                (0, signature(SpxVariant::Sha2128F, 0xa1)),
                (3, signature(SpxVariant::Sha2192S, 0xc3)),
            ],
        ),
        "Signer index 3 out of range",
    );
    assert_error_contains(
        assemble_multisig_witness(
            &config,
            &[
                (0, vec![0xee; 17]),
                (2, signature(SpxVariant::Sha2192S, 0xc3)),
            ],
        ),
        "signature length mismatch",
    );
}
