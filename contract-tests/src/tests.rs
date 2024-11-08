use std::io::Write;
use std::sync::atomic::AtomicUsize;

use crate::Loader;
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::bytes::Bytes;
use ckb_testtool::ckb_types::core::TransactionBuilder;
use ckb_testtool::ckb_types::packed::{CellDep, CellInput, CellOutput, ScriptOpt, WitnessArgs};
use ckb_testtool::ckb_types::prelude::Builder;
use ckb_testtool::ckb_types::prelude::{Entity, Pack};
use ckb_testtool::{ckb_types::packed::OutPoint, context::Context};
use rand::seq::SliceRandom;
use rand::Rng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rsa::RsaPrivateKey;
use signature_tools::candidate::{encode_candidate_cell, Candidate};
use signature_tools::check_size_and_write;
use signature_tools::rsa_tools::create_signature;
use signature_tools::rsa_tools::merkle_tree::{
    create_merkle_tree_with_proof_rsa, create_merkle_tree_with_root_hash_rsa, MerkleProofResult,
};

const KEY_COUNT: usize = 1000;
const CHUNK_SIZE: usize = 15;
const CANDIDATE_COUNT: usize = 100;
const MAX_CYCLES: u64 = 35_0000_0000;

#[derive(Debug)]
struct PreparedState {
    #[allow(unused)]
    candidate_cell: OutPoint,
    keys: Vec<RsaPrivateKey>,
    candidates: Vec<Candidate>,
    merkle_root_cell: OutPoint,
}

fn prepare(ctx: &mut Context) -> PreparedState {
    let generated_count = AtomicUsize::new(0);
    let keys = (0..KEY_COUNT)
        .into_par_iter()
        .map(|_| {
            let mut rng = rand::thread_rng();
            let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
            println!(
                "Key generating done {}",
                generated_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1
            );
            priv_key
        })
        .collect::<Vec<_>>();

    let mut rng = rand::thread_rng();
    let candidates = (0..CANDIDATE_COUNT)
        .map(|idx| Candidate {
            description: format!("{}-th candidate", idx),
            id: rng.gen(),
        })
        .collect::<Vec<_>>();
    let candidate_cell = { ctx.deploy_cell(encode_candidate_cell(&candidates).into()) };
    let merkle_root = {
        let mut data = create_merkle_tree_with_root_hash_rsa(&keys, CHUNK_SIZE).unwrap();
        data.write_all(&(keys.len() as u32).to_le_bytes()).unwrap();
        data.write_all(&(keys.len().div_ceil(CHUNK_SIZE) as u32).to_le_bytes())
            .unwrap();

        data
    };

    PreparedState {
        candidate_cell,
        candidates,
        keys,
        merkle_root_cell: ctx.deploy_cell(merkle_root.into()),
    }
}

#[test]
fn test_verify_signature() {
    let mut rng = rand::thread_rng();
    let mut ctx = Context::default();
    let loader = Loader::default();
    let verifier_bin = loader.load_binary("ring-signature-verify");
    let script_out_point = ctx.deploy_cell(verifier_bin);
    let state = prepare(&mut ctx);
    let signer = rng.gen_range(0usize..state.keys.len());
    let signer_block = signer / CHUNK_SIZE;
    let signer_index = signer % CHUNK_SIZE;
    let selected_candidate = state.candidates.choose(&mut rng).unwrap();
    let signature = create_signature(
        &state.keys
            [CHUNK_SIZE * signer_block..(CHUNK_SIZE * (signer_block + 1)).min(state.keys.len())]
            .iter()
            .map(|s| s.to_public_key())
            .collect::<Vec<_>>(),
        &state.keys[signer],
        signer_index,
        &selected_candidate.id,
    )
    .unwrap();
    let MerkleProofResult {
        proof,
        leaf_hash: _,
    } = create_merkle_tree_with_proof_rsa(&state.keys, CHUNK_SIZE, signer_block).unwrap();

    let always_success_script_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let always_success_script = ctx
        .build_script(&always_success_script_op, Default::default())
        .unwrap();

    let cell_deps: Vec<CellDep> = vec![
        CellDep::new_builder()
            .out_point(state.candidate_cell)
            .build(),
        CellDep::new_builder()
            .out_point(state.merkle_root_cell.clone())
            .build(),
        CellDep::new_builder()
            .out_point(always_success_script_op)
            .build(),
        CellDep::new_builder()
            .out_point(script_out_point.clone())
            .build(),
    ];

    let tx_input = {
        let input_out_point = ctx.create_cell(
            CellOutput::new_builder()
                .capacity(1000u64.pack())
                .lock(always_success_script)
                .build(),
            Bytes::new(),
        );
        vec![CellInput::new_builder()
            .previous_output(input_out_point)
            .build()]
    };

    let (tx_output, tx_output_data) = {
        let mut cell_data = vec![0u8; 0];
        cell_data.write_all(&selected_candidate.id).unwrap();
        check_size_and_write(&mut cell_data, &signature.i, 256).unwrap();
        let type_script = ctx.build_script(&script_out_point, Bytes::new()).unwrap();
        (
            vec![CellOutput::new_builder()
                .capacity((cell_data.len() as u64).pack())
                .type_(ScriptOpt::new_builder().set(Some(type_script)).build())
                .build()],
            vec![Bytes::from(cell_data)],
        )
    };
    let witness = {
        let mut witness_data = vec![0u8; 0];
        check_size_and_write(&mut witness_data, &signature.c, 256).unwrap();
        witness_data
            .write_all(&(signature.r_and_pubkey.len() as u32).to_le_bytes())
            .unwrap();
        for item in signature.r_and_pubkey.iter() {
            check_size_and_write(&mut witness_data, &item.r, 256).unwrap();
        }
        for item in signature.r_and_pubkey.iter() {
            check_size_and_write(&mut witness_data, &item.n, 256).unwrap();
        }
        for item in signature.r_and_pubkey.iter() {
            check_size_and_write(&mut witness_data, &item.e, 4).unwrap();
        }
        witness_data
            .write_all(&(signer_block as u32).to_le_bytes())
            .unwrap();
        witness_data
            .write_all(&(proof.len() as u32).to_le_bytes())
            .unwrap();
        witness_data.write_all(&proof).unwrap();
        vec![WitnessArgs::new_builder()
            .output_type(Some(Bytes::from(witness_data)).pack())
            .lock(Option::<Bytes>::None.pack())
            .input_type(Option::<Bytes>::None.pack())
            .build()
            .as_bytes()
            .pack()]
    };
    let tx = {
        let tx = TransactionBuilder::default()
            .cell_deps(cell_deps.clone())
            .inputs(tx_input.clone())
            .outputs(tx_output.clone())
            .outputs_data(tx_output_data.pack())
            .witnesses(witness.clone())
            .build();
        tx.as_advanced_builder().build()
    };
    let cycles = ctx.verify_tx(&tx, MAX_CYCLES).unwrap();
    println!("Cycles: {}", cycles);
    // Test bad signature
    let (tx_output, tx_output_data) = {
        let mut cell_data = vec![0u8; 0];
        cell_data.write_all(&selected_candidate.id).unwrap();
        check_size_and_write(&mut cell_data, &signature.i, 256).unwrap();
        // Create an invalid signature
        cell_data[0] ^= 1;

        let type_script = ctx.build_script(&script_out_point, Bytes::new()).unwrap();
        (
            vec![CellOutput::new_builder()
                .capacity((cell_data.len() as u64).pack())
                .type_(ScriptOpt::new_builder().set(Some(type_script)).build())
                .build()],
            vec![Bytes::from(cell_data)],
        )
    };
    let tx = {
        let tx = TransactionBuilder::default()
            .cell_deps(cell_deps)
            .inputs(tx_input)
            .outputs(tx_output)
            .outputs_data(tx_output_data.pack())
            .witnesses(witness)
            .build();
        tx.as_advanced_builder().build()
    };
    ctx.verify_tx(&tx, MAX_CYCLES).unwrap_err();
}
