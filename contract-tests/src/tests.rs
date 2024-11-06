use std::io::Write;

use crate::Loader;
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::bytes::Bytes;
use ckb_testtool::ckb_types::core::TransactionBuilder;
use ckb_testtool::ckb_types::packed::{CellDep, CellInput, CellOutput, ScriptOpt, WitnessArgs};
use ckb_testtool::ckb_types::prelude::{Builder, Unpack};
use ckb_testtool::ckb_types::prelude::{Entity, Pack};
use ckb_testtool::{ckb_types::packed::OutPoint, context::Context};
use rand::seq::SliceRandom;
use rand::Rng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rsa::RsaPrivateKey;
use signature_tools::{
    check_size_and_write, create_signature, encode_candidate_cell, encode_public_key_cell,
    encode_public_key_index_cell, Candidate, PublicKeyIndexEntry,
};

const KEY_COUNT: usize = 1000;
const CHUNK_SIZE: usize = 450;
const CANDIDATE_COUNT: usize = 100;
const MAX_CYCLES: u64 = 35_0000_0000;

#[derive(Debug)]
struct PreparedState {
    #[allow(unused)]
    public_key_index_cell: OutPoint,
    public_key_cells: Vec<OutPoint>,
    candidate_cell: OutPoint,
    keys: Vec<RsaPrivateKey>,
    candidates: Vec<Candidate>,
}

fn prepare(ctx: &mut Context) -> PreparedState {
    let keys = (0..KEY_COUNT)
        .into_par_iter()
        .map(|idx| {
            let mut rng = rand::thread_rng();
            let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
            println!("Key generating done {}", idx);
            priv_key
        })
        .collect::<Vec<_>>();
    let key_cells = keys
        .chunks(CHUNK_SIZE)
        .enumerate()
        .map(|(_, chunk)| ctx.deploy_cell(encode_public_key_cell(chunk).into()))
        .collect::<Vec<_>>();
    let key_index_cell = {
        let buf = encode_public_key_index_cell(
            &key_cells
                .iter()
                .map(|v| PublicKeyIndexEntry {
                    hash: v.tx_hash().raw_data().to_vec(),
                    index: v.index().unpack(),
                })
                .collect::<Vec<_>>(),
        );
        ctx.deploy_cell(buf.into())
    };
    let mut rng = rand::thread_rng();
    let candidates = (0..CANDIDATE_COUNT)
        .map(|idx| Candidate {
            description: format!("{}-th candidate", idx),
            id: rng.gen(),
        })
        .collect::<Vec<_>>();
    let candidate_cell = { ctx.deploy_cell(encode_candidate_cell(&candidates).into()) };
    PreparedState {
        candidate_cell,
        candidates,
        keys,
        public_key_cells: key_cells,
        public_key_index_cell: key_index_cell,
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
    let always_success_script_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let always_success_script = ctx
        .build_script(&always_success_script_op, Default::default())
        .unwrap();

    let cell_deps: Vec<CellDep> = vec![
        CellDep::new_builder()
            .out_point(state.candidate_cell)
            .build(),
        CellDep::new_builder()
            .out_point(state.public_key_cells[signer_block].clone())
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
        cell_data.push(1); // R[] and I are in witness
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
        for item in signature.r_and_pubkey.iter() {
            check_size_and_write(&mut witness_data, &item.r, 256).unwrap();
        }
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
            .witnesses(witness)
            .build();
        tx.as_advanced_builder().build()
    };
    let cycles = ctx.verify_tx(&tx, MAX_CYCLES).unwrap();
    println!("Cycles: {}", cycles);
    // Test bad signature
    let witness = {
        let mut witness_data = vec![0u8; 0];
        check_size_and_write(&mut witness_data, &signature.c, 256).unwrap();
        witness_data[0] ^= 1; // Do some modification
        for item in signature.r_and_pubkey.iter() {
            check_size_and_write(&mut witness_data, &item.r, 256).unwrap();
        }
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
