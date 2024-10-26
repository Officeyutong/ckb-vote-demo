use std::io::Write;

use crate::Loader;
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::bytes::Bytes;
use ckb_testtool::ckb_types::core::TransactionBuilder;
use ckb_testtool::ckb_types::packed::{CellDep, CellInput, CellOutput, ScriptOpt, WitnessArgs};
use ckb_testtool::ckb_types::prelude::{Entity, Pack};
use ckb_testtool::{bytes::BufMut, ckb_types::packed::OutPoint, context::Context};
use rand::seq::SliceRandom;
use rand::Rng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rsa::{traits::PublicKeyParts, RsaPrivateKey};

const KEY_COUNT: usize = 2000;
const CHUNK_SIZE: usize = 500;
const CANDIDATE_COUNT: usize = 10;
#[derive(Debug)]
struct Candidate {
    id: [u8; 4],
    description: String,
}
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
        .map(|(_, chunk)| {
            let mut buf = Vec::<u8>::new();
            buf.put_u16_le(chunk.len() as _);
            for item in chunk {
                let num_buf = item.n().to_bytes_le();
                assert_eq!(num_buf.len(), 256);
                buf.write_all(&num_buf).unwrap();
            }
            for item in chunk {
                let mut num_buf = item.e().to_bytes_le();
                num_buf.resize(4, 0);
                buf.write_all(&num_buf).unwrap();
            }
            // println!("Key cell {} = {:?}", idx, buf);
            ctx.deploy_cell(buf.into())
        })
        .collect::<Vec<_>>();
    let key_index_cell = {
        let mut buf = Vec::<u8>::new();
        buf.put_u16_le(key_cells.len() as _);
        for key_hash in key_cells.iter() {
            buf.write_all(&key_hash.tx_hash().raw_data()).unwrap();
        }
        for key_hash in key_cells.iter() {
            buf.write_all(&key_hash.index().raw_data()).unwrap();
        }
        ctx.deploy_cell(buf.into())
    };
    let mut rng = rand::thread_rng();
    let candidates = (0..CANDIDATE_COUNT)
        .map(|idx| Candidate {
            description: format!("{}-th candidate", idx),
            id: rng.gen(),
        })
        .collect::<Vec<_>>();
    let candidate_cell = {
        let mut buf = Vec::<u8>::new();
        buf.put_u16_le(candidates.len() as _);
        for item in candidates.iter() {
            buf.write_all(&item.id).unwrap();
            let mut str_bytes = item.description.as_bytes().to_vec();
            while str_bytes.len() > 99 {
                str_bytes.pop();
            }
            while str_bytes.len() < 100 {
                str_bytes.push(0);
            }
            buf.write_all(&str_bytes).unwrap()
        }
        // println!("Candidate cell data {:?}", buf);
        ctx.deploy_cell(buf.into())
    };
    PreparedState {
        candidate_cell,
        candidates,
        keys,
        public_key_cells: key_cells,
        public_key_index_cell: key_index_cell,
    }
}

use ckb_testtool::ckb_types::prelude::Builder;
use rsa_ring_sign_linkable::{check_size_and_write, create_signature};

const MAX_CYCLES: u64 = 35_0000_0000;

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
        &state.keys[CHUNK_SIZE * signer_block..CHUNK_SIZE * (signer_block + 1)]
            .iter()
            .map(|s| s.to_public_key())
            .collect::<Vec<_>>(),
        &state.keys[signer_index],
        signer_index,
        &selected_candidate.id,
    )
    .unwrap();
    // println!("signature={:?}", signature);
    // println!("selectted candidate {:?}", selected_candidate);
    let always_success_script_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let always_success_script = ctx
        .build_script(&always_success_script_op, Default::default())
        .unwrap();

    let cell_deps: Vec<CellDep> = vec![
        CellDep::new_builder()
            .out_point(state.candidate_cell)
            .build(),
        CellDep::new_builder()
            .out_point(state.public_key_cells[signer / CHUNK_SIZE].clone())
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
        // println!("Vote cell data {:?}", cell_data);
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
        // println!("witness data={:?}", witness_data);
        WitnessArgs::new_builder()
            .output_type(Some(Bytes::from(witness_data)).pack())
            .lock(Option::<Bytes>::None.pack())
            .input_type(Option::<Bytes>::None.pack())
            .build()
    };
    let tx = {
        let tx = TransactionBuilder::default()
            .cell_deps(cell_deps.clone())
            .inputs(tx_input.clone())
            .outputs(tx_output.clone())
            .outputs_data(tx_output_data.pack())
            .witness(witness.as_bytes().pack())
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
        WitnessArgs::new_builder()
            .output_type(Some(Bytes::from(witness_data)).pack())
            .lock(Option::<Bytes>::None.pack())
            .input_type(Option::<Bytes>::None.pack())
            .build()
    };
    let tx = {
        let tx = TransactionBuilder::default()
            .cell_deps(cell_deps)
            .inputs(tx_input)
            .outputs(tx_output)
            .outputs_data(tx_output_data.pack())
            .witness(witness.as_bytes().pack())
            .build();
        tx.as_advanced_builder().build()
    };
    ctx.verify_tx(&tx, MAX_CYCLES).unwrap_err();
}
