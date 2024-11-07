use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};

use anyhow::{anyhow, bail, Context};
use ckb_jsonrpc_types::JsonBytes;
use ckb_sdk::{
    rpc::{ckb_indexer::Order, ResponseFormatGetter},
    traits::{CellQueryOptions, PrimaryScriptType},
    CkbRpcClient,
};
use ckb_types::{
    core::ScriptHashType,
    packed::Byte,
    prelude::{hex_string, Builder},
};
use ckb_types::{
    packed::{Byte32, Script},
    prelude::Entity,
    H256,
};
use clap::Parser;
use frozenset::{Freeze, FrozenMap};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
#[derive(Parser, Debug)]
struct Args {
    /// Cell containing information of all candidatex, in hex format
    #[arg(short = 'c')]
    candidate_cell_tx: String,
    // Tx hash of public key index cell, in hex format
    #[arg(short = 'm')]
    merkle_tree_root_cell_tx: String,

    /// Script hash for vote cells
    #[arg(long = "tx", short = 't')]
    signature_verify_type_script_hash: String,
    // URL of ckb node
    #[arg(default_value_t=String::from("http://127.0.0.1:9000"))]
    rpc_url: String,
}

fn parse_candidate_cell(buf: &[u8]) -> anyhow::Result<HashMap<[u8; 4], String>> {
    let mut result = HashMap::new();
    let n = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    for i in 0..n {
        let start = 2 + i * 104;
        let c = &buf[start..start + 104];
        let id = [c[0], c[1], c[2], c[3]];
        let mut last_idx = 4 + 100 - 1;
        while last_idx >= 4 && c[last_idx] == 0 {
            last_idx -= 1;
        }
        let desc = String::from_utf8(c[4..last_idx + 1].to_vec())
            .with_context(|| anyhow!("Bad utf8 bytes for candidate index {}", i))?
            .to_string();
        result.insert(id, desc);
    }
    Ok(result)
}

struct VoteValidator {
    // pub_key_cells: FrozenSet<PublicKeyCellEntry>,
    candidate: FrozenMap<[u8; 4], String>,
    merkle_tree_root_cell_tx: (H256, u32),
}

impl VoteValidator {
    pub fn validate_tx(&self, tx: &ckb_jsonrpc_types::Transaction) -> anyhow::Result<()> {
        let cell_dep_2 = tx.cell_deps.get(1).ok_or_else(|| {
            anyhow!("Missing second celldep, which should be merkle tree root cell")
        })?;
        if self.merkle_tree_root_cell_tx.0 != cell_dep_2.out_point.tx_hash
            || self.merkle_tree_root_cell_tx.1 != cell_dep_2.out_point.index.value()
        {
            bail!("Bad public key cell");
        }
        let vote_cell_data = &tx
            .outputs_data
            .get(0)
            .ok_or_else(|| anyhow!("Missing output data 0"))?
            .as_bytes();
        let candidate_id: [u8; 4] = vote_cell_data[0..4].try_into().unwrap();
        if !self.candidate.contains_key(&candidate_id) {
            bail!("Invalid candidate id: {:?}", candidate_id);
        }

        Ok(())
    }
}
#[derive(Debug)]

struct VoteTarget {
    candidate_id: [u8; 4],
    image: Vec<u8>,
}

fn main() -> anyhow::Result<()> {
    flexi_logger::Logger::try_with_env_or_str("info")
        .with_context(|| anyhow!("Failed to initialize logger"))?
        .start()
        .with_context(|| anyhow!("Failed to start logger"))?;
    let args = Args::parse();
    let client = CkbRpcClient::new(&args.rpc_url);
    let merkle_tree_root_hash: [u8; 32] = {
        let tx = client
            .get_transaction(
                H256::from_str(&args.merkle_tree_root_cell_tx[2..])
                    .with_context(|| anyhow!("Failed to parse public key index cell tx"))?,
            )
            .with_context(|| anyhow!("Unable to get public index cell tx"))?
            .ok_or_else(|| anyhow!("Invalid public key index cell tx"))?;
        let data = tx
            .transaction
            .ok_or_else(|| anyhow!("Transaction body not found"))?
            .get_value()?
            .inner
            .outputs_data[0]
            .as_bytes()
            .to_vec();
        data[0..32].try_into().unwrap()
    };
    let candidates = {
        let tx = client
            .get_transaction(
                H256::from_str(&args.candidate_cell_tx[2..])
                    .with_context(|| anyhow!("Failed to parse candidate cell tx"))?,
            )
            .with_context(|| anyhow!("Unable to get public index cell tx"))?
            .ok_or_else(|| anyhow!("Invalid public key index cell tx"))?;
        parse_candidate_cell(
            tx.transaction
                .ok_or_else(|| anyhow!("Transaction body not found"))?
                .get_value()?
                .inner
                .outputs_data[0]
                .as_bytes(),
        )?
    };

    log::debug!("merkle_tree_root_hash= {:?}", merkle_tree_root_hash);
    log::debug!("candidates = {:?}", candidates);
    type VoteCounter = HashMap<[u8; 4], usize>;
    let result = {
        let script_hash_bytes = H256::from_str(&args.signature_verify_type_script_hash[2..])
            .with_context(|| anyhow!("Failed to parse signature verify type script hash"))?;
        let tx_validator = VoteValidator {
            candidate: candidates.clone().freeze(),
            merkle_tree_root_cell_tx: (
                H256::from_str(&args.merkle_tree_root_cell_tx[2..]).unwrap(),
                0,
            ),
        };
        let mut last_cursor: Option<JsonBytes> = None;
        let batch_size = 500;
        let mut used_image = HashSet::<Vec<u8>>::new();

        let mut counter = VoteCounter::new();

        loop {
            log::info!("Start a batch..");
            let current_batch = client
                .get_transactions(
                    CellQueryOptions::new(
                        Script::new_builder()
                            .code_hash(Byte32::from_slice(script_hash_bytes.as_bytes())?)
                            .args(Default::default())
                            .hash_type(Byte::new(ScriptHashType::Data1 as u8))
                            .build(),
                        PrimaryScriptType::Type,
                    )
                    .into(),
                    Order::Asc,
                    batch_size.into(),
                    last_cursor,
                )
                .with_context(|| anyhow!("Failed to get transaction batch"))?;
            log::info!("Got {} records", current_batch.objects.len());

            let initial_verified = current_batch
                .objects
                .into_par_iter()
                .map(|item| -> anyhow::Result<Option<VoteTarget>> {
                    let tx = client
                        .get_transaction(item.tx_hash())
                        .with_context(|| anyhow!("Failed to get transaction"))?
                        .ok_or_else(|| anyhow!("Transaction is empty!"))?
                        .transaction
                        .ok_or_else(|| anyhow!("Transaction is empty!"))?
                        .get_value()?
                        .inner;

                    if let Err(e) = tx_validator
                        .validate_tx(&tx)
                        .with_context(|| anyhow!("Failed to verify tx"))
                    {
                        log::warn!("Bad tx encountered: {:?}", e);
                        return Ok(None);
                    }
                    let vote_cell = tx
                        .outputs_data
                        .get(0)
                        .ok_or_else(|| anyhow!("Missing output data 0"))?
                        .as_bytes();
                    Ok(Some(VoteTarget {
                        candidate_id: [vote_cell[0], vote_cell[1], vote_cell[2], vote_cell[3]],
                        image: vote_cell[4..4 + 256].to_vec(),
                    }))
                })
                .collect::<Vec<_>>();
            if initial_verified.is_empty() {
                break;
            }
            last_cursor = Some(current_batch.last_cursor);
            log::debug!("Initial verified: {:?}", initial_verified);
            for item in initial_verified.into_iter() {
                if let Some(item) = item? {
                    if used_image.contains(&item.image) {
                        log::warn!("Duplicated image: {}", hex_string(&item.image));
                        continue;
                    }
                    used_image.insert(item.image);
                    *counter.entry(item.candidate_id).or_insert(0) += 1;
                }
            }
        }
        counter
    };
    log::debug!("vote result = {:?}", result);
    println!("Counting result:");
    for (key, value) in result.iter() {
        let desc = candidates
            .get(key)
            .ok_or_else(|| anyhow!("Unexpected candidate id: {:?}", key))?;
        println!("{:08}: {} <{:?}>", value, desc, key);
    }

    let vote_result_string_as_key = result
        .into_iter()
        .map(|(key, val)| (format!("{:08X}", u32::from_le_bytes(key)), val))
        .collect::<HashMap<_, _>>();
    println!(
        "{}",
        serde_json::to_string(&vote_result_string_as_key)
            .with_context(|| anyhow!("Failed to serialize vote result to string"))?
    );
    Ok(())
}
