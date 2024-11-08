use std::{
    collections::{HashMap, HashSet},
    io::Write,
    str::FromStr,
    sync::atomic::AtomicUsize,
    time::Duration,
};

use anyhow::{anyhow, bail, Context};
use ckb_jsonrpc_types::Status;
use ckb_sdk::{
    constants::{ONE_CKB, SIGHASH_TYPE_HASH},
    core::TransactionBuilder,
    traits::{
        CellCollector, DefaultCellCollector, DefaultCellDepResolver, DefaultHeaderDepResolver,
        DefaultTransactionDependencyProvider, SecpCkbRawKeySigner,
    },
    tx_builder::{CapacityBalancer, TxBuilder},
    unlock::{ScriptUnlocker, SecpSighashUnlocker},
    Address, AddressPayload, CkbRpcClient, ScriptId,
};
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, DepType, ScriptHashType},
    packed::{Byte32, CellDep, CellOutput, OutPoint, Script, WitnessArgs, WitnessArgsBuilder},
    prelude::{Entity, Pack},
    H256,
};
use ckb_types::{core::TransactionView, prelude::Builder};
use clap::Parser;
use rand::{thread_rng, Rng};
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelBridge,
    ParallelIterator,
};
use rsa::RsaPrivateKey;
use secp256k1::Secp256k1;
use signature_tools::{
    candidate::{encode_candidate_cell, Candidate},
    check_size_and_write,
    rsa_tools::{
        create_signature,
        merkle_tree::{
            create_merkle_tree_with_proof_rsa, create_merkle_tree_with_root_hash_rsa,
            MerkleProofResult,
        },
    },
};

#[derive(Parser)]
struct Args {
    #[arg(short = 'u', default_value_t = 100)]
    /// How many users for testing
    test_user_count: usize,
    #[arg(short = 'c', default_value_t = 15)]
    /// How many users in a ring?
    chunk_size: usize,
    #[arg(short = 'p')]
    /// secp256k1 private key of administrator
    administrator_private_key: String,
    #[arg(default_value_t=String::from("http://127.0.0.1:8114"))]
    /// URL of rpc server
    rpc_url: String,
    #[arg(long,default_value_t=String::from("0xe3067794f05a9f1fa716bd28dd703f99cdf174492ade183331cc7882aca85919"))]
    /// Code hash of the type script
    typescript_code_hash: String,
    #[arg(long,default_value_t=String::from("0x2f2e4802e64c29593da5d073a77424bc5ecdcad17f3b27fc17e05c0a82c89e06"))]
    /// Outpoint of the typescript, index defaults to 0
    typescript_out_point_tx: String,
}

struct SimpleTransferBuilderWithWitness {
    pub outputs: Vec<(CellOutput, Bytes, Bytes)>,
    pub extra_cell_dep: Vec<CellDep>,
}

impl TxBuilder for SimpleTransferBuilderWithWitness {
    fn build_base(
        &self,
        _cell_collector: &mut dyn CellCollector,
        _cell_dep_resolver: &dyn ckb_sdk::traits::CellDepResolver,
        _header_dep_resolver: &dyn ckb_sdk::traits::HeaderDepResolver,
        _tx_dep_provider: &dyn ckb_sdk::traits::TransactionDependencyProvider,
    ) -> Result<TransactionView, ckb_sdk::tx_builder::TxBuilderError> {
        let mut cell_deps = Vec::new();
        cell_deps.extend(self.extra_cell_dep.iter().map(|x| x.clone()));
        let mut outputs = Vec::new();
        let mut outputs_data = Vec::new();
        let mut witnesses = Vec::new();
        for (output, output_data, witness) in &self.outputs {
            outputs.push(output.clone());
            outputs_data.push(output_data.pack());
            witnesses.push(witness.pack());
        }
        Ok(TransactionBuilder::default()
            .set_cell_deps(cell_deps.into_iter().collect())
            .set_outputs(outputs)
            .set_outputs_data(outputs_data)
            .set_witnesses(witnesses)
            .clone()
            .build())
    }
}

struct CellPublisher {
    sender_address: Address,
    rpc_url: String,
    client: CkbRpcClient,
    tx_dep_provider: DefaultTransactionDependencyProvider,
    cell_collector: DefaultCellCollector,
    signer: SecpCkbRawKeySigner,
}

impl CellPublisher {
    fn new(
        sender_address: &Address,
        sender_private_key: secp256k1::SecretKey,
        rpc_url: &str,
    ) -> Self {
        Self {
            client: CkbRpcClient::new(rpc_url),
            rpc_url: rpc_url.to_string(),
            sender_address: sender_address.clone(),
            tx_dep_provider: DefaultTransactionDependencyProvider::new(rpc_url, 10),
            cell_collector: DefaultCellCollector::new(rpc_url),
            signer: SecpCkbRawKeySigner::new_with_secret_keys(vec![sender_private_key]),
        }
    }
    fn publish_bytes_cell(
        &mut self,
        data: &[u8],
        receiver: &Address,
        output_type_witness: Option<&[u8]>,
        output_type_script: Option<(H256, ScriptHashType)>,
        extra_cell_dep: Vec<CellDep>,
        custom_capacity: Option<u64>,
    ) -> anyhow::Result<(H256, u32)> {
        let tx = self
            .build_transaction(
                receiver.clone(),
                data,
                output_type_witness,
                output_type_script,
                extra_cell_dep,
                custom_capacity,
            )
            .with_context(|| anyhow!("Failed to call build_transaction"))?;
        let tip_num = self
            .client
            .get_tip_block_number()
            .with_context(|| anyhow!("Failed to get tip block number"))?
            .value();
        self.cell_collector
            .apply_tx(tx.data(), tip_num)
            .with_context(|| anyhow!("Failed to apply_tx for cell_collector"))?;
        self.tx_dep_provider
            .apply_tx(tx.data(), tip_num)
            .with_context(|| anyhow!("Failed to apply_tx for tx_dep_provider"))?;

        let json_tx = ckb_jsonrpc_types::TransactionView::from(tx);
        log::trace!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());
        log::debug!("Transaction build, hash = {}", json_tx.hash);
        let tx_hash = self
            .client
            .send_transaction(
                json_tx.inner,
                Some(ckb_jsonrpc_types::OutputsValidator::Passthrough),
            )
            .with_context(|| anyhow!("Failed to send transaction"))?;
        let mut retry_count = 100;
        loop {
            if retry_count == 0 {
                log::debug!("Failed to wait the transaction to be received");
                break;
            }
            let status = self
                .client
                .get_transaction_status(tx_hash.clone())
                .with_context(|| anyhow!("Failed to query transaction status"))?;
            log::debug!("status: {:?}", status.tx_status.status);
            match status.tx_status.status {
                Status::Unknown => {
                    retry_count -= 1;
                }
                Status::Committed | Status::Proposed | Status::Pending => {
                    break;
                }
                Status::Rejected => {
                    bail!("Transacton rejected: {:?}", status.tx_status);
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Ok((tx_hash, 0))
    }

    fn build_transaction(
        &mut self,
        receiver: Address,
        data: &[u8],
        output_type_witness: Option<&[u8]>,
        output_type_script: Option<(H256, ScriptHashType)>,
        extra_cell_dep: Vec<CellDep>,
        custom_capacity: Option<u64>,
    ) -> anyhow::Result<TransactionView> {
        let sighash_unlocker = SecpSighashUnlocker::from(Box::new(self.signer.clone()) as Box<_>);
        let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
        let mut unlockers = HashMap::default();
        unlockers.insert(
            sighash_script_id,
            Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
        );

        let placeholder_witness = WitnessArgs::new_builder()
            .lock(Some(Bytes::from(vec![0u8; 65])).pack())
            .build();
        let balancer =
            CapacityBalancer::new_simple((&self.sender_address).into(), placeholder_witness, 1000);
        // balancer.set_max_fee(Some(1_0000_0000));
        let cell_dep_resolver = {
            let genesis_block = self.client.get_block_by_number(0.into())?.unwrap();
            DefaultCellDepResolver::from_genesis(&BlockView::from(genesis_block))?
        };
        let header_dep_resolver = DefaultHeaderDepResolver::new(&self.rpc_url);
        let capacity = custom_capacity.unwrap_or((61 + 100 + data.len()) as u64 * ONE_CKB);
        log::debug!("capacity={}", capacity);
        let output = CellOutput::new_builder()
            .lock(Script::from(&receiver))
            .capacity(capacity.pack())
            .type_(
                output_type_script
                    .map(|(hash, hash_type)| {
                        Script::new_builder()
                            .code_hash(Byte32::from_slice(hash.as_bytes()).unwrap())
                            .hash_type(hash_type.into())
                            .build()
                            .into()
                    })
                    .pack(),
            )
            .build();

        let builder = SimpleTransferBuilderWithWitness {
            outputs: vec![(
                output,
                Bytes::copy_from_slice(data),
                output_type_witness
                    .map(|x| {
                        WitnessArgsBuilder::default()
                            .output_type(Some(Bytes::copy_from_slice(x)).pack())
                            .build()
                            .as_bytes()
                    })
                    .unwrap_or_else(|| Default::default()),
            )],
            extra_cell_dep,
        };

        let (tx, _) = builder.build_unlocked(
            &mut self.cell_collector,
            &cell_dep_resolver,
            &header_dep_resolver,
            &mut self.tx_dep_provider,
            &balancer,
            &unlockers,
        )?;

        Ok(tx)
    }
}
#[derive(Clone, Debug)]
struct VoteData {
    candidate_id: [u8; 4],
    vote_cell_data: Vec<u8>,
    witness_data: Vec<u8>,
}
fn main() -> anyhow::Result<()> {
    flexi_logger::Logger::try_with_env_or_str("info")
        .with_context(|| anyhow!("Failed to initialize logger"))?
        .start()
        .with_context(|| anyhow!("Failed to start logger"))?;
    let args = Args::parse();

    let admin_private_key = secp256k1::SecretKey::from_slice(
        H256::from_str(&args.administrator_private_key[2..])
            .with_context(|| anyhow!("Failed to parse administrator private key"))?
            .as_bytes(),
    )?;
    log::debug!("admin_private_key={:#?}", admin_private_key);
    let admin_addr = {
        let ctx = Secp256k1::new();
        Address::new(
            ckb_sdk::NetworkType::Dev,
            AddressPayload::from_pubkey(&admin_private_key.public_key(&ctx)),
            true,
        )
    };
    log::debug!("admin_address={:#?}", admin_addr);
    let ts_code_hash = H256::from_str(&args.typescript_code_hash[2..])
        .with_context(|| anyhow!("Failed to parse typescript code hash"))?;
    let ts_outpoint = H256::from_str(&args.typescript_out_point_tx[2..])
        .with_context(|| anyhow!("Failed to parse typescript outpoint"))?;
    let keys = {
        let done_count = AtomicUsize::new(0);
        (0..args.test_user_count)
            .into_par_iter()
            .map(|_| {
                let mut rng = rand::thread_rng();
                let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();

                log::info!(
                    "private key {} generation done",
                    done_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1
                );
                priv_key
            })
            .collect::<Vec<_>>()
    };
    let mut publisher = CellPublisher::new(&admin_addr, admin_private_key, &args.rpc_url);
    let merkle_root_cell = {
        let mut data = create_merkle_tree_with_root_hash_rsa(&keys, args.chunk_size)
            .with_context(|| anyhow!("Failed to create merkle tree root"))?;
        data.write_all(&(keys.len() as u32).to_le_bytes()).unwrap();
        data.write_all(
            &(keys.len() as u32)
                .div_ceil(args.chunk_size as _)
                .to_le_bytes(),
        )
        .unwrap();

        publisher
            .publish_bytes_cell(&data, &admin_addr, None, None, vec![], None)
            .with_context(|| anyhow!("Failed to publish merkle root cell"))?
    };

    let (candidates, candidate_cell) = {
        let mut rng = thread_rng();
        let candidates = (0..100)
            .map(|x| Candidate {
                description: format!("Candidate {}", x + 1),
                id: rng.gen(),
            })
            .collect::<Vec<_>>();
        let encoded = encode_candidate_cell(&candidates);
        (
            candidates,
            publisher
                .publish_bytes_cell(&encoded, &admin_addr, None, None, vec![], None)
                .with_context(|| anyhow!("Failed to publish candidate cell"))?,
        )
    };

    let done_count = AtomicUsize::new(0);
    let voted_target = keys
        .par_iter()
        .enumerate()
        .map(|(idx, private_key)| {
            let mut rng = thread_rng();
            let candidate_target = &candidates[rng.gen_range(0..candidates.len())];

            let belonging_block = idx / args.chunk_size;
            let block_index = idx % args.chunk_size;
            let ring_keys = &keys[belonging_block * args.chunk_size
                ..((belonging_block + 1) * args.chunk_size).min(keys.len())];
            let signature =
                create_signature(&ring_keys, private_key, block_index, &candidate_target.id)
                    .unwrap();
            let MerkleProofResult {
                proof,
                leaf_hash: _,
            } = create_merkle_tree_with_proof_rsa(&keys, args.chunk_size, belonging_block)
                .with_context(|| anyhow!("Failed to create merkle proof"))
                .unwrap();

            let vote_cell_data = {
                let mut buf = vec![0u8; 0];
                buf.write_all(&candidate_target.id).unwrap();
                check_size_and_write(&mut buf, &signature.i, 256).unwrap();
                buf
            };
            let witness_data = {
                let mut buf = vec![0u8; 0];
                check_size_and_write(&mut buf, &signature.c, 256).unwrap();
                buf.write_all(&(signature.r_and_pubkey.len() as u32).to_le_bytes())
                    .unwrap();
                for item in signature.r_and_pubkey.iter() {
                    check_size_and_write(&mut buf, &item.r, 256).unwrap();
                }
                for item in signature.r_and_pubkey.iter() {
                    check_size_and_write(&mut buf, &item.n, 256).unwrap();
                }
                for item in signature.r_and_pubkey.iter() {
                    check_size_and_write(&mut buf, &item.e, 4).unwrap();
                }
                buf.write_all(&(belonging_block as u32).to_le_bytes())
                    .unwrap();
                buf.write_all(&(proof.len() as u32).to_le_bytes()).unwrap();
                buf.write_all(&proof).unwrap();
                buf
            };
            log::info!(
                "{} sign done",
                done_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1
            );
            VoteData {
                candidate_id: candidate_target.id.clone(),
                vote_cell_data,
                witness_data,
            }
        })
        .collect::<Vec<_>>();

    let mut expected_vote_result = HashMap::<[u8; 4], usize>::default();
    for entry in voted_target.iter() {
        *expected_vote_result.entry(entry.candidate_id).or_insert(0) += 1;
    }
    let sqrt_n = (keys.len() as f64).sqrt() as usize;
    struct ChunkedVoteTarget {
        vote_targets: Vec<VoteData>,
        address: Address,
        required_ckb: u64,
        publisher: CellPublisher,
    }

    // Part vote entries into sqrt_n groups, each group with a new account
    let chunked_vote_target_with_account = {
        let done_count = AtomicUsize::new(0);
        voted_target
            .chunks(sqrt_n)
            .par_bridge()
            .map(|chunk| {
                let mut rng = rand::thread_rng();
                // Create a new keypair
                let (secret_key, public_key) =
                    secp256k1::Secp256k1::new().generate_keypair(&mut rng);
                let required_ckb = chunk
                    .iter()
                    .map(|x| x.vote_cell_data.len() as u64 + 62 + 200)
                    .sum();
                log::info!(
                    "Account generated: {}",
                    done_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                );
                let address = Address::new(
                    ckb_sdk::NetworkType::Dev,
                    AddressPayload::from_pubkey(&public_key),
                    true,
                );
                ChunkedVoteTarget {
                    address: address.clone(),
                    required_ckb,
                    vote_targets: chunk.to_vec(),
                    publisher: CellPublisher::new(&address, secret_key, &args.rpc_url),
                }
            })
            .collect::<Vec<_>>()
    };
    let mut transfer_txs = HashSet::new();
    // Send some money to each account
    for (
        index,
        ChunkedVoteTarget {
            address,
            required_ckb,
            vote_targets: _,
            publisher: _,
        },
    ) in chunked_vote_target_with_account.iter().enumerate()
    {
        let (tx, _) = publisher
            .publish_bytes_cell(
                &[],
                address,
                None,
                None,
                vec![],
                Some(*required_ckb * ONE_CKB),
            )
            .with_context(|| anyhow!("Failed to send balance to publisher account {}", index))?;
        log::info!(
            "Sended CKB {} to index {}, address {}",
            required_ckb,
            index,
            address
        );
        transfer_txs.insert(tx);
    }
    {
        let client = CkbRpcClient::new(&args.rpc_url);
        log::info!("Waiting for transactions to be confirmed..");
        while !transfer_txs.is_empty() {
            let top = transfer_txs.iter().next().unwrap().clone();
            let result = client
                .get_only_committed_transaction_status(top.clone())
                .with_context(|| anyhow!("Failed to fetch transaction status for {}", top))?;
            match result.tx_status.status {
                Status::Committed => {
                    log::info!(
                        "{} has been commited, remaining {}",
                        top,
                        transfer_txs.len()
                    );
                    transfer_txs.remove(&top);
                }
                s => {
                    log::debug!("{} has not been commited, current status: {:?}", top, s);
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }
    let total_count = AtomicUsize::new(0);
    chunked_vote_target_with_account
        .into_par_iter()
        .enumerate()
        .try_for_each(
            |(
                index,
                ChunkedVoteTarget {
                    vote_targets,
                    address: _,
                    required_ckb: _,
                    mut publisher,
                },
            )|
             -> anyhow::Result<()> {
                let total_len = vote_targets.len();
                for (vote_idx, target) in vote_targets.into_iter().enumerate() {
                    publisher
                        .publish_bytes_cell(
                            &target.vote_cell_data,
                            &admin_addr,
                            Some(&target.witness_data),
                            Some((ts_code_hash.clone(), ScriptHashType::Data1)),
                            vec![
                                CellDep::new_builder()
                                    .out_point(OutPoint::new(
                                        Byte32::from_slice(candidate_cell.0.as_bytes()).unwrap(),
                                        candidate_cell.1,
                                    ))
                                    .build(),
                                CellDep::new_builder()
                                    .out_point(OutPoint::new(
                                        Byte32::from_slice(merkle_root_cell.0.as_bytes()).unwrap(),
                                        merkle_root_cell.1,
                                    ))
                                    .build(),
                                CellDep::new_builder()
                                    .out_point(OutPoint::new(
                                        Byte32::from_slice(ts_outpoint.as_bytes()).unwrap(),
                                        0,
                                    ))
                                    .dep_type(DepType::Code.into())
                                    .build(),
                            ],
                            None,
                        )
                        .with_context(|| anyhow!("Failed to send transaction"))?;
                    log::info!(
                        "Worker {} sended transaction {}/{} (total {}/{})",
                        index,
                        vote_idx,
                        total_len,
                        total_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1,
                        keys.len()
                    );
                }
                Ok(())
            },
        )?;
    let vote_result_string_as_key = expected_vote_result
        .into_iter()
        .map(|(key, val)| (format!("{:08X}", u32::from_le_bytes(key)), val))
        .collect::<HashMap<_, _>>();
    println!(
        "Merkle tree root cell: 0x{}:{}",
        merkle_root_cell.0, merkle_root_cell.1
    );
    println!(
        "Candidate cell: 0x{}:{}",
        candidate_cell.0, candidate_cell.1
    );
    println!(
        "{}",
        serde_json::to_string(&vote_result_string_as_key)
            .with_context(|| anyhow!("Failed to serialize vote result to string"))?
    );

    Ok(())
}
