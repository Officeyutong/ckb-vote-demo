use std::{
    collections::HashMap, io::Write, str::FromStr, sync::atomic::AtomicUsize, time::Duration,
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
    Address, CkbRpcClient, ScriptId,
};
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, DepType, ScriptHashType},
    packed::{Byte32, CellDep, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::{Entity, Pack},
    H256,
};
use ckb_types::{core::TransactionView, prelude::Builder};
use clap::Parser;
use fallible_iterator::FallibleIterator;
use rand::{thread_rng, Rng};
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelIterator,
};
use rsa::{RsaPrivateKey, RsaPublicKey};
use signature_tools::{
    check_size_and_write, create_signature, encode_candidate_cell, encode_public_key_cell,
    encode_public_key_index_cell, Candidate, PublicKeyIndexEntry,
};

#[derive(Parser)]
struct Args {
    #[arg(short = 'c', default_value_t = 100)]
    /// How many users for testing
    test_user_count: usize,
    #[arg(short = 'c', default_value_t = 20)]
    /// How many users in a ring?
    chunk_size: usize,
    #[arg(short = 'p')]
    /// secp256k1 private key of administrator
    administrator_private_key: String,
    #[arg(short = 'a')]
    /// Account address of administrator
    administrator_address: String,
    #[arg(default_value_t=String::from("http://127.0.0.1:9000"))]
    /// URL of rpc server
    rpc_url: String,
    #[arg(long,default_value_t=String::from("0x2d9a206deac24746ec531f1505c0daaf846cf92a976380df0b350f59fa3a6561"))]
    /// Code hash of the type script
    typescript_code_hash: String,
    #[arg(long,default_value_t=String::from("0x46e5f3aab4e2ec522fef6d943cd75b242e224e33759c9400a91186fcc76b9757"))]
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
        witness: Option<&[u8]>,
        output_type_script: Option<(H256, ScriptHashType)>,
        extra_cell_dep: Vec<CellDep>,
    ) -> anyhow::Result<(H256, u32)> {
        let tx = self
            .build_transaction(
                receiver.clone(),
                data,
                witness,
                output_type_script,
                extra_cell_dep,
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
        log::debug!("Transaction build");
        let tx_hash = self
            .client
            .send_transaction(
                json_tx.inner,
                Some(ckb_jsonrpc_types::OutputsValidator::Passthrough),
            )
            .with_context(|| anyhow!("Failed to send transaction"))?;
        let mut retry_count = 20;
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
                Status::Committed | Status::Pending | Status::Proposed => {
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
        witness: Option<&[u8]>,
        output_type_script: Option<(H256, ScriptHashType)>,
        extra_cell_dep: Vec<CellDep>,
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
        let mut balancer =
            CapacityBalancer::new_simple((&self.sender_address).into(), placeholder_witness, 1000);
        balancer.set_max_fee(Some(100_000_000));
        let cell_dep_resolver = {
            let genesis_block = self.client.get_block_by_number(0.into())?.unwrap();
            DefaultCellDepResolver::from_genesis(&BlockView::from(genesis_block))?
        };
        let header_dep_resolver = DefaultHeaderDepResolver::new(&self.rpc_url);
        let capacity = (61 + 100 + 1 + data.len()) as u64 * ONE_CKB;

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
                witness
                    .map(|x| Bytes::copy_from_slice(x))
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

fn main() -> anyhow::Result<()> {
    flexi_logger::Logger::try_with_env_or_str("debug")
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
    let admin_addr = Address::from_str(&args.administrator_address)
        .map_err(|e| anyhow!("Failed to parse administrator address: {}", e))?;
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
    let public_key_hashes =
        fallible_iterator::convert(keys.chunks(args.chunk_size).enumerate().map(
            |(idx, chunk)| -> anyhow::Result<(H256, u32, Vec<RsaPublicKey>)> {
                log::info!("Publishing chunk {}", idx + 1);

                let data = encode_public_key_cell(chunk);
                let (txhash, index) = publisher
                    .publish_bytes_cell(&data, &admin_addr, None, None, vec![])
                    .with_context(|| anyhow!("Failed to publish chunk {}", idx + 1))?;

                log::info!("Published chunk {}", idx + 1);
                Ok((
                    txhash,
                    index,
                    chunk.into_iter().map(|x| x.to_public_key()).collect(),
                ))
            },
        ))
        .collect::<Vec<_>>()?;
    let index_cell = {
        let mut result = Vec::<PublicKeyIndexEntry>::default();
        for (tx, index, _) in public_key_hashes.iter() {
            result.push(PublicKeyIndexEntry {
                hash: tx.as_bytes().to_vec(),
                index: *index,
            });
        }
        let encoded = encode_public_key_index_cell(&result);
        publisher
            .publish_bytes_cell(&encoded, &admin_addr, None, None, vec![])
            .with_context(|| anyhow!("Failed to publish public key index cell"))?
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
                .publish_bytes_cell(&encoded, &admin_addr, None, None, vec![])
                .with_context(|| anyhow!("Failed to publish candidate cell"))?,
        )
    };

    struct VoteData {
        candidate_id: [u8; 4],
        vote_cell_data: Vec<u8>,
        public_key_cell: (H256, u32),
    }

    let done_count = AtomicUsize::new(0);
    let voted_target = keys
        .par_iter()
        .enumerate()
        .map(|(idx, private_key)| {
            let mut rng = thread_rng();
            let candidate_target = &candidates[rng.gen_range(0..candidates.len())];
            let belonging_block = idx / args.chunk_size;
            let block_index = idx % args.chunk_size;
            let ring = &public_key_hashes[belonging_block];
            let signature =
                create_signature(&ring.2, private_key, block_index, &candidate_target.id).unwrap();
            let mut buf = vec![];
            buf.push(0); // Don't use witness
            buf.write_all(&candidate_target.id).unwrap();
            check_size_and_write(&mut buf, &signature.c, 256).unwrap();
            for item in signature.r_and_pubkey.iter() {
                check_size_and_write(&mut buf, &item.r, 256).unwrap();
            }
            check_size_and_write(&mut buf, &signature.i, 256).unwrap();
            log::info!(
                "{} sign done",
                done_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1
            );
            VoteData {
                candidate_id: candidate_target.id.clone(),
                public_key_cell: (ring.0.clone(), ring.1.clone()),
                vote_cell_data: buf,
            }
        })
        .collect::<Vec<_>>();
    let mut vote_result = HashMap::<[u8; 4], usize>::default();

    for (idx, item) in voted_target.into_iter().enumerate() {
        log::info!("Sending signature {}", idx + 1);
        *vote_result.entry(item.candidate_id).or_insert(0) += 1;
        publisher
            .publish_bytes_cell(
                &item.vote_cell_data,
                &admin_addr,
                None,
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
                            Byte32::from_slice(item.public_key_cell.0.as_bytes()).unwrap(),
                            item.public_key_cell.1,
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
            )
            .with_context(|| anyhow!("Failed to send signature for {}", idx + 1))?;
        log::info!("Sended signature {}", idx + 1);
    }
    let vote_result_string_as_key = vote_result
        .into_iter()
        .map(|(key, val)| (format!("{:08X}", u32::from_le_bytes(key)), val))
        .collect::<HashMap<_, _>>();
    println!("Public key index cell: {}:{}", index_cell.0, index_cell.1);
    println!("Candidate cell: {}:{}", candidate_cell.0, candidate_cell.1);
    println!(
        "{}",
        serde_json::to_string(&vote_result_string_as_key)
            .with_context(|| anyhow!("Failed to serialize vote result to string"))?
    );

    Ok(())
}
