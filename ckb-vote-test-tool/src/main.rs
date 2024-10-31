use std::{fs::OpenOptions, io::Write, str::FromStr};

use anyhow::{anyhow, Context};
use ckb_sdk::{
    constants::ONE_CKB,
    transaction::{
        builder::{CkbTransactionBuilder, SimpleTransactionBuilder},
        handler::HandlerContexts,
        input::InputIterator,
        TransactionBuilderConfiguration,
    },
    tx_builder::omni_lock::OmniLockTransferBuilder,
    unlock::{IdentityFlag, OmniLockConfig, OmniLockUnlocker},
    Address, NetworkInfo,
};
use ckb_types::{
    packed::CellOutput,
    prelude::{Entity, Pack},
    H256,
};
use ckb_types::{prelude::Builder, H160};
use clap::Parser;
use jose_jwk::{Rsa, RsaOptional, RsaPrivate};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rsa::{
    traits::{PrivateKeyParts, PublicKeyParts},
    RsaPrivateKey,
};
#[derive(Parser)]
struct Args {
    #[arg(short = 'c', default_value_t = 0)]
    /// How many users for testing
    test_user_count: usize,
    #[arg(short = 'p')]
    /// Private key of administrator, on ETH
    administrator_private_key: Option<String>,
    #[arg(short = 'a')]
    /// ETH Address of the administrator
    address: String,
}

struct CellPublisher {
    sender: Address,
}

impl CellPublisher {
    fn publish_bytes_cell(&self, data: &[u8], receiver: &Address) -> anyhow::Result<H256> {
        let network_info = NetworkInfo::testnet();
        let configuration =
            TransactionBuilderConfiguration::new_with_network(network_info.clone())?;
        let iter =
            InputIterator::new_with_address(&[self.sender.clone()], configuration.network_info());

        let mut builder = SimpleTransactionBuilder::new(configuration, iter);
        let output = CellOutput::new_builder()
            .capacity(((61 + data.len() + 1) as u64 * ONE_CKB).pack())
            .lock(receiver.into())
            .build();
        builder.add_output_and_data(output.clone(), data.to_vec().pack());
        builder.set_change_lock((&self.sender).into());

        let mut contexts = HandlerContexts::default();
        // self.sender.payload().
        let address_args = &self.sender.payload().args();

        let omni_cfg = OmniLockConfig::new(
            address_args[0]
                .try_into()
                .map_err(|e| anyhow!("Failed to parse omnilock args: {}", e))?,
            H160::from_slice(&address_args[1..21])
                .with_context(|| anyhow!("Failed to parse omnilock args"))?,
        );
        // ckb_sdk::transaction::handler::sighash::Secp256k1Blake160SighashAllScriptHandler::new_with_network(network)
        // let context =
        //    OmnilockScriptContext::new(omni_cfg.clone(), network_info.url.clone());
        // todo!();
        // builder.build(contexts)
        todo!();
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    flexi_logger::Logger::try_with_env_or_str("info")
        .with_context(|| anyhow!("Failed to initialize logger"))?
        .start()
        .with_context(|| anyhow!("Failed to start logger"))?;

    let admin_addr =
        Address::from_str(&args.address).map_err(|e| anyhow!("Failed to parse address: {}", e))?;
    log::info!("{:#?}", admin_addr);
    let network_info = NetworkInfo::testnet();

    let keys = (0..args.test_user_count)
        .into_par_iter()
        .map(|idx| {
            let mut rng = rand::thread_rng();
            let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();

            log::info!("private key {} generation done", idx);
            priv_key
        })
        .collect::<Vec<_>>();

    Ok(())
}
