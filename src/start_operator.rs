#![allow(missing_docs)]
use alloy_network::{Ethereum, EthereumSigner};
use alloy_provider::RootProvider;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types::{BlockNumberOrTag, Filter};
use alloy_sol_types::{sol, SolEvent};
use alloy_transport_http::Client;
use chrono::Utc;
use dotenv::dotenv;
use once_cell::sync::Lazy;
use rand::RngCore;
use reqwest::Url;
// use SimpleSidetreeManager::Anchor;
use alloy_primitives::{Address, FixedBytes, U256};
use alloy_provider::fillers::{
    ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, SignerFiller,
};
use alloy_signer::Signer;
use alloy_signer_wallet::LocalWallet;
use anyhow::Result;
use eigen_client_elcontracts::{
    reader::ELChainReader,
    writer::{ELChainWriter, Operator},
};
use std::sync::Arc;
use std::{env, str::FromStr};
use tokio::sync::Mutex;
use tokio::task;
use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_SIGNER, DEFAULT_TARGET};
use ECDSAStakeRegistry::SignatureWithSaltAndExpiry;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    SimpleSidetreeManager,
    "json_abi/SimpleSidetreeAnchorAVS.json"
);

use eigen_utils::binding::ECDSAStakeRegistry;

static KEY: Lazy<String> =
    Lazy::new(|| env::var("PRIVATE_KEY").expect("failed to retrieve private key"));

pub static RPC_URL: Lazy<String> =
    Lazy::new(|| env::var("RPC_URL").expect("failed to get rpc url from env"));

pub static SIDETREE_DID_CONTRACT_ADDRESS: Lazy<String> = Lazy::new(|| {
    env::var("CONTRACT_ADDRESS").expect("failed to get sidetree did contract address from env")
});

static DELEGATION_MANAGER_CONTRACT_ADDRESS: Lazy<String> = Lazy::new(|| {
    env::var("DELEGATION_MANAGER_ADDRESS")
        .expect("failed to get delegation manager contract address from env")
});

static STAKE_REGISTRY_CONTRACT_ADDRESS: Lazy<String> = Lazy::new(|| {
    env::var("STAKE_REGISTRY_ADDRESS")
        .expect("failed to get stake registry contract address from env")
});

static AVS_DIRECTORY_CONTRACT_ADDRESS: Lazy<String> = Lazy::new(|| {
    env::var("AVS_DIRECTORY_ADDRESS")
        .expect("failed to get delegation manager contract address from env")
});
async fn sign_and_response_to_anchor(
    transation_reference: U256,
    anchor_hash: FixedBytes<32>,
) -> Result<()> {
    let provider = get_provider_with_wallet(KEY.clone());

    let wallet = LocalWallet::from_str(&KEY.clone()).expect("failed to generate wallet ");

    let signature = wallet.sign_hash(&anchor_hash).await?;

    println!(
        "Signing and responding to anchoring transaction : {:?}",
        anchor_hash
    );
    let side_tree_did_contract_address =
        Address::from_str(&SIDETREE_DID_CONTRACT_ADDRESS).expect("wrong sidetree contract address");
    let side_tree_did_contract = SimpleSidetreeManager::new(side_tree_did_contract_address, &provider);

    side_tree_did_contract
        .verifyAnchor(
            transation_reference,
            anchor_hash,
            signature.as_bytes().into(),
        )
        .gas_price(20000000000)
        .gas(300000)
        .send()
        .await?
        .get_receipt()
        .await?;
    println!("Anchor Verified by operator");
    Ok(())
}

async fn sign_and_verify_did_operation(did_suffix: FixedBytes<32>) -> Result<()> {
    let provider = get_provider_with_wallet(KEY.clone());

    let wallet = LocalWallet::from_str(&KEY.clone()).expect("failed to generate wallet ");

    let signature = wallet.sign_hash(&did_suffix).await?;

    println!("Signing and responding to did operation : {:?}", did_suffix);
    let sidetree_did_contract_address = Address::from_str(&SIDETREE_DID_CONTRACT_ADDRESS)
        .expect("wrong sidetree did contract address");
    let sidetree_did_contract = SimpleSidetreeManager::new(sidetree_did_contract_address, &provider);

    sidetree_did_contract
        .verifyDIDOperation(did_suffix, signature.as_bytes().into())
        .gas_price(20000000000)
        .gas(300000)
        .send()
        .await?
        .get_receipt()
        .await?;
    println!("Did Operation Verified by operator");
    Ok(())
}
/// Monitor new did operations
async fn monitor_new_did_operations(plugin: Arc<Mutex<VadeEvan>>) -> Result<()> {
    let provider = get_provider_with_wallet(KEY.clone());

    let sidetree_did_contract_address = Address::from_str(&SIDETREE_DID_CONTRACT_ADDRESS)
        .expect("wrong sidetree_did contract address");
    println!(
        "sidetree_did contrat address:{:?}",
        sidetree_did_contract_address
    );
    let sidetree_did_contract = SimpleSidetreeManager::new(sidetree_did_contract_address, &provider);
    println!("sidetree_did contract :{:?}", sidetree_did_contract);
    // let word: &str = "EigenWorld";

    // // If you want to send this tx to holesky , please uncomment the gas price and gas limit
    // let _new_task_tx = hello_world_contract
    //     .anchorHash(word.to_owned())
    //     .gas_price(20000000000)
    //     .gas(300000)
    //     .send()
    //     .await?
    //     .get_receipt()
    //     .await?;

    let mut latest_processed_block = provider.get_block_number().await?;

    loop {
        println!("Monitoring for new did operations..");
        let current_block = provider.get_block_number().await?;
        let filter = Filter::new()
            .address(sidetree_did_contract_address)
            .from_block(BlockNumberOrTag::Number(latest_processed_block));
        let logs = provider.get_logs(&filter).await?;
        for log in logs {
            match log.topic0() {
                // Some(&SimpleSidetreeManager::Anchor::SIGNATURE_HASH) => {
                //     let SimpleSidetreeManager::Anchor {
                //         anchorFileHash,
                //         transactionNumber,
                //         numberOfOperations,
                //     } = log
                //         .log_decode()
                //         .expect("Failed to decode log new sidetree anchor")
                //         .inner
                //         .data;
                //     println!(
                //         "New anchorHash and transaction number :{:?} {:?}",
                //         anchorFileHash, transactionNumber
                //     );

                //     let _ = sign_and_response_to_task(transactionNumber, anchorFileHash).await;
                // }
                Some(&SimpleSidetreeManager::NewDIDOperation::SIGNATURE_HASH) => {
                    let SimpleSidetreeManager::NewDIDOperation { didSuffix } = log
                        .log_decode()
                        .expect("Failed to decode log new sidetree anchor")
                        .inner
                        .data;

                    // resolve did
                    // Lock the plugin and clone or extract what you need
                    let did = {
                        let prefix: [u8; 2] = [0x12, 0x20];
                        let mut combined: [u8; 34] = [0; 34];
                        combined[..2].copy_from_slice(&prefix);
                        combined[2..].copy_from_slice(&didSuffix.0);

                        let did = base64::encode_config(combined, base64::URL_SAFE_NO_PAD);
                        did
                    }; // Lock is dropped here

                    let did = format!("did:elem:eigen:{}", did);
                    println!("resolving {}", did);
                    // Retry the did_resolve call up to 3 times with a 20-second delay between attempts
                    let mut attempts = 0;
                    let result = loop {
                        attempts += 1;
                        let mut vade_evan = plugin.lock().await;
                        match vade_evan.did_resolve(&did).await {
                            Ok(res) => {
                                if res.contains("Not Found") && attempts < 5 {
                                    eprintln!(
                                        "did not found, attempt {} of 5. Retrying in 60 seconds...",
                                        attempts
                                    );
                                    tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                                } else {
                                    break Ok(res);
                                }
                            } // If the call succeeds, break the loop
                            Err(e) if attempts < 5 => {
                                eprintln!(
                                            "did_resolve failed, attempt {} of 5. Retrying in 60 seconds...",
                                            attempts
                                        );
                                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                            }
                            Err(e) => break Err(e), // If all attempts fail, return the last error
                        }
                    };

                    // Handle the result of the retry loop
                    match result {
                        Ok(res) => {
                            println!("{}", res);
                            // Verify operation by signing it
                            let _ = sign_and_verify_did_operation(didSuffix).await;
                        }
                        Err(e) => {
                            eprintln!("did_resolve failed after 5 attempts: {:?}", e);
                        }
                    }
                }
                _ => {}
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        latest_processed_block = current_block + 1;
    }
}

async fn register_operator() -> Result<()> {
    let wallet = LocalWallet::from_str(&KEY).expect("failed to generate wallet ");

    let provider = get_provider_with_wallet(KEY.clone());
    let sidetree_did_contract_address = Address::from_str(&SIDETREE_DID_CONTRACT_ADDRESS)
        .expect("wrong sidetree_did contract address");
    let delegation_manager_contract_address =
        Address::from_str(&DELEGATION_MANAGER_CONTRACT_ADDRESS)
            .expect("wrong delegation manager contract address");
    let stake_registry_contract_address = Address::from_str(&STAKE_REGISTRY_CONTRACT_ADDRESS)
        .expect("wrong stake registry contract address");
    let avs_directory_contract_address = Address::from_str(&AVS_DIRECTORY_CONTRACT_ADDRESS)
        .expect("wrong delegation manager contract address");

    let default_slasher = Address::ZERO; // We don't need slasher for our example.
    let default_strategy = Address::ZERO; // We don't need strategy for our example.
    let elcontracts_reader_instance = ELChainReader::new(
        default_slasher,
        delegation_manager_contract_address,
        avs_directory_contract_address,
        RPC_URL.clone(),
    );
    let elcontracts_writer_instance = ELChainWriter::new(
        delegation_manager_contract_address,
        default_strategy,
        elcontracts_reader_instance.clone(),
        RPC_URL.clone(),
        KEY.clone(),
    );

    let operator = Operator::new(
        wallet.address(),
        wallet.address(),
        Address::ZERO,
        0u32,
        None,
    );
    #[allow(unused_doc_comments)]
    ///In case you are running holesky. Comment the below register_as_operator call after the first
    /// call . Since we can register only once per operator.
    let _tx_hash = elcontracts_writer_instance
        .register_as_operator(operator)
        .await;
    println!("Operator registered on EL successfully");
    let mut salt = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let salt = FixedBytes::from_slice(&salt);
    let now = Utc::now().timestamp();
    let expiry: U256 = U256::from(now + 3600);
    let digest_hash = elcontracts_reader_instance
        .calculate_operator_avs_registration_digest_hash(
            wallet.address(),
            sidetree_did_contract_address,
            salt,
            expiry,
        )
        .await
        .expect("not able to calculate operator ");

    let signature = wallet.sign_hash(&digest_hash).await?;

    let operator_signature = SignatureWithSaltAndExpiry {
        signature: signature.as_bytes().into(),
        salt,
        expiry: expiry,
    };

    let contract_ecdsa_stake_registry =
        ECDSAStakeRegistry::new(stake_registry_contract_address, provider.clone());
    println!("initialize new ecdsa ");

    // If you wish to run on holesky, please deploy the stake registry contract(it's not deployed right now)
    // and uncomment the gas and gas_price
    let registeroperator_details = contract_ecdsa_stake_registry
        .registerOperatorWithSignature(wallet.clone().address(), operator_signature);
    let _tx = registeroperator_details
        .gas(800000)
        .gas_price(50000000000)
        .send()
        .await?
        .get_receipt()
        .await?;
    println!(
        "Operator registered on AVS successfully :{:?}",
        wallet.address()
    );

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
pub async fn main() -> Result<()> {
    dotenv().ok();

    let vade = VadeEvan::new(VadeEvanConfig {
        target: DEFAULT_TARGET,
        signer: DEFAULT_SIGNER,
    })?;

    if let Err(e) = register_operator().await {
        eprintln!("Failed to register operator: {:?}", e);
        return Err(e);
    }

    let plugin: Arc<Mutex<VadeEvan>> = Arc::new(Mutex::new(vade));
    let local = task::LocalSet::new();
    local.spawn_local(async move {
        if let Err(e) = monitor_new_did_operations(plugin).await {
            eprintln!("Failed to monitor new did operations: {:?}", e);
        }
    });
    local.await;
    // // Keep the process running indefinitely
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
    }
    // return Ok(());
}

pub fn get_provider_with_wallet(
    key: String,
) -> FillProvider<
    JoinFill<
        JoinFill<
            JoinFill<JoinFill<alloy_provider::Identity, GasFiller>, NonceFiller>,
            ChainIdFiller,
        >,
        SignerFiller<EthereumSigner>,
    >,
    RootProvider<alloy_transport_http::Http<Client>>,
    alloy_transport_http::Http<Client>,
    Ethereum,
> {
    let wallet = LocalWallet::from_str(&key.to_string()).expect("failed to generate wallet ");
    let url = Url::parse(&RPC_URL.clone()).expect("Wrong rpc url");
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .signer(EthereumSigner::from(wallet.clone()))
        .on_http(url);

    return provider;
}
