use anyhow::{Result, bail};
use libra_management::{
   error::Error
};
use libra_wallet::{Mnemonic, WalletLibrary, key_factory::{ChildNumber, ExtendedPrivKey}};
use libra_genesis_tool::{verify::compute_genesis};
use libra_temppath::TempPath;
use libra_types::{
    access_path::AccessPath,
    account_address::AccountAddress,
    account_config::{
        coin1_tmp_tag, from_currency_code_string,
        treasury_compliance_account_address, BalanceResource, COIN1_NAME,
        AccountResource
    },
    validator_config::ValidatorConfigResource,
    account_state::AccountState,
    account_state_blob::AccountStateBlob,
    contract_event::ContractEvent,
    on_chain_config,
    on_chain_config::{config_address, ConfigurationResource, OnChainConfig, ValidatorSet},
    transaction::{
        ChangeSet, Transaction, WriteSetPayload
    },
    write_set::{WriteOp, WriteSetMut},
};
use executor::{
    db_bootstrapper::{generate_waypoint, maybe_bootstrap, get_balance},
};
use storage_interface::DbReaderWriter;

use libra_vm::LibraVM;
use libradb::{LibraDB};
use std::{convert::TryFrom, fs::File, io::Write, io::Read};
use move_core_types::move_resource::MoveResource;
use ol_keys::{scheme::KeyScheme, wallet::get_account_from_mnem};

pub fn verify_genesis_from_blob(account_state_blobs: &Vec<AccountStateBlob>, _db_rw: DbReaderWriter) -> Result<(), anyhow::Error> {
    println!(">> Verifying the blob against account balances");
    let home = dirs::home_dir().unwrap();
    let genesis_path = home.join(".0L/genesis_from_snapshot.blob");

    let db_dir_tmp = TempPath::new();
    let (_db, db_rw) = DbReaderWriter::wrap(LibraDB::new_for_test(&db_dir_tmp));

    let mut file = File::open(genesis_path)
        .map_err(|e| Error::UnexpectedError(format!("Unable to open genesis file: {}", e)))?;
    let mut buffer = vec![];
    file.read_to_end(&mut buffer)
        .map_err(|e| Error::UnexpectedError(format!("Unable to read genesis: {}", e)))?;
    let genesis_txn = lcs::from_bytes(&buffer)
        .map_err(|e| Error::UnexpectedError(format!("Unable to parse genesis: {}", e)))?;

    let waypoint = generate_waypoint::<LibraVM>(&db_rw, &genesis_txn).unwrap();
    
    println!(">> Waypoint: {}", waypoint.clone());
    assert!(maybe_bootstrap::<LibraVM>(&db_rw, &genesis_txn, waypoint).unwrap());

    let mut index = 0;
    for blob in account_state_blobs {
        match get_account_details(blob) {
            Ok(details) => {
                if get_balance(&details.0, &db_rw) != details.1.coin() {
                    bail!("Balance not matching for blob index: {}", index);
                };
            },
            Err(e) => {
                println!(">>> Warning on verify: get_account_details at index {}: {}", index, e)
            }
        }
        index += 1;
    };
    Ok(())
}

fn get_configuration(db: &DbReaderWriter) -> ConfigurationResource {
    let config_blob = db
        .reader
        .get_latest_account_state(config_address())
        .unwrap()
        .unwrap();
    let config_state = AccountState::try_from(&config_blob).unwrap();
    config_state.get_configuration_resource().unwrap().unwrap()
}

pub fn write_genesis_blob(genesis_txn: Transaction) -> Result<(), anyhow::Error> {
    let home = dirs::home_dir().unwrap();
    let ol_path = home.join(".0L/genesis_from_snapshot.blob");

    let mut file = File::create(ol_path.clone()).map_err(|e| {
        Error::UnexpectedError(format!("Unable to create genesis file: {}", e.to_string()))
    })?;
    let bytes = lcs::to_bytes(&genesis_txn).map_err(|e| {
        Error::UnexpectedError(format!("Unable to serialize genesis: {}", e.to_string()))
    })?;
    file.write_all(&bytes).map_err(|e| {
        Error::UnexpectedError(format!("Unable to write genesis file: {}", e.to_string()))
    })?;
    println!("\n\n========================================================================================");
    println!("genesis written to: {}", ol_path.to_str().unwrap());
    println!("========================================================================================\n\n");
    Ok(())
}

pub fn add_account_states_to_write_set(write_set_mut: &mut WriteSetMut, account_state_blobs: &Vec<AccountStateBlob>) -> Result<(), anyhow::Error> {
    let mut index = 0;

    let mnemonic_string = std::string::String::from("talent sunset lizard pill fame nuclear spy noodle basket okay critic grow sleep legend hurry pitch blanket clerk impose rough degree sock insane purse");
    let account_details = get_account_from_mnem(mnemonic_string);
    let authentication_key = account_details.0.to_vec();
    for blob in account_state_blobs {
        let account_state = AccountState::try_from(blob)
                                .map_err(|e| Error::UnexpectedError(format!("Failed to parse blob: {}", e)))?;
        let address_option = account_state.get_account_address()?;
        match address_option {
            Some(address) => {
                for (k, v) in account_state.iter() {
                    if k.clone()==AccountResource::resource_path() {
                        let account_resource_option = account_state.get_account_resource()?;
                        match account_resource_option {
                            Some(mut account_resource) => {
                                let account_resource_new = account_resource.clone_with_authentication_key(
                                    authentication_key.clone(), account_details.1
                                );
                                write_set_mut.push((
                                    AccessPath::new(address, k.clone()),
                                    WriteOp::Value(lcs::to_bytes(&account_resource_new).unwrap()),
                                ));
                            }, None => {
                                println!("Account resource not found for index: {}", index);
                            }
                        }
                    // } else if k.clone()==ValidatorConfigResource::resource_path() {
                    //     let validator_config_resource_option = account_state.get_validator_config_resource()?;
                    //     match validator_config_resource_option {
                    //         Some(vcr) => {
                    //             let s = String::from_utf8(vcr.human_name).unwrap();
                    //             println!("human name: {}", s);
                    //             match vcr.delegated_account {
                    //                 Some(addr) => {
                    //                     println!("delegated account address: {}", addr);
                    //                 }, None => {
                    //                     println!("no delegated account");
                    //                 }
                    //             }
                    //             match vcr.validator_config {
                    //                 Some(vc) => {
                    //                     println!("consensus_public_key: {}", vc.consensus_public_key);
                    //                 }, None => {
                    //                     println!("No validator config");
                    //                 }
                    //             }
                    //         }, None => {

                    //         }
                    //     }
                    // } 
                    } else {
                        write_set_mut.push((
                            AccessPath::new(address, k.clone()),
                            WriteOp::Value(v.clone()),
                        ));
                    }
                }
            }, None => {
                println!("No address for error: {}", index);
            }
        }
        index += 1;
    }
    println!("Total accounts read: {}", index);
    Ok(())
}

pub fn generate_genesis_from_snapshot(account_state_blobs: &Vec<AccountStateBlob>, db: &DbReaderWriter) -> Result<Transaction, anyhow::Error> {
    let configuration = get_configuration(&db);
    let mut write_set_mut = WriteSetMut::new(vec![
        (
            ValidatorSet::CONFIG_ID.access_path(),
            WriteOp::Value(lcs::to_bytes(&ValidatorSet::new(vec![])).unwrap()),
        ),
        (
            AccessPath::new(config_address(), ConfigurationResource::resource_path()),
            WriteOp::Value(lcs::to_bytes(&configuration.bump_epoch_for_test()).unwrap()),
        )]
    );

    add_account_states_to_write_set(&mut write_set_mut, account_state_blobs);

    Ok(Transaction::GenesisTransaction(WriteSetPayload::Direct(ChangeSet::new(
        write_set_mut
        .freeze()?,
        vec![ContractEvent::new(
            on_chain_config::new_epoch_event_key(),
            0,
            coin1_tmp_tag(),
            vec![],
        )],
    ))))
}

pub fn get_account_details(blob: &AccountStateBlob) -> Result<(AccountAddress, BalanceResource), anyhow::Error> {
    let account_state = AccountState::try_from(blob)
                                .map_err(|e| Error::UnexpectedError(format!("Failed to parse blob: {}", e)))?;
    let address_option = account_state.get_account_address()?;
    match address_option {
        Some(address) => {
            let balance_resource_map = account_state
            .get_balance_resources(&[from_currency_code_string(COIN1_NAME)?])?; 

            let balance_resource_option = balance_resource_map
                                    .get(&from_currency_code_string(COIN1_NAME)?);
            match balance_resource_option {
                Some(balance_resource) => {
                    Ok((address, BalanceResource::new(balance_resource.coin())))
                }, 
                None => {
                    bail!("Balance resource not found");
                }
            }
        }, 
        None => {
            bail!("Account address not found");
        }
    }
}