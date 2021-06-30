// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0


use move_core_types::{
    language_storage::{StructTag, TypeTag},
};
use libra_management::{error::Error};
use libra_types::{
    access_path::AccessPath,
    account_address::AccountAddress,
    account_config::{
        constants::{from_currency_code_string, CORE_CODE_ADDRESS},
        BalanceResource, COIN1_NAME,
    },
    account_state::AccountState,
    account_state_blob::AccountStateBlob,
    contract_event::ContractEvent,
    on_chain_config,
    on_chain_config::{config_address, ConfigurationResource, OnChainConfig, ValidatorSet},
    proof::SparseMerkleRangeProof,
    transaction::{
        authenticator::AuthenticationKey, ChangeSet, Transaction, Version, WriteSetPayload,
        PRE_GENESIS_VERSION,
    },
    trusted_state::TrustedState,
    validator_signer::ValidatorSigner,
    waypoint::Waypoint,
    write_set::{WriteOp, WriteSetMut},
};
use std::{
    convert::TryFrom,
};
use anyhow::{bail};
use libra_temppath::TempPath;
use storage_interface::{DbReader, DbReaderWriter};
use libradb::{GetRestoreHandler, LibraDB};
use executor_test_helpers::{
    bootstrap_genesis, gen_ledger_info_with_sigs, get_test_signed_transaction,
};
use libra_vm::LibraVM;
use std::{fs::File, io::Write, path::{PathBuf, Path}};

#[test]
fn test() {

}

fn write_genesis_blob(genesis_txn: Transaction) {
    let test_run_path = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root_source_path = test_run_path.parent().unwrap().parent().unwrap();
    let genesis_path = root_source_path.join("genesis_test.blob");

    // let tmp_dir = TempPath::new();
    // let (db, db_rw) = DbReaderWriter::wrap(LibraDB::new_for_test(&tmp_dir));
    // let waypoint = bootstrap_genesis::<LibraVM>(&db_rw, &genesis_txn).unwrap();

    let mut file = File::create(genesis_path).map_err(|e| {
        Error::UnexpectedError(format!("Unable to create genesis file: {}", e.to_string()))
    }).unwrap();
    let bytes = lcs::to_bytes(&genesis_txn).map_err(|e| {
        Error::UnexpectedError(format!("Unable to serialize genesis: {}", e.to_string()))
    }).unwrap();
    file.write_all(&bytes).map_err(|e| {
        Error::UnexpectedError(format!("Unable to write genesis file: {}", e.to_string()))
    }).unwrap();
}

#[test]
pub fn read_genesis_blob_file() {
    
}

pub fn read_genesis() {
    let test_run_path = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root_source_path = test_run_path.parent().unwrap().parent().unwrap();
    let genesis_path = root_source_path.join("genesis_test.blob");

    let mut file = File::open(genesis_path).unwrap();
    let mut buffer = vec![];
    file.read_to_end(&mut buffer)
        .map_err(|e| Error::UnexpectedError(format!("Unable to read genesis: {}", e))).unwrap();
    let genesis = lcs::from_bytes(&buffer)
        .map_err(|e| Error::UnexpectedError(format!("Unable to parse genesis: {}", e))).unwrap();
}

pub fn gas_tag() -> TypeTag {
    TypeTag::Struct(StructTag {
        address: CORE_CODE_ADDRESS,
        module: from_currency_code_string(COIN1_NAME).unwrap(),
        name: from_currency_code_string(COIN1_NAME).unwrap(),
        type_params: vec![],
    })
}

fn generate_genesis_from_account_states(account_state_blob_vec: Vec<AccountStateBlob>) -> Result<Transaction, Error> {
    let mut write_set_mut = WriteSetMut::new(vec![]);
    for account_state_blob in account_state_blob_vec {
        let account_state = AccountState::try_from(&account_state_blob)
                                .map_err(|e| Error::UnexpectedError(format!("Failed to parse blob: {}", e)))
                                .unwrap();
        let account_address = account_state.get_account_address().expect("Could not get address from state");
        if let Some(address) = account_address {
            write_set_mut.push(
                (
                    AccessPath::new(address, BalanceResource::access_path_for(gas_tag())),
                    WriteOp::Value(lcs::to_bytes(&account_state
                        .get_balance_resources(&[from_currency_code_string(COIN1_NAME).unwrap()])
                        .unwrap()
                        .get(&from_currency_code_string(COIN1_NAME).unwrap())
                        .unwrap()).unwrap()),
                )
            );
        }
    }
    let genesis_txn = Transaction::GenesisTransaction(WriteSetPayload::Direct(ChangeSet::new(
        write_set_mut
        .freeze()
        .unwrap(),
        vec![ContractEvent::new(
            on_chain_config::new_epoch_event_key(),
            0,
            gas_tag(),
            vec![],
        )],
    )));

    Ok(genesis_txn)
}



