//! recovery

use std::{convert::TryFrom, fs, io::Write, path::PathBuf};

use anyhow::{bail, Error};
use libra_types::{account_address::AccountAddress, account_config::BalanceResource, account_state::AccountState, account_state_blob::AccountStateBlob, on_chain_config::ConfigurationResource, transaction::authenticator::AuthenticationKey, validator_config::{ValidatorConfigResource, ValidatorOperatorConfigResource}};
use move_core_types::move_resource::MoveResource;
use ol_types::{community_wallet::CommunityWalletsResource, miner_state::MinerStateResource};
use serde::{Deserialize, Serialize};
use vm_genesis::{OperRecover, ValRecover};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
/// Account role
pub enum AccountRole {
    /// System Accounts
    System,
    /// Vals
    Validator,
    /// Opers
    Operator,
    /// Users
    EndUser,
}

/// Wallet type
#[derive(Debug, Serialize, Deserialize)]
pub enum WalletType {
    ///
    None,
    ///
    Slow,
    ///
    Community,
}

/// The basic structs needed to recover account state in a new network.
/// This is necessary for catastrophic recoveries, when the source code changes too much. Like what is going to happen between v4 and v5, where the source code of v5 will not be able to work with objects from v4. We need an intermediary file.
#[derive(Debug, Serialize, Deserialize)]
pub struct LegacyRecovery {
    ///
    pub account: AccountAddress,
    ///
    pub auth_key: Option<AuthenticationKey>,
    ///
    pub role: AccountRole,
    ///
    pub balance: Option<BalanceResource>,
    ///
    pub val_cfg: Option<ValidatorConfigResource>,
    ///
    pub miner_state: Option<MinerStateResource>,
    // wallet_type: Option<WalletType>,
    // TODO: Fullnode State? // rust struct does not exist
    // TODO: Autopay? // rust struct does not exist
}

/// RecoveryFile
#[derive(Debug, Clone)]
pub struct RecoverConsensusAccounts {
    ///
    pub vals: Vec<ValRecover>,
    ///
    pub opers: Vec<OperRecover>,

}

impl Default for RecoverConsensusAccounts {
  fn default() -> Self {
      RecoverConsensusAccounts {
        vals: vec!(),
        opers: vec!(),
      }
  }
}

/// make the writeset for the genesis case. Starts with an unmodified account state and make into a writeset.
pub fn accounts_into_recovery(
    account_state_blobs: &Vec<AccountStateBlob>,
) -> Result<Vec<LegacyRecovery>, Error> {
    let mut to_recover = vec![];
    for blob in account_state_blobs {
        let account_state = AccountState::try_from(blob)?;
        match parse_recovery(&account_state) {
            Ok(gr) => to_recover.push(gr),
            Err(e) => println!(
                "WARN: could not recover account, continuing. Message: {:?}",
                e
            ),
        }
    }
    println!("Total accounts read: {}", &account_state_blobs.len());
    println!("Total accounts recovered: {}", &to_recover.len());

    Ok(to_recover)
}

/// create a recovery struct from an account state.
pub fn parse_recovery(state: &AccountState) -> Result<LegacyRecovery, Error> {
    let mut l = LegacyRecovery {
        account: AccountAddress::ZERO,
        auth_key: None,
        role: AccountRole::EndUser,
        balance: None,
        val_cfg: None,
        miner_state: None,
    };
    let test = state.get_account_address()?;
    dbg!(&test);

    if let Some(address) = state.get_account_address()? {
        l.account = address;
        // iterate over all the account's resources\
        for (k, v) in state.iter() {
            // extract the validator config resource
            if k == &BalanceResource::resource_path() {
                l.balance = lcs::from_bytes(v).ok();
            } else if k == &ValidatorConfigResource::resource_path() {
                l.role = AccountRole::Validator;
                l.val_cfg = lcs::from_bytes(v).ok();
            } else if k == &ValidatorOperatorConfigResource::resource_path() {
                l.role = AccountRole::Operator;
            } else if k == &MinerStateResource::resource_path() {
                l.miner_state = lcs::from_bytes(v).ok();
            }

            if address == AccountAddress::ZERO {
                l.role = AccountRole::System;
                // structs only on 0x0 address
                if k == &ConfigurationResource::resource_path() {
                    l.miner_state = lcs::from_bytes(v).ok();
                } else if k == &CommunityWalletsResource::resource_path() {
                    l.miner_state = lcs::from_bytes(v).ok();
                }
            }
        }
        println!("processed account: {:?}", address);
        return Ok(l)
    } else {
      bail!("ERROR: No address for AccountState: {:?}", state.get_account_address());
    }
}

/// Make recovery file in format needed
pub fn recover_consensus_accounts(
    recover: &Vec<LegacyRecovery>,
) -> Result<RecoverConsensusAccounts, Error> {
    use AccountRole::*;
    let mut set = RecoverConsensusAccounts::default();

    for i in recover {
        let account: AccountAddress = i.account;
        // get deduplicated validators info
        match i.role {
            Validator => {
                let val_cfg = i
                    .val_cfg
                    .as_ref()
                    .unwrap()
                    .validator_config
                    .as_ref()
                    .unwrap()
                    .clone();

                let operator_delegated_account =
                    i.val_cfg.as_ref().unwrap().delegated_account.unwrap();
                // prevent duplicate accounts
                if set
                    .vals
                    .iter()
                    .find(|&a| a.val_account == account)
                    .is_none()
                {
                    set.vals.push(ValRecover {
                        val_account: account,
                        operator_delegated_account,
                        val_auth_key: i.auth_key.unwrap(),
                    });
                }

                // find the operator's authkey
                let oper_data = recover
                    .iter()
                    .find(|&a| a.account == operator_delegated_account && a.role == Operator);

                match oper_data {
                    Some(o) => {
                        // get the operator info, preventing duplicates
                        if set
                            .opers
                            .iter()
                            .find(|&a| a.operator_account == operator_delegated_account)
                            .is_none()
                        {
                            set.opers.push(OperRecover {
                                operator_account: o.account,
                                operator_auth_key: o.auth_key.unwrap(),
                                validator_to_represent: account,
                                // TODO: Check conversion of public key
                                operator_consensus_pubkey: val_cfg
                                    .consensus_public_key
                                    .to_bytes()
                                    .to_vec(),
                                validator_network_addresses: val_cfg.validator_network_addresses,
                                fullnode_network_addresses: val_cfg.fullnode_network_addresses,
                            });
                        }
                    }
                    None => {}
                }
            }
            _ => {}
        }
    }
    Ok(set)
}


/// Save genesis recovery file
pub fn save_recovery_file(data: &Vec<LegacyRecovery>, path: &PathBuf) -> Result<(), Error> {
    let j = serde_json::to_string(data)?;
    let mut file = fs::File::create(path).expect("Could not genesis_recovery create file");
    file.write_all(j.as_bytes())
        .expect("Could not write account recovery");
    Ok(())
}
