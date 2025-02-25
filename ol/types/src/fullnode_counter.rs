//! fullnode counter for system address

use libra_types::{
    access_path::AccessPath,
    account_config::constants:: CORE_CODE_ADDRESS,
};
use anyhow::Result;
use move_core_types::{
    language_storage::{ResourceKey, StructTag},
    move_resource::MoveResource,
};
use serde::{Deserialize, Serialize};
use move_core_types::account_address::AccountAddress;

/// Struct that represents a CurrencyInfo resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullnodeCounterResource {
    ///
    pub proofs_submitted_in_epoch: u64,
    ///
    pub proofs_paid_in_epoch: u64,
    ///
    pub subsidy_in_epoch: u64,
    ///
    pub cumulative_proofs_submitted: u64,
    ///
    pub cumulative_proofs_paid: u64,
    ///
    pub cumulative_subsidy: u64,
}

impl MoveResource for FullnodeCounterResource {
    const MODULE_NAME: &'static str = "FullnodeState";
    const STRUCT_NAME: &'static str = "FullnodeCounter";
}

impl FullnodeCounterResource {
    ///
    pub fn struct_tag() -> StructTag {
        StructTag {
            address: CORE_CODE_ADDRESS,
            module: FullnodeCounterResource::module_identifier(),
            name: FullnodeCounterResource::struct_identifier(),
            type_params: vec![],
        }
    }
    ///
    pub fn access_path(account: AccountAddress) -> AccessPath {
        let resource_key = ResourceKey::new(
            account,
            FullnodeCounterResource::struct_tag(),
        );
        AccessPath::resource_access_path(&resource_key)
    }
    ///
    pub fn resource_path() -> Vec<u8> {
        AccessPath::resource_access_vec(&FullnodeCounterResource::struct_tag())
    }

    /// 
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
        lcs::from_bytes(bytes).map_err(Into::into)
    }
}
