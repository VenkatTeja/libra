// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{account_address::AccountAddress, account_config::constants::ACCOUNT_MODULE_NAME};
use move_core_types::move_resource::MoveResource;
#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct WithdrawCapabilityResource {
    account_address: AccountAddress,
}

impl WithdrawCapabilityResource {
    pub fn new(account_address: AccountAddress) -> Self {
        WithdrawCapabilityResource {
            account_address: account_address
        }
    }
}

impl MoveResource for WithdrawCapabilityResource {
    const MODULE_NAME: &'static str = ACCOUNT_MODULE_NAME;
    const STRUCT_NAME: &'static str = "WithdrawCapability";
}
