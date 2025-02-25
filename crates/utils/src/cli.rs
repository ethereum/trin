use core::fmt;
use std::{str::FromStr, sync::Arc};

use alloy::primitives::{B256, U256};
use ethportal_api::types::{
    distance::Distance,
    network::Subnetwork,
    portal_wire::{NetworkSpec, ANGELFOOD, MAINNET},
};

#[derive(Debug, PartialEq, Clone)]
pub enum Web3TransportType {
    HTTP,
    IPC,
}

impl fmt::Display for Web3TransportType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::HTTP => write!(f, "http"),
            Self::IPC => write!(f, "ipc"),
        }
    }
}

impl FromStr for Web3TransportType {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "http" => Ok(Web3TransportType::HTTP),
            "ipc" => Ok(Web3TransportType::IPC),
            _ => Err("Invalid web3-transport arg. Expected either 'http' or 'ipc'"),
        }
    }
}

pub fn check_private_key_length(private_key: &str) -> Result<B256, String> {
    if private_key.len() == 66 {
        return B256::from_str(private_key).map_err(|err| format!("HexError: {err}"));
    }
    Err(format!(
        "Invalid private key length: {}, expected 66 (0x-prefixed 32 byte hexstring)",
        private_key.len()
    ))
}

pub fn network_parser(network_string: &str) -> Result<Arc<NetworkSpec>, String> {
    match network_string {
        "mainnet" => Ok(MAINNET.clone()),
        "angelfood" => Ok(ANGELFOOD.clone()),
        _ => Err(format!(
            "Not a valid network: {network_string}, must be 'angelfood' or 'mainnet'"
        )),
    }
}

pub fn subnetwork_parser(subnetwork_string: &str) -> Result<Arc<Vec<Subnetwork>>, String> {
    let subnetworks = subnetwork_string
        .split(',')
        .map(Subnetwork::from_str)
        .collect::<Result<Vec<Subnetwork>, String>>()?;

    if subnetworks.is_empty() {
        return Err("At least one subnetwork must be enabled".to_owned());
    }

    for subnetwork in &subnetworks {
        if !subnetwork.is_active() {
            return Err("{subnetwork} subnetwork has not yet been activated".to_owned());
        }
    }

    Ok(Arc::new(subnetworks))
}

pub fn max_radius_parser(max_radius_str: &str) -> Result<Distance, String> {
    let max_radius_percentage = match max_radius_str.parse::<U256>() {
        Ok(val) => val,
        Err(err) => {
            return Err(format!(
                "Invalid max radius percentage, expected a number, received: {err}"
            ))
        }
    };

    if max_radius_percentage > U256::from(100) {
        return Err(format!(
            "Invalid max radius percentage, expected 0 to 100, received: {max_radius_percentage}"
        ));
    }

    // If the max radius is 100% return it, as arithmetic multiplication loses precision and will be
    // off by 5.
    if max_radius_percentage == U256::from(100) {
        return Ok(Distance::MAX);
    }

    Ok(Distance::from(
        U256::MAX / U256::from(100) * max_radius_percentage,
    ))
}
