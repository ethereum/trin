use std::str::FromStr;

use anyhow::anyhow;
use ethportal_api::{types::network::Network, Enr};
use lazy_static::lazy_static;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bootnode {
    pub enr: Enr,
    pub alias: String,
}

impl From<Enr> for Bootnode {
    fn from(enr: Enr) -> Self {
        Iterator::chain(DEFAULT_BOOTNODES.iter(), ANGELFOOD_BOOTNODES.iter())
            .find(|bootnode| bootnode.enr == enr)
            .cloned()
            .unwrap_or_else(|| Self {
                enr,
                alias: "custom".to_string(),
            })
    }
}

lazy_static! {
    pub static ref DEFAULT_BOOTNODES: Vec<Bootnode> = vec![
        // https://github.com/ethereum/portal-network-specs/blob/master/bootnodes.md
        // Trin bootstrap nodes
        Bootnode{
            enr: Enr::from_str("enr:-Jm4QBcjAoXU79kbUGNGfeDwW9OjiaknvaiKwZa81U91xC9ODSpQvzsEbNd_lww3CCHsqxgGHR8O18frKStu4A3F7sGEaBUIa2OJdCBhZmE1N2MxgmlkgnY0gmlwhKEjVaWCcHaCAAGJc2VjcDI1NmsxoQLSC_nhF1iRwsCw0n3J4jRjqoaRxtKgsEe5a-Dz7y0JloN1ZHCCIyg").expect("Parsing static bootnode enr to work"),
            alias: "trin-ams3-1".to_string()
        },
        Bootnode{
            enr: Enr::from_str("enr:-Jm4QAtSz2CaRwEceSHfSeI2g15cumv9oPqlKAVCHoi34-X6NZuQHYEieuZz-acnmww3yAPTDd4BZeFyv248apKSsKaEaBUIYWOJdCBhZmE1N2MxgmlkgnY0gmlwhJO2oc6CcHaCAAGJc2VjcDI1NmsxoQLMSGVlxXL62N3sPtaV-n_TbZFCEM5AR7RDyIwOadbQK4N1ZHCCIyg").expect("Parsing static bootnode enr to work"),
            alias: "trin-nyc1-1".to_string()
        },
        Bootnode{
            enr: Enr::from_str("enr:-Jm4QNepJO38VOGGsuj0fBjeLHU2fsNBvYewhpCRDHyCFjgFI7EKdBptbi_jwCsGDQhrgh4X5TikBlqYcSUJyExbSMqEaBUIeGOJdCBhZmE1N2MxgmlkgnY0gmlwhJ31OTWCcHaCAAGJc2VjcDI1NmsxoQPC0eRkjRajDiETr_DRa5N5VJRm-ttCWDoO1QAMMCg5pIN1ZHCCIyg").expect("Parsing static bootnode enr to work"),
            alias: "trin-sgp1-1".to_string()
        },

        // Fluffy bootstrap nodes
        Bootnode{
            enr: Enr::from_str("enr:-I64QBKOAFoNByj98RU-UbHPk7zKl8EoIyqiI1hxgMpJQ4Snf--RWm_qBU9eSRfBv0hhZOdDwgMmYq74kNYMePaRr1uCG5xjZoJpZIJ2NIJpcITCISsggnB2ggABiXNlY3AyNTZrMaECedPKSKkarI7L5lEH2Br2lBU8X7BCz7KP-thSg6pcSNuDdWRwgiOM").expect("Parsing static bootnode enr to work"),
            alias: "fluffy-1".to_string()
        },
        Bootnode{
            enr: Enr::from_str("enr:-I64QIgwjKS4gH06AhSDUP7SY3C7KfKXmauGNs6QSYXztefacltV9neVVRIfGFI-ICHoeRSVX-NSoktGXETxcPC9ABSCGlJjZoJpZIJ2NIJpcITCISshgnB2ggABiXNlY3AyNTZrMaEDNpAR0-bP1IeILDYjnJUA7yyuJD6aELnIHt5rW7i7lBmDdWRwgiOM").expect("Parsing static bootnode enr to work"),
            alias: "fluffy-2".to_string()
        },
        Bootnode{
            enr: Enr::from_str("enr:-I64QPjnD7qcuc5Odzh4889v2X-zrjs1KFHqqJQhIaTxNNh6HOx5xokIX6uUYbbAzxt9tkg_MzYt8ZoeIZxiVwRRNTWCHcxjZoJpZIJ2NIJpcITCIStAgnB2ggABiXNlY3AyNTZrMaEDjt4BbmggMkCrHGojSwvR3y21cxXSHqxEhZThnBLilh-DdWRwgiOM").expect("Parsing static bootnode enr to work"),
            alias: "fluffy-3".to_string()
        },
        Bootnode{
            enr: Enr::from_str("enr:-I64QGx6qrUIrcIryYUq43_wx6fol4JDOLTPIEwHH3jOHcXaLvy3rDx8lLJEJLNSYMW5B1A6H_SxWmxaknKmcZoZJ7eCG_pjZoJpZIJ2NIJpcITCIStBgnB2ggABiXNlY3AyNTZrMaEDE6ugncdx5i90PbIrWr3Dxz22CshImyjyr8lcjpTRfCeDdWRwgiOM").expect("Parsing static bootnode enr to work"),
            alias: "fluffy-4".to_string()
        },

        // Ultralight bootstrap nodes
        Bootnode{
            enr: Enr::from_str("enr:-JG4QCE8znFiA118byLyXtBPcecRVK7AMyWsv70pzDo8587ZVKJ5JB2QBhIiHw53T06rMgK4d2qg2-CKZCFxneJP8EAGY4d1IDAuMC4xgmlkgnY0gmlwhKRc9_OCcHYAiXNlY3AyNTZrMaECcTyRg2C2f0E1N9dHjkRaevjRLOk4Rl6TVC5wFz8oisuDdWRwghOK").expect("Parsing static bootnode enr to work"),
            alias: "ultralight-1".to_string()
        },
        Bootnode{
            enr: Enr::from_str("enr:-JG4QBnJydF5xbJPDd_MnvWPW8h0rI3wDcHosw833Mq6EiLcRqFY3b72XgLiwgZGRwncliK9haAVAB0KDHQT4U92_a0GY4d1IDAuMC4xgmlkgnY0gmlwhKRc9_OCcHYAiXNlY3AyNTZrMaEChz7eQkNA-urnk7UlKsBo34bHFPy4sEtvELydBoCRXfmDdWRwghOJ").expect("Parsing static bootnode enr to work"),
            alias: "ultralight-2".to_string()
        },
        Bootnode{
            enr: Enr::from_str("enr:-JG4QDi6-UzxEMbFXSs7EXNs8pMdsNQ_OwX6AUWq_KZcGUeESHAW8mwoozpkR29lSkceK6mt39p3Nz3ARN8mLixAGDsGY4d1IDAuMC4xgmlkgnY0gmlwhKRc9_OCcHYAiXNlY3AyNTZrMaEDuw2RPONWnbTHYfKrA2Ag8k4xi7ndR2SYPj_jgG0w1c-DdWRwghOL").expect("Parsing static bootnode enr to work"),
            alias: "ultralight-3".to_string()
        },
    ];

    // AngelFood bootstrap nodes
    pub static ref ANGELFOOD_BOOTNODES: Vec<Bootnode> = vec![
        Bootnode{
            enr: Enr::from_str("enr:-LC4QMnoW2m4YYQRPjZhJ5hEpcA6a3V7iQs3slQ1TepzKBIVWQtjpcHsPINc0TcheMCbx6I2n5aax8M3AtUObt74ySUCY6p0IDVhYzI2NzViNGRmMjNhNmEwOWVjNDFkZTRlYTQ2ODQxNjk2ZTQ1YzSCaWSCdjSCaXCEQONKaYlzZWNwMjU2azGhAvZgYbpA9G8NQ6X4agu-R7Ymtu0hcX6xBQ--UEel_b6Pg3VkcIIjKA").expect("Parsing static bootnode enr to work"),
            alias: "angelfood-trin-1".to_string()
        },
    ];
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum Bootnodes {
    #[default]
    Default,
    // use explicit None here instead of Option<Bootnodes>, since default value is
    // DEFAULT_BOOTNODES
    None,
    Custom(Vec<Bootnode>),
}

impl Bootnodes {
    pub fn to_enrs(&self, network: Network) -> Vec<Enr> {
        match (self, network) {
            (Bootnodes::Default, Network::Mainnet) => {
                DEFAULT_BOOTNODES.iter().map(|bn| bn.enr.clone()).collect()
            }
            (Bootnodes::Default, Network::Angelfood) => ANGELFOOD_BOOTNODES
                .iter()
                .map(|bn| bn.enr.clone())
                .collect(),
            (Bootnodes::None, _) => vec![],
            (Bootnodes::Custom(bootnodes), _) => {
                bootnodes.iter().map(|bn| bn.enr.clone()).collect()
            }
        }
    }
}

impl FromStr for Bootnodes {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "default" => Ok(Bootnodes::Default),
            "none" => Ok(Bootnodes::None),
            _ => {
                let bootnodes: Result<Vec<Enr>, _> = s.split(',').map(Enr::from_str).collect();
                match bootnodes {
                    Ok(val) => {
                        let bootnodes = val.into_iter().map(|enr| enr.into()).collect();
                        Ok(Bootnodes::Custom(bootnodes))
                    }
                    Err(_) => Err(anyhow!("Invalid bootnode argument")),
                }
            }
        }
    }
}
