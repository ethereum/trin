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
            enr: Enr::from_str("enr:-Jy4QIs2pCyiKna9YWnAF0zgf7bT0GzlAGoF8MEKFJOExmtofBIqzm71zDvmzRiiLkxaEJcs_Amr7XIhLI74k1rtlXICY5Z0IDAuMS4xLWFscGhhLjEtMTEwZjUwgmlkgnY0gmlwhKEjVaWJc2VjcDI1NmsxoQLSC_nhF1iRwsCw0n3J4jRjqoaRxtKgsEe5a-Dz7y0JloN1ZHCCIyg").expect("Parsing static bootnode enr to work"),
            alias: "trin-ams3-1".to_string()
        },
        Bootnode{
            enr: Enr::from_str("enr:-Jy4QKSLYMpku9F0Ebk84zhIhwTkmn80UnYvE4Z4sOcLukASIcofrGdXVLAUPVHh8oPCfnEOZm1W1gcAxB9kV2FJywkCY5Z0IDAuMS4xLWFscGhhLjEtMTEwZjUwgmlkgnY0gmlwhJO2oc6Jc2VjcDI1NmsxoQLMSGVlxXL62N3sPtaV-n_TbZFCEM5AR7RDyIwOadbQK4N1ZHCCIyg").expect("Parsing static bootnode enr to work"),
            alias: "trin-nyc1-1".to_string()
        },
        Bootnode{
        enr: Enr::from_str("enr:-Jy4QH4_H4cW--ejWDl_W7ngXw2m31MM2GT8_1ZgECnfWxMzZTiZKvHDgkmwUS_l2aqHHU54Q7hcFSPz6VGzkUjOqkcCY5Z0IDAuMS4xLWFscGhhLjEtMTEwZjUwgmlkgnY0gmlwhJ31OTWJc2VjcDI1NmsxoQPC0eRkjRajDiETr_DRa5N5VJRm-ttCWDoO1QAMMCg5pIN1ZHCCIyg").expect("Parsing static bootnode enr to work"),
            alias: "trin-sgp1-1".to_string()
        },

        // Fluffy bootstrap nodes
        Bootnode{
            enr:
        Enr::from_str("enr:-Ia4QLBxlH0Y8hGPQ1IRF5EStZbZvCPHQ2OjaJkuFMz0NRoZIuO2dLP0L-W_8ZmgnVx5SwvxYCXmX7zrHYv0FeHFFR0TY2aCaWSCdjSCaXCEwiErIIlzZWNwMjU2azGhAnnTykipGqyOy-ZRB9ga9pQVPF-wQs-yj_rYUoOqXEjbg3VkcIIjjA").expect("Parsing static bootnode enr to work"),
            alias: "fluffy-1".to_string()
        },
        Bootnode{
            enr:
        Enr::from_str("enr:-Ia4QM4amOkJf5z84Lv5Fl0RgWeSSDUekwnOPRn6XA1eMWgrHwWmn_gJGtOeuVfuX7ywGuPMRwb0odqQ9N_w_2Qc53gTY2aCaWSCdjSCaXCEwiErIYlzZWNwMjU2azGhAzaQEdPmz9SHiCw2I5yVAO8sriQ-mhC5yB7ea1u4u5QZg3VkcIIjjA").expect("Parsing static bootnode enr to work"),
            alias: "fluffy-2".to_string()
        },
        Bootnode{
            enr:
        Enr::from_str("enr:-Ia4QKVuHjNafkYuvhU7yCvSarNIVXquzJ8QOp5YbWJRIJw_EDVOIMNJ_fInfYoAvlRCHEx9LUQpYpqJa04pUDU21uoTY2aCaWSCdjSCaXCEwiErQIlzZWNwMjU2azGhA47eAW5oIDJAqxxqI0sL0d8ttXMV0h6sRIWU4ZwS4pYfg3VkcIIjjA").expect("Parsing static bootnode enr to work"),
            alias: "fluffy-3".to_string()
        },
        Bootnode{
            enr:
        Enr::from_str("enr:-Ia4QIU9U3zrP2DM7sfpgLJbbYpg12sWeXNeYcpKN49-6fhRCng0IUoVRI2E51mN-2eKJ4tbTimxNLaAnbA7r7fxVjcTY2aCaWSCdjSCaXCEwiErQYlzZWNwMjU2azGhAxOroJ3HceYvdD2yK1q9w8c9tgrISJso8q_JXI6U0Xwng3VkcIIjjA").expect("Parsing static bootnode enr to work"),
            alias: "fluffy-4".to_string()
        },

        // Ultralight bootstrap nodes
        Bootnode{
            enr:
        Enr::from_str("enr:-IS4QFV_wTNknw7qiCGAbHf6LxB-xPQCktyrCEZX-b-7PikMOIKkBg-frHRBkfwhI3XaYo_T-HxBYmOOQGNwThkBBHYDgmlkgnY0gmlwhKRc9_OJc2VjcDI1NmsxoQKHPt5CQ0D66ueTtSUqwGjfhscU_LiwS28QvJ0GgJFd-YN1ZHCCE4k").expect("Parsing static bootnode enr to work"),
            alias: "ultralight-1".to_string()
        },
        Bootnode{
            enr:
        Enr::from_str("enr:-IS4QDpUz2hQBNt0DECFm8Zy58Hi59PF_7sw780X3qA0vzJEB2IEd5RtVdPUYZUbeg4f0LMradgwpyIhYUeSxz2Tfa8DgmlkgnY0gmlwhKRc9_OJc2VjcDI1NmsxoQJd4NAVKOXfbdxyjSOUJzmA4rjtg43EDeEJu1f8YRhb_4N1ZHCCE4o").expect("Parsing static bootnode enr to work"),
            alias: "ultralight-2".to_string()
        },
        Bootnode{
            enr:
        Enr::from_str("enr:-IS4QGG6moBhLW1oXz84NaKEHaRcim64qzFn1hAG80yQyVGNLoKqzJe887kEjthr7rJCNlt6vdVMKMNoUC9OCeNK-EMDgmlkgnY0gmlwhKRc9-KJc2VjcDI1NmsxoQLJhXByb3LmxHQaqgLDtIGUmpANXaBbFw3ybZWzGqb9-IN1ZHCCE4k").expect("Parsing static bootnode enr to work"),
            alias: "ultralight-3".to_string()
        },
        Bootnode{
            enr:
        Enr::from_str("enr:-IS4QA5hpJikeDFf1DD1_Le6_ylgrLGpdwn3SRaneGu9hY2HUI7peHep0f28UUMzbC0PvlWjN8zSfnqMG07WVcCyBhADgmlkgnY0gmlwhKRc9-KJc2VjcDI1NmsxoQJMpHmGj1xSP1O-Mffk_jYIHVcg6tY5_CjmWVg1gJEsPIN1ZHCCE4o").expect("Parsing static bootnode enr to work"),
            alias: "ultralight-4".to_string()
        }];

    // AngelFood bootstrap nodes
    pub static ref ANGELFOOD_BOOTNODES: Vec<Bootnode> = vec![
        Bootnode{
            enr: Enr::from_str("enr:-LC4QMnoW2m4YYQRPjZhJ5hEpcA6a3V7iQs3slQ1TepzKBIVWQtjpcHsPINc0TcheMCbx6I2n5aax8M3AtUObt74ySUCY6p0IDVhYzI2NzViNGRmMjNhNmEwOWVjNDFkZTRlYTQ2ODQxNjk2ZTQ1YzSCaWSCdjSCaXCEQONKaYlzZWNwMjU2azGhAvZgYbpA9G8NQ6X4agu-R7Ymtu0hcX6xBQ--UEel_b6Pg3VkcIIjKA").expect("Parsing static bootnode enr to work"),
            alias: "angelfood-trin-1".to_string()
        }];
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
