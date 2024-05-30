use std::str::FromStr;

use anyhow::anyhow;

use crate::types::enr::Enr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bootnode {
    pub enr: Enr,
    pub alias: String,
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
        Enr::from_str("enr:-IS4QGUtAA29qeT3cWVr8lmJfySmkceR2wp6oFQtvO_uMe7KWaK_qd1UQvd93MJKXhMnubSsTQPJ6KkbIu0ywjvNdNEBgmlkgnY0gmlwhMIhKO6Jc2VjcDI1NmsxoQJ508pIqRqsjsvmUQfYGvaUFTxfsELPso_62FKDqlxI24N1ZHCCI40").expect("Parsing static bootnode enr to work"),
            alias: "fluffy-1".to_string()
        },
        Bootnode{
            enr:
        Enr::from_str("enr:-IS4QNaaoQuHGReAMJKoDd6DbQKMbQ4Mked3Gi3GRatwgRVVPXynPlO_-gJKRF_ZSuJr3wyHfwMHyJDbd6q1xZQVZ2kBgmlkgnY0gmlwhMIhKO6Jc2VjcDI1NmsxoQM2kBHT5s_Uh4gsNiOclQDvLK4kPpoQucge3mtbuLuUGYN1ZHCCI44").expect("Parsing static bootnode enr to work"),
            alias: "fluffy-2".to_string()
        },
        Bootnode{
            enr:
        Enr::from_str("enr:-IS4QBdIjs6S1ZkvlahSkuYNq5QW3DbD-UDcrm1l81f2PPjnNjb_NDa4B5x4olHCXtx0d2ZeZBHQyoHyNnuVZ-P1GVkBgmlkgnY0gmlwhMIhKO-Jc2VjcDI1NmsxoQOO3gFuaCAyQKscaiNLC9HfLbVzFdIerESFlOGcEuKWH4N1ZHCCI40").expect("Parsing static bootnode enr to work"),
            alias: "fluffy-3".to_string()
        },
        Bootnode{
            enr:
        Enr::from_str("enr:-IS4QM731tV0CvQXLTDcZNvgFyhhpAjYDKU5XLbM7sZ1WEzIRq4zsakgrv3KO3qyOYZ8jFBK-VzENF8o-vnykuQ99iABgmlkgnY0gmlwhMIhKO-Jc2VjcDI1NmsxoQMTq6Cdx3HmL3Q9sitavcPHPbYKyEibKPKvyVyOlNF8J4N1ZHCCI44").expect("Parsing static bootnode enr to work"),
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

impl From<Enr> for Bootnode {
    fn from(enr: Enr) -> Self {
        for bootnode in DEFAULT_BOOTNODES.clone().into_iter() {
            if bootnode.enr == enr {
                return bootnode;
            }
        }
        Bootnode {
            enr,
            alias: "custom".to_string(),
        }
    }
}

impl From<Bootnodes> for Vec<Enr> {
    fn from(bootnodes: Bootnodes) -> Self {
        match bootnodes {
            Bootnodes::Default => DEFAULT_BOOTNODES.iter().map(|bn| bn.enr.clone()).collect(),
            Bootnodes::None => vec![],
            Bootnodes::Custom(bootnodes) => bootnodes.iter().map(|bn| bn.enr.clone()).collect(),
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use crate::types::cli::TrinConfig;
    use rstest::rstest;

    #[test_log::test]
    fn test_bootnodes_default_with_angelfood_bootnodes() {
        let config = TrinConfig::new_from(["trin"].iter()).unwrap();
        assert_eq!(config.bootnodes, Bootnodes::Default);
        let bootnodes: Vec<Enr> = config.bootnodes.into();
        assert_eq!(bootnodes.len(), 11);
    }

    #[test_log::test]
    fn test_bootnodes_default_with_no_bootnodes() {
        let config = TrinConfig::new_from(["trin", "--bootnodes", "none"].iter()).unwrap();
        assert_eq!(config.bootnodes, Bootnodes::None);
        let bootnodes: Vec<Enr> = config.bootnodes.into();
        assert_eq!(bootnodes.len(), 0);
    }

    #[rstest]
    #[case("invalid")]
    #[case("enr:-IS4QBISSFfBzsBrjq61iSIxPMfp5ShBTW6KQUglzH_tj8_SJaehXdlnZI-NAkTGeoclwnTB-pU544BQA44BiDZ2rkMBgmlkgnY0gmlwhKEjVaWJc2VjcDI1NmsxoQOSGugH1jSdiE_fRK1FIBe9oLxaWH8D_7xXSnaOVBe-SYN1ZHCCIyg,invalid")]
    #[should_panic]
    fn test_bootnodes_invalid_enr(#[case] bootnode: &str) {
        TrinConfig::new_from(["trin", "--bootnodes", bootnode].iter()).unwrap();
    }

    #[rstest]
    #[case("enr:-IS4QBISSFfBzsBrjq61iSIxPMfp5ShBTW6KQUglzH_tj8_SJaehXdlnZI-NAkTGeoclwnTB-pU544BQA44BiDZ2rkMBgmlkgnY0gmlwhKEjVaWJc2VjcDI1NmsxoQOSGugH1jSdiE_fRK1FIBe9oLxaWH8D_7xXSnaOVBe-SYN1ZHCCIyg", 1)]
    #[case("enr:-IS4QBISSFfBzsBrjq61iSIxPMfp5ShBTW6KQUglzH_tj8_SJaehXdlnZI-NAkTGeoclwnTB-pU544BQA44BiDZ2rkMBgmlkgnY0gmlwhKEjVaWJc2VjcDI1NmsxoQOSGugH1jSdiE_fRK1FIBe9oLxaWH8D_7xXSnaOVBe-SYN1ZHCCIyg,enr:-IS4QPUT9hwV4YfNTxazR2ltch4qKzvX_HwxQBw8gUN3q1MDfNyaD1EHc1wQZRTUzQQD-RVYx3h4nA1Sqk0Wx9DwzNABgmlkgnY0gmlwhM69ZOyJc2VjcDI1NmsxoQLaI-m2CDIjpwcnUf1ESspvOctJLpIrLA8AZ4zbo_1bFIN1ZHCCIyg", 2)]
    #[case("enr:-IS4QBISSFfBzsBrjq61iSIxPMfp5ShBTW6KQUglzH_tj8_SJaehXdlnZI-NAkTGeoclwnTB-pU544BQA44BiDZ2rkMBgmlkgnY0gmlwhKEjVaWJc2VjcDI1NmsxoQOSGugH1jSdiE_fRK1FIBe9oLxaWH8D_7xXSnaOVBe-SYN1ZHCCIyg,enr:-IS4QPUT9hwV4YfNTxazR2ltch4qKzvX_HwxQBw8gUN3q1MDfNyaD1EHc1wQZRTUzQQD-RVYx3h4nA1Sqk0Wx9DwzNABgmlkgnY0gmlwhM69ZOyJc2VjcDI1NmsxoQLaI-m2CDIjpwcnUf1ESspvOctJLpIrLA8AZ4zbo_1bFIN1ZHCCIyg,enr:-IS4QB77AROcGX-TSkY-U-SaZJ5ma9ICQj6ETO3FqUdCnTZeJ0mDrdCKUqd5AQ0jrHa7m9-mOLvFFKMV_-tBD8uDYZUBgmlkgnY0gmlwhJ_fCDaJc2VjcDI1NmsxoQN9rahqamBOJfj4u6yssJQJ1-EZoyAw-7HIgp1FwNUdnoN1ZHCCIyg", 3)]
    fn test_bootnodes_valid_enrs(#[case] bootnode: &str, #[case] expected_length: usize) {
        let config = TrinConfig::new_from(["trin", "--bootnodes", bootnode].iter()).unwrap();
        match config.bootnodes.clone() {
            Bootnodes::Custom(bootnodes) => {
                assert_eq!(bootnodes.len(), expected_length);
            }
            _ => panic!("Bootnodes should be custom"),
        };
        let bootnodes: Vec<Enr> = config.bootnodes.into();
        assert_eq!(bootnodes.len(), expected_length);
    }
}
