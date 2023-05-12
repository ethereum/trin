use std::str::FromStr;

use anyhow::anyhow;

use crate::types::enr::Enr;

lazy_static! {
    pub static ref DEFAULT_BOOTNODES: Vec<Enr> = vec![
        // https://github.com/ethereum/portal-network-specs/blob/master/testnet.md
        // Trin bootstrap nodes
        // trin-ams3-1
        Enr::from_str("enr:-I24QDy_atpK3KlPjl6X5yIrK7FosdHI1cW0I0MeiaIVuYg3AEEH9tRSTyFb2k6lpUiFsqxt8uTW3jVMUzoSlQf5OXYBY4d0IDAuMS4wgmlkgnY0gmlwhKEjVaWJc2VjcDI1NmsxoQOSGugH1jSdiE_fRK1FIBe9oLxaWH8D_7xXSnaOVBe-SYN1ZHCCIyg").expect("Parsing static bootnode enr to work"),
        // trin-nyc1-1
        Enr::from_str("enr:-I24QIdQtNSyUNcoyR4R7pWLfGj0YuX550Qld0HuInYo_b7JE9CIzmi2TF9hPg-OFL3kebYgLjnPkRu17niXB6xKQugBY4d0IDAuMS4wgmlkgnY0gmlwhJO2oc6Jc2VjcDI1NmsxoQJal-rNlNBoOMikJ7PcGk1h6Mlt_XtTWihHwOKmFVE-GoN1ZHCCIyg").expect("Parsing static bootnode enr to work"),
        // trin-sgp1-1
        Enr::from_str("enr:-I24QI_QC3IsdxHUX_jk8udbQ4U2bv-Gncsdg9GzgaPU95ayHdAwnH7mY22A6ggd_aZegFiBBOAPamkP2pyHbjNH61sBY4d0IDAuMS4wgmlkgnY0gmlwhJ31OTWJc2VjcDI1NmsxoQMo_DLYhV1nqAVC1ayEIwrhoFCcHvWuhC_J-w-n_4aHP4N1ZHCCIyg").expect("Parsing static bootnode enr to work"),

        // Fluffy bootstrap nodes
        Enr::from_str("enr:-IS4QGeIshGTdA7EpUV9SYYKUWxzMg1mihWOEg-_Kf1lndQRTYY5jXRIiZnL8XJ-wnwuUXnZvwLjhbaXfOAhf_qNkUUBgmlkgnY0gmlwhEFsKgOJc2VjcDI1NmsxoQPlKmIWSMXPn_FgUiVnopQ_Y0T64f7zKIAu26T8BhVPdIN1ZHCCI40").expect("Parsing static bootnode enr to work"),
        Enr::from_str("enr:-IS4QBDo5n39042MrxWU8tOmGgleD2tc42ODP-EMoUEdFBXxchTyNRVjlcxfajOwnUmi9Ro-BS5_Z5JwpWW58kUarLwBgmlkgnY0gmlwhEFsKgOJc2VjcDI1NmsxoQLj_0Y6aW4yEhZolYwQRW6Tya10jVB_UB1vplJzC4o0hYN1ZHCCI44").expect("Parsing static bootnode enr to work"),
        Enr::from_str("enr:-IS4QFzPZ7Cc7BGYSQBlWdkPyep8XASIVlviHbi-ZzcCdvkcE382unsRq8Tb_dYQFNZFWLqhJsJljdgJ7WtWP830Gq0BgmlkgnY0gmlwhEFsKq6Jc2VjcDI1NmsxoQPjz2Y1Hsa0edvzvn6-OADS3re-FOkSiJSmBB7DVrsAXIN1ZHCCI40").expect("Parsing static bootnode enr to work"),
        Enr::from_str("enr:-IS4QHA1PJCdmESyKkQsBmMUhSkRDgwKjwTtPZYMcbMiqCb8I1Xt-Xyh9Nj0yWeIN4S3sOpP9nxI6qCCR1Nf4LjY0IABgmlkgnY0gmlwhEFsKq6Jc2VjcDI1NmsxoQLMWRNAgXVdGc0Ij9RZCPsIyrrL67eYfE9PPwqwRvmZooN1ZHCCI44").expect("Parsing static bootnode enr to work"),

        // Ultralight bootstrap nodes
        Enr::from_str("enr:-IS4QFV_wTNknw7qiCGAbHf6LxB-xPQCktyrCEZX-b-7PikMOIKkBg-frHRBkfwhI3XaYo_T-HxBYmOOQGNwThkBBHYDgmlkgnY0gmlwhKRc9_OJc2VjcDI1NmsxoQKHPt5CQ0D66ueTtSUqwGjfhscU_LiwS28QvJ0GgJFd-YN1ZHCCE4k").expect("Parsing static bootnode enr to work"),
        Enr::from_str("enr:-IS4QDpUz2hQBNt0DECFm8Zy58Hi59PF_7sw780X3qA0vzJEB2IEd5RtVdPUYZUbeg4f0LMradgwpyIhYUeSxz2Tfa8DgmlkgnY0gmlwhKRc9_OJc2VjcDI1NmsxoQJd4NAVKOXfbdxyjSOUJzmA4rjtg43EDeEJu1f8YRhb_4N1ZHCCE4o").expect("Parsing static bootnode enr to work"),
        Enr::from_str("enr:-IS4QGG6moBhLW1oXz84NaKEHaRcim64qzFn1hAG80yQyVGNLoKqzJe887kEjthr7rJCNlt6vdVMKMNoUC9OCeNK-EMDgmlkgnY0gmlwhKRc9-KJc2VjcDI1NmsxoQLJhXByb3LmxHQaqgLDtIGUmpANXaBbFw3ybZWzGqb9-IN1ZHCCE4k").expect("Parsing static bootnode enr to work"),
        Enr::from_str("enr:-IS4QA5hpJikeDFf1DD1_Le6_ylgrLGpdwn3SRaneGu9hY2HUI7peHep0f28UUMzbC0PvlWjN8zSfnqMG07WVcCyBhADgmlkgnY0gmlwhKRc9-KJc2VjcDI1NmsxoQJMpHmGj1xSP1O-Mffk_jYIHVcg6tY5_CjmWVg1gJEsPIN1ZHCCE4o").expect("Parsing static bootnode enr to work"),
            ];
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Bootnodes {
    Default,
    // use explicit None here instead of Option<Bootnodes>, since default value is DEFAULT_BOOTNODES
    None,
    Custom(Vec<Enr>),
}

impl From<Bootnodes> for Vec<Enr> {
    fn from(bootnodes: Bootnodes) -> Self {
        match bootnodes {
            Bootnodes::Default => DEFAULT_BOOTNODES.to_vec(),
            Bootnodes::None => vec![],
            Bootnodes::Custom(bootnodes) => bootnodes,
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
                    Ok(val) => Ok(Bootnodes::Custom(val)),
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
    fn test_bootnodes_default_with_testnet_bootnodes() {
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
