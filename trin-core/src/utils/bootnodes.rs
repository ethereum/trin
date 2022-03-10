use std::str::FromStr;

use anyhow::anyhow;

use crate::portalnet::Enr;

lazy_static! {
     pub static ref DEFAULT_BOOTNODES: Vec<Enr> = vec![
        Enr::from_str("enr:-IS4QBISSFfBzsBrjq61iSIxPMfp5ShBTW6KQUglzH_tj8_SJaehXdlnZI-NAkTGeoclwnTB-pU544BQA44BiDZ2rkMBgmlkgnY0gmlwhKEjVaWJc2VjcDI1NmsxoQOSGugH1jSdiE_fRK1FIBe9oLxaWH8D_7xXSnaOVBe-SYN1ZHCCIyg").unwrap(),
        Enr::from_str("enr:-IS4QPUT9hwV4YfNTxazR2ltch4qKzvX_HwxQBw8gUN3q1MDfNyaD1EHc1wQZRTUzQQD-RVYx3h4nA1Sqk0Wx9DwzNABgmlkgnY0gmlwhM69ZOyJc2VjcDI1NmsxoQLaI-m2CDIjpwcnUf1ESspvOctJLpIrLA8AZ4zbo_1bFIN1ZHCCIyg").unwrap(),
        Enr::from_str("enr:-IS4QB77AROcGX-TSkY-U-SaZJ5ma9ICQj6ETO3FqUdCnTZeJ0mDrdCKUqd5AQ0jrHa7m9-mOLvFFKMV_-tBD8uDYZUBgmlkgnY0gmlwhJ_fCDaJc2VjcDI1NmsxoQN9rahqamBOJfj4u6yssJQJ1-EZoyAw-7HIgp1FwNUdnoN1ZHCCIyg").unwrap()
    ];
}

pub fn parse_bootnodes(bootnodes: &[String]) -> anyhow::Result<Vec<Enr>> {
    let default = vec!["default".to_string()];
    if bootnodes == default {
        Ok(DEFAULT_BOOTNODES.to_vec())
    } else {
        let bootnodes: Result<Vec<Enr>, _> = bootnodes
            .iter()
            .map(|nodestr| Enr::from_str(nodestr))
            .collect();
        match bootnodes {
            Ok(val) => Ok(val),
            Err(_) => Err(anyhow!("Invalid bootnode argument")),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cli::TrinConfig;
    use rstest::rstest;

    #[test]
    fn test_parse_bootnodes_default_flag() {
        let config = TrinConfig::new_from(["trin", "--bootnodes", "default"].iter()).unwrap();
        let actual = parse_bootnodes(&config.bootnodes).unwrap();
        assert_eq!(actual, DEFAULT_BOOTNODES.to_vec());
    }

    #[rstest]
    #[case("invalid")]
    #[case("enr:-IS4QBISSFfBzsBrjq61iSIxPMfp5ShBTW6KQUglzH_tj8_SJaehXdlnZI-NAkTGeoclwnTB-pU544BQA44BiDZ2rkMBgmlkgnY0gmlwhKEjVaWJc2VjcDI1NmsxoQOSGugH1jSdiE_fRK1FIBe9oLxaWH8D_7xXSnaOVBe-SYN1ZHCCIyg,invalid")]
    #[should_panic]
    fn test_parse_bootnodes_invalid_enr(#[case] bootnode: &str) {
        let config = TrinConfig::new_from(["trin", "--bootnodes", bootnode].iter()).unwrap();
        parse_bootnodes(&config.bootnodes).unwrap();
    }

    #[rstest]
    #[case("enr:-IS4QBISSFfBzsBrjq61iSIxPMfp5ShBTW6KQUglzH_tj8_SJaehXdlnZI-NAkTGeoclwnTB-pU544BQA44BiDZ2rkMBgmlkgnY0gmlwhKEjVaWJc2VjcDI1NmsxoQOSGugH1jSdiE_fRK1FIBe9oLxaWH8D_7xXSnaOVBe-SYN1ZHCCIyg", 1)]
    #[case("enr:-IS4QBISSFfBzsBrjq61iSIxPMfp5ShBTW6KQUglzH_tj8_SJaehXdlnZI-NAkTGeoclwnTB-pU544BQA44BiDZ2rkMBgmlkgnY0gmlwhKEjVaWJc2VjcDI1NmsxoQOSGugH1jSdiE_fRK1FIBe9oLxaWH8D_7xXSnaOVBe-SYN1ZHCCIyg,enr:-IS4QPUT9hwV4YfNTxazR2ltch4qKzvX_HwxQBw8gUN3q1MDfNyaD1EHc1wQZRTUzQQD-RVYx3h4nA1Sqk0Wx9DwzNABgmlkgnY0gmlwhM69ZOyJc2VjcDI1NmsxoQLaI-m2CDIjpwcnUf1ESspvOctJLpIrLA8AZ4zbo_1bFIN1ZHCCIyg", 2)]
    #[case("enr:-IS4QBISSFfBzsBrjq61iSIxPMfp5ShBTW6KQUglzH_tj8_SJaehXdlnZI-NAkTGeoclwnTB-pU544BQA44BiDZ2rkMBgmlkgnY0gmlwhKEjVaWJc2VjcDI1NmsxoQOSGugH1jSdiE_fRK1FIBe9oLxaWH8D_7xXSnaOVBe-SYN1ZHCCIyg,enr:-IS4QPUT9hwV4YfNTxazR2ltch4qKzvX_HwxQBw8gUN3q1MDfNyaD1EHc1wQZRTUzQQD-RVYx3h4nA1Sqk0Wx9DwzNABgmlkgnY0gmlwhM69ZOyJc2VjcDI1NmsxoQLaI-m2CDIjpwcnUf1ESspvOctJLpIrLA8AZ4zbo_1bFIN1ZHCCIyg,enr:-IS4QB77AROcGX-TSkY-U-SaZJ5ma9ICQj6ETO3FqUdCnTZeJ0mDrdCKUqd5AQ0jrHa7m9-mOLvFFKMV_-tBD8uDYZUBgmlkgnY0gmlwhJ_fCDaJc2VjcDI1NmsxoQN9rahqamBOJfj4u6yssJQJ1-EZoyAw-7HIgp1FwNUdnoN1ZHCCIyg", 3)]
    fn test_parse_bootnodes_valid_enrs(#[case] bootnode: &str, #[case] expected_length: usize) {
        let config = TrinConfig::new_from(["trin", "--bootnodes", bootnode].iter()).unwrap();
        let bootnodes = parse_bootnodes(&config.bootnodes).unwrap();
        assert_eq!(bootnodes.len(), expected_length);
    }
}
