use std::env;
use std::ffi::OsString;
use structopt::StructOpt;

#[derive(StructOpt, Debug, PartialEq)]
#[structopt(
    name = "trin-devp2p2",
    version = "0.0.1",
    about = "Testing framework for portal network peer-to-peer network calls"
)]
pub struct DummyConfig {
    #[structopt(
        use_delimiter = true,
        short = "tn",
        long = "target_node",
        help = "Base64-encoded ENR's of the nodes under test"
    )]
    pub target_nodes: Vec<String>,
}

impl DummyConfig {
    pub fn new() -> Self {
        Self::new_from(env::args_os()).expect("Could not parse trin arguments")
    }

    pub fn new_from<I, T>(args: I) -> Result<Self, String>
    where
        I: Iterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let config = Self::from_iter(args);

        Ok(config)
    }
}

impl Default for DummyConfig {
    fn default() -> Self {
        Self::new()
    }
}
