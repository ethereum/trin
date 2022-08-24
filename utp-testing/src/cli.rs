use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "utP test app CLI")]
pub struct TestAppConfig {
    #[structopt(long, required = true)]
    pub udp_listen_address: String,

    #[structopt(long, required = true)]
    pub rpc_listen_address: String,

    #[structopt(long, required = true)]
    pub udp_port: u16,

    #[structopt(long, required = true)]
    pub rpc_port: u16,
}
