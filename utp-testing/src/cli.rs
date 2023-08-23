use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "utP test app CLI")]
pub struct TestAppConfig {
    #[arg(long, required = true)]
    pub udp_listen_address: String,

    #[arg(long, required = true)]
    pub rpc_listen_address: String,

    #[arg(long, required = true)]
    pub udp_port: u16,

    #[arg(long, required = true)]
    pub rpc_port: u16,
}
