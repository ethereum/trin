// This number was chosen after some experimentation with different batch sizes.
// It was found that a batch size of 128 was the best compromise between speed and
// successful response rate. This number may change in the future.
pub const BATCH_SIZE: u64 = 128;

// PANDAOPS refers to the group of clients provisioned by the EF devops team.
// These are only intended to be used by core team members who have access to the nodes.
// If you don't have access to the PANDAOPS nodes, but still want to use the bridge feature, let us
// know on Discord or Github and we'll prioritize support for any provider.
pub const PANDAOPS_URL: &str = "https://geth-lighthouse.mainnet.ethpandaops.io/";
pub const BEACON_PANDAOPS_URL: &str = "https://beacon.mainnet.ethpandaops.io/";
