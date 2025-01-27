use ethportal_api::types::{
    network::Subnetwork,
    ping_extensions::extensions::{
        type_0::ClientInfoRadiusCapabilities, type_1::BasicRadius, type_2::HistoryRadius,
    },
};
use tracing::warn;

use crate::types::node::Node;

pub fn handle_capabilities(
    radius_capabilities: ClientInfoRadiusCapabilities,
    mut node: Node,
    protocol: Subnetwork,
) -> Option<Node> {
    let Ok(capabilities) = radius_capabilities.capabilities() else {
        warn!(
            protocol = %protocol,
            request.source = %node.enr.node_id(),
            "Capabilities weren't decoded correctly",
        );
        return None;
    };
    if node.data_radius != radius_capabilities.data_radius
        || node.compare_capabilities(&capabilities)
    {
        node.set_data_radius(radius_capabilities.data_radius);
        node.set_capabilities(capabilities);
        return Some(node);
    }
    None
}

pub fn handle_basic_radius(basic_radius: BasicRadius, mut node: Node) -> Option<Node> {
    let data_radius = basic_radius.data_radius;
    if node.data_radius != data_radius {
        node.set_data_radius(data_radius);
        return Some(node);
    }
    None
}

pub fn handle_history_radius(history_radius: HistoryRadius, mut node: Node) -> Option<Node> {
    let data_radius = history_radius.data_radius;
    let ephemeral_header_count = history_radius.ephemeral_header_count;
    if node.data_radius != data_radius
        || node.ephemeral_header_count != Some(ephemeral_header_count)
    {
        node.set_data_radius(data_radius);
        node.set_ephemeral_header_count(ephemeral_header_count);
        return Some(node);
    }
    None
}
