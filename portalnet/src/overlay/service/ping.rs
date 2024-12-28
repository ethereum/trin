use std::marker::Sync;

use discv5::{enr::NodeId, rpc::RequestId};
use ethportal_api::{
    types::{
        distance::Metric,
        enr::Enr,
        ping_extensions::{
            decode::DecodedExtension,
            extensions::{
                type_0::ClientInfoRadiusCapabilities,
                type_1::BasicRadius,
                type_2::HistoryRadius,
                type_65535::{ErrorCodes, PingError},
            },
            CustomPayloadExtensionsFormat, Extensions,
        },
        portal_wire::{CustomPayload, Ping, Pong, Request},
    },
    OverlayContentKey,
};
use tracing::{trace, warn};
use trin_storage::ContentStore;
use trin_validation::validator::Validator;

use super::OverlayService;
use crate::{
    overlay::{
        command::OverlayCommand,
        ping_extensions::PingExtension,
        request::{OverlayRequest, RequestDirection},
    },
    types::node::Node,
};

impl<
        TContentKey: 'static + OverlayContentKey + Send + Sync,
        TMetric: Metric + Send + Sync,
        TValidator: 'static + Validator<TContentKey> + Send + Sync,
        TStore: 'static + ContentStore<Key = TContentKey> + Send + Sync,
        TPingExtensions: 'static + PingExtension + Send + Sync,
    > OverlayService<TContentKey, TMetric, TValidator, TStore, TPingExtensions>
{
    /// Builds a `Pong` response for a `Ping` request.
    pub(super) fn handle_ping(
        &self,
        request: Ping,
        source: &NodeId,
        request_id: RequestId,
    ) -> Pong {
        trace!(
            protocol = %self.protocol,
            request.source = %source,
            request.discv5.id = %request_id,
            "Handling Ping message {request}",
        );

        let Ok(ping_custom_payload): anyhow::Result<CustomPayloadExtensionsFormat> =
            request.custom_payload.clone().try_into()
        else {
            warn!(
                protocol = %self.protocol,
                request.source = %source,
                request.discv5.id = %request_id,
                "Invalid Ping message: {request}",
            );
            return Pong {
                enr_seq: self.local_enr().seq(),
                custom_payload: PingError::new(ErrorCodes::FailedToDecodePayload).into(),
            };
        };

        let extension_type: Extensions = match ping_custom_payload.r#type.try_into() {
            Ok(extension) => extension,
            Err(_) => {
                warn!(
                    protocol = %self.protocol,
                    request.source = %source,
                    request.discv5.id = %request_id,
                    "Invalid Ping message: {request}",
                );
                return Pong {
                    enr_seq: self.local_enr().seq(),
                    custom_payload: PingError::new(ErrorCodes::ExtensionNotSupported).into(),
                };
            }
        };

        if !self.ping_extensions.is_supported(extension_type) {
            warn!(
                protocol = %self.protocol,
                request.source = %source,
                request.discv5.id = %request_id,
                "Unsupported extension type: {extension_type:?}",
            );
            return Pong {
                enr_seq: self.local_enr().seq(),
                custom_payload: PingError::new(ErrorCodes::ExtensionNotSupported).into(),
            };
        }

        match extension_type {
            Extensions::Capabilities => Pong {
                enr_seq: self.local_enr().seq(),
                custom_payload: self.create_capabilities().into(),
            },
            Extensions::BasicRadius => {
                let data_radius = self.data_radius();
                let basic_payload = BasicRadius { data_radius };
                Pong {
                    enr_seq: self.local_enr().seq(),
                    custom_payload: basic_payload.into(),
                }
            }
            Extensions::HistoryRadius => {
                let history_payload = HistoryRadius {
                    data_radius: self.data_radius(),
                    ephemeral_header_count: 0,
                };
                Pong {
                    enr_seq: self.local_enr().seq(),
                    custom_payload: history_payload.into(),
                }
            }
            Extensions::Error => {
                warn!(
                    protocol = %self.protocol,
                    request.source = %source,
                    request.discv5.id = %request_id,
                    "Invalid Ping message, Error's should only be received from pongs: {request}",
                );
                Pong {
                    enr_seq: self.local_enr().seq(),
                    custom_payload: PingError::new(ErrorCodes::SystemError).into(),
                }
            }
        }
    }

    /// Processes a ping request from some source node.
    pub(super) fn process_ping(&self, ping: Ping, source: NodeId) {
        // If the node is in the routing table, then check if we need to update the node.
        if let Some(mut node) = self.kbuckets.entry(source).present_or_pending() {
            // TODO: How do we handle data in the custom payload? This is unique to each overlay
            // network, so there may need to be some way to parameterize the update for a
            // ping/pong.

            // If the ENR sequence number in pong is less than the ENR sequence number for the
            // routing table entry, then request the node.
            if node.enr().seq() < ping.enr_seq {
                self.request_node(&node.enr());
            }

            let extension = match DecodedExtension::try_from(ping.custom_payload) {
                Ok(extension) => extension,
                Err(err) => {
                    warn!(
                        protocol = %self.protocol,
                        request.source = %source,
                        "Failed to decode custom payload during process_ping: {err:?}",
                    );
                    return;
                }
            };

            if !self.ping_extensions.is_supported(extension.clone().into()) {
                warn!(
                    protocol = %self.protocol,
                    request.source = %source,
                    "Extension type isn't supported on this subnetwork: {extension:?}",
                );
                return;
            }

            match extension {
                DecodedExtension::Capabilities(radius_capabilities) => {
                    let Ok(capabilities) = radius_capabilities.capabilities() else {
                        warn!(
                            protocol = %self.protocol,
                            request.source = %source,
                            "Capabilities weren't decoded correctly",
                        );
                        return;
                    };
                    if node.data_radius != radius_capabilities.data_radius
                        || node.capabilities != Some(capabilities.clone())
                    {
                        node.set_data_radius(radius_capabilities.data_radius);
                        node.set_capabilities(capabilities);
                        self.update_node(node);
                    }
                }
                DecodedExtension::BasicRadius(basic_radius) => {
                    let data_radius = basic_radius.data_radius;
                    if node.data_radius != data_radius {
                        node.set_data_radius(data_radius);
                        self.update_node(node);
                    }
                }
                DecodedExtension::HistoryRadius(history_radius) => {
                    let data_radius = history_radius.data_radius;
                    let ephemeral_header_count = history_radius.ephemeral_header_count;
                    if node.data_radius != data_radius
                        || node.ephemeral_header_count != Some(ephemeral_header_count)
                    {
                        node.set_data_radius(data_radius);
                        node.set_ephemeral_header_count(ephemeral_header_count);
                        self.update_node(node);
                    }
                }
                DecodedExtension::Error(ping_error) => {
                    warn!(
                        protocol = %self.protocol,
                        request.source = %source,
                        "Received an error response from a ping request: {ping_error:?}",
                    );
                }
            }
        }
    }

    /// Processes a Pong response.
    ///
    /// Refreshes the node if necessary. Attempts to mark the node as connected.
    pub(super) fn process_pong(&self, pong: Pong, source: Enr) {
        let node_id = source.node_id();
        trace!(
            protocol = %self.protocol,
            response.source = %node_id,
            "Processing Pong message {pong}"
        );

        // If the ENR sequence number in pong is less than the ENR sequence number for the routing
        // table entry, then request the node.
        //
        // TODO: Perform update on non-ENR node entry state. See note in `process_ping`.
        if let Some(mut node) = self.kbuckets.entry(node_id).present_or_pending() {
            if node.enr().seq() < pong.enr_seq {
                self.request_node(&node.enr());
            }

            let extension = match DecodedExtension::try_from(pong.custom_payload) {
                Ok(extension) => extension,
                Err(err) => {
                    warn!(
                        protocol = %self.protocol,
                        request.source = %source,
                        "Failed to decode custom payload during process_ping: {err:?}",
                    );
                    return;
                }
            };

            if !self.ping_extensions.is_supported(extension.clone().into()) {
                warn!(
                    protocol = %self.protocol,
                    request.source = %source,
                    "Extension type isn't supported on this subnetwork: {extension:?}",
                );
                return;
            }

            match extension {
                DecodedExtension::Capabilities(radius_capabilities) => {
                    let Ok(capabilities) = radius_capabilities.capabilities() else {
                        warn!(
                            protocol = %self.protocol,
                            request.source = %source,
                            "Capabilities weren't decoded correctly",
                        );
                        return;
                    };
                    if node.data_radius != radius_capabilities.data_radius
                        || node.compare_capabilities(&capabilities)
                    {
                        node.set_data_radius(radius_capabilities.data_radius);
                        node.set_capabilities(capabilities);
                        self.update_node(node);
                    }
                }
                DecodedExtension::BasicRadius(basic_radius) => {
                    let data_radius = basic_radius.data_radius;
                    if node.data_radius != data_radius {
                        node.set_data_radius(data_radius);
                        self.update_node(node);
                    }
                }
                DecodedExtension::HistoryRadius(history_radius) => {
                    let data_radius = history_radius.data_radius;
                    let ephemeral_header_count = history_radius.ephemeral_header_count;
                    if node.data_radius != data_radius
                        || node.ephemeral_header_count != Some(ephemeral_header_count)
                    {
                        node.set_data_radius(data_radius);
                        node.set_ephemeral_header_count(ephemeral_header_count);
                        self.update_node(node);
                    }
                }
                DecodedExtension::Error(ping_error) => {
                    warn!(
                        protocol = %self.protocol,
                        request.source = %source,
                        "Received an error response from a pong request: {ping_error:?}",
                    );
                }
            }
        }
    }

    fn create_capabilities(&self) -> ClientInfoRadiusCapabilities {
        ClientInfoRadiusCapabilities::new(self.data_radius(), self.ping_extensions.raw_extensions())
    }

    fn handle_base_extension(&self, extension: Extensions, node_id: NodeId) -> CustomPayload {
        match extension {
            Extensions::BasicRadius => BasicRadius {
                data_radius: self.data_radius(),
            }
            .into(),
            Extensions::HistoryRadius => HistoryRadius {
                data_radius: self.data_radius(),
                ephemeral_header_count: 0,
            }
            .into(),
            _ => {
                warn!(
                    protocol = %self.protocol,
                    request.dest = %node_id,
                    "Base extension wasn't implemented: {extension:?}, sending Capabilities instead this is a bug",
                );
                self.create_capabilities().into()
            }
        }
    }

    /// Submits a request to ping a destination (target) node.
    ///
    /// This can block the thread, so make sure you are not holding any lock while calling this.
    pub(super) fn ping_node(&self, node: Node) {
        trace!(
            protocol = %self.protocol,
            request.dest = %node.enr.node_id(),
            "Sending Ping message",
        );

        let custom_payload = match node.capabilities().map(|capabilities| {
            self.ping_extensions
                .newest_commonly_supported_base_extension(capabilities)
        }) {
            Some(Some(extension)) => self.handle_base_extension(extension, node.enr.node_id()),
            _ => self.create_capabilities().into(),
        };

        let ping = Request::Ping(Ping {
            enr_seq: self.local_enr().seq(),
            custom_payload,
        });
        let request = OverlayRequest::new(
            ping,
            RequestDirection::Outgoing {
                destination: node.enr.clone(),
            },
            None,
            None,
            None,
        );
        let _ = self.command_tx.send(OverlayCommand::Request(request));
    }
}
